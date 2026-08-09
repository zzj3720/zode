use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use aimux_core::{
    content::ContentPart,
    language_model::LanguageModel,
    language_model_message::{LanguageModelPrompt, LanguageModelPromptMessage},
    message::Role,
    options::{CallOptions, TimeoutConfiguration},
    stream_part::StreamPart,
    tool::{FunctionTool, Tool},
    types::FinishReasonUnified,
};
use aimux_providers::{
    anthropic::{AnthropicConfig, AnthropicProvider},
    openai::{OpenAIConfig, OpenAIProvider},
};
use futures_util::StreamExt;
use getrandom::fill as fill_random;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use ulid::Ulid;
use url::Url;

use crate::{
    domain::{
        DurablePayload, ProviderExecutionSelection, ToolCall, TranscriptMessage, TranscriptRole,
        MAX_PROVIDER_EXECUTION_OPTIONS_BYTES,
    },
    runtime::{ModelError, ModelExecutor, ModelOutcome, ModelRequest},
};

const REPLICA_SCHEMA: &str = "zode.auth-replica.record.v1";
const RECEIPT_SCHEMA: &str = "zode.auth-replica.receipt.v1";
const INSTALL_SCHEMA: &str = "zode.auth-replica.install.v1";
const TOMBSTONE_SCHEMA: &str = "zode.auth-replica.tombstone.v1";
const SECRET_ENCODING: &str = "application/zode-secret-envelope";
const CREDENTIAL_SCHEMA_OPENAI: &str = "openai-compatible.api-key.v1";
const CREDENTIAL_SCHEMA_ANTHROPIC: &str = "anthropic.api-key.v1";
const MAX_SECRET_BYTES: usize = 64 * 1024;
pub const MAX_REPLICA_REQUEST_BYTES: usize = 128 * 1024;
const MAX_NAME_BYTES: usize = 256;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 1_024;
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum ReplicaError {
    #[error("credential replicas are not configured")]
    Disabled,
    #[error("credential replica request is invalid")]
    Invalid,
    #[error("credential replica conflicts with an existing revision")]
    Conflict,
    #[error("credential replica was not found")]
    NotFound,
    #[error("credential replica is unavailable")]
    Unavailable,
    #[error("credential replica storage failed")]
    Storage(#[source] std::io::Error),
    #[error("credential replica record is invalid")]
    Record(#[source] serde_json::Error),
    #[error("credential replica secret is unavailable")]
    SecretUnavailable,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaInstallRequest {
    pub schema: String,
    pub authority_id: String,
    pub provider: String,
    pub kind: String,
    pub revision: u64,
    pub credential_schema: String,
    #[serde(default)]
    pub expires_at_ms: Option<i64>,
    pub secret: ReplicaSecretEnvelope,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaSecretEnvelope {
    pub encoding: String,
    pub payload: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaTombstoneRequest {
    pub schema: String,
    pub authority_id: String,
    pub provider: String,
    pub revision: u64,
}

#[derive(Debug)]
pub enum ReplicaMutation {
    Install(ReplicaInstallRequest),
    Tombstone(ReplicaTombstoneRequest),
}

#[derive(Clone, Debug)]
pub struct ReplicaInstallOutcome {
    pub status: u16,
    pub metadata: ReplicaMetadata,
}

#[derive(Clone, Debug)]
pub struct ReplicaMetadata {
    pub authority_id: String,
    pub profile_id: String,
    pub provider: String,
    pub revision: u64,
    pub expires_at_ms: Option<i64>,
    pub status: &'static str,
}

#[derive(Clone, Debug)]
pub struct ResolvedCredential {
    pub revision: u64,
    pub credential_schema: String,
    pub secret: String,
}

#[derive(Clone)]
pub struct ReplicaStore {
    root: Option<PathBuf>,
    mutation: Arc<Mutex<()>>,
}

impl ReplicaStore {
    pub fn open(directory: Option<&Path>) -> Result<Self, ReplicaError> {
        let root = match directory {
            Some(directory) => {
                fs::create_dir_all(directory).map_err(ReplicaError::Storage)?;
                ensure_private_directory(directory)?;
                Some(fs::canonicalize(directory).map_err(ReplicaError::Storage)?)
            }
            None => None,
        };
        Ok(Self {
            root,
            mutation: Arc::new(Mutex::new(())),
        })
    }

    pub fn install(
        &self,
        profile_id: &str,
        authority_id: &str,
        idempotency_key: &str,
        request: ReplicaInstallRequest,
    ) -> Result<ReplicaInstallOutcome, ReplicaError> {
        self.apply(
            profile_id,
            authority_id,
            idempotency_key,
            ReplicaMutation::Install(request),
        )
    }

    pub fn apply(
        &self,
        profile_id: &str,
        authority_id: &str,
        idempotency_key: &str,
        mutation: ReplicaMutation,
    ) -> Result<ReplicaInstallOutcome, ReplicaError> {
        validate_mutation(profile_id, authority_id, idempotency_key, &mutation)?;
        let root = self.root.as_deref().ok_or(ReplicaError::Disabled)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| ReplicaError::Unavailable)?;
        let key = self.load_or_create_key()?;
        let fingerprint = request_fingerprint(&key, profile_id, idempotency_key, &mutation)?;
        let provider = mutation_provider(&mutation);
        let revision = mutation_revision(&mutation);
        let receipt_path = receipt_path(root, authority_id, profile_id, idempotency_key);
        if receipt_path.exists() {
            let receipt = read_receipt(&receipt_path)?;
            validate_receipt(&receipt, authority_id, profile_id)?;
            if receipt
                .fingerprint
                .as_bytes()
                .ct_eq(fingerprint.as_bytes())
                .into()
            {
                return outcome_from_receipt(&receipt);
            }
            return Err(ReplicaError::Conflict);
        }

        let path = replica_path(root, authority_id, profile_id);
        if path.exists() {
            let record = read_record(&path)?;
            validate_record(&record, authority_id, profile_id)?;
            if record.provider != provider {
                return Err(ReplicaError::Conflict);
            }
            if record.revision == revision {
                if record
                    .fingerprint
                    .as_bytes()
                    .ct_eq(fingerprint.as_bytes())
                    .into()
                {
                    let outcome = ReplicaInstallOutcome {
                        status: record.response_status,
                        metadata: metadata_from_record(&record),
                    };
                    write_receipt(&receipt_path, &receipt_from_record(&record, &fingerprint))?;
                    return Ok(outcome);
                }
                return Err(ReplicaError::Conflict);
            }
            if revision < record.revision {
                return Err(ReplicaError::Conflict);
            }
        }

        let record = match mutation {
            ReplicaMutation::Install(request) => ReplicaRecord {
                schema: REPLICA_SCHEMA.to_owned(),
                authority_id: authority_id.to_owned(),
                profile_id: profile_id.to_owned(),
                provider: request.provider,
                kind: Some(request.kind),
                revision: request.revision,
                credential_schema: Some(request.credential_schema),
                expires_at_ms: request.expires_at_ms,
                fingerprint,
                response_status: 201,
                status: "ready".to_owned(),
                secret: Some(request.secret.payload),
            },
            ReplicaMutation::Tombstone(request) => ReplicaRecord {
                schema: REPLICA_SCHEMA.to_owned(),
                authority_id: authority_id.to_owned(),
                profile_id: profile_id.to_owned(),
                provider: request.provider,
                kind: None,
                revision: request.revision,
                credential_schema: None,
                expires_at_ms: None,
                fingerprint,
                response_status: 200,
                status: "tombstoned".to_owned(),
                secret: None,
            },
        };
        let bytes = serde_json::to_vec(&record).map_err(ReplicaError::Record)?;
        atomic_write(&path, &bytes)?;
        let outcome = ReplicaInstallOutcome {
            status: record.response_status,
            metadata: metadata_from_record(&record),
        };
        write_receipt(
            &receipt_path,
            &receipt_from_record(&record, &record.fingerprint),
        )?;
        Ok(outcome)
    }

    pub fn resolve(
        &self,
        authority_id: &str,
        profile_id: &str,
        provider: &str,
        minimum_revision: u64,
    ) -> Result<ResolvedCredential, ReplicaError> {
        if authority_id.is_empty()
            || profile_id.is_empty()
            || provider.is_empty()
            || minimum_revision == 0
        {
            return Err(ReplicaError::Invalid);
        }
        let root = self.root.as_deref().ok_or(ReplicaError::Disabled)?;
        let path = replica_path(root, authority_id, profile_id);
        let record = read_record(&path).map_err(|error| match error {
            ReplicaError::Storage(ref source) if source.kind() == ErrorKind::NotFound => {
                ReplicaError::SecretUnavailable
            }
            other => other,
        })?;
        validate_record(&record, authority_id, profile_id)?;
        if record.provider != provider {
            return Err(ReplicaError::SecretUnavailable);
        }
        if record.status != "ready" {
            return Err(ReplicaError::SecretUnavailable);
        }
        if record.revision < minimum_revision {
            return Err(ReplicaError::SecretUnavailable);
        }
        if record
            .expires_at_ms
            .is_some_and(|expires| expires <= current_time_ms())
        {
            return Err(ReplicaError::SecretUnavailable);
        }
        Ok(ResolvedCredential {
            revision: record.revision,
            credential_schema: record
                .credential_schema
                .ok_or(ReplicaError::SecretUnavailable)?,
            secret: record.secret.ok_or(ReplicaError::SecretUnavailable)?,
        })
    }

    pub fn read_metadata(
        &self,
        authority_id: &str,
        profile_id: &str,
    ) -> Result<ReplicaMetadata, ReplicaError> {
        if authority_id.is_empty() || profile_id.is_empty() {
            return Err(ReplicaError::Invalid);
        }
        let root = self.root.as_deref().ok_or(ReplicaError::Disabled)?;
        // The active replica record is the metadata authority. Receipts are
        // historical idempotency facts and may legitimately lag the active
        // promotion when a process crashes between the two atomic writes.
        // Reading receipts as the current projection would therefore expose
        // a stale revision after restart (the split-brain failure captured by
        // the provider recovery E2E).
        let path = replica_path(root, authority_id, profile_id);
        let record = read_record(&path).map_err(|error| match error {
            ReplicaError::Storage(ref source) if source.kind() == ErrorKind::NotFound => {
                ReplicaError::NotFound
            }
            other => other,
        })?;
        validate_record(&record, authority_id, profile_id)?;
        Ok(metadata_from_record(&record))
    }

    pub fn list_metadata(&self, authority_id: &str) -> Result<Vec<ReplicaMetadata>, ReplicaError> {
        if authority_id.is_empty() {
            return Err(ReplicaError::Invalid);
        }
        let root = self.root.as_deref().ok_or(ReplicaError::Disabled)?;
        let mut records = BTreeMap::<String, ReplicaRecord>::new();
        for entry in fs::read_dir(root).map_err(ReplicaError::Storage)? {
            let entry = entry.map_err(ReplicaError::Storage)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with("replica-") || !name.ends_with(".json") {
                continue;
            }
            let record = read_record(&entry.path())?;
            if record.authority_id != authority_id {
                continue;
            }
            validate_record(&record, authority_id, &record.profile_id)?;
            let replace = records
                .get(&record.profile_id)
                .is_none_or(|current| record.revision > current.revision);
            if replace {
                records.insert(record.profile_id.clone(), record);
            }
        }
        Ok(records.values().map(metadata_from_record).collect())
    }

    fn load_or_create_key(&self) -> Result<Vec<u8>, ReplicaError> {
        let root = self.root.as_deref().ok_or(ReplicaError::Disabled)?;
        let path = root.join(".replica-key");
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                set_private_file(&file)?;
                let mut key = [0u8; 32];
                fill_random(&mut key).map_err(|_| ReplicaError::Unavailable)?;
                file.write_all(&key).map_err(ReplicaError::Storage)?;
                file.sync_all().map_err(ReplicaError::Storage)?;
                sync_parent(&path)?;
                Ok(key.to_vec())
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => read_private_file(&path, 64)
                .and_then(|key| {
                    if key.len() != 32 {
                        return Err(ReplicaError::SecretUnavailable);
                    }
                    Ok(key)
                }),
            Err(error) => Err(ReplicaError::Storage(error)),
        }
    }
}

pub struct AimuxProvider {
    replicas: Arc<ReplicaStore>,
    policy: ProviderExecutionPolicy,
}

#[derive(Debug, Error)]
pub enum ProviderExecutionValidationError {
    #[error("invalid provider execution descriptor")]
    Invalid,
    #[error("provider adapter is disabled")]
    AdapterDisabled,
    #[error("provider origin is disallowed")]
    DisallowedOrigin,
}

#[derive(Clone, Debug)]
pub struct ProviderExecutionPolicy {
    adapter_kinds: Vec<String>,
    allowed_origins: Vec<String>,
}

pub fn credential_schema_for_adapter(kind: &str) -> Option<&'static str> {
    match kind {
        "openai_compatible" => Some(CREDENTIAL_SCHEMA_OPENAI),
        "anthropic" => Some(CREDENTIAL_SCHEMA_ANTHROPIC),
        _ => None,
    }
}

impl ProviderExecutionPolicy {
    pub fn new(adapter_kinds: Vec<String>, allowed_origins: Vec<String>) -> Self {
        Self {
            adapter_kinds,
            allowed_origins,
        }
    }

    pub fn validate(
        &self,
        descriptor: &ProviderExecutionSelection,
    ) -> Result<(), ProviderExecutionValidationError> {
        validate_provider_execution_descriptor(descriptor, self)
    }
}

pub fn validate_provider_execution_descriptor(
    descriptor: &ProviderExecutionSelection,
    policy: &ProviderExecutionPolicy,
) -> Result<(), ProviderExecutionValidationError> {
    if descriptor.schema != "zode.provider-execution.v1" || descriptor.revision == 0 {
        return Err(ProviderExecutionValidationError::Invalid);
    }
    let url =
        Url::parse(&descriptor.base_url).map_err(|_| ProviderExecutionValidationError::Invalid)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || serde_json::to_vec(&descriptor.options).map_or(true, |bytes| {
            bytes.len() > MAX_PROVIDER_EXECUTION_OPTIONS_BYTES
        })
        || descriptor
            .options
            .iter()
            .any(|(key, value)| sensitive_option_key(key) || contains_sensitive_option(value))
    {
        return Err(ProviderExecutionValidationError::Invalid);
    }
    if !policy
        .adapter_kinds
        .iter()
        .any(|kind| kind == &descriptor.kind)
        || credential_schema_for_adapter(&descriptor.kind).is_none()
    {
        return Err(ProviderExecutionValidationError::AdapterDisabled);
    }
    if !origin_allowed(&url, &policy.allowed_origins) {
        return Err(ProviderExecutionValidationError::DisallowedOrigin);
    }
    Ok(())
}

impl AimuxProvider {
    pub fn new(replicas: Arc<ReplicaStore>, policy: ProviderExecutionPolicy) -> Self {
        Self { replicas, policy }
    }

    async fn complete_request(&self, request: ModelRequest) -> Result<ModelOutcome, ModelError> {
        let selection = request.selection;
        if let Err(error) = self.policy.validate(&selection.provider_execution) {
            return Err(match error {
                ProviderExecutionValidationError::AdapterDisabled => ModelError::Unavailable,
                ProviderExecutionValidationError::Invalid
                | ProviderExecutionValidationError::DisallowedOrigin => {
                    ModelError::InvalidSelection
                }
            });
        }
        let replicas = self.replicas.clone();
        let authority = selection.auth_authority_id.clone();
        let profile = selection.auth_profile_id.clone();
        let provider = selection.provider.clone();
        let minimum_revision = selection.auth_revision;
        let credential = tokio::task::spawn_blocking(move || {
            replicas.resolve(&authority, &profile, &provider, minimum_revision)
        })
        .await
        .map_err(|_| ModelError::Unavailable)?
        .map_err(|error| match error {
            ReplicaError::Disabled | ReplicaError::SecretUnavailable => {
                ModelError::AuthReplicaUnavailable
            }
            ReplicaError::Invalid => ModelError::InvalidSelection,
            ReplicaError::Conflict
            | ReplicaError::NotFound
            | ReplicaError::Unavailable
            | ReplicaError::Storage(_)
            | ReplicaError::Record(_) => ModelError::Unavailable,
        })?;

        let expected_credential_schema =
            credential_schema_for_adapter(&selection.provider_execution.kind)
                .ok_or(ModelError::InvalidSelection)?;
        if credential.credential_schema != expected_credential_schema {
            return Err(ModelError::AuthReplicaUnavailable);
        }

        let prompt = prompt_from_transcript(
            &request.transcript,
            selection.provider_execution.kind == "openai_compatible",
        )?;
        let tools = request
            .tools
            .iter()
            .map(|tool| {
                Tool::Function(
                    FunctionTool::new(tool.name.clone(), tool.input_schema.clone())
                        .with_description(tool.description.clone()),
                )
            })
            .collect::<Vec<_>>();
        let provider_options: Option<HashMap<String, Value>> =
            (!selection.provider_execution.options.is_empty()).then(|| {
                selection
                    .provider_execution
                    .options
                    .clone()
                    .into_iter()
                    .collect()
            });
        let options = CallOptions {
            tools: Some(tools),
            provider_options,
            timeout: Some(TimeoutConfiguration {
                total_ms: None,
                first_chunk_ms: Some(timeout_millis(request.stream_idle_timeout)),
                chunk_ms: Some(timeout_millis(request.stream_idle_timeout)),
            }),
            ..CallOptions::new(prompt)
        };
        let mut stream = match selection.provider_execution.kind.as_str() {
            "openai_compatible" => {
                let config = OpenAIConfig::new(credential.secret.clone())
                    .with_base_url(selection.provider_execution.base_url.clone())
                    .with_provider(selection.provider.clone());
                OpenAIProvider::new(config)
                    .model(&selection.model)
                    .do_stream(&options)
                    .await
            }
            "anthropic" => {
                let config = AnthropicConfig::new(credential.secret.clone())
                    .with_base_url(selection.provider_execution.base_url.clone());
                AnthropicProvider::new(config)
                    .model(&selection.model)
                    .do_stream(&options)
                    .await
            }
            _ => return Err(ModelError::InvalidSelection),
        }
        .map_err(|_| ModelError::ProviderFailed)?
        .stream;
        let mut text = String::new();
        let mut tool_calls = Vec::<(String, String, String, Option<Value>)>::new();
        let mut finish = None;
        while let Some(part) = stream.next().await {
            match part.map_err(|_| ModelError::ProviderFailed)? {
                StreamPart::TextDelta { delta, .. } => {
                    if let Some(observer) = request.stream_observer.as_ref() {
                        observer.text_delta(
                            &request.session_id,
                            &request.activation_id,
                            &request.round_id,
                            &delta,
                        );
                    }
                    text.push_str(&delta);
                }
                StreamPart::ToolInputStart { id, tool_name, .. } => {
                    if !tool_calls.iter().any(|(call_id, ..)| call_id == &id) {
                        tool_calls.push((id, tool_name, String::new(), None));
                    }
                }
                StreamPart::ToolInputDelta { id, delta, .. } => {
                    let Some((_, _, input, _)) =
                        tool_calls.iter_mut().find(|(call_id, ..)| call_id == &id)
                    else {
                        return Err(ModelError::ProviderFailed);
                    };
                    input.push_str(&delta);
                }
                StreamPart::ToolInputEnd { id, .. } => {
                    let Some((_, _, input, parsed)) =
                        tool_calls.iter_mut().find(|(call_id, ..)| call_id == &id)
                    else {
                        return Err(ModelError::ProviderFailed);
                    };
                    *parsed =
                        Some(serde_json::from_str(input).map_err(|_| ModelError::ProviderFailed)?);
                }
                StreamPart::ToolCall {
                    tool_call_id,
                    tool_name,
                    input,
                    ..
                } => {
                    if let Some((_, name, _, parsed)) = tool_calls
                        .iter_mut()
                        .find(|(call_id, ..)| call_id == &tool_call_id)
                    {
                        *name = tool_name;
                        *parsed = Some(input);
                    } else {
                        tool_calls.push((tool_call_id, tool_name, String::new(), Some(input)));
                    }
                }
                StreamPart::Finish { finish_reason, .. } => finish = Some(finish_reason),
                StreamPart::Error { .. } => return Err(ModelError::ProviderFailed),
                _ => {}
            }
        }
        let finish = finish.ok_or(ModelError::ProviderFailed)?;
        match finish.unified {
            FinishReasonUnified::Stop => {
                if !tool_calls.is_empty() {
                    return Err(ModelError::ProviderFailed);
                }
                Ok(ModelOutcome {
                    text,
                    tool_calls: Vec::new(),
                })
            }
            FinishReasonUnified::ToolCalls => {
                if tool_calls.is_empty() {
                    return Err(ModelError::ProviderFailed);
                }
                let allowed = request
                    .tools
                    .iter()
                    .map(|tool| tool.name.as_str())
                    .collect::<std::collections::HashSet<_>>();
                let mut calls = Vec::with_capacity(tool_calls.len());
                for (tool_call_id, tool_name, input, parsed) in tool_calls {
                    if !allowed.contains(tool_name.as_str()) {
                        return Err(ModelError::ProviderFailed);
                    }
                    let input = match parsed {
                        Some(input) => input,
                        None => {
                            serde_json::from_str(&input).map_err(|_| ModelError::ProviderFailed)?
                        }
                    };
                    if !input.is_object() {
                        return Err(ModelError::ProviderFailed);
                    }
                    calls.push(ToolCall {
                        tool_call_id,
                        tool_name,
                        input: DurablePayload::inline(input)
                            .map_err(|_| ModelError::ProviderFailed)?,
                    });
                }
                Ok(ModelOutcome {
                    text,
                    tool_calls: calls,
                })
            }
            FinishReasonUnified::Error
            | FinishReasonUnified::Length
            | FinishReasonUnified::ContentFilter
            | FinishReasonUnified::Other => Err(ModelError::ProviderFailed),
        }
    }
}

fn timeout_millis(timeout: std::time::Duration) -> u64 {
    timeout.as_millis().min(u64::MAX as u128) as u64
}

impl ModelExecutor for AimuxProvider {
    fn complete<'a>(
        &'a self,
        request: ModelRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ModelOutcome, ModelError>> + Send + 'a>,
    > {
        Box::pin(self.complete_request(request))
    }
}

fn prompt_from_transcript(
    transcript: &[TranscriptMessage],
    suppress_assistant_tool_preamble: bool,
) -> Result<LanguageModelPrompt, ModelError> {
    transcript
        .iter()
        .map(|message| {
            let role = match message.role {
                TranscriptRole::System => Role::System,
                TranscriptRole::User => Role::User,
                TranscriptRole::Assistant => Role::Assistant,
                TranscriptRole::Tool => Role::Tool,
                TranscriptRole::Runtime => Role::System,
            };
            let mut content = Vec::new();
            // The durable transcript keeps any assistant preamble alongside
            // its tool calls, but OpenAI-compatible tool-call turns use a
            // null/omitted content field on the wire. Projecting that text
            // back into the next request changes the provider conversation
            // (and breaks replay) even though the text remains observable in
            // Endpoint history.
            let assistant_tool_turn = suppress_assistant_tool_preamble
                && message.role == TranscriptRole::Assistant
                && !message.tool_calls.is_empty();
            if message.role != TranscriptRole::Tool
                && !message.content.is_empty()
                && !assistant_tool_turn
            {
                content.push(ContentPart::text(message.content.clone()));
            }
            if message.role == TranscriptRole::Assistant {
                for call in &message.tool_calls {
                    let DurablePayload::Inline(input) = &call.input else {
                        return Err(ModelError::ProviderFailed);
                    };
                    content.push(ContentPart::tool_call(
                        call.tool_call_id.clone(),
                        call.tool_name.clone(),
                        input.value().clone(),
                    ));
                }
            }
            if message.role == TranscriptRole::Tool {
                let tool_call_id = message
                    .tool_call_id
                    .clone()
                    .ok_or(ModelError::ProviderFailed)?;
                let result = serde_json::from_str(&message.content)
                    .unwrap_or_else(|_| Value::String(message.content.clone()));
                content.push(ContentPart::tool_result(tool_call_id, result));
            }
            if content.is_empty() {
                content.push(ContentPart::text(String::new()));
            }
            Ok(LanguageModelPromptMessage {
                role,
                content,
                provider_options: None,
            })
        })
        .collect()
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplicaRecord {
    schema: String,
    authority_id: String,
    profile_id: String,
    provider: String,
    #[serde(default)]
    kind: Option<String>,
    revision: u64,
    #[serde(default)]
    credential_schema: Option<String>,
    expires_at_ms: Option<i64>,
    fingerprint: String,
    #[serde(default = "default_install_status")]
    response_status: u16,
    #[serde(default = "default_ready_status")]
    status: String,
    #[serde(default)]
    secret: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplicaReceipt {
    schema: String,
    authority_id: String,
    profile_id: String,
    provider: String,
    revision: u64,
    #[serde(default = "default_no_expiry")]
    expires_at_ms: Option<i64>,
    response_status: u16,
    metadata_status: String,
    fingerprint: String,
}

fn mutation_provider(mutation: &ReplicaMutation) -> &str {
    match mutation {
        ReplicaMutation::Install(request) => &request.provider,
        ReplicaMutation::Tombstone(request) => &request.provider,
    }
}

fn mutation_revision(mutation: &ReplicaMutation) -> u64 {
    match mutation {
        ReplicaMutation::Install(request) => request.revision,
        ReplicaMutation::Tombstone(request) => request.revision,
    }
}

fn validate_mutation(
    profile_id: &str,
    authority_id: &str,
    idempotency_key: &str,
    mutation: &ReplicaMutation,
) -> Result<(), ReplicaError> {
    let provider = mutation_provider(mutation);
    let revision = mutation_revision(mutation);
    if idempotency_key.is_empty()
        || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || profile_id.is_empty()
        || authority_id.is_empty()
        || profile_id.len() > MAX_NAME_BYTES
        || authority_id.len() > MAX_NAME_BYTES
        || provider.is_empty()
        || provider.len() > MAX_NAME_BYTES
        || revision == 0
    {
        return Err(ReplicaError::Invalid);
    }
    match mutation {
        ReplicaMutation::Install(request) => {
            if request.schema != INSTALL_SCHEMA
                || request.authority_id != authority_id
                || request.kind != "api_key"
                || !supported_credential_schema(&request.credential_schema)
                || request.secret.encoding != SECRET_ENCODING
                || request.secret.payload.is_empty()
                || request.secret.payload.len() > MAX_SECRET_BYTES
                || request.secret.payload.contains('\0')
                || !valid_expiry(request.expires_at_ms)
            {
                return Err(ReplicaError::Invalid);
            }
        }
        ReplicaMutation::Tombstone(request) => {
            if request.schema != TOMBSTONE_SCHEMA || request.authority_id != authority_id {
                return Err(ReplicaError::Invalid);
            }
        }
    }
    Ok(())
}

fn default_install_status() -> u16 {
    201
}

fn default_ready_status() -> String {
    "ready".to_owned()
}

fn default_no_expiry() -> Option<i64> {
    None
}

fn valid_expiry(expires_at_ms: Option<i64>) -> bool {
    expires_at_ms.is_none_or(|expires| expires >= 0)
}

fn validate_receipt(
    receipt: &ReplicaReceipt,
    authority_id: &str,
    profile_id: &str,
) -> Result<(), ReplicaError> {
    if receipt.schema != RECEIPT_SCHEMA
        || receipt.authority_id != authority_id
        || receipt.profile_id != profile_id
        || receipt.provider.is_empty()
        || receipt.provider.len() > MAX_NAME_BYTES
        || receipt.revision == 0
        || !valid_expiry(receipt.expires_at_ms)
        || receipt.fingerprint.is_empty()
    {
        return Err(ReplicaError::SecretUnavailable);
    }
    match receipt.metadata_status.as_str() {
        "ready" if matches!(receipt.response_status, 200 | 201) => {}
        "tombstoned" if receipt.response_status == 200 && receipt.expires_at_ms.is_none() => {}
        _ => return Err(ReplicaError::SecretUnavailable),
    }
    Ok(())
}

fn receipt_from_record(record: &ReplicaRecord, fingerprint: &str) -> ReplicaReceipt {
    ReplicaReceipt {
        schema: RECEIPT_SCHEMA.to_owned(),
        authority_id: record.authority_id.clone(),
        profile_id: record.profile_id.clone(),
        provider: record.provider.clone(),
        revision: record.revision,
        expires_at_ms: record.expires_at_ms,
        response_status: record.response_status,
        metadata_status: record.status.clone(),
        fingerprint: fingerprint.to_owned(),
    }
}

fn outcome_from_receipt(receipt: &ReplicaReceipt) -> Result<ReplicaInstallOutcome, ReplicaError> {
    Ok(ReplicaInstallOutcome {
        status: receipt.response_status,
        metadata: metadata_from_receipt(receipt),
    })
}

fn metadata_from_receipt(receipt: &ReplicaReceipt) -> ReplicaMetadata {
    ReplicaMetadata {
        authority_id: receipt.authority_id.clone(),
        profile_id: receipt.profile_id.clone(),
        provider: receipt.provider.clone(),
        revision: receipt.revision,
        expires_at_ms: receipt.expires_at_ms,
        status: metadata_status(&receipt.metadata_status),
    }
}

fn validate_record(
    record: &ReplicaRecord,
    authority_id: &str,
    profile_id: &str,
) -> Result<(), ReplicaError> {
    if record.schema != REPLICA_SCHEMA
        || record.authority_id != authority_id
        || record.profile_id != profile_id
        || record.provider.is_empty()
        || record.provider.len() > MAX_NAME_BYTES
        || record.revision == 0
        || !valid_expiry(record.expires_at_ms)
        || !matches!(record.response_status, 200 | 201)
        || record.fingerprint.is_empty()
    {
        return Err(ReplicaError::SecretUnavailable);
    }
    match record.status.as_str() {
        "ready"
            if record.kind.as_deref() == Some("api_key")
                && record
                    .credential_schema
                    .as_deref()
                    .is_some_and(supported_credential_schema)
                && record.secret.as_ref().is_some_and(|secret| {
                    !secret.is_empty() && secret.len() <= MAX_SECRET_BYTES
                }) => {}
        "tombstoned" if record.secret.is_none() && record.expires_at_ms.is_none() => {}
        _ => return Err(ReplicaError::SecretUnavailable),
    }
    Ok(())
}

fn supported_credential_schema(schema: &str) -> bool {
    matches!(
        schema,
        CREDENTIAL_SCHEMA_OPENAI | CREDENTIAL_SCHEMA_ANTHROPIC
    )
}

fn metadata_from_record(record: &ReplicaRecord) -> ReplicaMetadata {
    ReplicaMetadata {
        authority_id: record.authority_id.clone(),
        profile_id: record.profile_id.clone(),
        provider: record.provider.clone(),
        revision: record.revision,
        expires_at_ms: record.expires_at_ms,
        status: metadata_status(&record.status),
    }
}

fn metadata_status(status: &str) -> &'static str {
    match status {
        "tombstoned" => "tombstoned",
        _ => "ready",
    }
}

fn replica_path(root: &Path, authority_id: &str, profile_id: &str) -> PathBuf {
    let mut digest = Sha256::new();
    for value in [authority_id, profile_id] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    root.join(format!("replica-{:x}.json", digest.finalize()))
}

fn receipt_path(
    root: &Path,
    authority_id: &str,
    profile_id: &str,
    idempotency_key: &str,
) -> PathBuf {
    let mut digest = Sha256::new();
    digest.update(b"zode:auth-replica-receipt:v1");
    for value in [authority_id, profile_id, idempotency_key] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    root.join(format!("receipt-{:x}.json", digest.finalize()))
}

fn request_fingerprint(
    key: &[u8],
    profile_id: &str,
    idempotency_key: &str,
    mutation: &ReplicaMutation,
) -> Result<String, ReplicaError> {
    let canonical = match mutation {
        ReplicaMutation::Install(request) => serde_json::to_vec(&(
            "install",
            profile_id,
            idempotency_key,
            &request.schema,
            &request.authority_id,
            &request.provider,
            &request.kind,
            request.revision,
            &request.credential_schema,
            request.expires_at_ms,
            &request.secret.encoding,
            &request.secret.payload,
        )),
        ReplicaMutation::Tombstone(request) => serde_json::to_vec(&(
            "tombstone",
            profile_id,
            idempotency_key,
            &request.schema,
            &request.authority_id,
            &request.provider,
            request.revision,
        )),
    }
    .map_err(ReplicaError::Record)?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ReplicaError::Unavailable)?;
    mac.update(b"zode:auth-replica-fingerprint:v1");
    mac.update(&canonical);
    Ok(format!(
        "hmac-sha256:v1:{}",
        hex_bytes(&mac.finalize().into_bytes())
    ))
}

fn read_record(path: &Path) -> Result<ReplicaRecord, ReplicaError> {
    let bytes = read_private_file(path, MAX_REPLICA_REQUEST_BYTES)?;
    serde_json::from_slice(&bytes).map_err(ReplicaError::Record)
}

fn read_receipt(path: &Path) -> Result<ReplicaReceipt, ReplicaError> {
    let bytes = read_private_file(path, MAX_REPLICA_REQUEST_BYTES)?;
    serde_json::from_slice(&bytes).map_err(ReplicaError::Record)
}

fn write_receipt(path: &Path, receipt: &ReplicaReceipt) -> Result<(), ReplicaError> {
    if path.exists() {
        return Err(ReplicaError::Conflict);
    }
    let bytes = serde_json::to_vec(receipt).map_err(ReplicaError::Record)?;
    atomic_write(path, &bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ReplicaError> {
    let temporary = path.with_file_name(format!(".tmp-{}", Ulid::new()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(ReplicaError::Storage)?;
        set_private_file(&file)?;
        file.write_all(bytes).map_err(ReplicaError::Storage)?;
        file.sync_all().map_err(ReplicaError::Storage)?;
        fs::rename(&temporary, path).map_err(ReplicaError::Storage)?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_private_file(path: &Path, maximum: usize) -> Result<Vec<u8>, ReplicaError> {
    let file = open_private_read(path).map_err(|error| match error {
        ReplicaError::Storage(source) if source.kind() == ErrorKind::NotFound => {
            ReplicaError::Storage(source)
        }
        ReplicaError::Storage(_) | ReplicaError::SecretUnavailable => {
            ReplicaError::SecretUnavailable
        }
        other => other,
    })?;
    let metadata = file.metadata().map_err(ReplicaError::Storage)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(ReplicaError::Storage)?;
    if bytes.len() > maximum {
        return Err(ReplicaError::SecretUnavailable);
    }
    Ok(bytes)
}

fn open_private_read(path: &Path) -> Result<File, ReplicaError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(ReplicaError::Storage)?;
    let metadata = file.metadata().map_err(ReplicaError::Storage)?;
    if !metadata.is_file() || !is_private_file(&metadata) {
        return Err(ReplicaError::SecretUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(ReplicaError::SecretUnavailable);
        }
    }
    Ok(file)
}

fn is_private_file(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), ReplicaError> {
    let metadata = fs::metadata(path).map_err(ReplicaError::Storage)?;
    if !metadata.is_dir() {
        return Err(ReplicaError::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = metadata.permissions();
        if permissions.mode() & 0o077 != 0 {
            permissions.set_mode(PRIVATE_DIRECTORY_MODE);
            fs::set_permissions(path, permissions).map_err(ReplicaError::Storage)?;
        }
    }
    Ok(())
}

fn set_private_file(file: &File) -> Result<(), ReplicaError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = file
            .metadata()
            .map_err(ReplicaError::Storage)?
            .permissions();
        permissions.set_mode(PRIVATE_FILE_MODE);
        file.set_permissions(permissions)
            .map_err(ReplicaError::Storage)?;
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), ReplicaError> {
    #[cfg(unix)]
    {
        File::open(path.parent().ok_or(ReplicaError::Invalid)?)
            .map_err(ReplicaError::Storage)?
            .sync_all()
            .map_err(ReplicaError::Storage)?;
    }
    Ok(())
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

fn sensitive_option_key(value: &str) -> bool {
    let key = value.to_ascii_lowercase().replace('-', "_");
    key == "authorization"
        || key == "headers"
        || key.contains("api_key")
        || key.contains("access_token")
        || key.contains("refresh_token")
        || key.contains("secret")
}

fn contains_sensitive_option(value: &Value) -> bool {
    match value {
        Value::Object(object) => object
            .iter()
            .any(|(key, value)| sensitive_option_key(key) || contains_sensitive_option(value)),
        Value::Array(values) => values.iter().any(contains_sensitive_option),
        _ => false,
    }
}

fn origin_allowed(base: &Url, allowed_origins: &[String]) -> bool {
    allowed_origins.iter().any(|allowed| {
        let Ok(allowed) = Url::parse(allowed) else {
            return false;
        };
        // Compare complete URL origins. A host-only allowlist entry denotes
        // that host's default origin; it must not wildcard arbitrary
        // explicit listener ports on the same host.
        allowed.origin() == base.origin()
    })
}

use std::collections::HashMap;

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
use serde_json::Value;
use thiserror::Error;
use url::Url;

use crate::{
    domain::{
        DurablePayload, ProviderExecutionSelection, ToolCall, TranscriptMessage, TranscriptRole,
        MAX_PROVIDER_EXECUTION_OPTIONS_BYTES,
    },
    runtime::{
        ExecutionPolicyError, ExecutionPolicyPort, ModelError, ModelExecutor, ModelOutcome,
        ModelRequest, SecretLease,
    },
};

const CREDENTIAL_SCHEMA_OPENAI: &str = "openai-compatible.api-key.v1";
const CREDENTIAL_SCHEMA_ANTHROPIC: &str = "anthropic.api-key.v1";

pub struct AimuxProvider {
    policy: ProviderExecutionPolicy,
}

#[derive(Clone, Copy, Debug)]
pub struct ProviderTransportRetryPolicy {
    pub initial_delay: std::time::Duration,
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
    transport_retry: ProviderTransportRetryPolicy,
}

pub fn credential_schema_for_adapter(kind: &str) -> Option<&'static str> {
    match kind {
        "openai_compatible" => Some(CREDENTIAL_SCHEMA_OPENAI),
        "anthropic" => Some(CREDENTIAL_SCHEMA_ANTHROPIC),
        _ => None,
    }
}

impl ProviderExecutionPolicy {
    pub fn new(
        adapter_kinds: Vec<String>,
        allowed_origins: Vec<String>,
        transport_retry: ProviderTransportRetryPolicy,
    ) -> Self {
        Self {
            adapter_kinds,
            allowed_origins,
            transport_retry,
        }
    }

    pub fn validate(
        &self,
        descriptor: &ProviderExecutionSelection,
    ) -> Result<(), ProviderExecutionValidationError> {
        validate_provider_execution_descriptor(descriptor, self)
    }
}

impl ExecutionPolicyPort for ProviderExecutionPolicy {
    fn validate_descriptor(
        &self,
        descriptor: &ProviderExecutionSelection,
    ) -> Result<(), ExecutionPolicyError> {
        self.validate(descriptor)
            .map_err(|_| ExecutionPolicyError::Invalid)
    }

    fn credential_schema(&self, adapter_kind: &str) -> Option<&'static str> {
        credential_schema_for_adapter(adapter_kind)
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
    pub fn new(policy: ProviderExecutionPolicy) -> Self {
        Self { policy }
    }

    async fn complete_request(
        &self,
        request: &ModelRequest,
        lease: SecretLease,
    ) -> Result<ModelOutcome, ModelError> {
        let selection = &request.selection;
        if let Err(error) = self.policy.validate(&selection.provider_execution) {
            return Err(match error {
                ProviderExecutionValidationError::AdapterDisabled => ModelError::Unavailable,
                ProviderExecutionValidationError::Invalid
                | ProviderExecutionValidationError::DisallowedOrigin => {
                    ModelError::InvalidSelection
                }
            });
        }

        let expected_credential_schema =
            credential_schema_for_adapter(&selection.provider_execution.kind)
                .ok_or(ModelError::InvalidSelection)?;
        if lease.credential_schema() != expected_credential_schema {
            return Err(ModelError::AuthReplicaUnavailable);
        }

        let prompt = prompt_from_transcript(
            request.transcript.as_slice(),
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
            max_output_tokens: request.max_output_tokens,
            provider_options,
            timeout: Some(TimeoutConfiguration {
                total_ms: None,
                first_chunk_ms: Some(timeout_millis(request.stream_idle_timeout)),
                chunk_ms: Some(timeout_millis(request.stream_idle_timeout)),
            }),
            ..CallOptions::new(prompt)
        };
        let transport_retry = self.policy.transport_retry;
        let mut stream = match selection.provider_execution.kind.as_str() {
            "openai_compatible" => {
                let mut config = OpenAIConfig::new(lease.secret().to_owned())
                    .with_base_url(selection.provider_execution.base_url.clone())
                    .with_provider(selection.provider.clone());
                config.retry_config.initial_delay = transport_retry.initial_delay;
                OpenAIProvider::new(config)
                    .model(&selection.model)
                    .do_stream(&options)
                    .await
            }
            "anthropic" => {
                let mut config = AnthropicConfig::new(lease.secret().to_owned())
                    .with_base_url(selection.provider_execution.base_url.clone());
                config.retry_config.initial_delay = transport_retry.initial_delay;
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
        let mut token_usage = None;
        while let Some(part) = stream.next().await {
            match part.map_err(|_| ModelError::ProviderFailed)? {
                StreamPart::TextDelta { delta, .. } => {
                    request.stream_observer.text_delta(
                        &request.session_id,
                        &request.activation_id,
                        &request.round_id,
                        &delta,
                    );
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
                StreamPart::Finish {
                    finish_reason,
                    usage,
                    ..
                } => {
                    if finish_reason.raw.is_none() {
                        return Err(ModelError::ProviderFailed);
                    }
                    token_usage = usage.input_tokens.total.map(|input_tokens| {
                        crate::runtime::ModelTokenUsage {
                            input_tokens: u64::from(input_tokens),
                            output_tokens: u64::from(usage.output_tokens.total.unwrap_or(0)),
                        }
                    });
                    finish = Some(finish_reason);
                }
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
                    usage: token_usage,
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
                    usage: token_usage,
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
        request: &'a ModelRequest,
        lease: SecretLease,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ModelOutcome, ModelError>> + Send + 'a>,
    > {
        Box::pin(self.complete_request(request, lease))
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

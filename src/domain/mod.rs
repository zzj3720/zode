use std::collections::{BTreeMap, BTreeSet, VecDeque};

mod reducer;
pub use reducer::DomainError;

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;

pub const EVENT_SCHEMA_VERSION: u32 = 1;
pub const STATE_SCHEMA_VERSION: u32 = 1;
pub const REDUCER_SCHEMA_VERSION: u32 = 1;
pub const SESSION_CREATED_SCHEMA_VERSION: u32 = 2;
pub const WAIT_MIN_SECONDS: u32 = 1;
pub const WAIT_MAX_SECONDS: u32 = 600;
pub const WAIT_FOR_TOOL_NAME: &str = "wait_for";
pub const MAX_INLINE_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_ERROR_MESSAGE_BYTES: usize = 8 * 1024;
pub const MAX_RECENT_DEDUPE_FACTS: usize = 256;
pub const MAX_IDENTIFIER_BYTES: usize = 512;
pub const MAX_MESSAGE_CONTENT_BYTES: usize = 256 * 1024;
pub const MAX_TRANSCRIPT_MESSAGES: usize = 8 * 1024;
pub const MAX_DELIVERY_QUEUE_ITEMS: usize = 4 * 1024;
pub const MAX_ASYNC_TOOL_CALLS: usize = 1_024;
pub const MAX_TOOL_CALLS_PER_MESSAGE: usize = 128;
pub const MAX_WAIT_TOOL_CALLS: usize = 128;
pub const MAX_SELECTED_TOOLS: usize = 256;
pub const MAX_OPAQUE_CONTINUATION_BYTES: usize = 64 * 1024;
pub const MAX_OPAQUE_CONTINUATIONS: usize = 8;
pub const MAX_PROVIDER_EXECUTION_OPTIONS_BYTES: usize = 64 * 1024;
pub const MAX_MODEL_ATTEMPTS_PER_STEP: u32 = 32;
pub const MAX_MODEL_FINGERPRINT_BYTES: usize = 512;

pub type StreamVersion = u64;
pub type GlobalPosition = u64;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    #[default]
    Idle,
    Active,
}

/// Durable execution status for the one activation that may own a session.
///
/// The in-memory runtime actor is disposable; this record is the durable
/// fencing fact used by restart reconciliation and by the next round boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationOutcome {
    Finished,
    Wait,
    Failed,
    Interrupted,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ActiveActivation {
    pub activation_id: String,
    pub selection: SessionSelection,
    pub selection_version: u64,
    pub minimum_auth_revision: u64,
    pub started_at_ms: i64,
    /// Retained only so schema-v1 state digests remain compatible with
    /// existing durable streams. This counter never gates execution.
    #[serde(default, rename = "rounds_started")]
    pub legacy_rounds_started: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ActiveModelRound {
    pub activation_id: String,
    pub round_id: String,
    #[serde(default, skip_serializing_if = "ModelRequestPurpose::is_conversation")]
    pub purpose: ModelRequestPurpose,
    pub delivery_through_queue_id: u64,
    pub started_at_ms: i64,
    #[serde(default)]
    pub request: Option<ModelRequestFact>,
    #[serde(default)]
    pub attempt: Option<ModelAttemptRecord>,
    #[serde(default)]
    pub retry: Option<ModelRetrySchedule>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ModelRequestFact {
    pub activation_id: String,
    pub round_id: String,
    pub request_id: String,
    pub request_fingerprint: String,
    pub provider_execution_fingerprint: String,
    pub prompt_fingerprint: String,
    pub tool_schema_fingerprint: String,
    /// Historical request-content field retained only so existing snapshots
    /// and event streams keep their exact state digest. New request
    /// declarations always leave it absent, and runtime recovery never reads
    /// it.
    #[serde(default, rename = "envelope", skip_serializing_if = "Option::is_none")]
    pub legacy_envelope: Option<DurablePayload>,
    pub maximum_attempts: u32,
    pub minimum_auth_revision: u64,
}

/// Safe numeric context accounting returned by the provider for one completed
/// conversation request. It anchors the next preflight calculation without
/// persisting any request, prompt, transcript, or provider payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelUsageAnchor {
    pub context_generation: u64,
    pub selection_fingerprint: String,
    pub tool_schema_fingerprint: String,
    pub result_message_id: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Provider-independent estimate of the exact request whose provider usage
    /// is recorded above. This is numeric calibration metadata only; it never
    /// contains request, prompt, transcript, tool, or provider payload data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_input_estimate_tokens: Option<u64>,
    /// Highest provider/local input-token ratio observed in this context
    /// generation, expressed in millionths. The next preflight applies it only
    /// to context appended after this anchor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_estimate_scale_millionths: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ModelAttemptRecord {
    pub activation_id: String,
    pub round_id: String,
    pub request_id: String,
    pub attempt_id: String,
    pub attempt_number: u32,
    pub auth_revision: u64,
    pub started_at_ms: i64,
    #[serde(default)]
    pub outcome: ModelAttemptOutcome,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelAttemptOutcome {
    #[default]
    Running,
    Failed,
    Interrupted,
    Completed,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRequestPurpose {
    #[default]
    Conversation,
    ContextHandoff,
}

impl ModelRequestPurpose {
    fn is_conversation(&self) -> bool {
        *self == Self::Conversation
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ModelRetrySchedule {
    pub activation_id: String,
    pub round_id: String,
    pub request_id: String,
    pub failed_attempt_id: String,
    pub next_attempt_id: String,
    pub failed_attempt_number: u32,
    pub next_attempt_number: u32,
    pub delay_ms: u64,
    pub not_before_ms: i64,
    pub maximum_attempts: u32,
    pub error_class: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ContextHandoffPlan {
    pub plan_id: String,
    pub activation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_handoff_id: Option<String>,
    pub next_generation: u64,
    pub covered_through_message_id: String,
    pub source_digest: String,
    pub source_tokens: u64,
    pub token_accounting_version: u32,
    pub selection: SessionModelSelection,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ContextHandoffDocument {
    pub handoff_id: String,
    pub plan_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_handoff_id: Option<String>,
    pub next_generation: u64,
    pub covered_through_message_id: String,
    pub source_digest: String,
    /// Agent-authored plain text for the next context generation. This is a
    /// first-class session fact, not a generic provider/tool payload envelope.
    pub document: String,
    pub document_digest: String,
    pub source_tokens: u64,
    pub document_tokens: u64,
    pub token_accounting_version: u32,
    pub selection: SessionModelSelection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WaitTimerIntent {
    pub wait_id: String,
    pub deadline_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionOwner {
    pub authority_id: String,
    pub subject: String,
}

impl SessionOwner {
    pub fn new(authority_id: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            authority_id: authority_id.into(),
            subject: subject.into(),
        }
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        validate_identifier("authority_id", &self.authority_id)?;
        validate_identifier("subject", &self.subject)
    }

    pub fn try_new(
        authority_id: impl Into<String>,
        subject: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let owner = Self::new(authority_id, subject);
        owner.validate()?;
        Ok(owner)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderExecutionSelection {
    pub schema: String,
    pub revision: u64,
    pub kind: String,
    pub base_url: String,
    #[serde(default)]
    pub options: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionModelSelection {
    pub provider: String,
    pub provider_execution: ProviderExecutionSelection,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<ModelLimits>,
    pub auth_authority_id: String,
    pub auth_profile_id: String,
    pub auth_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelLimits {
    pub context_window_tokens: u64,
    pub max_output_tokens: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionSelection {
    #[serde(default)]
    pub model: Option<SessionModelSelection>,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub callback_base_url: Option<String>,
}

impl SessionSelection {
    pub fn validate(&self) -> Result<(), DomainError> {
        if let Some(model) = &self.model {
            validate_identifier("provider", &model.provider)?;
            validate_identifier(
                "provider execution schema",
                &model.provider_execution.schema,
            )?;
            if model.provider_execution.revision == 0 {
                return Err(DomainError::InvalidState(
                    "provider execution revision must be positive".into(),
                ));
            }
            validate_identifier("provider execution kind", &model.provider_execution.kind)?;
            validate_bounded_text(
                "provider execution base_url",
                &model.provider_execution.base_url,
            )?;
            let options_bytes = serde_json::to_vec(&model.provider_execution.options)
                .map_err(|_| {
                    DomainError::InvalidState("provider execution options are invalid".into())
                })?
                .len();
            if options_bytes > MAX_PROVIDER_EXECUTION_OPTIONS_BYTES {
                return Err(DomainError::TextTooLarge {
                    field: "provider execution options",
                    bytes: options_bytes,
                    max: MAX_PROVIDER_EXECUTION_OPTIONS_BYTES,
                });
            }
            validate_identifier("model", &model.model)?;
            if let Some(limits) = &model.limits {
                if limits.context_window_tokens == 0
                    || limits.max_output_tokens == 0
                    || u64::from(limits.max_output_tokens) >= limits.context_window_tokens
                {
                    return Err(DomainError::InvalidState(
                        "model limits must leave a positive input window".into(),
                    ));
                }
            }
            validate_identifier("auth_authority_id", &model.auth_authority_id)?;
            validate_identifier("auth_profile_id", &model.auth_profile_id)?;
            if model.auth_revision == 0 {
                return Err(DomainError::InvalidState(
                    "auth revision must be positive".into(),
                ));
            }
        }
        if self.tools.len() > MAX_SELECTED_TOOLS {
            return Err(DomainError::CollectionTooLarge {
                field: "selected tools",
                items: self.tools.len(),
                max: MAX_SELECTED_TOOLS,
            });
        }
        let mut tools = BTreeSet::new();
        for tool in &self.tools {
            validate_identifier("tool", tool)?;
            if !tools.insert(tool) {
                return Err(DomainError::InvalidState(
                    "session tool selection contains duplicates".into(),
                ));
            }
        }
        if let Some(callback_base_url) = &self.callback_base_url {
            validate_bounded_text("callback_base_url", callback_base_url)?;
        }
        Ok(())
    }
}

/// A provider-neutral continuation that may be carried across model rounds.
///
/// The reducer only validates its envelope and bound.  The bytes are opaque to
/// the domain and are never decoded, logged, or used to make an effect
/// decision.  Provider adapters are responsible for constructing and
/// interpreting a value after it has been admitted by the application layer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpaqueContinuation {
    pub provider_type: String,
    pub codec_version: u32,
    pub semantic_kind: String,
    pub bytes: Vec<u8>,
}

impl OpaqueContinuation {
    pub fn new(
        provider_type: impl Into<String>,
        codec_version: u32,
        semantic_kind: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Result<Self, DomainError> {
        let continuation = Self {
            provider_type: provider_type.into(),
            codec_version,
            semantic_kind: semantic_kind.into(),
            bytes,
        };
        continuation.validate()?;
        Ok(continuation)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        validate_identifier("continuation provider type", &self.provider_type)?;
        if self.codec_version == 0 {
            return Err(DomainError::InvalidState(
                "continuation codec version must be positive".into(),
            ));
        }
        validate_identifier("continuation semantic kind", &self.semantic_kind)?;
        if self.bytes.len() > MAX_OPAQUE_CONTINUATION_BYTES {
            return Err(DomainError::CollectionTooLarge {
                field: "opaque continuation bytes",
                items: self.bytes.len(),
                max: MAX_OPAQUE_CONTINUATION_BYTES,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptRole {
    System,
    User,
    Assistant,
    Tool,
    Runtime,
}

#[derive(Clone, Debug, PartialEq)]
pub struct InlinePayload {
    value: Value,
    encoded_len: usize,
}

impl InlinePayload {
    pub fn new(value: Value) -> Result<Self, DomainError> {
        let encoded_len = serde_json::to_vec(&value)
            .map_err(|error| DomainError::InvalidDurablePayload(error.to_string()))?
            .len();
        if encoded_len > MAX_INLINE_PAYLOAD_BYTES {
            return Err(DomainError::DurablePayloadTooLarge {
                bytes: encoded_len,
                max: MAX_INLINE_PAYLOAD_BYTES,
            });
        }
        Ok(Self { value, encoded_len })
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    fn encoded_len(&self) -> usize {
        self.encoded_len
    }
}

impl Serialize for InlinePayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for InlinePayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(Value::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlobRef {
    pub blob_id: String,
    pub byte_len: u64,
    pub sha256: String,
    #[serde(default)]
    pub media_type: Option<String>,
}

impl BlobRef {
    pub fn validate(&self) -> Result<(), DomainError> {
        validate_identifier("blob_id", &self.blob_id)?;
        validate_bounded_text("sha256", &self.sha256)?;
        if let Some(media_type) = &self.media_type {
            validate_bounded_text("media_type", media_type)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactedPayload {
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum DurablePayload {
    Inline(InlinePayload),
    BlobRef(BlobRef),
    Redacted(RedactedPayload),
}

impl DurablePayload {
    pub fn inline(value: Value) -> Result<Self, DomainError> {
        Ok(Self::Inline(InlinePayload::new(value)?))
    }

    pub fn blob_ref(
        blob_id: impl Into<String>,
        byte_len: u64,
        sha256: impl Into<String>,
        media_type: Option<String>,
    ) -> Self {
        Self::BlobRef(BlobRef {
            blob_id: blob_id.into(),
            byte_len,
            sha256: sha256.into(),
            media_type,
        })
    }

    pub fn redacted(reason: impl Into<String>) -> Self {
        Self::Redacted(RedactedPayload {
            reason: reason.into(),
        })
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        match self {
            Self::Inline(value) => {
                let bytes = value.encoded_len();
                if bytes > MAX_INLINE_PAYLOAD_BYTES {
                    return Err(DomainError::DurablePayloadTooLarge {
                        bytes,
                        max: MAX_INLINE_PAYLOAD_BYTES,
                    });
                }
            }
            Self::BlobRef(blob) => {
                blob.validate()?;
            }
            Self::Redacted(redacted) => {
                require_text("redaction reason", &redacted.reason)?;
                if redacted.reason.len() > MAX_ERROR_MESSAGE_BYTES {
                    return Err(DomainError::TextTooLarge {
                        field: "redaction reason",
                        bytes: redacted.reason.len(),
                        max: MAX_ERROR_MESSAGE_BYTES,
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ToolCall {
    pub tool_call_id: String,
    pub tool_name: String,
    pub input: DurablePayload,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct TranscriptMessage {
    pub message_id: String,
    pub role: TranscriptRole,
    pub content: String,
    #[serde(default)]
    pub tool_call_id: Option<String>,
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
    #[serde(default)]
    pub dedupe_key: Option<String>,
    #[serde(default)]
    pub source_queue_id: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryKind {
    UserInput,
    RuntimeNotification,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct QueuedDelivery {
    pub queue_id: u64,
    pub delivery_id: String,
    pub kind: DeliveryKind,
    pub payload: DurablePayload,
    pub dedupe_key: String,
    #[serde(default = "default_true")]
    pub wake: bool,
    #[serde(default)]
    pub created_at_ms: Option<i64>,
    #[serde(default)]
    pub source_tool_call_id: Option<String>,
    #[serde(default)]
    pub materialized_message_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitSource {
    WaitFor,
    AutoToolBatch,
    Runtime,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ActiveWait {
    pub wait_id: String,
    pub reason: String,
    pub timeout_seconds: u32,
    pub deadline_ms: i64,
    pub source: WaitSource,
    #[serde(default)]
    pub tool_call_ids: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionMode {
    #[default]
    ProcessLocal,
    ExternalCallback,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AsyncToolStatus {
    Planned,
    Running,
    UnknownOutcome,
    RuntimeRestarted,
    Completed,
    Failed,
    Cancelled,
}

impl AsyncToolStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::RuntimeRestarted | Self::Completed | Self::Failed | Self::Cancelled
        )
    }

    pub fn is_reconcilable(&self) -> bool {
        matches!(self, Self::UnknownOutcome)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ToolError {
    pub class: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelAttemptErrorClass {
    AuthReplicaUnavailable,
    InvalidToolArguments,
    ContextHandoffFailed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelAttemptError {
    pub class: ModelAttemptErrorClass,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelAttemptFailure {
    pub trigger_message_id: String,
    pub error: ModelAttemptError,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AsyncToolCallRecord {
    pub tool_call_id: String,
    pub tool_name: String,
    pub input: DurablePayload,
    pub status: AsyncToolStatus,
    pub started_at_ms: i64,
    #[serde(default)]
    pub auto_wait_seconds: Option<u32>,
    #[serde(default)]
    pub completion_mode: CompletionMode,
    #[serde(default)]
    pub retry_dispatch_deduplicated: bool,
    #[serde(default)]
    pub progress: Option<DurablePayload>,
    #[serde(default)]
    pub result: Option<DurablePayload>,
    #[serde(default)]
    pub error: Option<ToolError>,
    #[serde(default)]
    pub cancel_reason: Option<String>,
    #[serde(default)]
    pub completed_at_ms: Option<i64>,
}

/// Durable, non-secret mapping used by the external callback boundary.
///
/// The bearer itself is never retained; `bearer_fingerprint` is a keyed
/// digest produced by the application/runtime boundary.  The payload
/// fingerprint is populated only after a callback terminal transition so a
/// canonical duplicate can replay without appending another terminal fact.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AsyncCallbackBinding {
    pub callback_id: String,
    pub tool_call_id: String,
    pub bearer_fingerprint: String,
    #[serde(default)]
    pub payload_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ModelAttemptsExhaustedFact {
    pub activation_id: String,
    pub round_id: String,
    pub request_id: String,
    pub attempt_id: String,
    pub attempt_number: u32,
    pub maximum_attempts: u32,
    pub finished_at_ms: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DedupeFacts {
    pub recent_keys: VecDeque<String>,
}

impl DedupeFacts {
    pub fn contains(&self, key: &str) -> bool {
        self.recent_keys.iter().any(|existing| existing == key)
    }

    fn remember(&mut self, key: impl Into<String>) {
        let key = key.into();
        if let Some(index) = self
            .recent_keys
            .iter()
            .position(|existing| existing == &key)
        {
            self.recent_keys.remove(index);
        }
        self.recent_keys.push_back(key);
        while self.recent_keys.len() > MAX_RECENT_DEDUPE_FACTS {
            self.recent_keys.pop_front();
        }
    }

    fn validate(&self) -> Result<(), DomainError> {
        if self.recent_keys.len() > MAX_RECENT_DEDUPE_FACTS
            || self.recent_keys.iter().any(String::is_empty)
        {
            return Err(DomainError::InvalidState(
                "dedupe facts exceed the bounded recent window".into(),
            ));
        }
        Ok(())
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionEvent {
    SessionCreated {
        schema_version: u32,
        session_id: String,
        owner: SessionOwner,
        created_at_ms: i64,
        selection: SessionSelection,
    },
    ModelSelectionChanged {
        selection: SessionSelection,
    },
    StatusChanged {
        status: SessionStatus,
    },
    DeliveryQueued {
        delivery: QueuedDelivery,
    },
    DeliveryAcknowledged {
        through_queue_id: u64,
    },
    DeliveryMaterialized {
        queue_id: u64,
        message: TranscriptMessage,
    },
    MessageAppended {
        message: TranscriptMessage,
        #[serde(default)]
        wake_wait: bool,
    },
    /// Claims one session activation and freezes the selection used by all
    /// rounds in that activation.
    ActivationStarted {
        activation_id: String,
        selection: SessionSelection,
        selection_version: u64,
        minimum_auth_revision: u64,
        started_at_ms: i64,
    },
    ModelRoundStarted {
        activation_id: String,
        round_id: String,
        #[serde(default)]
        purpose: ModelRequestPurpose,
        delivery_through_queue_id: u64,
        started_at_ms: i64,
    },
    ContextHandoffPlanned {
        plan: ContextHandoffPlan,
    },
    ContextHandoffCreated {
        handoff: ContextHandoffDocument,
    },
    ContextHandoffFailed {
        plan_id: String,
        error: ModelAttemptError,
        finished_at_ms: i64,
    },
    /// Historical request-content event retained only to replay immutable
    /// streams written before request snapshots were removed. New runtime
    /// code never emits this variant and never treats its envelope as
    /// recovery authority.
    ModelRequestPrepared {
        activation_id: String,
        round_id: String,
        request_id: String,
        request_fingerprint: String,
        provider_execution_fingerprint: String,
        prompt_fingerprint: String,
        tool_schema_fingerprint: String,
        envelope: DurablePayload,
        maximum_attempts: u32,
        minimum_auth_revision: u64,
    },
    ModelRequestDeclared {
        activation_id: String,
        round_id: String,
        request_id: String,
        request_fingerprint: String,
        provider_execution_fingerprint: String,
        prompt_fingerprint: String,
        tool_schema_fingerprint: String,
        maximum_attempts: u32,
        minimum_auth_revision: u64,
    },
    ModelAttemptStarted {
        activation_id: String,
        round_id: String,
        request_id: String,
        attempt_id: String,
        attempt_number: u32,
        auth_revision: u64,
        started_at_ms: i64,
    },
    /// Lifecycle failure fact. The older `ModelAttemptFailed` event remains
    /// for the admission-time auth failure compatibility path.
    ModelAttemptFailedFact {
        activation_id: String,
        round_id: String,
        request_id: String,
        attempt_id: String,
        attempt_number: u32,
        error_class: String,
        retryable: bool,
    },
    ModelAttemptInterrupted {
        activation_id: String,
        round_id: String,
        request_id: String,
        attempt_id: String,
        attempt_number: u32,
        reason: String,
    },
    ModelRequestAbandoned {
        activation_id: String,
        round_id: String,
        request_id: String,
        attempt_id: String,
        reason: String,
        abandoned_at_ms: i64,
    },
    ModelAttemptsExhausted {
        fact: ModelAttemptsExhaustedFact,
    },
    ModelStepRetryScheduled {
        schedule: ModelRetrySchedule,
    },
    ModelRequestCompleted {
        activation_id: String,
        round_id: String,
        request_id: String,
        attempt_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        usage: Option<ModelUsageAnchor>,
    },
    ActivationFinished {
        activation_id: String,
        outcome: ActivationOutcome,
        finished_at_ms: i64,
    },
    ModelAttemptFailed {
        failure: ModelAttemptFailure,
    },
    WaitSet {
        wait: ActiveWait,
    },
    WaitTimerScheduled {
        timer: WaitTimerIntent,
    },
    WaitCleared {
        wait_id: String,
    },
    WaitExpired {
        wait_id: String,
    },
    AsyncToolCallStarted {
        record: AsyncToolCallRecord,
    },
    AsyncToolCallRunning {
        tool_call_id: String,
    },
    AsyncToolCallUnknownOutcome {
        tool_call_id: String,
        reason: String,
    },
    AsyncToolCallRuntimeRestarted {
        tool_call_id: String,
        reason: String,
        completed_at_ms: i64,
    },
    AsyncToolCallCallbackPlanned {
        binding: AsyncCallbackBinding,
    },
    AsyncToolCallCallbackCompleted {
        callback_id: String,
        tool_call_id: String,
        payload_fingerprint: String,
        result: DurablePayload,
        completed_at_ms: i64,
    },
    AsyncToolCallCallbackFailed {
        callback_id: String,
        tool_call_id: String,
        payload_fingerprint: String,
        error: ToolError,
        completed_at_ms: i64,
    },
    AsyncToolCallProgress {
        tool_call_id: String,
        progress: DurablePayload,
    },
    AsyncToolCallCompleted {
        tool_call_id: String,
        result: DurablePayload,
        completed_at_ms: i64,
    },
    AsyncToolCallFailed {
        tool_call_id: String,
        error: ToolError,
        completed_at_ms: i64,
    },
    AsyncToolCallCancelled {
        tool_call_id: String,
        reason: String,
        completed_at_ms: i64,
    },
    DedupeRecorded {
        key: String,
    },
}

impl SessionEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::SessionCreated { .. } => "session_created",
            Self::ModelSelectionChanged { .. } => "model_selection_changed",
            Self::StatusChanged { .. } => "status_changed",
            Self::DeliveryQueued { .. } => "delivery_queued",
            Self::DeliveryAcknowledged { .. } => "delivery_acknowledged",
            Self::DeliveryMaterialized { .. } => "delivery_materialized",
            Self::MessageAppended { .. } => "message_appended",
            Self::ActivationStarted { .. } => "activation_started",
            Self::ModelRoundStarted { .. } => "model_round_started",
            Self::ContextHandoffPlanned { .. } => "context_handoff_planned",
            Self::ContextHandoffCreated { .. } => "context_handoff_created",
            Self::ContextHandoffFailed { .. } => "context_handoff_failed",
            Self::ModelRequestPrepared { .. } => "model_request_prepared",
            Self::ModelRequestDeclared { .. } => "model_request_declared",
            Self::ModelAttemptStarted { .. } => "model_attempt_started",
            Self::ModelAttemptFailedFact { .. } => "model_attempt_failed",
            Self::ModelAttemptInterrupted { .. } => "model_attempt_interrupted",
            Self::ModelRequestAbandoned { .. } => "model_request_abandoned",
            Self::ModelAttemptsExhausted { .. } => "model_attempts_exhausted",
            Self::ModelStepRetryScheduled { .. } => "model_step_retry_scheduled",
            Self::ModelRequestCompleted { .. } => "model_request_completed",
            Self::ActivationFinished { .. } => "activation_finished",
            Self::ModelAttemptFailed { .. } => "model_attempt_failed",
            Self::WaitSet { .. } => "wait_set",
            Self::WaitTimerScheduled { .. } => "wait_timer_scheduled",
            Self::WaitCleared { .. } => "wait_cleared",
            Self::WaitExpired { .. } => "wait_expired",
            Self::AsyncToolCallStarted { .. } => "async_tool_call_started",
            Self::AsyncToolCallRunning { .. } => "async_tool_call_running",
            Self::AsyncToolCallUnknownOutcome { .. } => "async_tool_call_unknown_outcome",
            Self::AsyncToolCallRuntimeRestarted { .. } => "async_tool_call_runtime_restarted",
            Self::AsyncToolCallCallbackPlanned { .. } => "async_tool_call_callback_planned",
            Self::AsyncToolCallCallbackCompleted { .. } => "async_tool_call_callback_completed",
            Self::AsyncToolCallCallbackFailed { .. } => "async_tool_call_callback_failed",
            Self::AsyncToolCallProgress { .. } => "async_tool_call_progress",
            Self::AsyncToolCallCompleted { .. } => "async_tool_call_completed",
            Self::AsyncToolCallFailed { .. } => "async_tool_call_failed",
            Self::AsyncToolCallCancelled { .. } => "async_tool_call_cancelled",
            Self::DedupeRecorded { .. } => "dedupe_recorded",
        }
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        match self {
            Self::SessionCreated {
                schema_version,
                session_id,
                owner,
                created_at_ms,
                selection,
            } => {
                if *schema_version != SESSION_CREATED_SCHEMA_VERSION {
                    return Err(DomainError::UnsupportedSessionCreatedSchema(
                        *schema_version,
                    ));
                }
                validate_identifier("session_id", session_id)?;
                owner.validate()?;
                if *created_at_ms < 0 {
                    return Err(DomainError::InvalidCreatedAt);
                }
                selection.validate()?;
            }
            Self::ModelSelectionChanged { selection } => selection.validate()?,
            Self::StatusChanged { .. } => {}
            Self::DeliveryQueued { delivery } => validate_delivery(delivery, false)?,
            Self::DeliveryAcknowledged { .. } => {}
            Self::DeliveryMaterialized { queue_id, message } => {
                if *queue_id == 0 {
                    return Err(DomainError::InvalidState(
                        "delivery materialization needs a queue id".into(),
                    ));
                }
                validate_message(message)?;
            }
            Self::MessageAppended { message, .. } => validate_message(message)?,
            Self::ActivationStarted {
                activation_id,
                selection,
                selection_version,
                minimum_auth_revision,
                started_at_ms,
            } => {
                validate_identifier("activation_id", activation_id)?;
                selection.validate()?;
                if *selection_version == 0 || *minimum_auth_revision == 0 {
                    return Err(DomainError::InvalidState(
                        "activation selection and auth revisions must be positive".into(),
                    ));
                }
                validate_non_negative_timestamp("activation started_at_ms", *started_at_ms)?;
            }
            Self::ModelRoundStarted {
                activation_id,
                round_id,
                purpose: _,
                delivery_through_queue_id,
                started_at_ms,
            } => {
                validate_identifier("activation_id", activation_id)?;
                validate_identifier("round_id", round_id)?;
                validate_non_negative_timestamp("model round started_at_ms", *started_at_ms)?;
                if *delivery_through_queue_id == 0 {
                    return Err(DomainError::InvalidState(
                        "model round delivery boundary must be positive".into(),
                    ));
                }
            }
            Self::ContextHandoffPlanned { plan } => {
                validate_context_handoff_plan(plan)?;
            }
            Self::ContextHandoffCreated { handoff } => {
                validate_context_handoff_document(handoff)?;
            }
            Self::ContextHandoffFailed {
                plan_id,
                error,
                finished_at_ms,
            } => {
                validate_identifier("context handoff plan_id", plan_id)?;
                validate_model_error(error)?;
                validate_non_negative_timestamp("context handoff finished_at_ms", *finished_at_ms)?;
            }
            Self::ModelRequestDeclared {
                activation_id,
                round_id,
                request_id,
                request_fingerprint,
                provider_execution_fingerprint,
                prompt_fingerprint,
                tool_schema_fingerprint,
                maximum_attempts,
                minimum_auth_revision,
            }
            | Self::ModelRequestPrepared {
                activation_id,
                round_id,
                request_id,
                request_fingerprint,
                provider_execution_fingerprint,
                prompt_fingerprint,
                tool_schema_fingerprint,
                maximum_attempts,
                minimum_auth_revision,
                ..
            } => {
                if let Self::ModelRequestPrepared { envelope, .. } = self {
                    envelope.validate()?;
                }
                validate_identifier("activation_id", activation_id)?;
                validate_identifier("round_id", round_id)?;
                validate_identifier("request_id", request_id)?;
                validate_model_fingerprint("request_fingerprint", request_fingerprint)?;
                validate_model_fingerprint(
                    "provider_execution_fingerprint",
                    provider_execution_fingerprint,
                )?;
                validate_model_fingerprint("prompt_fingerprint", prompt_fingerprint)?;
                validate_model_fingerprint("tool_schema_fingerprint", tool_schema_fingerprint)?;
                if *maximum_attempts == 0 || *maximum_attempts > MAX_MODEL_ATTEMPTS_PER_STEP {
                    return Err(DomainError::InvalidState(
                        "model request maximum attempts are outside the bounded range".into(),
                    ));
                }
                if *minimum_auth_revision == 0 {
                    return Err(DomainError::InvalidState(
                        "model request minimum auth revision must be positive".into(),
                    ));
                }
            }
            Self::ModelAttemptStarted {
                activation_id,
                round_id,
                request_id,
                attempt_id,
                attempt_number,
                auth_revision,
                started_at_ms,
            } => {
                validate_identifier("activation_id", activation_id)?;
                validate_identifier("round_id", round_id)?;
                validate_identifier("request_id", request_id)?;
                validate_identifier("attempt_id", attempt_id)?;
                if *attempt_number == 0 || *attempt_number > MAX_MODEL_ATTEMPTS_PER_STEP {
                    return Err(DomainError::InvalidState(
                        "model attempt number is outside the bounded range".into(),
                    ));
                }
                if *auth_revision == 0 {
                    return Err(DomainError::InvalidState(
                        "model attempt auth revision must be positive".into(),
                    ));
                }
                validate_non_negative_timestamp("model attempt started_at_ms", *started_at_ms)?;
            }
            Self::ModelAttemptFailedFact {
                activation_id,
                round_id,
                request_id,
                attempt_id,
                attempt_number,
                error_class,
                ..
            } => {
                validate_identifier("activation_id", activation_id)?;
                validate_identifier("round_id", round_id)?;
                validate_identifier("request_id", request_id)?;
                validate_identifier("attempt_id", attempt_id)?;
                validate_identifier("model attempt error class", error_class)?;
                if *attempt_number == 0 || *attempt_number > MAX_MODEL_ATTEMPTS_PER_STEP {
                    return Err(DomainError::InvalidState(
                        "model attempt number is outside the bounded range".into(),
                    ));
                }
            }
            Self::ModelAttemptInterrupted {
                activation_id,
                round_id,
                request_id,
                attempt_id,
                attempt_number,
                reason,
            } => {
                validate_identifier("activation_id", activation_id)?;
                validate_identifier("round_id", round_id)?;
                validate_identifier("request_id", request_id)?;
                validate_identifier("attempt_id", attempt_id)?;
                validate_bounded_text("model interruption reason", reason)?;
                if *attempt_number == 0 || *attempt_number > MAX_MODEL_ATTEMPTS_PER_STEP {
                    return Err(DomainError::InvalidState(
                        "model attempt number is outside the bounded range".into(),
                    ));
                }
            }
            Self::ModelRequestAbandoned {
                activation_id,
                round_id,
                request_id,
                attempt_id,
                reason,
                abandoned_at_ms,
            } => {
                validate_identifier("activation_id", activation_id)?;
                validate_identifier("round_id", round_id)?;
                validate_identifier("request_id", request_id)?;
                validate_identifier("attempt_id", attempt_id)?;
                validate_bounded_text("model request abandonment reason", reason)?;
                validate_non_negative_timestamp("model request abandoned_at_ms", *abandoned_at_ms)?;
            }
            Self::ModelAttemptsExhausted { fact } => {
                validate_model_attempts_exhausted(fact)?;
            }
            Self::ModelStepRetryScheduled { schedule } => validate_retry_schedule(schedule)?,
            Self::ModelRequestCompleted {
                activation_id,
                round_id,
                request_id,
                attempt_id,
                usage,
            } => {
                validate_identifier("activation_id", activation_id)?;
                validate_identifier("round_id", round_id)?;
                validate_identifier("request_id", request_id)?;
                validate_identifier("attempt_id", attempt_id)?;
                if let Some(usage) = usage {
                    validate_model_usage_anchor(usage)?;
                }
            }
            Self::ActivationFinished {
                activation_id,
                finished_at_ms,
                ..
            } => {
                validate_identifier("activation_id", activation_id)?;
                validate_non_negative_timestamp("activation finished_at_ms", *finished_at_ms)?;
            }
            Self::ModelAttemptFailed { failure } => validate_model_attempt_failure(failure)?,
            Self::WaitSet { wait } => validate_wait(wait)?,
            Self::WaitTimerScheduled { timer } => {
                validate_identifier("wait timer wait_id", &timer.wait_id)?;
                validate_non_negative_timestamp("wait timer deadline_ms", timer.deadline_ms)?;
            }
            Self::WaitCleared { wait_id } | Self::WaitExpired { wait_id } => {
                validate_identifier("wait_id", wait_id)?;
            }
            Self::AsyncToolCallStarted { record } => validate_started_record(record)?,
            Self::AsyncToolCallRunning { tool_call_id } => {
                validate_identifier("tool_call_id", tool_call_id)?;
            }
            Self::AsyncToolCallUnknownOutcome {
                tool_call_id,
                reason,
            } => {
                validate_identifier("tool_call_id", tool_call_id)?;
                validate_bounded_text("unknown outcome reason", reason)?;
            }
            Self::AsyncToolCallRuntimeRestarted {
                tool_call_id,
                reason,
                completed_at_ms,
            } => {
                validate_identifier("tool_call_id", tool_call_id)?;
                validate_bounded_text("runtime restart reason", reason)?;
                validate_non_negative_timestamp(
                    "async runtime restarted completed_at_ms",
                    *completed_at_ms,
                )?;
            }
            Self::AsyncToolCallCallbackPlanned { binding } => {
                validate_callback_binding(binding)?;
            }
            Self::AsyncToolCallCallbackCompleted {
                callback_id,
                tool_call_id,
                payload_fingerprint,
                result,
                completed_at_ms,
            } => {
                validate_identifier("callback_id", callback_id)?;
                validate_identifier("tool_call_id", tool_call_id)?;
                validate_model_fingerprint("callback payload fingerprint", payload_fingerprint)?;
                result.validate()?;
                validate_non_negative_timestamp("callback completed_at_ms", *completed_at_ms)?;
            }
            Self::AsyncToolCallCallbackFailed {
                callback_id,
                tool_call_id,
                payload_fingerprint,
                error,
                completed_at_ms,
            } => {
                validate_identifier("callback_id", callback_id)?;
                validate_identifier("tool_call_id", tool_call_id)?;
                validate_model_fingerprint("callback payload fingerprint", payload_fingerprint)?;
                validate_tool_error(error)?;
                validate_non_negative_timestamp("callback failed_at_ms", *completed_at_ms)?;
            }
            Self::AsyncToolCallProgress {
                tool_call_id,
                progress,
            } => {
                validate_identifier("tool_call_id", tool_call_id)?;
                progress.validate()?;
            }
            Self::AsyncToolCallCompleted {
                tool_call_id,
                result,
                completed_at_ms,
            } => {
                validate_identifier("tool_call_id", tool_call_id)?;
                result.validate()?;
                if *completed_at_ms < 0 {
                    return Err(DomainError::InvalidTimestamp {
                        field: "async tool completed_at_ms",
                    });
                }
            }
            Self::AsyncToolCallFailed {
                tool_call_id,
                error,
                completed_at_ms,
            } => {
                validate_identifier("tool_call_id", tool_call_id)?;
                validate_tool_error(error)?;
                if *completed_at_ms < 0 {
                    return Err(DomainError::InvalidTimestamp {
                        field: "async tool completed_at_ms",
                    });
                }
            }
            Self::AsyncToolCallCancelled {
                tool_call_id,
                reason,
                completed_at_ms,
            } => {
                validate_identifier("tool_call_id", tool_call_id)?;
                validate_bounded_text("reason", reason)?;
                if *completed_at_ms < 0 {
                    return Err(DomainError::InvalidTimestamp {
                        field: "async tool completed_at_ms",
                    });
                }
            }
            Self::DedupeRecorded { key } => validate_identifier("key", key)?,
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EventDraft {
    pub event_id: String,
    pub event: SessionEvent,
}

impl EventDraft {
    pub fn new(event_id: impl Into<String>, event: SessionEvent) -> Self {
        Self {
            event_id: event_id.into(),
            event,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EventRecord {
    pub stream_id: String,
    pub stream_version: StreamVersion,
    pub global_position: GlobalPosition,
    pub event_id: String,
    pub command_id: String,
    pub event_schema_version: u32,
    pub event: SessionEvent,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SessionState {
    pub session_id: String,
    pub owner: Option<SessionOwner>,
    pub created_at_ms: Option<i64>,
    pub selection: SessionSelection,
    #[serde(default = "default_created_selection_version")]
    pub selection_version: u64,
    pub status: SessionStatus,
    pub transcript: Vec<TranscriptMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_model_attempt_failure: Option<ModelAttemptFailure>,
    pub delivery_queue: Vec<QueuedDelivery>,
    pub delivery_ack: u64,
    pub active_wait: Option<ActiveWait>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_timer: Option<WaitTimerIntent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake_pending_wait_id: Option<String>,
    pub async_tool_calls: BTreeMap<String, AsyncToolCallRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_activation: Option<ActiveActivation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_model_round: Option<ActiveModelRound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_context_handoff: Option<ContextHandoffPlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_context_handoff: Option<ContextHandoffDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_model_usage: Option<ModelUsageAnchor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_context_handoff_failure: Option<ModelAttemptError>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub callback_bindings: BTreeMap<String, AsyncCallbackBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_model_attempts_exhausted: Option<ModelAttemptsExhaustedFact>,
    pub stream_version: StreamVersion,
    pub dedupe_facts: DedupeFacts,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DomainDecision {
    pub effective_events: Vec<SessionEvent>,
    pub state: SessionState,
}

fn validate_delivery(
    delivery: &QueuedDelivery,
    allow_materialized: bool,
) -> Result<(), DomainError> {
    validate_identifier("delivery_id", &delivery.delivery_id)?;
    validate_identifier("dedupe_key", &delivery.dedupe_key)?;
    if delivery.queue_id == 0 {
        return Err(DomainError::InvalidState(
            "delivery queue ids start at one".into(),
        ));
    }
    delivery.payload.validate()?;
    if let Some(source_tool_call_id) = &delivery.source_tool_call_id {
        validate_identifier("source_tool_call_id", source_tool_call_id)?;
    }
    if let Some(created_at_ms) = delivery.created_at_ms {
        if created_at_ms < 0 {
            return Err(DomainError::InvalidTimestamp {
                field: "delivery created_at_ms",
            });
        }
    }
    if !allow_materialized && delivery.materialized_message_id.is_some() {
        return Err(DomainError::InvalidState(
            "new deliveries cannot already be materialized".into(),
        ));
    }
    Ok(())
}

fn validate_message(message: &TranscriptMessage) -> Result<(), DomainError> {
    validate_identifier("message_id", &message.message_id)?;
    if message.content.len() > MAX_MESSAGE_CONTENT_BYTES {
        return Err(DomainError::TextTooLarge {
            field: "message content",
            bytes: message.content.len(),
            max: MAX_MESSAGE_CONTENT_BYTES,
        });
    }
    if let Some(tool_call_id) = &message.tool_call_id {
        validate_identifier("tool_call_id", tool_call_id)?;
    }
    if message.tool_calls.len() > MAX_TOOL_CALLS_PER_MESSAGE {
        return Err(DomainError::CollectionTooLarge {
            field: "message tool calls",
            items: message.tool_calls.len(),
            max: MAX_TOOL_CALLS_PER_MESSAGE,
        });
    }
    if let Some(dedupe_key) = &message.dedupe_key {
        validate_identifier("message dedupe_key", dedupe_key)?;
    }
    if message.source_queue_id == Some(0) {
        return Err(DomainError::InvalidState(
            "message source queue ids start at one".into(),
        ));
    }
    let mut tool_call_ids = BTreeSet::new();
    if let Some(tool_call_id) = &message.tool_call_id {
        tool_call_ids.insert(tool_call_id.as_str());
    }
    for call in &message.tool_calls {
        validate_identifier("tool_call_id", &call.tool_call_id)?;
        validate_identifier("tool_name", &call.tool_name)?;
        call.input.validate()?;
        if !tool_call_ids.insert(call.tool_call_id.as_str()) {
            return Err(DomainError::DuplicateTranscriptToolCallId(
                call.tool_call_id.clone(),
            ));
        }
    }
    Ok(())
}

fn validate_wait(wait: &ActiveWait) -> Result<(), DomainError> {
    validate_identifier("wait_id", &wait.wait_id)?;
    validate_bounded_text("reason", &wait.reason)?;
    if !(WAIT_MIN_SECONDS..=WAIT_MAX_SECONDS).contains(&wait.timeout_seconds) {
        return Err(DomainError::InvalidWaitTimeout);
    }
    if wait.deadline_ms < 0 {
        return Err(DomainError::InvalidTimestamp {
            field: "wait deadline_ms",
        });
    }
    if wait.tool_call_ids.len() > MAX_WAIT_TOOL_CALLS {
        return Err(DomainError::CollectionTooLarge {
            field: "wait tool call ids",
            items: wait.tool_call_ids.len(),
            max: MAX_WAIT_TOOL_CALLS,
        });
    }
    for tool_call_id in &wait.tool_call_ids {
        validate_identifier("tool_call_id", tool_call_id)?;
    }
    Ok(())
}

fn validate_started_record(record: &AsyncToolCallRecord) -> Result<(), DomainError> {
    if !matches!(
        record.status,
        AsyncToolStatus::Planned | AsyncToolStatus::Running
    ) || record.progress.is_some()
        || record.result.is_some()
        || record.error.is_some()
        || record.cancel_reason.is_some()
        || record.completed_at_ms.is_some()
    {
        return Err(DomainError::InvalidAsyncToolStart(
            record.tool_call_id.clone(),
        ));
    }
    validate_async_identity_and_input(record)?;
    Ok(())
}

fn validate_async_record(record: &AsyncToolCallRecord) -> Result<(), DomainError> {
    validate_async_identity_and_input(record)?;
    if record.started_at_ms < 0 {
        return Err(DomainError::InvalidTimestamp {
            field: "async tool started_at_ms",
        });
    }
    if let Some(progress) = &record.progress {
        progress.validate()?;
    }
    match record.status {
        AsyncToolStatus::Planned | AsyncToolStatus::Running => {
            if record.result.is_some()
                || record.error.is_some()
                || record.cancel_reason.is_some()
                || record.completed_at_ms.is_some()
            {
                return Err(DomainError::InvalidState(
                    "running async tool calls cannot have terminal fields".into(),
                ));
            }
        }
        AsyncToolStatus::UnknownOutcome => {
            if record.result.is_some()
                || record.error.is_some()
                || record.cancel_reason.is_some()
                || record.completed_at_ms.is_some()
            {
                return Err(DomainError::InvalidState(
                    "unknown-outcome async tool calls cannot have terminal fields".into(),
                ));
            }
        }
        AsyncToolStatus::RuntimeRestarted => {
            if record.result.is_some()
                || record.error.is_none()
                || record.cancel_reason.is_some()
                || record.completed_at_ms.is_none()
            {
                return Err(DomainError::InvalidState(
                    "runtime-restarted async tool calls need only error and completion time".into(),
                ));
            }
            validate_tool_error(record.error.as_ref().unwrap())?;
            validate_terminal_timestamp(record.started_at_ms, record.completed_at_ms)?;
        }
        AsyncToolStatus::Completed => {
            if record.result.is_none()
                || record.error.is_some()
                || record.cancel_reason.is_some()
                || record.completed_at_ms.is_none()
            {
                return Err(DomainError::InvalidState(
                    "completed async tool calls need only result and completion time".into(),
                ));
            }
            record.result.as_ref().unwrap().validate()?;
            validate_terminal_timestamp(record.started_at_ms, record.completed_at_ms)?;
        }
        AsyncToolStatus::Failed => {
            if record.result.is_some()
                || record.error.is_none()
                || record.cancel_reason.is_some()
                || record.completed_at_ms.is_none()
            {
                return Err(DomainError::InvalidState(
                    "failed async tool calls need only error and completion time".into(),
                ));
            }
            validate_tool_error(record.error.as_ref().unwrap())?;
            validate_terminal_timestamp(record.started_at_ms, record.completed_at_ms)?;
        }
        AsyncToolStatus::Cancelled => {
            if record.result.is_some()
                || record.error.is_some()
                || record.cancel_reason.is_none()
                || record.completed_at_ms.is_none()
            {
                return Err(DomainError::InvalidState(
                    "cancelled async tool calls need only cancel reason and completion time".into(),
                ));
            }
            validate_bounded_text("cancel_reason", record.cancel_reason.as_ref().unwrap())?;
            validate_terminal_timestamp(record.started_at_ms, record.completed_at_ms)?;
        }
    }
    Ok(())
}

fn validate_async_identity_and_input(record: &AsyncToolCallRecord) -> Result<(), DomainError> {
    validate_identifier("tool_call_id", &record.tool_call_id)?;
    validate_identifier("tool_name", &record.tool_name)?;
    record.input.validate()?;
    if let Some(seconds) = record.auto_wait_seconds {
        if !(WAIT_MIN_SECONDS..=WAIT_MAX_SECONDS).contains(&seconds) {
            return Err(DomainError::InvalidWaitTimeout);
        }
    }
    Ok(())
}

fn validate_callback_binding(binding: &AsyncCallbackBinding) -> Result<(), DomainError> {
    validate_identifier("callback_id", &binding.callback_id)?;
    validate_identifier("tool_call_id", &binding.tool_call_id)?;
    validate_model_fingerprint("callback bearer fingerprint", &binding.bearer_fingerprint)?;
    if let Some(payload_fingerprint) = &binding.payload_fingerprint {
        validate_model_fingerprint("callback payload fingerprint", payload_fingerprint)?;
    }
    Ok(())
}

fn validate_tool_error(error: &ToolError) -> Result<(), DomainError> {
    validate_identifier("error.class", &error.class)?;
    validate_bounded_text("error.message", &error.message)
}

fn validate_model_attempt_failure(failure: &ModelAttemptFailure) -> Result<(), DomainError> {
    validate_identifier("trigger_message_id", &failure.trigger_message_id)?;
    validate_bounded_text("model error message", &failure.error.message)?;
    validate_model_error(&failure.error)
}

fn validate_model_error(error: &ModelAttemptError) -> Result<(), DomainError> {
    validate_bounded_text("model error message", &error.message)
}

fn validate_model_usage_anchor(anchor: &ModelUsageAnchor) -> Result<(), DomainError> {
    if anchor.context_generation == 0
        || anchor.input_tokens == 0
        || anchor.local_input_estimate_tokens == Some(0)
        || anchor.input_estimate_scale_millionths == Some(0)
    {
        return Err(DomainError::InvalidState(
            "model usage anchor has invalid token accounting".into(),
        ));
    }
    validate_model_fingerprint(
        "model usage selection fingerprint",
        &anchor.selection_fingerprint,
    )?;
    validate_model_fingerprint(
        "model usage tool schema fingerprint",
        &anchor.tool_schema_fingerprint,
    )?;
    validate_identifier("model usage result_message_id", &anchor.result_message_id)
}

fn validate_context_handoff_plan(plan: &ContextHandoffPlan) -> Result<(), DomainError> {
    validate_identifier("context handoff plan_id", &plan.plan_id)?;
    validate_identifier("context handoff activation_id", &plan.activation_id)?;
    if let Some(previous_handoff_id) = &plan.previous_handoff_id {
        validate_identifier("previous context handoff_id", previous_handoff_id)?;
    }
    validate_identifier(
        "context handoff covered message_id",
        &plan.covered_through_message_id,
    )?;
    validate_model_fingerprint("context handoff source digest", &plan.source_digest)?;
    if plan.next_generation < 2 || plan.source_tokens == 0 || plan.token_accounting_version == 0 {
        return Err(DomainError::InvalidState(
            "context handoff plan has invalid generation or token accounting".into(),
        ));
    }
    SessionSelection {
        model: Some(plan.selection.clone()),
        tools: Vec::new(),
        callback_base_url: None,
    }
    .validate()
}

fn validate_context_handoff_document(handoff: &ContextHandoffDocument) -> Result<(), DomainError> {
    validate_identifier("context handoff_id", &handoff.handoff_id)?;
    validate_identifier("context handoff plan_id", &handoff.plan_id)?;
    if let Some(previous_handoff_id) = &handoff.previous_handoff_id {
        validate_identifier("previous context handoff_id", previous_handoff_id)?;
    }
    validate_identifier(
        "context handoff covered message_id",
        &handoff.covered_through_message_id,
    )?;
    validate_model_fingerprint("context handoff source digest", &handoff.source_digest)?;
    validate_model_fingerprint("context handoff document digest", &handoff.document_digest)?;
    require_text("context handoff document", &handoff.document)?;
    if handoff.document.len() > MAX_MESSAGE_CONTENT_BYTES {
        return Err(DomainError::TextTooLarge {
            field: "context handoff document",
            bytes: handoff.document.len(),
            max: MAX_MESSAGE_CONTENT_BYTES,
        });
    }
    if handoff.next_generation < 2
        || handoff.source_tokens == 0
        || handoff.document_tokens == 0
        || handoff.token_accounting_version == 0
    {
        return Err(DomainError::InvalidState(
            "context handoff document has invalid generation or token accounting".into(),
        ));
    }
    SessionSelection {
        model: Some(handoff.selection.clone()),
        tools: Vec::new(),
        callback_base_url: None,
    }
    .validate()
}

fn validate_non_negative_timestamp(field: &'static str, value: i64) -> Result<(), DomainError> {
    if value < 0 {
        Err(DomainError::InvalidTimestamp { field })
    } else {
        Ok(())
    }
}

fn validate_model_fingerprint(field: &'static str, value: &str) -> Result<(), DomainError> {
    validate_identifier(field, value)?;
    if value.len() > MAX_MODEL_FINGERPRINT_BYTES {
        return Err(DomainError::TextTooLarge {
            field,
            bytes: value.len(),
            max: MAX_MODEL_FINGERPRINT_BYTES,
        });
    }
    Ok(())
}

fn validate_model_attempts_exhausted(fact: &ModelAttemptsExhaustedFact) -> Result<(), DomainError> {
    validate_identifier("activation_id", &fact.activation_id)?;
    validate_identifier("round_id", &fact.round_id)?;
    validate_identifier("request_id", &fact.request_id)?;
    validate_identifier("attempt_id", &fact.attempt_id)?;
    if fact.attempt_number == 0
        || fact.attempt_number > MAX_MODEL_ATTEMPTS_PER_STEP
        || fact.maximum_attempts == 0
        || fact.maximum_attempts > MAX_MODEL_ATTEMPTS_PER_STEP
        || fact.attempt_number != fact.maximum_attempts
    {
        return Err(DomainError::InvalidState(
            "model attempts exhausted fact has invalid attempt bounds".into(),
        ));
    }
    validate_non_negative_timestamp(
        "model attempts exhausted finished_at_ms",
        fact.finished_at_ms,
    )
}

fn validate_retry_schedule(schedule: &ModelRetrySchedule) -> Result<(), DomainError> {
    validate_identifier("activation_id", &schedule.activation_id)?;
    validate_identifier("round_id", &schedule.round_id)?;
    validate_identifier("request_id", &schedule.request_id)?;
    validate_identifier("failed_attempt_id", &schedule.failed_attempt_id)?;
    validate_identifier("next_attempt_id", &schedule.next_attempt_id)?;
    validate_identifier("retry error class", &schedule.error_class)?;
    if schedule.failed_attempt_number == 0
        || schedule.next_attempt_number != schedule.failed_attempt_number.saturating_add(1)
        || schedule.next_attempt_number > schedule.maximum_attempts
        || schedule.maximum_attempts == 0
        || schedule.maximum_attempts > MAX_MODEL_ATTEMPTS_PER_STEP
    {
        return Err(DomainError::InvalidState(
            "model retry schedule has invalid attempt bounds".into(),
        ));
    }
    validate_non_negative_timestamp("retry not_before_ms", schedule.not_before_ms)
}

fn validate_active_activation(activation: &ActiveActivation) -> Result<(), DomainError> {
    validate_identifier("activation_id", &activation.activation_id)?;
    activation.selection.validate()?;
    if activation.selection_version == 0 || activation.minimum_auth_revision == 0 {
        return Err(DomainError::InvalidState(
            "active activation revisions must be positive".into(),
        ));
    }
    validate_non_negative_timestamp("activation started_at_ms", activation.started_at_ms)?;
    Ok(())
}

fn validate_active_model_round(round: &ActiveModelRound) -> Result<(), DomainError> {
    validate_identifier("activation_id", &round.activation_id)?;
    validate_identifier("round_id", &round.round_id)?;
    validate_non_negative_timestamp("model round started_at_ms", round.started_at_ms)?;
    if round.delivery_through_queue_id == 0 {
        return Err(DomainError::InvalidState(
            "active model round delivery boundary must be positive".into(),
        ));
    }
    if let Some(request) = &round.request {
        validate_identifier("request_id", &request.request_id)?;
        if request.activation_id != round.activation_id || request.round_id != round.round_id {
            return Err(DomainError::InvalidState(
                "declared model request belongs to another round".into(),
            ));
        }
        validate_model_fingerprint("request_fingerprint", &request.request_fingerprint)?;
        validate_model_fingerprint(
            "provider_execution_fingerprint",
            &request.provider_execution_fingerprint,
        )?;
        validate_model_fingerprint("prompt_fingerprint", &request.prompt_fingerprint)?;
        validate_model_fingerprint("tool_schema_fingerprint", &request.tool_schema_fingerprint)?;
        if let Some(envelope) = &request.legacy_envelope {
            envelope.validate()?;
        }
        if request.maximum_attempts == 0
            || request.maximum_attempts > MAX_MODEL_ATTEMPTS_PER_STEP
            || request.minimum_auth_revision == 0
        {
            return Err(DomainError::InvalidState(
                "declared model request has invalid bounds".into(),
            ));
        }
        if let Some(attempt) = &round.attempt {
            if attempt.activation_id != round.activation_id
                || attempt.round_id != round.round_id
                || attempt.request_id != request.request_id
            {
                return Err(DomainError::InvalidState(
                    "model attempt belongs to another request".into(),
                ));
            }
            validate_identifier("attempt_id", &attempt.attempt_id)?;
            if attempt.attempt_number == 0 || attempt.attempt_number > request.maximum_attempts {
                return Err(DomainError::InvalidState(
                    "model attempt number is outside declared request bounds".into(),
                ));
            }
            if attempt.auth_revision == 0 {
                return Err(DomainError::InvalidState(
                    "model attempt auth revision must be positive".into(),
                ));
            }
            validate_non_negative_timestamp("model attempt started_at_ms", attempt.started_at_ms)?;
        }
    } else if round.attempt.is_some() || round.retry.is_some() {
        return Err(DomainError::InvalidState(
            "model attempt/retry requires a declared request".into(),
        ));
    }
    if let Some(schedule) = &round.retry {
        validate_retry_schedule(schedule)?;
        let request = round.request.as_ref().expect("checked above");
        if schedule.activation_id != round.activation_id
            || schedule.round_id != round.round_id
            || schedule.request_id != request.request_id
        {
            return Err(DomainError::InvalidState(
                "retry schedule belongs to another request".into(),
            ));
        }
    }
    Ok(())
}

fn current_model_attempt_mut<'a>(
    state: &'a mut SessionState,
    activation_id: &str,
    round_id: &str,
    request_id: &str,
    attempt_id: &str,
    attempt_number: u32,
) -> Result<&'a mut ModelAttemptRecord, DomainError> {
    let round = state
        .active_model_round
        .as_mut()
        .ok_or_else(|| DomainError::InvalidState("model attempt has no active round".into()))?;
    let request = round
        .request
        .as_ref()
        .ok_or_else(|| DomainError::InvalidState("model attempt has no declared request".into()))?;
    if request.activation_id != activation_id
        || request.round_id != round_id
        || request.request_id != request_id
        || round.activation_id != activation_id
        || round.round_id != round_id
    {
        return Err(DomainError::InvalidState(
            "model attempt belongs to another request".into(),
        ));
    }
    let attempt = round
        .attempt
        .as_mut()
        .ok_or_else(|| DomainError::InvalidState("model attempt has no started attempt".into()))?;
    if attempt.attempt_id != attempt_id || attempt.attempt_number != attempt_number {
        return Err(DomainError::InvalidState(
            "model attempt identity does not match".into(),
        ));
    }
    Ok(attempt)
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), DomainError> {
    require_text(field, value)?;
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(DomainError::TextTooLarge {
            field,
            bytes: value.len(),
            max: MAX_IDENTIFIER_BYTES,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(DomainError::InvalidState(format!(
            "{field} contains a control character"
        )));
    }
    Ok(())
}

fn validate_bounded_text(field: &'static str, value: &str) -> Result<(), DomainError> {
    require_text(field, value)?;
    validate_text(field, value)
}

fn validate_text(field: &'static str, value: &str) -> Result<(), DomainError> {
    if value.len() > MAX_ERROR_MESSAGE_BYTES {
        return Err(DomainError::TextTooLarge {
            field,
            bytes: value.len(),
            max: MAX_ERROR_MESSAGE_BYTES,
        });
    }
    Ok(())
}

fn validate_terminal_timestamp(start: i64, end: Option<i64>) -> Result<(), DomainError> {
    let Some(end) = end else {
        return Err(DomainError::InvalidState(
            "terminal async tool state requires completion time".into(),
        ));
    };
    if end < 0 {
        return Err(DomainError::InvalidTimestamp {
            field: "async tool completed_at_ms",
        });
    }
    if end < start {
        return Err(DomainError::InvalidTimestampOrder { start, end });
    }
    Ok(())
}

fn require_text(field: &'static str, value: &str) -> Result<(), DomainError> {
    if value.is_empty() {
        Err(DomainError::EmptyField { field })
    } else {
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

fn default_created_selection_version() -> u64 {
    1
}

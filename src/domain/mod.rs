use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const EVENT_SCHEMA_VERSION: u32 = 1;
pub const STATE_SCHEMA_VERSION: u32 = 1;
pub const REDUCER_SCHEMA_VERSION: u32 = 1;
pub const SESSION_CREATED_SCHEMA_VERSION: u32 = 2;
pub const WAIT_MIN_SECONDS: u32 = 1;
pub const WAIT_MAX_SECONDS: u32 = 600;
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
pub const MAX_MODEL_ROUNDS_PER_ACTIVATION: u32 = 64;
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
    pub rounds_started: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ActiveModelRound {
    pub activation_id: String,
    pub round_id: String,
    pub delivery_through_queue_id: u64,
    pub started_at_ms: i64,
    #[serde(default)]
    pub request: Option<ModelRequestRecord>,
    #[serde(default)]
    pub attempt: Option<ModelAttemptRecord>,
    #[serde(default)]
    pub retry: Option<ModelRetrySchedule>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ModelRequestRecord {
    pub activation_id: String,
    pub round_id: String,
    pub request_id: String,
    pub request_fingerprint: String,
    pub provider_execution_fingerprint: String,
    pub prompt_fingerprint: String,
    pub tool_schema_fingerprint: String,
    pub envelope: DurablePayload,
    pub maximum_attempts: u32,
    pub minimum_auth_revision: u64,
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
    pub auth_authority_id: String,
    pub auth_profile_id: String,
    pub auth_revision: u64,
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

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct InlinePayload(Value);

impl InlinePayload {
    pub fn new(value: Value) -> Result<Self, DomainError> {
        let bytes = serde_json::to_vec(&value)
            .map_err(|error| DomainError::InvalidDurablePayload(error.to_string()))?
            .len();
        if bytes > MAX_INLINE_PAYLOAD_BYTES {
            return Err(DomainError::DurablePayloadTooLarge {
                bytes,
                max: MAX_INLINE_PAYLOAD_BYTES,
            });
        }
        Ok(Self(value))
    }

    pub fn value(&self) -> &Value {
        &self.0
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
                let bytes = serde_json::to_vec(value.value())
                    .map_err(|error| DomainError::InvalidDurablePayload(error.to_string()))?
                    .len();
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
        delivery_through_queue_id: u64,
        started_at_ms: i64,
    },
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
            Self::ModelRequestPrepared { .. } => "model_request_prepared",
            Self::ModelAttemptStarted { .. } => "model_attempt_started",
            Self::ModelAttemptFailedFact { .. } => "model_attempt_failed",
            Self::ModelAttemptInterrupted { .. } => "model_attempt_interrupted",
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
            Self::ModelRequestPrepared {
                activation_id,
                round_id,
                request_id,
                request_fingerprint,
                provider_execution_fingerprint,
                prompt_fingerprint,
                tool_schema_fingerprint,
                envelope,
                maximum_attempts,
                minimum_auth_revision,
            } => {
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
                envelope.validate()?;
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
            Self::ModelAttemptsExhausted { fact } => {
                validate_model_attempts_exhausted(fact)?;
            }
            Self::ModelStepRetryScheduled { schedule } => validate_retry_schedule(schedule)?,
            Self::ModelRequestCompleted {
                activation_id,
                round_id,
                request_id,
                attempt_id,
            } => {
                validate_identifier("activation_id", activation_id)?;
                validate_identifier("round_id", round_id)?;
                validate_identifier("request_id", request_id)?;
                validate_identifier("attempt_id", attempt_id)?;
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

impl SessionState {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            owner: None,
            created_at_ms: None,
            selection: SessionSelection::default(),
            selection_version: 0,
            status: SessionStatus::Idle,
            transcript: Vec::new(),
            last_model_attempt_failure: None,
            delivery_queue: Vec::new(),
            delivery_ack: 0,
            active_wait: None,
            active_timer: None,
            wake_pending_wait_id: None,
            async_tool_calls: BTreeMap::new(),
            active_activation: None,
            active_model_round: None,
            callback_bindings: BTreeMap::new(),
            last_model_attempts_exhausted: None,
            stream_version: 0,
            dedupe_facts: DedupeFacts::default(),
        }
    }

    pub fn apply_event(&self, event: &SessionEvent) -> Result<Self, DomainError> {
        self.validate()?;
        self.validate_event_position(event)?;
        event.validate()?;
        let mut next = self.clone();
        next.apply_payload(event)?;
        if next == *self {
            return Ok(next);
        }
        // Validate the projected state at the version that the event will
        // occupy. Creation installs owner/timestamp/selection while the
        // input projection still has stream_version zero; validating before
        // advancing would classify that legitimate transition as an
        // uncreated state. No-op transitions return above and retain the
        // caller's version for reducer-level idempotency filtering.
        next.stream_version = next
            .stream_version
            .checked_add(1)
            .ok_or(DomainError::VersionOverflow)?;
        next.validate()?;
        Ok(next)
    }

    pub fn decide_batch(&self, events: &[SessionEvent]) -> Result<DomainDecision, DomainError> {
        if events.is_empty() {
            return Err(DomainError::EmptyEventBatch);
        }
        self.validate()?;
        let mut state = self.clone();
        let mut effective_events = Vec::with_capacity(events.len());
        for event in events {
            let next = state.apply_event(event)?;
            if next.stream_version != state.stream_version {
                effective_events.push(event.clone());
            }
            state = next;
        }
        Ok(DomainDecision {
            effective_events,
            state,
        })
    }

    pub fn apply_events<I>(&self, events: I) -> Result<Self, DomainError>
    where
        I: IntoIterator<Item = SessionEvent>,
    {
        let next = events
            .into_iter()
            .try_fold(self.clone(), |state, event| state.apply_event(&event))?;
        next.validate()?;
        Ok(next)
    }

    pub fn apply_record(&self, record: &EventRecord) -> Result<Self, DomainError> {
        self.validate()?;
        if record.event_schema_version != EVENT_SCHEMA_VERSION {
            return Err(DomainError::UnsupportedEventSchema(
                record.event_schema_version,
            ));
        }
        if record.stream_id != self.session_id {
            return Err(DomainError::SessionMismatch {
                expected: self.session_id.clone(),
                actual: record.stream_id.clone(),
            });
        }
        let expected_version = self
            .stream_version
            .checked_add(1)
            .ok_or(DomainError::VersionOverflow)?;
        if record.stream_version != expected_version {
            return Err(DomainError::StreamVersionGap {
                expected: expected_version,
                actual: record.stream_version,
            });
        }
        let event_key = format!("event:{}", record.event_id);
        if self.dedupe_facts.contains(&event_key) {
            return Err(DomainError::DuplicateEventId(record.event_id.clone()));
        }
        self.validate_event_position(&record.event)?;
        record.event.validate()?;
        let mut next = self.clone();
        next.apply_payload(&record.event)?;
        next.stream_version = record.stream_version;
        next.dedupe_facts.remember(event_key);
        next.validate()?;
        Ok(next)
    }

    /// Rebuild a projection from the immutable event records in stream order.
    ///
    /// This is intentionally the only replay path exposed by the domain.  It
    /// does not inspect storage metadata or allocate repair facts; callers
    /// provide the records and receive either a complete projection or the
    /// first invalid transition.
    pub fn replay<I>(session_id: impl Into<String>, records: I) -> Result<Self, DomainError>
    where
        I: IntoIterator<Item = EventRecord>,
    {
        records
            .into_iter()
            .try_fold(Self::new(session_id), |state, record| {
                state.apply_record(&record)
            })
    }

    pub fn terminal_model_failure_for_last_user(&self) -> Option<&ModelAttemptFailure> {
        let message = self.transcript.last()?;
        let failure = self.last_model_attempt_failure.as_ref()?;
        (message.role == TranscriptRole::User && message.message_id == failure.trigger_message_id)
            .then_some(failure)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        require_text("session_id", &self.session_id)?;
        validate_text("session_id", &self.session_id)?;
        match (self.stream_version, self.owner.as_ref(), self.created_at_ms) {
            (0, None, None) => {
                if self.selection != SessionSelection::default() {
                    return Err(DomainError::InvalidState(
                        "uncreated session contains an initial selection".into(),
                    ));
                }
                if self.selection_version != 0 {
                    return Err(DomainError::InvalidState(
                        "uncreated session has a selection version".into(),
                    ));
                }
            }
            (0, _, _) => {
                return Err(DomainError::InvalidState(
                    "uncreated session contains creation facts".into(),
                ));
            }
            (_, Some(owner), Some(created_at_ms)) => {
                owner.validate()?;
                if created_at_ms < 0 {
                    return Err(DomainError::InvalidCreatedAt);
                }
                self.selection.validate()?;
                if self.selection_version == 0 {
                    return Err(DomainError::InvalidState(
                        "created session selection version must be positive".into(),
                    ));
                }
            }
            _ => return Err(DomainError::SessionNotCreated),
        }
        self.dedupe_facts.validate()?;
        let mut message_ids = BTreeSet::new();
        let mut declared_tool_calls = BTreeMap::new();
        for message in &self.transcript {
            validate_message(message)?;
            if !message_ids.insert(message.message_id.as_str()) {
                return Err(DomainError::ConflictingTranscriptMessage(
                    message.message_id.clone(),
                ));
            }
            if !message.tool_calls.is_empty() && message.role != TranscriptRole::Assistant {
                return Err(DomainError::InvalidState(
                    "only assistant messages may declare tool calls".into(),
                ));
            }
            for call in &message.tool_calls {
                if declared_tool_calls
                    .insert(call.tool_call_id.as_str(), call)
                    .is_some()
                {
                    return Err(DomainError::DuplicateTranscriptToolCallId(
                        call.tool_call_id.clone(),
                    ));
                }
            }
            if let Some(tool_call_id) = &message.tool_call_id {
                if message.role != TranscriptRole::Tool {
                    return Err(DomainError::InvalidState(
                        "tool_call_id may only be attached to tool messages".into(),
                    ));
                }
                if !declared_tool_calls.contains_key(tool_call_id.as_str()) {
                    return Err(DomainError::UnknownToolCall(tool_call_id.clone()));
                }
            }
        }
        if let Some(failure) = &self.last_model_attempt_failure {
            validate_model_attempt_failure(failure)?;
            if !self.transcript.iter().any(|message| {
                message.role == TranscriptRole::User
                    && message.message_id == failure.trigger_message_id
            }) {
                return Err(DomainError::InvalidState(
                    "model attempt failure has no causal user message".into(),
                ));
            }
        }
        let mut expected_queue_id = self
            .delivery_ack
            .checked_add(1)
            .ok_or(DomainError::VersionOverflow)?;
        for delivery in &self.delivery_queue {
            validate_delivery(delivery, true)?;
            if delivery.queue_id != expected_queue_id {
                return Err(DomainError::DeliveryQueueOrder {
                    expected: expected_queue_id,
                    actual: delivery.queue_id,
                });
            }
            expected_queue_id = expected_queue_id
                .checked_add(1)
                .ok_or(DomainError::VersionOverflow)?;
        }
        if self.delivery_queue.len() > MAX_DELIVERY_QUEUE_ITEMS {
            return Err(DomainError::CollectionTooLarge {
                field: "delivery queue",
                items: self.delivery_queue.len(),
                max: MAX_DELIVERY_QUEUE_ITEMS,
            });
        }
        if let Some(wait) = &self.active_wait {
            validate_wait(wait)?;
            if let Some(pending_wait_id) = &self.wake_pending_wait_id {
                if pending_wait_id != &wait.wait_id {
                    return Err(DomainError::InvalidState(
                        "pending wake belongs to a different active wait".into(),
                    ));
                }
            }
        } else if self.wake_pending_wait_id.is_some() {
            return Err(DomainError::InvalidState(
                "pending wake requires an active wait".into(),
            ));
        }
        if let Some(timer) = &self.active_timer {
            if self
                .active_wait
                .as_ref()
                .is_none_or(|wait| wait.wait_id != timer.wait_id)
            {
                return Err(DomainError::InvalidState(
                    "wait timer must belong to the active wait".into(),
                ));
            }
            if timer.deadline_ms
                != self
                    .active_wait
                    .as_ref()
                    .map(|wait| wait.deadline_ms)
                    .unwrap_or_default()
            {
                return Err(DomainError::InvalidState(
                    "wait timer deadline does not match active wait".into(),
                ));
            }
        }
        if let Some(activation) = &self.active_activation {
            validate_active_activation(activation)?;
        }
        if let Some(round) = &self.active_model_round {
            validate_active_model_round(round)?;
            let Some(activation) = &self.active_activation else {
                return Err(DomainError::InvalidState(
                    "active model round requires an active activation".into(),
                ));
            };
            if round.activation_id != activation.activation_id {
                return Err(DomainError::InvalidState(
                    "active model round belongs to another activation".into(),
                ));
            }
        }
        if self.async_tool_calls.len() > MAX_ASYNC_TOOL_CALLS {
            return Err(DomainError::CollectionTooLarge {
                field: "async tool calls",
                items: self.async_tool_calls.len(),
                max: MAX_ASYNC_TOOL_CALLS,
            });
        }
        for (tool_call_id, record) in &self.async_tool_calls {
            validate_async_record(record)?;
            if tool_call_id != &record.tool_call_id {
                return Err(DomainError::InvalidState(
                    "async tool call map key does not match tool_call_id".into(),
                ));
            }
            let Some(declared) = declared_tool_calls.get(tool_call_id.as_str()) else {
                return Err(DomainError::UnknownToolCall(tool_call_id.clone()));
            };
            if declared.tool_name != record.tool_name || declared.input != record.input {
                return Err(DomainError::ConflictingToolCallIdentity(
                    tool_call_id.clone(),
                ));
            }
        }
        if self.callback_bindings.len() > MAX_ASYNC_TOOL_CALLS {
            return Err(DomainError::CollectionTooLarge {
                field: "callback bindings",
                items: self.callback_bindings.len(),
                max: MAX_ASYNC_TOOL_CALLS,
            });
        }
        let mut callback_tool_ids = BTreeSet::new();
        for (callback_id, binding) in &self.callback_bindings {
            validate_callback_binding(binding)?;
            if callback_id != &binding.callback_id {
                return Err(DomainError::InvalidState(
                    "callback binding map key does not match callback_id".into(),
                ));
            }
            let Some(record) = self.async_tool_calls.get(&binding.tool_call_id) else {
                return Err(DomainError::UnknownAsyncToolCall(
                    binding.tool_call_id.clone(),
                ));
            };
            if record.completion_mode != CompletionMode::ExternalCallback {
                return Err(DomainError::InvalidState(
                    "callback binding requires external-callback tool mode".into(),
                ));
            }
            if binding.payload_fingerprint.is_some() && !record.status.is_terminal() {
                return Err(DomainError::InvalidState(
                    "callback payload fingerprint requires a terminal tool call".into(),
                ));
            }
            if !callback_tool_ids.insert(binding.tool_call_id.as_str()) {
                return Err(DomainError::InvalidState(
                    "tool call already has a callback binding".into(),
                ));
            }
        }
        if let Some(fact) = &self.last_model_attempts_exhausted {
            validate_model_attempts_exhausted(fact)?;
        }
        Ok(())
    }

    fn apply_payload(&mut self, event: &SessionEvent) -> Result<(), DomainError> {
        match event {
            SessionEvent::SessionCreated {
                session_id,
                owner,
                created_at_ms,
                selection,
                ..
            } => {
                if session_id != &self.session_id {
                    return Err(DomainError::SessionMismatch {
                        expected: self.session_id.clone(),
                        actual: session_id.clone(),
                    });
                }
                self.owner = Some(owner.clone());
                self.created_at_ms = Some(*created_at_ms);
                self.selection = selection.clone();
                self.selection_version = 1;
            }
            SessionEvent::ModelSelectionChanged { selection } => {
                self.selection = selection.clone();
                self.selection_version = self
                    .selection_version
                    .checked_add(1)
                    .ok_or(DomainError::VersionOverflow)?;
            }
            SessionEvent::StatusChanged { status } => self.status = status.clone(),
            SessionEvent::DeliveryQueued { delivery } => {
                if delivery.queue_id <= self.delivery_ack {
                    return Ok(());
                }
                if let Some(existing) = self
                    .delivery_queue
                    .iter()
                    .find(|queued| queued.queue_id == delivery.queue_id)
                {
                    if existing == delivery {
                        return Ok(());
                    }
                    return Err(DomainError::ConflictingDelivery(
                        delivery.delivery_id.clone(),
                    ));
                }
                if self
                    .dedupe_facts
                    .contains(&format!("delivery:{}", delivery.delivery_id))
                    || self.dedupe_facts.contains(&delivery.dedupe_key)
                {
                    return Ok(());
                }
                if self.delivery_queue.len() >= MAX_DELIVERY_QUEUE_ITEMS {
                    return Err(DomainError::CollectionTooLarge {
                        field: "delivery queue",
                        items: self.delivery_queue.len() + 1,
                        max: MAX_DELIVERY_QUEUE_ITEMS,
                    });
                }
                let expected_queue_id = self
                    .delivery_ack
                    .checked_add(self.delivery_queue.len() as u64 + 1)
                    .ok_or(DomainError::VersionOverflow)?;
                if delivery.queue_id != expected_queue_id {
                    return Err(DomainError::DeliveryQueueOrder {
                        expected: expected_queue_id,
                        actual: delivery.queue_id,
                    });
                }
                self.delivery_queue.push(delivery.clone());
                self.dedupe_facts
                    .remember(format!("delivery:{}", delivery.delivery_id));
                self.dedupe_facts.remember(delivery.dedupe_key.clone());
                if delivery.wake {
                    if let Some(wait) = &self.active_wait {
                        self.wake_pending_wait_id = Some(wait.wait_id.clone());
                    }
                }
            }
            SessionEvent::DeliveryAcknowledged { through_queue_id } => {
                if *through_queue_id <= self.delivery_ack {
                    return Ok(());
                }
                let max_queued = self
                    .delivery_ack
                    .checked_add(self.delivery_queue.len() as u64)
                    .ok_or(DomainError::VersionOverflow)?;
                if *through_queue_id > max_queued {
                    return Err(DomainError::AckBeyondEnqueued {
                        requested: *through_queue_id,
                        max_queued,
                    });
                }
                if self
                    .delivery_queue
                    .iter()
                    .take_while(|delivery| delivery.queue_id <= *through_queue_id)
                    .any(|delivery| delivery.materialized_message_id.is_none())
                {
                    return Err(DomainError::DeliveryNotMaterialized(*through_queue_id));
                }
                self.delivery_ack = *through_queue_id;
                self.delivery_queue
                    .retain(|delivery| delivery.queue_id > self.delivery_ack);
            }
            SessionEvent::DeliveryMaterialized { queue_id, message } => {
                let index = self
                    .delivery_queue
                    .iter()
                    .position(|delivery| delivery.queue_id == *queue_id)
                    .ok_or(DomainError::UnknownDelivery(*queue_id))?;
                if message.source_queue_id != Some(*queue_id) {
                    return Err(DomainError::MaterializationIdentity(*queue_id));
                }
                if self
                    .delivery_queue
                    .iter()
                    .take(index)
                    .any(|delivery| delivery.materialized_message_id.is_none())
                {
                    return Err(DomainError::InvalidState(
                        "deliveries must materialize in queue order".into(),
                    ));
                }
                if let Some(existing_message_id) = self.delivery_queue[index]
                    .materialized_message_id
                    .as_deref()
                {
                    if existing_message_id == message.message_id
                        && self.transcript.iter().any(|existing| existing == message)
                    {
                        return Ok(());
                    }
                    return Err(DomainError::ConflictingDelivery(
                        self.delivery_queue[index].delivery_id.clone(),
                    ));
                }
                if let Some(existing) = self
                    .transcript
                    .iter()
                    .find(|existing| existing.message_id == message.message_id)
                {
                    if existing != message {
                        return Err(DomainError::ConflictingTranscriptMessage(
                            message.message_id.clone(),
                        ));
                    }
                } else {
                    self.transcript.push(message.clone());
                }
                self.delivery_queue[index].materialized_message_id =
                    Some(message.message_id.clone());
                self.dedupe_facts
                    .remember(format!("message:{}", message.message_id));
                if self.delivery_queue[index].wake {
                    self.active_wait = None;
                    self.active_timer = None;
                    self.wake_pending_wait_id = None;
                }
            }
            SessionEvent::MessageAppended { message, wake_wait } => {
                if let Some(existing) = self
                    .transcript
                    .iter()
                    .find(|existing| existing.message_id == message.message_id)
                {
                    if existing == message {
                        return Ok(());
                    }
                    return Err(DomainError::ConflictingTranscriptMessage(
                        message.message_id.clone(),
                    ));
                }
                if message
                    .dedupe_key
                    .as_ref()
                    .is_some_and(|key| self.dedupe_facts.contains(key))
                {
                    return Ok(());
                }
                if self.transcript.len() >= MAX_TRANSCRIPT_MESSAGES {
                    return Err(DomainError::CollectionTooLarge {
                        field: "transcript",
                        items: self.transcript.len() + 1,
                        max: MAX_TRANSCRIPT_MESSAGES,
                    });
                }
                if !message.tool_calls.is_empty() {
                    if message.role != TranscriptRole::Assistant {
                        return Err(DomainError::InvalidState(
                            "only assistant messages may declare tool calls".into(),
                        ));
                    }
                    for call in &message.tool_calls {
                        if self.transcript.iter().any(|existing| {
                            existing.tool_calls.iter().any(|existing_call| {
                                existing_call.tool_call_id == call.tool_call_id
                            })
                        }) {
                            return Err(DomainError::DuplicateTranscriptToolCallId(
                                call.tool_call_id.clone(),
                            ));
                        }
                    }
                }
                if let Some(tool_call_id) = &message.tool_call_id {
                    if message.role != TranscriptRole::Tool {
                        return Err(DomainError::InvalidState(
                            "tool_call_id may only be attached to tool messages".into(),
                        ));
                    }
                    if !self.transcript.iter().any(|existing| {
                        existing
                            .tool_calls
                            .iter()
                            .any(|call| call.tool_call_id == *tool_call_id)
                    }) {
                        return Err(DomainError::UnknownToolCall(tool_call_id.clone()));
                    }
                }
                self.transcript.push(message.clone());
                self.dedupe_facts
                    .remember(format!("message:{}", message.message_id));
                if let Some(key) = &message.dedupe_key {
                    self.dedupe_facts.remember(key.clone());
                }
                if *wake_wait {
                    self.active_wait = None;
                    self.active_timer = None;
                    self.wake_pending_wait_id = None;
                }
            }
            SessionEvent::ActivationStarted {
                activation_id,
                selection,
                selection_version,
                minimum_auth_revision,
                started_at_ms,
            } => {
                if self.active_activation.is_some() {
                    return Err(DomainError::InvalidState(
                        "session already has an active activation".into(),
                    ));
                }
                if *selection_version != self.selection_version {
                    return Err(DomainError::InvalidState(
                        "activation selection version does not match session selection".into(),
                    ));
                }
                self.active_activation = Some(ActiveActivation {
                    activation_id: activation_id.clone(),
                    selection: selection.clone(),
                    selection_version: *selection_version,
                    minimum_auth_revision: *minimum_auth_revision,
                    started_at_ms: *started_at_ms,
                    rounds_started: 0,
                });
                self.active_model_round = None;
            }
            SessionEvent::ModelRoundStarted {
                activation_id,
                round_id,
                delivery_through_queue_id,
                started_at_ms,
            } => {
                let activation = self.active_activation.as_mut().ok_or_else(|| {
                    DomainError::InvalidState("model round has no activation".into())
                })?;
                if activation.activation_id != *activation_id {
                    return Err(DomainError::InvalidState(
                        "model round belongs to another activation".into(),
                    ));
                }
                if let Some(existing) = &self.active_model_round {
                    let completed = existing
                        .attempt
                        .as_ref()
                        .is_some_and(|attempt| attempt.outcome == ModelAttemptOutcome::Completed);
                    if !completed {
                        return Err(DomainError::InvalidState(
                            "session already has an active model round".into(),
                        ));
                    }
                    // A completed request is a round boundary. The next
                    // round replaces that completed projection while keeping
                    // its immutable facts in the event stream.
                    self.active_model_round = None;
                }
                activation.rounds_started = activation
                    .rounds_started
                    .checked_add(1)
                    .ok_or(DomainError::VersionOverflow)?;
                if activation.rounds_started > MAX_MODEL_ROUNDS_PER_ACTIVATION {
                    return Err(DomainError::CollectionTooLarge {
                        field: "model rounds per activation",
                        items: activation.rounds_started as usize,
                        max: MAX_MODEL_ROUNDS_PER_ACTIVATION as usize,
                    });
                }
                self.active_model_round = Some(ActiveModelRound {
                    activation_id: activation_id.clone(),
                    round_id: round_id.clone(),
                    delivery_through_queue_id: *delivery_through_queue_id,
                    started_at_ms: *started_at_ms,
                    request: None,
                    attempt: None,
                    retry: None,
                });
            }
            SessionEvent::ModelRequestPrepared {
                activation_id,
                round_id,
                request_id,
                request_fingerprint,
                provider_execution_fingerprint,
                prompt_fingerprint,
                tool_schema_fingerprint,
                envelope,
                maximum_attempts,
                minimum_auth_revision,
            } => {
                let round = self.active_model_round.as_mut().ok_or_else(|| {
                    DomainError::InvalidState("model request has no active round".into())
                })?;
                if round.activation_id != *activation_id || round.round_id != *round_id {
                    return Err(DomainError::InvalidState(
                        "model request belongs to another round".into(),
                    ));
                }
                if round.request.is_some() {
                    return Err(DomainError::InvalidState(
                        "model request was prepared more than once".into(),
                    ));
                }
                if self.active_activation.as_ref().is_none_or(|activation| {
                    activation.minimum_auth_revision > *minimum_auth_revision
                }) {
                    return Err(DomainError::InvalidState(
                        "model request minimum auth revision is below activation requirement"
                            .into(),
                    ));
                }
                round.request = Some(ModelRequestRecord {
                    activation_id: activation_id.clone(),
                    round_id: round_id.clone(),
                    request_id: request_id.clone(),
                    request_fingerprint: request_fingerprint.clone(),
                    provider_execution_fingerprint: provider_execution_fingerprint.clone(),
                    prompt_fingerprint: prompt_fingerprint.clone(),
                    tool_schema_fingerprint: tool_schema_fingerprint.clone(),
                    envelope: envelope.clone(),
                    maximum_attempts: *maximum_attempts,
                    minimum_auth_revision: *minimum_auth_revision,
                });
            }
            SessionEvent::ModelAttemptStarted {
                activation_id,
                round_id,
                request_id,
                attempt_id,
                attempt_number,
                auth_revision,
                started_at_ms,
            } => {
                let round = self.active_model_round.as_mut().ok_or_else(|| {
                    DomainError::InvalidState("model attempt has no active round".into())
                })?;
                let request = round.request.as_ref().ok_or_else(|| {
                    DomainError::InvalidState("model attempt has no prepared request".into())
                })?;
                if request.activation_id != *activation_id
                    || request.round_id != *round_id
                    || request.request_id != *request_id
                {
                    return Err(DomainError::InvalidState(
                        "model attempt belongs to another request".into(),
                    ));
                }
                if *attempt_number > request.maximum_attempts {
                    return Err(DomainError::InvalidState(
                        "model attempt exceeds prepared request budget".into(),
                    ));
                }
                if let Some(existing) = &round.attempt {
                    if existing.attempt_id == *attempt_id
                        && existing.attempt_number == *attempt_number
                    {
                        return Ok(());
                    }
                    return Err(DomainError::InvalidState(
                        "model request already has an attempt".into(),
                    ));
                }
                if let Some(schedule) = &round.retry {
                    if schedule.next_attempt_id != *attempt_id
                        || schedule.next_attempt_number != *attempt_number
                    {
                        return Err(DomainError::InvalidState(
                            "model attempt does not claim the scheduled retry".into(),
                        ));
                    }
                } else if *attempt_number != 1 {
                    return Err(DomainError::InvalidState(
                        "first model attempt must have number one".into(),
                    ));
                }
                round.attempt = Some(ModelAttemptRecord {
                    activation_id: activation_id.clone(),
                    round_id: round_id.clone(),
                    request_id: request_id.clone(),
                    attempt_id: attempt_id.clone(),
                    attempt_number: *attempt_number,
                    auth_revision: *auth_revision,
                    started_at_ms: *started_at_ms,
                    outcome: ModelAttemptOutcome::Running,
                });
                round.retry = None;
            }
            SessionEvent::ModelAttemptFailedFact {
                activation_id,
                round_id,
                request_id,
                attempt_id,
                attempt_number,
                ..
            } => {
                let attempt = current_model_attempt_mut(
                    self,
                    activation_id,
                    round_id,
                    request_id,
                    attempt_id,
                    *attempt_number,
                )?;
                match attempt.outcome {
                    ModelAttemptOutcome::Running => attempt.outcome = ModelAttemptOutcome::Failed,
                    ModelAttemptOutcome::Failed => return Ok(()),
                    _ => {
                        return Err(DomainError::InvalidState(
                            "model attempt failure is not first-wins".into(),
                        ))
                    }
                }
            }
            SessionEvent::ModelAttemptInterrupted {
                activation_id,
                round_id,
                request_id,
                attempt_id,
                attempt_number,
                ..
            } => {
                let attempt = current_model_attempt_mut(
                    self,
                    activation_id,
                    round_id,
                    request_id,
                    attempt_id,
                    *attempt_number,
                )?;
                match attempt.outcome {
                    ModelAttemptOutcome::Running => {
                        attempt.outcome = ModelAttemptOutcome::Interrupted
                    }
                    ModelAttemptOutcome::Interrupted => return Ok(()),
                    _ => {
                        return Err(DomainError::InvalidState(
                            "model attempt interruption is not first-wins".into(),
                        ))
                    }
                }
            }
            SessionEvent::ModelAttemptsExhausted { fact } => {
                if let Some(existing) = &self.last_model_attempts_exhausted {
                    if existing == fact {
                        return Ok(());
                    }
                    return Err(DomainError::InvalidState(
                        "model exhaustion has conflicting semantics".into(),
                    ));
                }
                let round = self.active_model_round.as_ref().ok_or_else(|| {
                    DomainError::InvalidState("model exhaustion has no active round".into())
                })?;
                let request = round.request.as_ref().ok_or_else(|| {
                    DomainError::InvalidState("model exhaustion has no prepared request".into())
                })?;
                let attempt = round.attempt.as_ref().ok_or_else(|| {
                    DomainError::InvalidState("model exhaustion has no active attempt".into())
                })?;
                if round.activation_id != fact.activation_id
                    || round.round_id != fact.round_id
                    || request.request_id != fact.request_id
                    || attempt.attempt_id != fact.attempt_id
                    || attempt.attempt_number != fact.attempt_number
                    || request.maximum_attempts != fact.maximum_attempts
                {
                    return Err(DomainError::InvalidState(
                        "model exhaustion belongs to another attempt".into(),
                    ));
                }
                if !matches!(
                    attempt.outcome,
                    ModelAttemptOutcome::Failed | ModelAttemptOutcome::Interrupted
                ) {
                    return Err(DomainError::InvalidState(
                        "model exhaustion requires a failed or interrupted attempt".into(),
                    ));
                }
                self.last_model_attempts_exhausted = Some(fact.clone());
            }
            SessionEvent::ModelStepRetryScheduled { schedule } => {
                let round = self.active_model_round.as_mut().ok_or_else(|| {
                    DomainError::InvalidState("retry has no active model round".into())
                })?;
                let attempt = round.attempt.as_ref().ok_or_else(|| {
                    DomainError::InvalidState("retry has no model attempt".into())
                })?;
                if attempt.activation_id != schedule.activation_id
                    || attempt.round_id != schedule.round_id
                    || attempt.request_id != schedule.request_id
                    || attempt.attempt_id != schedule.failed_attempt_id
                    || attempt.attempt_number != schedule.failed_attempt_number
                {
                    return Err(DomainError::InvalidState(
                        "retry schedule does not match failed attempt".into(),
                    ));
                }
                if !matches!(
                    attempt.outcome,
                    ModelAttemptOutcome::Failed | ModelAttemptOutcome::Interrupted
                ) {
                    return Err(DomainError::InvalidState(
                        "retry schedule requires a failed or interrupted attempt".into(),
                    ));
                }
                if let Some(existing) = &round.retry {
                    if existing == schedule {
                        return Ok(());
                    }
                    return Err(DomainError::InvalidState(
                        "model retry schedule has conflicting semantics".into(),
                    ));
                }
                round.retry = Some(schedule.clone());
                round.attempt = None;
            }
            SessionEvent::ModelRequestCompleted {
                activation_id,
                round_id,
                request_id,
                attempt_id,
            } => {
                let round = self.active_model_round.as_mut().ok_or_else(|| {
                    DomainError::InvalidState("model completion has no active round".into())
                })?;
                let attempt = round.attempt.as_mut().ok_or_else(|| {
                    DomainError::InvalidState("model completion has no attempt".into())
                })?;
                if attempt.activation_id != *activation_id
                    || attempt.round_id != *round_id
                    || attempt.request_id != *request_id
                    || attempt.attempt_id != *attempt_id
                {
                    return Err(DomainError::InvalidState(
                        "model completion belongs to another attempt".into(),
                    ));
                }
                match attempt.outcome {
                    ModelAttemptOutcome::Running => {
                        attempt.outcome = ModelAttemptOutcome::Completed
                    }
                    ModelAttemptOutcome::Completed => return Ok(()),
                    _ => {
                        return Err(DomainError::InvalidState(
                            "model completion requires a running attempt".into(),
                        ))
                    }
                }
            }
            SessionEvent::ActivationFinished {
                activation_id,
                outcome: _,
                finished_at_ms: _,
            } => {
                let active = self.active_activation.as_ref().ok_or_else(|| {
                    DomainError::InvalidState("activation finish has no active activation".into())
                })?;
                if active.activation_id != *activation_id {
                    return Err(DomainError::InvalidState(
                        "activation finish belongs to another activation".into(),
                    ));
                }
                self.active_activation = None;
                self.active_model_round = None;
            }
            SessionEvent::ModelAttemptFailed { failure } => {
                if !self.transcript.last().is_some_and(|message| {
                    message.role == TranscriptRole::User
                        && message.message_id == failure.trigger_message_id
                }) {
                    return Err(DomainError::InvalidState(
                        "model attempt failure does not match the current user message".into(),
                    ));
                }
                if let Some(existing) = &self.last_model_attempt_failure {
                    if existing.trigger_message_id == failure.trigger_message_id {
                        if existing == failure {
                            return Ok(());
                        }
                        return Err(DomainError::InvalidState(
                            "current user message has conflicting terminal model failures".into(),
                        ));
                    }
                }
                self.last_model_attempt_failure = Some(failure.clone());
            }
            SessionEvent::WaitSet { wait } => {
                self.active_wait = Some(wait.clone());
                self.active_timer = None;
                self.wake_pending_wait_id = None;
            }
            SessionEvent::WaitTimerScheduled { timer } => {
                let wait = self.active_wait.as_ref().ok_or_else(|| {
                    DomainError::InvalidState("wait timer has no active wait".into())
                })?;
                if wait.wait_id != timer.wait_id || wait.deadline_ms != timer.deadline_ms {
                    return Err(DomainError::InvalidState(
                        "wait timer does not match active wait".into(),
                    ));
                }
                self.active_timer = Some(timer.clone());
            }
            SessionEvent::WaitCleared { wait_id } | SessionEvent::WaitExpired { wait_id } => {
                if self.wake_pending_wait_id.as_deref() == Some(wait_id.as_str()) {
                    return Ok(());
                }
                if self
                    .active_wait
                    .as_ref()
                    .is_some_and(|wait| wait.wait_id == *wait_id)
                {
                    self.active_wait = None;
                    self.active_timer = None;
                    self.wake_pending_wait_id = None;
                }
            }
            SessionEvent::AsyncToolCallStarted { record } => {
                if let Some(existing) = self.async_tool_calls.get(&record.tool_call_id) {
                    if existing == record {
                        return Ok(());
                    }
                    return Err(DomainError::ConflictingAsyncToolCallStart(
                        record.tool_call_id.clone(),
                    ));
                }
                let Some(declared) = self.transcript.iter().find_map(|message| {
                    message
                        .tool_calls
                        .iter()
                        .find(|call| call.tool_call_id == record.tool_call_id)
                }) else {
                    return Err(DomainError::UnknownToolCall(record.tool_call_id.clone()));
                };
                if declared.tool_name != record.tool_name || declared.input != record.input {
                    return Err(DomainError::ConflictingToolCallIdentity(
                        record.tool_call_id.clone(),
                    ));
                }
                if self.async_tool_calls.len() >= MAX_ASYNC_TOOL_CALLS {
                    return Err(DomainError::CollectionTooLarge {
                        field: "async tool calls",
                        items: self.async_tool_calls.len() + 1,
                        max: MAX_ASYNC_TOOL_CALLS,
                    });
                }
                self.async_tool_calls
                    .insert(record.tool_call_id.clone(), record.clone());
            }
            SessionEvent::AsyncToolCallRunning { tool_call_id } => {
                let record = self
                    .async_tool_calls
                    .get_mut(tool_call_id)
                    .ok_or_else(|| DomainError::UnknownAsyncToolCall(tool_call_id.clone()))?;
                if record.completion_mode == CompletionMode::ExternalCallback
                    && !self
                        .callback_bindings
                        .values()
                        .any(|binding| binding.tool_call_id == *tool_call_id)
                {
                    return Err(DomainError::InvalidState(
                        "external callback tool must be bound before it becomes running".into(),
                    ));
                }
                match record.status {
                    AsyncToolStatus::Planned => record.status = AsyncToolStatus::Running,
                    AsyncToolStatus::Running => return Ok(()),
                    _ => {
                        return Err(DomainError::InvalidState(
                            "only a planned tool call can become running".into(),
                        ))
                    }
                }
            }
            SessionEvent::AsyncToolCallUnknownOutcome {
                tool_call_id,
                reason: _,
            } => {
                let record = self
                    .async_tool_calls
                    .get_mut(tool_call_id)
                    .ok_or_else(|| DomainError::UnknownAsyncToolCall(tool_call_id.clone()))?;
                match record.status {
                    AsyncToolStatus::Running => record.status = AsyncToolStatus::UnknownOutcome,
                    AsyncToolStatus::UnknownOutcome => return Ok(()),
                    _ => {
                        return Err(DomainError::InvalidState(
                            "only a running tool call can become unknown outcome".into(),
                        ))
                    }
                }
            }
            SessionEvent::AsyncToolCallRuntimeRestarted {
                tool_call_id,
                reason,
                completed_at_ms,
            } => {
                let record = self
                    .async_tool_calls
                    .get_mut(tool_call_id)
                    .ok_or_else(|| DomainError::UnknownAsyncToolCall(tool_call_id.clone()))?;
                if record.status == AsyncToolStatus::UnknownOutcome {
                    return Ok(());
                }
                if record.status.is_terminal() {
                    return Ok(());
                }
                if *completed_at_ms < record.started_at_ms {
                    return Err(DomainError::InvalidTimestampOrder {
                        start: record.started_at_ms,
                        end: *completed_at_ms,
                    });
                }
                record.status = AsyncToolStatus::RuntimeRestarted;
                record.result = None;
                record.error = Some(ToolError {
                    class: "runtime_restarted".into(),
                    message: reason.clone(),
                });
                record.cancel_reason = None;
                record.completed_at_ms = Some(*completed_at_ms);
            }
            SessionEvent::AsyncToolCallCallbackPlanned { binding } => {
                let record = self
                    .async_tool_calls
                    .get(&binding.tool_call_id)
                    .ok_or_else(|| {
                        DomainError::UnknownAsyncToolCall(binding.tool_call_id.clone())
                    })?;
                if record.completion_mode != CompletionMode::ExternalCallback {
                    return Err(DomainError::InvalidState(
                        "callback binding requires external-callback tool mode".into(),
                    ));
                }
                if !matches!(
                    record.status,
                    AsyncToolStatus::Planned | AsyncToolStatus::Running
                ) {
                    return Err(DomainError::InvalidState(
                        "callback binding requires a nonterminal tool call".into(),
                    ));
                }
                if let Some(existing) = self.callback_bindings.get(&binding.callback_id) {
                    if existing == binding {
                        return Ok(());
                    }
                    return Err(DomainError::InvalidState(
                        "callback id has conflicting binding".into(),
                    ));
                }
                if self
                    .callback_bindings
                    .values()
                    .any(|existing| existing.tool_call_id == binding.tool_call_id)
                {
                    return Err(DomainError::InvalidState(
                        "tool call already has a callback binding".into(),
                    ));
                }
                self.callback_bindings
                    .insert(binding.callback_id.clone(), binding.clone());
            }
            SessionEvent::AsyncToolCallCallbackCompleted {
                callback_id,
                tool_call_id,
                payload_fingerprint,
                result,
                completed_at_ms,
            } => {
                let binding = self
                    .callback_bindings
                    .get_mut(callback_id)
                    .ok_or_else(|| DomainError::UnknownCallback(callback_id.clone()))?;
                if binding.tool_call_id != *tool_call_id {
                    return Err(DomainError::InvalidState(
                        "callback completion belongs to another tool call".into(),
                    ));
                }
                if let Some(existing) = &binding.payload_fingerprint {
                    if existing == payload_fingerprint {
                        return Ok(());
                    }
                    return Err(DomainError::CallbackPayloadConflict(callback_id.clone()));
                }
                let record = self
                    .async_tool_calls
                    .get_mut(tool_call_id)
                    .ok_or_else(|| DomainError::UnknownAsyncToolCall(tool_call_id.clone()))?;
                if record.status.is_terminal() {
                    return Err(DomainError::CallbackTerminalConflict(tool_call_id.clone()));
                }
                if *completed_at_ms < record.started_at_ms {
                    return Err(DomainError::InvalidTimestampOrder {
                        start: record.started_at_ms,
                        end: *completed_at_ms,
                    });
                }
                record.status = AsyncToolStatus::Completed;
                record.result = Some(result.clone());
                record.error = None;
                record.cancel_reason = None;
                record.completed_at_ms = Some(*completed_at_ms);
                binding.payload_fingerprint = Some(payload_fingerprint.clone());
            }
            SessionEvent::AsyncToolCallCallbackFailed {
                callback_id,
                tool_call_id,
                payload_fingerprint,
                error,
                completed_at_ms,
            } => {
                let binding = self
                    .callback_bindings
                    .get_mut(callback_id)
                    .ok_or_else(|| DomainError::UnknownCallback(callback_id.clone()))?;
                if binding.tool_call_id != *tool_call_id {
                    return Err(DomainError::InvalidState(
                        "callback completion belongs to another tool call".into(),
                    ));
                }
                if let Some(existing) = &binding.payload_fingerprint {
                    if existing == payload_fingerprint {
                        return Ok(());
                    }
                    return Err(DomainError::CallbackPayloadConflict(callback_id.clone()));
                }
                let record = self
                    .async_tool_calls
                    .get_mut(tool_call_id)
                    .ok_or_else(|| DomainError::UnknownAsyncToolCall(tool_call_id.clone()))?;
                if record.status.is_terminal() {
                    return Err(DomainError::CallbackTerminalConflict(tool_call_id.clone()));
                }
                if *completed_at_ms < record.started_at_ms {
                    return Err(DomainError::InvalidTimestampOrder {
                        start: record.started_at_ms,
                        end: *completed_at_ms,
                    });
                }
                record.status = AsyncToolStatus::Failed;
                record.result = None;
                record.error = Some(error.clone());
                record.cancel_reason = None;
                record.completed_at_ms = Some(*completed_at_ms);
                binding.payload_fingerprint = Some(payload_fingerprint.clone());
            }
            SessionEvent::AsyncToolCallProgress {
                tool_call_id,
                progress,
            } => {
                let record = self
                    .async_tool_calls
                    .get_mut(tool_call_id)
                    .ok_or_else(|| DomainError::UnknownAsyncToolCall(tool_call_id.clone()))?;
                if record.status.is_terminal() {
                    return Ok(());
                }
                record.progress = Some(progress.clone());
            }
            SessionEvent::AsyncToolCallCompleted {
                tool_call_id,
                result,
                completed_at_ms,
            } => {
                let record = self
                    .async_tool_calls
                    .get_mut(tool_call_id)
                    .ok_or_else(|| DomainError::UnknownAsyncToolCall(tool_call_id.clone()))?;
                if record.status == AsyncToolStatus::UnknownOutcome {
                    return Err(DomainError::UnknownOutcomeTerminalConflict(
                        tool_call_id.clone(),
                    ));
                }
                if record.status.is_terminal() {
                    return Ok(());
                }
                if *completed_at_ms < record.started_at_ms {
                    return Err(DomainError::InvalidTimestampOrder {
                        start: record.started_at_ms,
                        end: *completed_at_ms,
                    });
                }
                record.status = AsyncToolStatus::Completed;
                record.result = Some(result.clone());
                record.error = None;
                record.cancel_reason = None;
                record.completed_at_ms = Some(*completed_at_ms);
            }
            SessionEvent::AsyncToolCallFailed {
                tool_call_id,
                error,
                completed_at_ms,
            } => {
                let record = self
                    .async_tool_calls
                    .get_mut(tool_call_id)
                    .ok_or_else(|| DomainError::UnknownAsyncToolCall(tool_call_id.clone()))?;
                if record.status == AsyncToolStatus::UnknownOutcome {
                    return Err(DomainError::UnknownOutcomeTerminalConflict(
                        tool_call_id.clone(),
                    ));
                }
                if record.status.is_terminal() {
                    return Ok(());
                }
                if *completed_at_ms < record.started_at_ms {
                    return Err(DomainError::InvalidTimestampOrder {
                        start: record.started_at_ms,
                        end: *completed_at_ms,
                    });
                }
                record.status = AsyncToolStatus::Failed;
                record.result = None;
                record.error = Some(error.clone());
                record.cancel_reason = None;
                record.completed_at_ms = Some(*completed_at_ms);
            }
            SessionEvent::AsyncToolCallCancelled {
                tool_call_id,
                reason,
                completed_at_ms,
            } => {
                let record = self
                    .async_tool_calls
                    .get_mut(tool_call_id)
                    .ok_or_else(|| DomainError::UnknownAsyncToolCall(tool_call_id.clone()))?;
                if record.status == AsyncToolStatus::UnknownOutcome {
                    return Err(DomainError::UnknownOutcomeTerminalConflict(
                        tool_call_id.clone(),
                    ));
                }
                if record.status.is_terminal() {
                    return Ok(());
                }
                if *completed_at_ms < record.started_at_ms {
                    return Err(DomainError::InvalidTimestampOrder {
                        start: record.started_at_ms,
                        end: *completed_at_ms,
                    });
                }
                record.status = AsyncToolStatus::Cancelled;
                record.result = None;
                record.error = None;
                record.cancel_reason = Some(reason.clone());
                record.completed_at_ms = Some(*completed_at_ms);
            }
            SessionEvent::DedupeRecorded { key } => self.dedupe_facts.remember(key.clone()),
        }
        Ok(())
    }

    fn validate_event_position(&self, event: &SessionEvent) -> Result<(), DomainError> {
        match (self.stream_version, event) {
            (0, SessionEvent::SessionCreated { .. }) => Ok(()),
            (0, _) => Err(DomainError::SessionNotCreated),
            (_, SessionEvent::SessionCreated { .. }) => Err(DomainError::SessionAlreadyCreated),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum DomainError {
    #[error("{field} must not be empty")]
    EmptyField { field: &'static str },
    #[error("{field} is too large: {bytes} bytes, maximum is {max}")]
    TextTooLarge {
        field: &'static str,
        bytes: usize,
        max: usize,
    },
    #[error("{field} collection is too large: {items} items, maximum is {max}")]
    CollectionTooLarge {
        field: &'static str,
        items: usize,
        max: usize,
    },
    #[error("durable payload is too large: {bytes} bytes, maximum is {max}")]
    DurablePayloadTooLarge { bytes: usize, max: usize },
    #[error("invalid durable payload: {0}")]
    InvalidDurablePayload(String),
    #[error("wait timeout must be between {WAIT_MIN_SECONDS} and {WAIT_MAX_SECONDS} seconds")]
    InvalidWaitTimeout,
    #[error("event batch must not be empty")]
    EmptyEventBatch,
    #[error("session mismatch: expected {expected}, got {actual}")]
    SessionMismatch { expected: String, actual: String },
    #[error("stream version gap: expected {expected}, got {actual}")]
    StreamVersionGap {
        expected: StreamVersion,
        actual: StreamVersion,
    },
    #[error("event id was applied more than once: {0}")]
    DuplicateEventId(String),
    #[error("unsupported event schema version: {0}")]
    UnsupportedEventSchema(u32),
    #[error("unsupported SessionCreated schema version: {0}")]
    UnsupportedSessionCreatedSchema(u32),
    #[error("session stream does not begin with SessionCreated")]
    SessionNotCreated,
    #[error("SessionCreated can only be the first stream event")]
    SessionAlreadyCreated,
    #[error("session creation time must not be negative")]
    InvalidCreatedAt,
    #[error("{field} must not be negative")]
    InvalidTimestamp { field: &'static str },
    #[error("timestamp order is invalid: {start} is after {end}")]
    InvalidTimestampOrder { start: i64, end: i64 },
    #[error("invalid state: {0}")]
    InvalidState(String),
    #[error("async tool call {0} has an invalid start record")]
    InvalidAsyncToolStart(String),
    #[error("async tool call {0} was started with conflicting semantics")]
    ConflictingAsyncToolCallStart(String),
    #[error("async tool call {0} is unknown")]
    UnknownAsyncToolCall(String),
    #[error("async tool call {0} has an unknown outcome and cannot be rewritten")]
    UnknownOutcomeTerminalConflict(String),
    #[error("external callback {0} is unknown")]
    UnknownCallback(String),
    #[error("external callback {0} has a conflicting payload")]
    CallbackPayloadConflict(String),
    #[error("external callback terminal outcome conflicts for tool call {0}")]
    CallbackTerminalConflict(String),
    #[error("delivery {0} has conflicting semantics")]
    ConflictingDelivery(String),
    #[error("delivery {0} is unknown")]
    UnknownDelivery(u64),
    #[error("delivery {0} was not materialized")]
    DeliveryNotMaterialized(u64),
    #[error("delivery {0} materialization identity is invalid")]
    MaterializationIdentity(u64),
    #[error("delivery acknowledgement {requested} skips future queue ids; maximum enqueued is {max_queued}")]
    AckBeyondEnqueued { requested: u64, max_queued: u64 },
    #[error("delivery queue id expected {expected}, got {actual}")]
    DeliveryQueueOrder { expected: u64, actual: u64 },
    #[error("transcript message {0} has conflicting semantics")]
    ConflictingTranscriptMessage(String),
    #[error("transcript tool_call_id appears more than once: {0}")]
    DuplicateTranscriptToolCallId(String),
    #[error("tool call {0} is not declared by an assistant message")]
    UnknownToolCall(String),
    #[error("tool call {0} has conflicting durable identity")]
    ConflictingToolCallIdentity(String),
    #[error("stream version overflow")]
    VersionOverflow,
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
    if activation.rounds_started > MAX_MODEL_ROUNDS_PER_ACTIVATION {
        return Err(DomainError::CollectionTooLarge {
            field: "model rounds per activation",
            items: activation.rounds_started as usize,
            max: MAX_MODEL_ROUNDS_PER_ACTIVATION as usize,
        });
    }
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
                "prepared model request belongs to another round".into(),
            ));
        }
        validate_model_fingerprint("request_fingerprint", &request.request_fingerprint)?;
        validate_model_fingerprint(
            "provider_execution_fingerprint",
            &request.provider_execution_fingerprint,
        )?;
        validate_model_fingerprint("prompt_fingerprint", &request.prompt_fingerprint)?;
        validate_model_fingerprint("tool_schema_fingerprint", &request.tool_schema_fingerprint)?;
        request.envelope.validate()?;
        if request.maximum_attempts == 0
            || request.maximum_attempts > MAX_MODEL_ATTEMPTS_PER_STEP
            || request.minimum_auth_revision == 0
        {
            return Err(DomainError::InvalidState(
                "prepared model request has invalid bounds".into(),
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
                    "model attempt number is outside prepared request bounds".into(),
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
            "model attempt/retry requires a prepared request".into(),
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
        .ok_or_else(|| DomainError::InvalidState("model attempt has no prepared request".into()))?;
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

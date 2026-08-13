use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{broadcast, oneshot, Mutex as AsyncMutex};

mod callback;
mod commit;
mod context;
mod model;
pub mod ports;

pub use model::{ModelOutcome, ModelRequest, ModelTokenUsage};
use model::{MAX_CONTEXT_HANDOFF_DOCUMENT_TOKENS, MAX_CONTEXT_HANDOFF_GENERATION_TOKENS};
pub use ports::{
    AppendResult, BlobPort, BlobStore, Clock, EventStore, ExternalCallbackLookup, ModelExecutor,
    ModelPort, OwnedSessionRef, RehydrateError, SessionAppendResult, SessionCreate,
    SessionCreateCommand, SessionCreateResult, SessionListCursor, SessionListItem, SessionListPage,
    SnapshotRecord, StoreError, StorePort, StorePortError, ToolExecutor, ToolPort,
    VerifiedSessionState, MAX_OWNED_SESSION_SCAN_LIMIT, MAX_SESSION_LIST_LIMIT,
    SNAPSHOT_ENCODING_JSON,
};
mod stream;
mod transition;

use stream::{BroadcastModelStreamObserver, SilentModelStreamObserver};
pub use stream::{
    ModelStreamObserver, RuntimeStreamEvent, RuntimeStreamFence, RuntimeStreamMessage,
    RuntimeStreamPublisher, RuntimeStreamSubscription, TransientModelEvent,
};
use transition::*;

use callback::*;
use commit::*;
use context::{
    build_context_handoff_plan, context_handoff_source, context_handoff_source_facts,
    estimated_full_model_input_tokens, estimated_model_input_tokens_from_metrics,
    execute_runtime_read_tool, model_context_generation, model_context_metrics,
    model_context_metrics_from_serialized_transcript, model_context_text_tokens,
    model_input_budget, model_selection_fingerprint, provider_runtime_tool_definitions,
    runtime_tool_definitions, token_estimate_scale_millionths, ProviderContextCache,
};

use crate::domain::{
    ActivationOutcome, ActiveWait, AsyncToolCallRecord, AsyncToolStatus, CompletionMode,
    ContextHandoffDocument, ContextHandoffPlan, DeliveryKind, DurablePayload, EventDraft,
    EventRecord, ModelAttemptError, ModelAttemptErrorClass, ModelAttemptFailure,
    ModelRequestPurpose, ModelRetrySchedule, ModelUsageAnchor, SessionEvent, SessionModelSelection,
    SessionOwner, SessionSelection, SessionState, ToolCall, ToolError as DomainToolError,
    TranscriptMessage, TranscriptRole, WaitSource, WAIT_MAX_SECONDS, WAIT_MIN_SECONDS,
};

#[derive(Debug)]
pub enum ModelError {
    Unavailable,
    InvalidSelection,
    AuthReplicaUnavailable,
    ProviderFailed,
    InvalidToolArguments,
}

pub const WAIT_FOR_TOOL_NAME: &str = "wait_for";
pub const READ_CONTEXT_HANDOFF_TOOL_NAME: &str = "read_context_handoff";
pub const READ_SESSION_HISTORY_TOOL_NAME: &str = "read_session_history";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub completion_mode: CompletionMode,
    pub auto_wait_seconds: Option<u32>,
    pub running_restart: RunningRestartPolicy,
    pub retry_dispatch: RetryDispatchPolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunningRestartPolicy {
    UnknownOutcome,
    RuntimeRestarted,
    AwaitCallback,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryDispatchPolicy {
    Never,
    SameInvocationKeyDeduplicated,
}

impl ToolDefinition {
    pub fn wait_for() -> Self {
        Self {
            name: WAIT_FOR_TOOL_NAME.to_owned(),
            description: "Pause this session until new input or a runtime notification arrives."
                .to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "reason": {"type": "string"},
                    "timeout_seconds": {
                        "type": "integer",
                        "minimum": WAIT_MIN_SECONDS,
                        "maximum": WAIT_MAX_SECONDS
                    }
                },
                "required": ["reason"],
                "additionalProperties": false
            }),
            completion_mode: CompletionMode::ProcessLocal,
            auto_wait_seconds: None,
            running_restart: RunningRestartPolicy::RuntimeRestarted,
            retry_dispatch: RetryDispatchPolicy::Never,
        }
    }

    pub fn read_context_handoff() -> Self {
        Self {
            name: READ_CONTEXT_HANDOFF_TOOL_NAME.to_owned(),
            description: "Read a bounded chunk of the latest durable context handoff document for this session. An optional handoff_id asserts the expected latest document; continue with next_content_offset until it is null. Call this first after a fresh context generation begins.".to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "handoff_id": {"type": "string", "minLength": 1},
                    "content_offset": {"type": "integer", "minimum": 0}
                },
                "additionalProperties": false
            }),
            completion_mode: CompletionMode::ProcessLocal,
            auto_wait_seconds: None,
            running_restart: RunningRestartPolicy::RuntimeRestarted,
            retry_dispatch: RetryDispatchPolicy::Never,
        }
    }

    pub fn read_session_history() -> Self {
        Self {
            name: READ_SESSION_HISTORY_TOOL_NAME.to_owned(),
            description: "Read this session's durable append-only history. Without message_id, list a bounded chronological page ending before before_message_id. With message_id, read a bounded content chunk starting at content_offset.".to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "before_message_id": {"type": "string", "minLength": 1},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 16},
                    "message_id": {"type": "string", "minLength": 1},
                    "content_offset": {"type": "integer", "minimum": 0}
                },
                "additionalProperties": false
            }),
            completion_mode: CompletionMode::ProcessLocal,
            auto_wait_seconds: None,
            running_restart: RunningRestartPolicy::RuntimeRestarted,
            retry_dispatch: RetryDispatchPolicy::Never,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ToolInvocation {
    pub tool_call_id: String,
    pub tool_name: String,
    pub input: Value,
    pub callback_url: Option<String>,
    pub callback_bearer: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolExecutionCompletion {
    Response,
    AsyncRunning,
}

#[derive(Clone, Debug)]
pub struct ToolExecutionResult {
    pub content: String,
    pub is_error: bool,
    pub completion: ToolExecutionCompletion,
    pub auto_wait_seconds: Option<u32>,
    /// Durable result payload.  `None` means the runtime should construct the
    /// ordinary bounded inline `{content}` payload from `content`.
    pub result: Option<DurablePayload>,
}

/// Callback dispatch materialized before the tool batch transaction.  The raw
/// bearer is kept only in memory long enough to invoke the adapter; the
/// durable binding stores its keyed fingerprint through `CallbackPlanned`.
#[derive(Clone, Debug)]
struct CallbackPlan {
    tool_call_id: String,
    callback_id: String,
    callback_url: String,
    bearer: String,
    binding: crate::domain::AsyncCallbackBinding,
}

#[derive(Debug)]
pub enum ToolError {
    InvalidSelection,
    InvalidInvocation,
    Unavailable,
}

#[derive(Debug)]
pub struct BlobStoreError;

/// Runtime budgets and bounded effect windows.  Composition roots should use
/// [`Runtime::new_with_options`] so configuration is applied once at the
/// durable runtime boundary; [`Runtime::new`] remains a compatibility
/// constructor for callers that only provide a snapshot cadence.
#[derive(Clone, Debug)]
pub struct RuntimeOptions {
    pub snapshot_every: Option<u64>,
    pub tool_foreground: Duration,
    /// Maximum completion requested for an ordinary model round. This is a
    /// runtime request bound, not the selected model's advertised capability.
    pub model_request_max_output_tokens: u32,
    pub model_context_buffer_tokens: u64,
    pub model_context_handoff_generation_tokens: u32,
    pub model_context_handoff_document_tokens: u32,
    pub model_step_max_attempts: u32,
    pub model_retry_base: Duration,
    pub model_retry_max: Duration,
    pub model_stream_idle_timeout: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeCommandError {
    NotFound,
    Conflict,
    Invalid(&'static str),
    Backend,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallbackCompletion {
    Admitted(Value),
    Replayed(Value),
}

impl RuntimeOptions {
    pub fn defaults(snapshot_every: Option<u64>) -> Self {
        Self {
            snapshot_every,
            tool_foreground: Duration::from_secs(3),
            model_request_max_output_tokens: 128_000,
            model_context_buffer_tokens: 32_000,
            model_context_handoff_generation_tokens: 128_000,
            model_context_handoff_document_tokens: 4_096,
            model_step_max_attempts: 3,
            model_retry_base: Duration::from_millis(500),
            model_retry_max: Duration::from_secs(5),
            model_stream_idle_timeout: Duration::from_secs(30),
        }
    }

    fn bounded(mut self) -> Self {
        self.model_step_max_attempts = self.model_step_max_attempts.clamp(1, 32);
        self.model_request_max_output_tokens = self.model_request_max_output_tokens.max(1);
        self.model_context_buffer_tokens = self.model_context_buffer_tokens.max(1);
        self.model_context_handoff_document_tokens = self
            .model_context_handoff_document_tokens
            .clamp(1, MAX_CONTEXT_HANDOFF_DOCUMENT_TOKENS);
        self.model_context_handoff_generation_tokens = self
            .model_context_handoff_generation_tokens
            .max(self.model_context_handoff_document_tokens)
            .min(MAX_CONTEXT_HANDOFF_GENERATION_TOKENS);
        self.tool_foreground = self.tool_foreground.min(Duration::from_secs(86_400));
        self.model_retry_max = self.model_retry_max.min(Duration::from_secs(3_600));
        self.model_retry_base = self.model_retry_base.min(self.model_retry_max);
        self.model_stream_idle_timeout = self
            .model_stream_idle_timeout
            .clamp(Duration::from_millis(1), Duration::from_secs(86_400));
        self
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct SessionKey {
    authority_id: String,
    subject: String,
    session_id: String,
}

pub struct Runtime {
    store: Arc<dyn EventStore>,
    model: Arc<dyn ModelExecutor>,
    tools: Arc<dyn ToolExecutor>,
    clock: Arc<dyn Clock>,
    stream_publisher: Arc<RuntimeStreamPublisher>,
    stream_observer: Arc<dyn ModelStreamObserver>,
    options: RuntimeOptions,
    session_locks: Mutex<HashMap<SessionKey, Arc<AsyncMutex<()>>>>,
}

impl Runtime {
    pub fn new(
        store: Arc<dyn EventStore>,
        model: Arc<dyn ModelExecutor>,
        tools: Arc<dyn ToolExecutor>,
        snapshot_every: Option<u64>,
        clock: Arc<dyn Clock>,
    ) -> Arc<Self> {
        Self::new_with_options(
            store,
            model,
            tools,
            RuntimeOptions::defaults(snapshot_every),
            clock,
        )
    }

    pub fn new_with_options(
        store: Arc<dyn EventStore>,
        model: Arc<dyn ModelExecutor>,
        tools: Arc<dyn ToolExecutor>,
        options: RuntimeOptions,
        clock: Arc<dyn Clock>,
    ) -> Arc<Self> {
        let stream_publisher = RuntimeStreamPublisher::new(1_024);
        let stream_observer = Arc::new(BroadcastModelStreamObserver {
            publisher: stream_publisher.clone(),
        });
        Arc::new(Self {
            store,
            model,
            tools,
            clock,
            stream_publisher,
            stream_observer,
            options: options.bounded(),
            session_locks: Mutex::new(HashMap::new()),
        })
    }

    pub fn stream_publisher(&self) -> Arc<RuntimeStreamPublisher> {
        self.stream_publisher.clone()
    }

    pub fn now_ms(&self) -> i64 {
        self.clock.now_ms()
    }

    /// Validate a session's configured adapter-tool selection against the
    /// current runtime catalog.  The HTTP adapter calls this only after a
    /// create receipt miss; receipt replay therefore never consults the
    /// current catalog.
    pub fn validate_tool_selection(&self, selected: &[String]) -> Result<(), RuntimeCommandError> {
        self.tools
            .definitions(selected)
            .map(|_| ())
            .map_err(|_| RuntimeCommandError::Invalid("tool_selection"))
    }

    /// Complete an external callback through the durable stream.  The
    /// callback ID is the only routing identity; bearer verification and
    /// first-terminal semantics remain inside the runtime so the HTTP adapter
    /// cannot grow a second mapping state machine.
    pub async fn complete_external_callback(
        self: &Arc<Self>,
        callback_id: String,
        bearer: String,
        payload: Value,
    ) -> Result<CallbackCompletion, RuntimeCommandError> {
        let store = self.store.clone();
        let clock = self.clock.clone();
        let callback_lookup_id = callback_id.clone();
        let completion = tokio::task::spawn_blocking(move || {
            complete_external_callback_blocking(&*store, &*clock, &callback_id, &bearer, payload)
        })
        .await
        .map_err(|_| RuntimeCommandError::Backend)??;

        // A callback is a durable wakeable delivery.  Only the first admitted
        // terminal transition wakes the owning activation; canonical replay
        // must not create a second activation.
        if let CallbackCompletion::Admitted(_) = completion {
            let store = self.store.clone();
            if let Some(lookup) = tokio::task::spawn_blocking(move || {
                store.lookup_external_callback(&callback_lookup_id)
            })
            .await
            .map_err(|_| RuntimeCommandError::Backend)?
            .map_err(|_| RuntimeCommandError::Backend)?
            {
                self.wake_and_wait_for_activation(lookup.owner, lookup.session_id)
                    .await;
            }
        }
        Ok(completion)
    }

    pub async fn read_tool_call(
        &self,
        owner: SessionOwner,
        session_id: String,
        tool_call_id: String,
    ) -> Result<Option<AsyncToolCallRecord>, RuntimeCommandError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let state = store
                .rehydrate_owned(&owner, &session_id)
                .map_err(|_| RuntimeCommandError::NotFound)?;
            Ok(state.async_tool_calls.get(&tool_call_id).cloned())
        })
        .await
        .map_err(|_| RuntimeCommandError::Backend)?
    }

    pub async fn cancel_tool_call(
        &self,
        owner: SessionOwner,
        session_id: String,
        tool_call_id: String,
        reason: String,
        command_id: String,
    ) -> Result<AsyncToolCallRecord, RuntimeCommandError> {
        let store = self.store.clone();
        let clock = self.clock.clone();
        tokio::task::spawn_blocking(move || {
            cancel_tool_call_blocking(
                &*store,
                &*clock,
                &owner,
                &session_id,
                &tool_call_id,
                &reason,
                &command_id,
            )
        })
        .await
        .map_err(|_| RuntimeCommandError::Backend)?
    }

    pub async fn reconcile_tool_call(
        self: &Arc<Self>,
        owner: SessionOwner,
        session_id: String,
        tool_call_id: String,
        action: String,
        command_id: String,
    ) -> Result<AsyncToolCallRecord, RuntimeCommandError> {
        if action != "retry_dispatch" || command_id.is_empty() {
            return Err(RuntimeCommandError::Invalid("reconcile_action"));
        }
        let current = self
            .read_tool_call(owner.clone(), session_id.clone(), tool_call_id.clone())
            .await?
            .ok_or(RuntimeCommandError::NotFound)?;
        if !current.retry_dispatch_deduplicated
            || current.completion_mode != CompletionMode::ProcessLocal
        {
            return Err(RuntimeCommandError::Conflict);
        }
        let definitions = self
            .tools
            .definitions(std::slice::from_ref(&current.tool_name))
            .map_err(|_| RuntimeCommandError::Conflict)?;
        definitions
            .first()
            .filter(|definition| {
                definition.name == current.tool_name
                    && definition.completion_mode == CompletionMode::ProcessLocal
                    && definition.running_restart == RunningRestartPolicy::UnknownOutcome
                    && definition.retry_dispatch
                        == RetryDispatchPolicy::SameInvocationKeyDeduplicated
            })
            .ok_or(RuntimeCommandError::Conflict)?;
        let call = ToolCall {
            tool_call_id: current.tool_call_id.clone(),
            tool_name: current.tool_name.clone(),
            input: current.input.clone(),
        };
        let input = inline_tool_input(&call)
            .map_err(|_| RuntimeCommandError::Invalid("reconcile_tool_input"))?;
        let store = self.store.clone();
        let append_owner = owner.clone();
        let append_session_id = session_id.clone();
        let append_tool_call_id = tool_call_id.clone();
        let append_command_id = command_id.clone();
        let (record, admitted) = tokio::task::spawn_blocking(move || {
            reconcile_tool_call_blocking(
                &*store,
                &append_owner,
                &append_session_id,
                &append_tool_call_id,
                &append_command_id,
            )
        })
        .await
        .map_err(|_| RuntimeCommandError::Backend)??;
        let Some((append, state)) = admitted else {
            return Ok(record);
        };
        self.observe_commit(&append, &state).await;

        let invocation = ToolInvocation {
            tool_call_id: call.tool_call_id.clone(),
            tool_name: call.tool_name.clone(),
            input,
            callback_url: None,
            callback_bearer: None,
        };
        let executor = self.tools.clone();
        let runtime = Arc::clone(self);
        let batch_identity = format!("tool-reconcile:v1:{command_id}");
        tokio::spawn(async move {
            match executor.execute(invocation).await {
                Ok(result)
                    if !result.is_error
                        && result.completion == ToolExecutionCompletion::Response =>
                {
                    if let Err(error) = runtime
                        .append_background_tool_result(
                            owner,
                            session_id,
                            batch_identity,
                            call,
                            Ok(result),
                        )
                        .await
                    {
                        tracing::warn!(error, "reconciled tool completion append failed");
                    }
                }
                _ => {
                    if let Err(error) = runtime
                        .restore_retry_dispatch_unknown(
                            owner,
                            session_id,
                            batch_identity,
                            call.tool_call_id,
                        )
                        .await
                    {
                        tracing::warn!(error, "reconciled tool uncertainty append failed");
                    }
                }
            }
        });
        Ok(record)
    }

    pub async fn queue_startup_recovery(self: &Arc<Self>) -> Result<(), &'static str> {
        self.scan_startup_refs(false).await?;
        self.scan_startup_refs(true).await?;
        Ok(())
    }

    fn schedule_timer(
        self: &Arc<Self>,
        owner: SessionOwner,
        session_id: String,
        timer: crate::domain::WaitTimerIntent,
    ) {
        let runtime = Arc::downgrade(self);
        let clock = self.clock.clone();
        tokio::spawn(async move {
            let delay_ms = timer.deadline_ms.saturating_sub(clock.now_ms());
            if let Ok(delay_ms) = u64::try_from(delay_ms) {
                clock.sleep(Duration::from_millis(delay_ms)).await;
            }
            let Some(runtime) = runtime.upgrade() else {
                return;
            };
            match append_expired_timer(
                runtime.store.clone(),
                owner.clone(),
                session_id.clone(),
                clock.now_ms(),
            )
            .await
            {
                Ok(Some((append, state))) => {
                    runtime.observe_commit(&append, &state).await;
                    if !append.replayed {
                        runtime.wake(owner, session_id);
                    }
                }
                Ok(None) => {}
                Err(error) => tracing::warn!(error, session_id, "wait timer expiry failed"),
            }
        });
    }

    async fn scan_startup_refs(self: &Arc<Self>, wake: bool) -> Result<(), &'static str> {
        let mut after_creation_position = 0;
        loop {
            let store = self.store.clone();
            let page = tokio::task::spawn_blocking(move || {
                store
                    .scan_owned_session_refs(after_creation_position, MAX_OWNED_SESSION_SCAN_LIMIT)
                    .map_err(|_| "startup_scan")
            })
            .await
            .map_err(|_| "startup_scan_join")??;
            let page_len = page.len();
            let Some(last) = page.last() else {
                return Ok(());
            };
            after_creation_position = last.creation_global_position;
            if wake {
                for session in page {
                    let owner = session.owner.clone();
                    let session_id = session.session_id.clone();
                    match self
                        .recover_startup_session(owner.clone(), session_id.clone())
                        .await
                    {
                        Ok(state) => {
                            if let Some(timer) = state.active_timer.clone() {
                                self.schedule_timer(owner.clone(), session_id.clone(), timer);
                            }
                            if startup_session_is_runnable(&state) {
                                self.wake(owner, session_id);
                            }
                        }
                        Err(error) => {
                            tracing::warn!(
                                error,
                                session_id,
                                "startup recovery deferred for an invalid session stream"
                            );
                        }
                    }
                }
            }
            if page_len < MAX_OWNED_SESSION_SCAN_LIMIT {
                return Ok(());
            }
        }
    }

    /// Reconcile only durable work that was left in an in-flight state before
    /// exposing the readiness barrier.  The subsequent wake may run a normal
    /// activation, but GET immediately after READY must already observe the
    /// restart classification (for example `unknown_outcome`).
    async fn recover_startup_session(
        self: &Arc<Self>,
        owner: SessionOwner,
        session_id: String,
    ) -> Result<VerifiedSessionState, &'static str> {
        let mut state =
            rehydrate_verified(self.store.clone(), owner.clone(), session_id.clone()).await?;
        if state.active_activation.is_some() {
            state = self
                .recover_async_tools(owner.clone(), session_id.clone(), state)
                .await?;
            state = self.recover_model_round(owner, session_id, state).await?;
        }
        Ok(state)
    }

    pub async fn observe_commit(self: &Arc<Self>, append: &AppendResult, state: &SessionState) {
        if append.replayed {
            return;
        }
        let contains_legacy_request_content = state
            .active_model_round
            .as_ref()
            .and_then(|round| round.request.as_ref())
            .is_some_and(|request| request.legacy_envelope.is_some());
        if !contains_legacy_request_content
            && self.options.snapshot_every.is_some_and(|every| {
                every > 0 && state.stream_version > 0 && state.stream_version.is_multiple_of(every)
            })
        {
            let store = self.store.clone();
            let snapshot_state = state.clone();
            let result = tokio::task::spawn_blocking(move || {
                store
                    .write_state_snapshot(&snapshot_state)
                    .map_err(|_| "snapshot_write")
            })
            .await;
            match result {
                Err(error) => tracing::warn!(error = ?error, "snapshot creation failed"),
                Ok(Err(error)) => tracing::warn!(error, "snapshot creation failed"),
                Ok(Ok(())) => {}
            }
        }
        for event in &append.events {
            self.stream_publisher
                .publish(RuntimeStreamEvent::Durable(Box::new(event.clone())));
        }
        if let Some(timer) = append.events.iter().rev().find_map(|event| {
            if let SessionEvent::WaitTimerScheduled { timer } = &event.event {
                Some(timer.clone())
            } else {
                None
            }
        }) {
            if let Some(owner) = state.owner.clone() {
                self.schedule_timer(owner, state.session_id.clone(), timer);
            }
        }
    }

    pub fn wake(self: &Arc<Self>, owner: SessionOwner, session_id: String) {
        self.spawn_wake(owner, session_id, None);
    }

    /// Schedule a wake and wait only until the next activation has been
    /// durably claimed.  Callback admission uses this short barrier so a
    /// caller cannot observe an idle session between the durable delivery
    /// append and the activation that will consume it.  The model round and
    /// tool work continue asynchronously after the barrier is released.
    async fn wake_and_wait_for_activation(
        self: &Arc<Self>,
        owner: SessionOwner,
        session_id: String,
    ) {
        let (ready, completion) = oneshot::channel();
        self.spawn_wake(owner, session_id, Some(ready));
        let _ = completion.await;
    }

    fn spawn_wake(
        self: &Arc<Self>,
        owner: SessionOwner,
        session_id: String,
        mut ready: Option<oneshot::Sender<()>>,
    ) {
        let key = SessionKey {
            authority_id: owner.authority_id.clone(),
            subject: owner.subject.clone(),
            session_id: session_id.clone(),
        };
        let lock = match self.session_locks.lock() {
            Ok(mut locks) => locks
                .entry(key)
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone(),
            Err(_) => {
                if let Some(ready) = ready {
                    let _ = ready.send(());
                }
                return;
            }
        };
        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            let _guard = lock.lock().await;
            let result = runtime
                .activate(owner, session_id.clone(), &mut ready)
                .await;
            if let Some(ready) = ready.take() {
                let _ = ready.send(());
            }
            if let Err(error) = result {
                tracing::warn!(session_id = %session_id, error, "session activation stopped");
            }
        });
    }

    async fn activate(
        self: &Arc<Self>,
        owner: SessionOwner,
        session_id: String,
        ready: &mut Option<oneshot::Sender<()>>,
    ) -> Result<(), &'static str> {
        let mut state =
            rehydrate_verified(self.store.clone(), owner.clone(), session_id.clone()).await?;
        let Some(selection) = state
            .active_activation
            .as_ref()
            .and_then(|activation| activation.selection.model.clone())
            .or_else(|| state.selection.model.clone())
        else {
            if let Some(ready) = ready.take() {
                let _ = ready.send(());
            }
            return Ok(());
        };

        if state.active_activation.is_none() {
            // Wake requests may already be queued behind the per-session lock
            // when a prior activation reaches a terminal handoff failure.
            // Re-check durable runnable state after acquiring that lock so a
            // stale wake cannot start the same failed handoff again.
            if !startup_session_is_runnable(&state) {
                if let Some(ready) = ready.take() {
                    let _ = ready.send(());
                }
                return Ok(());
            }
            let (append, next_state) = start_activation(
                self.store.clone(),
                self.clock.clone(),
                owner.clone(),
                session_id.clone(),
                &state,
                &state.selection,
            )
            .await?;
            self.observe_commit(&append, &next_state).await;
            state = next_state;
        }
        if let Some(ready) = ready.take() {
            let _ = ready.send(());
        }

        // Process-bound tool recovery is performed synchronously by
        // `queue_startup_recovery` before readiness.  Do not classify a
        // running invocation as a restart merely because a timer or
        // completion wakes a later activation in the same process.
        state = self
            .recover_model_round(owner.clone(), session_id.clone(), state)
            .await?;
        let mut context_cache = ProviderContextCache::default();
        loop {
            if state.active_wait.is_some() && state.delivery_queue.is_empty() {
                if let Some(activation) = state.active_activation.as_ref() {
                    if let Some((append, next_state)) = finish_activation(
                        self.store.clone(),
                        self.clock.clone(),
                        owner.clone(),
                        session_id.clone(),
                        &state,
                        activation.activation_id.clone(),
                        ActivationOutcome::Wait,
                    )
                    .await?
                    {
                        self.observe_commit(&append, &next_state).await;
                    }
                }
                return Ok(());
            }

            let (append, next_state) =
                materialize_boundary(self.store.clone(), owner.clone(), session_id.clone(), state)
                    .await?;
            if let Some(append) = append {
                self.observe_commit(&append, &next_state).await;
                state = next_state;
                continue;
            }
            state = next_state;

            if let Some(trigger_identity) =
                unresolved_user(&state).map(|trigger| trigger.message_id.clone())
            {
                let (next_state, prepared) = self
                    .ensure_model_context(
                        &owner,
                        &session_id,
                        &selection,
                        state,
                        &mut context_cache,
                    )
                    .await?;
                state = next_state;
                if state.active_activation.is_none() {
                    return Ok(());
                }
                let prepared = prepared.ok_or("model_context_missing")?;
                let round = self
                    .run_model_round(
                        &owner,
                        &session_id,
                        &selection,
                        &state,
                        prepared,
                        trigger_identity,
                    )
                    .await;
                let (commits, next_state) = match round {
                    Ok(round) => round,
                    Err(error) => {
                        return Err(error);
                    }
                };
                for (append, commit_state) in commits {
                    self.observe_commit(&append, &commit_state).await;
                }
                state = next_state;
                if state.active_activation.is_none() {
                    return Ok(());
                }
                continue;
            }

            if let Some(round_identity) = model_followup_identity(&state) {
                let (next_state, prepared) = self
                    .ensure_model_context(
                        &owner,
                        &session_id,
                        &selection,
                        state,
                        &mut context_cache,
                    )
                    .await?;
                state = next_state;
                if state.active_activation.is_none() {
                    return Ok(());
                }
                let prepared = prepared.ok_or("model_context_missing")?;
                let round = self
                    .run_model_round(
                        &owner,
                        &session_id,
                        &selection,
                        &state,
                        prepared,
                        round_identity,
                    )
                    .await;
                let (commits, next_state) = match round {
                    Ok(round) => round,
                    Err(error) => {
                        return Err(error);
                    }
                };
                for (append, commit_state) in commits {
                    self.observe_commit(&append, &commit_state).await;
                }
                state = next_state;
                if state.active_activation.is_none() {
                    return Ok(());
                }
            } else {
                if let Some(activation) = state.active_activation.as_ref() {
                    if let Some((append, next_state)) = finish_activation(
                        self.store.clone(),
                        self.clock.clone(),
                        owner.clone(),
                        session_id.clone(),
                        &state,
                        activation.activation_id.clone(),
                        ActivationOutcome::Finished,
                    )
                    .await?
                    {
                        self.observe_commit(&append, &next_state).await;
                    }
                }
                return Ok(());
            }
        }
    }

    fn prepare_callback_plans(
        &self,
        owner: &SessionOwner,
        session_id: &str,
        state: &SessionState,
        definitions: &[ToolDefinition],
        calls: &[ToolCall],
    ) -> Result<Vec<CallbackPlan>, ToolError> {
        let base_url = state
            .selection
            .callback_base_url
            .as_deref()
            .filter(|value| !value.is_empty());
        let definitions = definitions
            .iter()
            .map(|definition| (definition.name.as_str(), definition))
            .collect::<HashMap<_, _>>();
        let existing = state
            .callback_bindings
            .values()
            .map(|binding| binding.tool_call_id.as_str())
            .collect::<HashSet<_>>();
        let mut plans = Vec::new();
        for call in calls
            .iter()
            .filter(|call| call.tool_name != WAIT_FOR_TOOL_NAME)
        {
            let Some(definition) = definitions.get(call.tool_name.as_str()) else {
                continue;
            };
            if definition.completion_mode != CompletionMode::ExternalCallback {
                continue;
            }
            let Some(base_url) = base_url else {
                return Err(ToolError::Unavailable);
            };
            if existing.contains(call.tool_call_id.as_str()) {
                return Err(ToolError::Unavailable);
            }
            let callback_id = stable_digest(
                "callback-id",
                &format!(
                    "{}\u{0}{}\u{0}{}\u{0}{}",
                    owner.authority_id, owner.subject, session_id, call.tool_call_id
                ),
            );
            let mut bearer_bytes = [0_u8; 32];
            getrandom::fill(&mut bearer_bytes).map_err(|_| ToolError::Unavailable)?;
            let bearer = bearer_bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let binding = crate::domain::AsyncCallbackBinding {
                callback_id: callback_id.clone(),
                tool_call_id: call.tool_call_id.clone(),
                bearer_fingerprint: stable_digest("callback-bearer", &bearer),
                payload_fingerprint: None,
            };
            plans.push(CallbackPlan {
                tool_call_id: call.tool_call_id.clone(),
                callback_url: format!("{}/{}", base_url.trim_end_matches('/'), callback_id),
                callback_id,
                bearer,
                binding,
            });
        }
        Ok(plans)
    }

    async fn finish_model_failure_activation(
        self: &Arc<Self>,
        owner: &SessionOwner,
        session_id: &str,
        state: VerifiedSessionState,
    ) -> Result<VerifiedSessionState, &'static str> {
        let Some(activation) = state.active_activation.as_ref() else {
            return Ok(state);
        };
        let Some((append, next_state)) = finish_activation(
            self.store.clone(),
            self.clock.clone(),
            owner.clone(),
            session_id.to_owned(),
            &state,
            activation.activation_id.clone(),
            ActivationOutcome::Failed,
        )
        .await?
        else {
            return Ok(state);
        };
        self.observe_commit(&append, &next_state).await;
        if !next_state.delivery_queue.is_empty() {
            self.wake(owner.clone(), session_id.to_owned());
        }
        Ok(next_state)
    }

    async fn execute_tool_calls(
        self: &Arc<Self>,
        owner: &SessionOwner,
        session_id: &str,
        batch_identity: &str,
        calls: &[ToolCall],
        selected: &[String],
        callback_plans: &[CallbackPlan],
    ) -> Vec<Result<ToolExecutionResult, ToolError>> {
        let mut definitions = self.tools.definitions(selected).unwrap_or_default();
        definitions.extend(runtime_tool_definitions());
        let definitions = definitions
            .into_iter()
            .map(|definition| (definition.name.clone(), definition))
            .collect::<HashMap<_, _>>();
        let mut tasks = Vec::new();
        let mut immediate = HashMap::new();
        let runtime_state = if calls.iter().any(|call| {
            matches!(
                call.tool_name.as_str(),
                READ_CONTEXT_HANDOFF_TOOL_NAME | READ_SESSION_HISTORY_TOOL_NAME
            )
        }) {
            rehydrate_verified(self.store.clone(), owner.clone(), session_id.to_owned())
                .await
                .ok()
                .map(VerifiedSessionState::into_state)
        } else {
            None
        };
        let callback_plans = callback_plans
            .iter()
            .map(|plan| (plan.tool_call_id.as_str(), plan))
            .collect::<HashMap<_, _>>();
        for call in calls
            .iter()
            .filter(|call| call.tool_name != WAIT_FOR_TOOL_NAME)
        {
            let Some(definition) = definitions.get(&call.tool_name).cloned() else {
                immediate.insert(call.tool_call_id.clone(), Err(ToolError::InvalidSelection));
                continue;
            };
            let input = match inline_tool_input(call) {
                Ok(input) => input,
                Err(_) => {
                    immediate.insert(call.tool_call_id.clone(), Err(ToolError::InvalidInvocation));
                    continue;
                }
            };
            if matches!(
                call.tool_name.as_str(),
                READ_CONTEXT_HANDOFF_TOOL_NAME | READ_SESSION_HISTORY_TOOL_NAME
            ) {
                let result = runtime_state
                    .as_ref()
                    .ok_or(ToolError::Unavailable)
                    .and_then(|state| execute_runtime_read_tool(state, &call.tool_name, &input));
                immediate.insert(call.tool_call_id.clone(), result);
                continue;
            }
            let (callback_url, callback_bearer) =
                if definition.completion_mode == CompletionMode::ExternalCallback {
                    let Some(plan) = callback_plans.get(call.tool_call_id.as_str()) else {
                        immediate.insert(call.tool_call_id.clone(), Err(ToolError::Unavailable));
                        continue;
                    };
                    (Some(plan.callback_url.clone()), Some(plan.bearer.clone()))
                } else {
                    (None, None)
                };
            let invocation = ToolInvocation {
                tool_call_id: call.tool_call_id.clone(),
                tool_name: call.tool_name.clone(),
                input,
                callback_url,
                callback_bearer,
            };
            let executor = self.tools.clone();
            let task = tokio::spawn(async move { executor.execute(invocation).await });
            tasks.push((call.tool_call_id.clone(), definition, task));
        }
        let mut results = HashMap::new();
        for (tool_call_id, definition, mut task) in tasks {
            let result = match tokio::time::timeout(self.options.tool_foreground, &mut task).await {
                Ok(Ok(Ok(mut result))) => {
                    if result.auto_wait_seconds.is_none() {
                        result.auto_wait_seconds = definition.auto_wait_seconds;
                    }
                    Ok(result)
                }
                Ok(Ok(Err(error))) => Err(error),
                Ok(Err(_)) => Err(ToolError::Unavailable),
                Err(_) => {
                    let runtime = Arc::clone(self);
                    let background_owner = owner.clone();
                    let background_session_id = session_id.to_owned();
                    let background_batch_identity = batch_identity.to_owned();
                    let background_call = calls
                        .iter()
                        .find(|call| call.tool_call_id == tool_call_id)
                        .cloned();
                    if let Some(background_call) = background_call {
                        tokio::spawn(async move {
                            let result = match task.await {
                                Ok(Ok(result)) => Ok(result),
                                Ok(Err(error)) => Err(error),
                                Err(_) => Err(ToolError::Unavailable),
                            };
                            if let Err(error) = runtime
                                .append_background_tool_result(
                                    background_owner,
                                    background_session_id,
                                    background_batch_identity,
                                    background_call,
                                    result,
                                )
                                .await
                            {
                                tracing::warn!(error, "background tool completion append failed");
                            }
                        });
                    }
                    Ok(ToolExecutionResult {
                        content: "async_running".to_owned(),
                        is_error: false,
                        completion: ToolExecutionCompletion::AsyncRunning,
                        auto_wait_seconds: definition.auto_wait_seconds,
                        result: None,
                    })
                }
            };
            results.insert(tool_call_id, result);
        }
        results.extend(immediate);
        calls
            .iter()
            .map(|call| {
                if call.tool_name == WAIT_FOR_TOOL_NAME {
                    Ok(ToolExecutionResult {
                        content: "wait_for accepted".to_owned(),
                        is_error: false,
                        completion: ToolExecutionCompletion::Response,
                        auto_wait_seconds: None,
                        result: None,
                    })
                } else {
                    results
                        .remove(&call.tool_call_id)
                        .unwrap_or(Err(ToolError::Unavailable))
                }
            })
            .collect()
    }

    async fn append_background_tool_result(
        self: &Arc<Self>,
        owner: SessionOwner,
        session_id: String,
        batch_identity: String,
        call: ToolCall,
        result: Result<ToolExecutionResult, ToolError>,
    ) -> Result<(), &'static str> {
        let store = self.store.clone();
        let clock = self.clock.clone();
        let append_owner = owner.clone();
        let append_session_id = session_id.clone();
        let append = tokio::task::spawn_blocking(move || {
            append_background_tool_result_blocking(
                &*store,
                &*clock,
                &append_owner,
                &append_session_id,
                &batch_identity,
                &call,
                result,
            )
        })
        .await
        .map_err(|_| "background_tool_join")??;
        let Some((append, state)) = append else {
            return Ok(());
        };
        let admitted = !append.replayed;
        self.observe_commit(&append, &state).await;
        if admitted {
            self.wake(owner, session_id);
        }
        Ok(())
    }

    async fn restore_retry_dispatch_unknown(
        self: &Arc<Self>,
        owner: SessionOwner,
        session_id: String,
        batch_identity: String,
        tool_call_id: String,
    ) -> Result<(), &'static str> {
        let store = self.store.clone();
        let result = tokio::task::spawn_blocking(move || {
            append_retry_dispatch_unknown_blocking(
                &*store,
                &owner,
                &session_id,
                &batch_identity,
                &tool_call_id,
            )
        })
        .await
        .map_err(|_| "retry_dispatch_unknown_join")??;
        if let Some((append, state)) = result {
            self.observe_commit(&append, &state).await;
        }
        Ok(())
    }
}

fn unresolved_user(state: &SessionState) -> Option<&TranscriptMessage> {
    let trigger = state.transcript.last()?;
    if trigger.role == TranscriptRole::User
        && state.terminal_model_failure_for_last_user().is_none()
    {
        Some(trigger)
    } else {
        None
    }
}

/// Startup recovery only schedules an activation when durable work can make
/// progress.  In particular, a completed assistant-only turn has no pending
/// delivery or unresolved model boundary; waking it would create an empty
/// activation and advance the stream merely because the process restarted.
fn startup_session_is_runnable(state: &SessionState) -> bool {
    if !state.delivery_queue.is_empty() {
        return true;
    }
    if state.last_context_handoff_failure.is_some() {
        return false;
    }
    if state.active_wait.is_some() {
        return false;
    }
    unresolved_user(state).is_some() || model_followup_identity(state).is_some()
}

/// Build the provider-facing context from the durable transcript.  Runtime
/// notifications are public coordination facts, not provider chat turns.
/// While an async call is still running its foreground `async_running` Tool
/// message is retained for public history; once the durable terminal fact is
/// present, replace that placeholder in the next request with the one
/// terminal Tool result so the provider never sees two results for one call.
/// Return the first queued user that follows an exhausted model attempt which
/// never committed an assistant message.  The empty assistant is provider
/// context only: it preserves the failed round's provider-context boundary without
/// adding a public transcript event.  A normal multi-user first round has no
/// exhaustion fact (or has an assistant between the users), so it is not
/// modified.
fn failed_round_placeholder_target(state: &SessionState) -> Option<String> {
    state.last_model_attempts_exhausted.as_ref()?;
    let failure = state.last_model_attempt_failure.as_ref()?;
    let failure_index = state.transcript.iter().position(|message| {
        message.role == TranscriptRole::User && message.message_id == failure.trigger_message_id
    })?;
    if !state
        .transcript
        .last()
        .is_some_and(|message| message.role == TranscriptRole::User)
    {
        return None;
    }
    let mut assistant_seen = false;
    for message in state.transcript.iter().skip(failure_index + 1) {
        match message.role {
            TranscriptRole::Assistant => assistant_seen = true,
            TranscriptRole::User => {
                return (!assistant_seen).then(|| message.message_id.clone());
            }
            TranscriptRole::System | TranscriptRole::Tool | TranscriptRole::Runtime => {}
        }
    }
    None
}

fn terminal_tool_content(record: &AsyncToolCallRecord) -> Option<String> {
    match record.status {
        AsyncToolStatus::Completed => match record.result.as_ref()? {
            DurablePayload::Inline(payload) => payload
                .value()
                .get("content")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| Some(payload.value().to_string())),
            DurablePayload::BlobRef(blob) => Some(
                json!({
                    "blob": {
                        "id": blob.blob_id,
                        "bytes": blob.byte_len,
                        "sha256": blob.sha256,
                        "media_type": blob.media_type,
                    }
                })
                .to_string(),
            ),
            DurablePayload::Redacted(redacted) => {
                Some(format!("tool result redacted: {}", redacted.reason))
            }
        },
        AsyncToolStatus::Failed
        | AsyncToolStatus::RuntimeRestarted
        | AsyncToolStatus::Cancelled => record
            .error
            .as_ref()
            .map(|error| error.message.clone())
            .or_else(|| Some("tool execution failed".to_owned())),
        AsyncToolStatus::Planned | AsyncToolStatus::Running | AsyncToolStatus::UnknownOutcome => {
            None
        }
    }
}

fn model_followup_identity(state: &SessionState) -> Option<String> {
    if state.active_wait.is_some() {
        return None;
    }
    let latest = state.transcript.last()?;
    if !matches!(latest.role, TranscriptRole::Tool | TranscriptRole::Runtime) {
        return None;
    }
    let assistant = state
        .transcript
        .iter()
        .rev()
        .skip_while(|message| {
            matches!(message.role, TranscriptRole::Tool | TranscriptRole::Runtime)
        })
        .find(|message| {
            message.role == TranscriptRole::Assistant && !message.tool_calls.is_empty()
        })?;

    // A timer expiry ends the current activation, but it does not turn a
    // still-running tool into a model input.  Wait until every ordinary call
    // from this assistant batch has a durable terminal fact; the completion
    // delivery will wake a fresh activation and re-enter this boundary.  The
    // internal `wait_for` call has no async record and is intentionally
    // ignored here so its timer can still resume a later round.
    let all_tools_terminal = assistant.tool_calls.iter().all(|call| {
        call.tool_name == WAIT_FOR_TOOL_NAME
            || state
                .async_tool_calls
                .get(&call.tool_call_id)
                .is_some_and(|record| record.status.is_terminal())
    });
    all_tools_terminal.then(|| assistant.message_id.clone())
}

fn inline_tool_input(call: &ToolCall) -> Result<Value, &'static str> {
    let DurablePayload::Inline(payload) = &call.input else {
        return Err("tool input must be inline");
    };
    if !payload.value().is_object() {
        return Err("tool input must be an object");
    }
    Ok(payload.value().clone())
}

fn validate_tool_calls(
    calls: &[ToolCall],
    definitions: &[ToolDefinition],
) -> Result<(), &'static str> {
    let mut ids = HashSet::new();
    let definitions = definitions
        .iter()
        .map(|definition| (definition.name.as_str(), definition))
        .collect::<HashMap<_, _>>();
    for call in calls {
        if !ids.insert(call.tool_call_id.as_str()) {
            return Err("duplicate tool call id");
        }
        if call.tool_name == WAIT_FOR_TOOL_NAME {
            continue;
        }
        let Some(definition) = definitions.get(call.tool_name.as_str()) else {
            return Err("unselected tool call");
        };
        let input = inline_tool_input(call)?;
        let validator = jsonschema::validator_for(&definition.input_schema)
            .map_err(|_| "invalid tool schema")?;
        if !validator.is_valid(&input) {
            return Err("invalid tool arguments");
        }
    }
    Ok(())
}

fn stable_digest(kind: &str, value: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"zode:runtime-identity:v1");
    digest.update((kind.len() as u64).to_be_bytes());
    digest.update(kind.as_bytes());
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
    format!("sha256:v1:{:x}", digest.finalize())
}

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{json, Value};
use tokio::sync::{broadcast, oneshot, Mutex as AsyncMutex};

use crate::{
    domain::{
        ActivationOutcome, ActiveWait, AsyncToolCallRecord, AsyncToolStatus, CompletionMode,
        DeliveryKind, DurablePayload, EventDraft, EventRecord, ModelAttemptError,
        ModelAttemptErrorClass, ModelAttemptFailure, ModelRetrySchedule, SessionEvent,
        SessionModelSelection, SessionOwner, SessionSelection, SessionState, ToolCall,
        ToolError as DomainToolError, TranscriptMessage, TranscriptRole, WaitSource,
        WAIT_MAX_SECONDS, WAIT_MIN_SECONDS,
    },
    storage::{AppendResult, EventStore, SnapshotRecord, StoreError, MAX_OWNED_SESSION_SCAN_LIMIT},
    REDUCER_SCHEMA_VERSION, STATE_SCHEMA_VERSION,
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

#[derive(Clone, Debug)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub completion_mode: CompletionMode,
    pub auto_wait_seconds: Option<u32>,
    pub running_restart: RunningRestartPolicy,
    pub retry_dispatch: RetryDispatchPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunningRestartPolicy {
    UnknownOutcome,
    RuntimeRestarted,
    AwaitCallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

/// Immutable output storage owned by the composition root.  Runtime/tools
/// write a blob before returning its reference; the event stream only ever
/// receives the resulting content-addressed `BlobRef`.
pub trait BlobStore: Send + Sync {
    fn put(
        &self,
        bytes: &[u8],
        media_type: Option<&str>,
    ) -> Result<crate::domain::BlobRef, BlobStoreError>;
}

pub trait ToolExecutor: Send + Sync {
    fn definitions(&self, selected: &[String]) -> Result<Vec<ToolDefinition>, ToolError>;

    fn execute<'a>(
        &'a self,
        invocation: ToolInvocation,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecutionResult, ToolError>> + Send + 'a>>;
}

#[derive(Clone, Debug)]
pub struct ModelRequest {
    pub owner: SessionOwner,
    pub session_id: String,
    pub activation_id: String,
    pub round_id: String,
    pub selection: SessionModelSelection,
    pub transcript: Vec<TranscriptMessage>,
    pub tools: Vec<ToolDefinition>,
    pub stream_idle_timeout: Duration,
    pub stream_observer: Arc<dyn ModelStreamObserver>,
}

/// Receives provider text deltas for transient browser observation only. The
/// observer is never consulted by the durable reducer and its output is not
/// persisted, replayed, or included in prepared model envelopes.
pub trait ModelStreamObserver: Send + Sync + std::fmt::Debug {
    fn text_delta(&self, session_id: &str, activation_id: &str, round_id: &str, text: &str);
}

/// A bounded, best-effort model text update for currently attached clients.
/// It deliberately has no public cursor: reconnects replay durable facts only.
#[derive(Clone, Debug)]
pub struct TransientModelEvent {
    pub session_id: String,
    pub activation_id: String,
    pub round_id: String,
    pub text: String,
}

const MAX_TRANSIENT_TEXT_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug)]
struct BroadcastModelStreamObserver {
    publisher: broadcast::Sender<TransientModelEvent>,
}

impl ModelStreamObserver for BroadcastModelStreamObserver {
    fn text_delta(&self, session_id: &str, activation_id: &str, round_id: &str, text: &str) {
        if text.is_empty() {
            return;
        }
        let mut remaining = text;
        while !remaining.is_empty() {
            let mut end = remaining.len().min(MAX_TRANSIENT_TEXT_BYTES);
            while !remaining.is_char_boundary(end) {
                end -= 1;
            }
            let (chunk, rest) = remaining.split_at(end);
            let _ = self.publisher.send(TransientModelEvent {
                session_id: session_id.to_owned(),
                activation_id: activation_id.to_owned(),
                round_id: round_id.to_owned(),
                text: chunk.to_owned(),
            });
            remaining = rest;
        }
    }
}

#[derive(Clone, Debug)]
pub struct ModelOutcome {
    pub text: String,
    pub tool_calls: Vec<ToolCall>,
}

pub trait ModelExecutor: Send + Sync {
    fn complete<'a>(
        &'a self,
        request: ModelRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ModelOutcome, ModelError>> + Send + 'a>>;
}

/// Runtime budgets and bounded effect windows.  Composition roots should use
/// [`Runtime::new_with_options`] so configuration is applied once at the
/// durable runtime boundary; [`Runtime::new`] remains a compatibility
/// constructor for callers that only provide a snapshot cadence.
#[derive(Clone, Debug)]
pub struct RuntimeOptions {
    pub snapshot_every: Option<u64>,
    pub tool_foreground: Duration,
    pub max_rounds_per_activation: u32,
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
            max_rounds_per_activation: 32,
            model_step_max_attempts: 3,
            model_retry_base: Duration::from_millis(500),
            model_retry_max: Duration::from_secs(5),
            model_stream_idle_timeout: Duration::from_secs(30),
        }
    }

    fn bounded(mut self) -> Self {
        self.max_rounds_per_activation = self.max_rounds_per_activation.clamp(1, 64);
        self.model_step_max_attempts = self.model_step_max_attempts.clamp(1, 32);
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
    publisher: broadcast::Sender<EventRecord>,
    transient_publisher: broadcast::Sender<TransientModelEvent>,
    stream_observer: Arc<dyn ModelStreamObserver>,
    options: RuntimeOptions,
    session_locks: Mutex<HashMap<SessionKey, Arc<AsyncMutex<()>>>>,
    timer_worker_started: AtomicBool,
}

impl Runtime {
    pub fn new(
        store: Arc<dyn EventStore>,
        model: Arc<dyn ModelExecutor>,
        tools: Arc<dyn ToolExecutor>,
        snapshot_every: Option<u64>,
    ) -> Arc<Self> {
        Self::new_with_options(
            store,
            model,
            tools,
            RuntimeOptions::defaults(snapshot_every),
        )
    }

    pub fn new_with_options(
        store: Arc<dyn EventStore>,
        model: Arc<dyn ModelExecutor>,
        tools: Arc<dyn ToolExecutor>,
        options: RuntimeOptions,
    ) -> Arc<Self> {
        let (publisher, _) = broadcast::channel(1_024);
        let (transient_publisher, _) = broadcast::channel(1_024);
        let stream_observer = Arc::new(BroadcastModelStreamObserver {
            publisher: transient_publisher.clone(),
        });
        Arc::new(Self {
            store,
            model,
            tools,
            publisher,
            transient_publisher,
            stream_observer,
            options: options.bounded(),
            session_locks: Mutex::new(HashMap::new()),
            timer_worker_started: AtomicBool::new(false),
        })
    }

    pub fn publisher(&self) -> broadcast::Sender<EventRecord> {
        self.publisher.clone()
    }

    pub fn transient_publisher(&self) -> broadcast::Sender<TransientModelEvent> {
        self.transient_publisher.clone()
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
        let callback_lookup_id = callback_id.clone();
        let completion = tokio::task::spawn_blocking(move || {
            complete_external_callback_blocking(&*store, &callback_id, &bearer, payload)
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
        tokio::task::spawn_blocking(move || {
            cancel_tool_call_blocking(
                &*store,
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
        &self,
        owner: SessionOwner,
        session_id: String,
        tool_call_id: String,
        action: String,
        command_id: String,
    ) -> Result<AsyncToolCallRecord, RuntimeCommandError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            reconcile_tool_call_blocking(
                &*store,
                &owner,
                &session_id,
                &tool_call_id,
                &action,
                &command_id,
            )
        })
        .await
        .map_err(|_| RuntimeCommandError::Backend)?
    }

    pub async fn queue_startup_recovery(self: &Arc<Self>) -> Result<(), &'static str> {
        self.scan_startup_refs(false).await?;
        self.scan_startup_refs(true).await?;
        self.start_timer_worker();
        Ok(())
    }

    fn start_timer_worker(self: &Arc<Self>) {
        if self.timer_worker_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let runtime = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let Some(runtime) = runtime.upgrade() else {
                    break;
                };
                if let Err(error) = runtime.expire_due_timers().await {
                    tracing::warn!(error, "timer scan stopped for this tick");
                }
            }
        });
    }

    async fn expire_due_timers(self: &Arc<Self>) -> Result<(), &'static str> {
        let now = current_time_ms();
        let mut after_creation_position = 0;
        loop {
            let store = self.store.clone();
            let page = tokio::task::spawn_blocking(move || {
                store
                    .scan_owned_session_refs(after_creation_position, MAX_OWNED_SESSION_SCAN_LIMIT)
                    .map_err(|_| "timer_scan")
            })
            .await
            .map_err(|_| "timer_scan_join")??;
            let page_len = page.len();
            let Some(last) = page.last() else {
                return Ok(());
            };
            after_creation_position = last.creation_global_position;
            for session in page {
                let Some((append, _state)) = append_expired_timer(
                    self.store.clone(),
                    session.owner.clone(),
                    session.session_id.clone(),
                    now,
                )
                .await?
                else {
                    continue;
                };
                self.observe_commit(&append, &_state).await;
                if !append.replayed {
                    self.wake(session.owner, session.session_id);
                }
            }
            if page_len < MAX_OWNED_SESSION_SCAN_LIMIT {
                return Ok(());
            }
        }
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
                        Ok(true) => self.wake(owner, session_id),
                        Ok(false) => {}
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
    ) -> Result<bool, &'static str> {
        let mut state = rehydrate(self.store.clone(), owner.clone(), session_id.clone()).await?;
        if state.active_activation.is_some() {
            state = self
                .recover_async_tools(owner.clone(), session_id.clone(), state)
                .await?;
            state = self.recover_model_round(owner, session_id, state).await?;
        }
        Ok(startup_session_is_runnable(&state))
    }

    pub async fn observe_commit(&self, append: &AppendResult, state: &SessionState) {
        if append.replayed {
            return;
        }
        if self.options.snapshot_every.is_some_and(|every| {
            every > 0 && state.stream_version > 0 && state.stream_version.is_multiple_of(every)
        }) {
            let store = self.store.clone();
            let snapshot_state = state.clone();
            let result = tokio::task::spawn_blocking(move || {
                let snapshot = SnapshotRecord::from_state(
                    snapshot_state.session_id.clone(),
                    &snapshot_state,
                    STATE_SCHEMA_VERSION,
                    REDUCER_SCHEMA_VERSION,
                )
                .map_err(|_| "snapshot_encode")?;
                store
                    .write_snapshot(&snapshot)
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
            let _ = self.publisher.send(event.clone());
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
        let mut state = rehydrate(self.store.clone(), owner.clone(), session_id.clone()).await?;
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
            let (append, next_state) = start_activation(
                self.store.clone(),
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

        loop {
            if state.active_wait.is_some() && state.delivery_queue.is_empty() {
                if let Some(activation) = state.active_activation.as_ref() {
                    if let Some((append, next_state)) = finish_activation(
                        self.store.clone(),
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

            if self.activation_round_budget_exhausted(&state) {
                self.finish_round_budget_activation(&owner, &session_id, &state)
                    .await?;
                return Ok(());
            }

            if let Some(trigger) = unresolved_user(&state) {
                let round = self
                    .run_model_round(
                        &owner,
                        &session_id,
                        &selection,
                        &state,
                        trigger.message_id.clone(),
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

            let (append, next_state) =
                materialize_boundary(self.store.clone(), owner.clone(), session_id.clone(), state)
                    .await?;
            if let Some(append) = append {
                self.observe_commit(&append, &next_state).await;
                state = next_state;
                continue;
            }
            state = next_state;

            if self.activation_round_budget_exhausted(&state) {
                self.finish_round_budget_activation(&owner, &session_id, &state)
                    .await?;
                return Ok(());
            }

            if let Some(round_identity) = model_followup_identity(&state) {
                let round = self
                    .run_model_round(&owner, &session_id, &selection, &state, round_identity)
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

    fn activation_round_budget_exhausted(&self, state: &SessionState) -> bool {
        let Some(activation) = state.active_activation.as_ref() else {
            return false;
        };
        if activation.rounds_started < self.options.max_rounds_per_activation {
            return false;
        }
        // A scheduled retry belongs to the already-counted round and must
        // still be claimed.  The budget limits model rounds, not attempts
        // within one prepared request.
        !state
            .active_model_round
            .as_ref()
            .is_some_and(|round| round.retry.is_some() && round.attempt.is_none())
    }

    async fn finish_round_budget_activation(
        self: &Arc<Self>,
        owner: &SessionOwner,
        session_id: &str,
        state: &SessionState,
    ) -> Result<(), &'static str> {
        let Some(activation) = state.active_activation.as_ref() else {
            return Ok(());
        };
        let Some((append, next_state)) = finish_activation(
            self.store.clone(),
            owner.clone(),
            session_id.to_owned(),
            state,
            activation.activation_id.clone(),
            ActivationOutcome::Finished,
        )
        .await?
        else {
            return Ok(());
        };
        self.observe_commit(&append, &next_state).await;
        let queued_input = next_state.transcript.last().is_some_and(|message| {
            message.role == TranscriptRole::User && message.source_queue_id.is_some()
        });
        if !next_state.delivery_queue.is_empty() || queued_input {
            self.wake(owner.clone(), session_id.to_owned());
        }
        Ok(())
    }

    async fn recover_model_round(
        self: &Arc<Self>,
        owner: SessionOwner,
        session_id: String,
        mut state: SessionState,
    ) -> Result<SessionState, &'static str> {
        let Some(round) = state.active_model_round.clone() else {
            return Ok(state);
        };
        let Some(attempt) = round.attempt.clone() else {
            return Ok(state);
        };
        if attempt.outcome == crate::domain::ModelAttemptOutcome::Failed {
            return self
                .recover_failed_model_round(owner, session_id, state, attempt)
                .await;
        }
        if attempt.outcome != crate::domain::ModelAttemptOutcome::Running {
            return Ok(state);
        }
        let interrupted = append_runtime_event(
            self.store.clone(),
            owner.clone(),
            session_id.clone(),
            format!("model-attempt-interrupted:{}", attempt.attempt_id),
            format!("model-attempt-interrupted-event:{}", attempt.attempt_id),
            SessionEvent::ModelAttemptInterrupted {
                activation_id: attempt.activation_id.clone(),
                round_id: attempt.round_id.clone(),
                request_id: attempt.request_id.clone(),
                attempt_id: attempt.attempt_id.clone(),
                attempt_number: attempt.attempt_number,
                reason: "runtime_restarted".to_owned(),
            },
        )
        .await?;
        self.observe_commit(&interrupted.0, &interrupted.1).await;
        state = interrupted.1;

        let Some(request) = state
            .active_model_round
            .as_ref()
            .and_then(|round| round.request.clone())
        else {
            return Ok(state);
        };
        if attempt.attempt_number >= request.maximum_attempts {
            let identity = PreparedRequestIdentity {
                activation_id: attempt.activation_id.clone(),
                round_id: attempt.round_id.clone(),
                request_id: attempt.request_id.clone(),
                maximum_attempts: request.maximum_attempts,
                attempt_id: attempt.attempt_id.clone(),
                attempt_number: attempt.attempt_number,
            };
            let exhausted = append_model_attempts_exhausted(
                self.store.clone(),
                owner.clone(),
                session_id.clone(),
                &identity,
                &attempt.attempt_id,
                attempt.attempt_number,
            )
            .await?;
            self.observe_commit(&exhausted.0, &exhausted.1).await;
            state = exhausted.1;
            if state
                .transcript
                .last()
                .is_some_and(|message| message.role == TranscriptRole::User)
            {
                let terminal = append_model_attempt_failure(
                    self.store.clone(),
                    owner.clone(),
                    session_id.clone(),
                    state
                        .transcript
                        .last()
                        .map(|message| message.message_id.clone())
                        .unwrap_or_default(),
                )
                .await?;
                self.observe_commit(&terminal.0, &terminal.1).await;
                state = terminal.1;
            }
            return self
                .finish_model_failure_activation(&owner, &session_id, state)
                .await;
        }
        let next_attempt_number = attempt.attempt_number.saturating_add(1);
        let next_attempt_id = stable_digest(
            "model-attempt",
            &format!("{}:{next_attempt_number}", attempt.request_id),
        );
        let delay_ms = retry_delay_ms(
            self.options.model_retry_base,
            self.options.model_retry_max,
            next_attempt_number,
        );
        let schedule = ModelRetrySchedule {
            activation_id: attempt.activation_id,
            round_id: attempt.round_id,
            request_id: attempt.request_id,
            failed_attempt_id: attempt.attempt_id,
            next_attempt_id,
            failed_attempt_number: attempt.attempt_number,
            next_attempt_number,
            delay_ms,
            not_before_ms: current_time_ms().saturating_add(delay_ms as i64),
            maximum_attempts: request.maximum_attempts,
            error_class: "model_attempt_interrupted".to_owned(),
        };
        let scheduled = append_runtime_event(
            self.store.clone(),
            owner,
            session_id,
            format!(
                "model-retry:{}:{}",
                schedule.request_id, schedule.next_attempt_number
            ),
            format!(
                "model-retry-event:{}:{}",
                schedule.request_id, schedule.next_attempt_number
            ),
            SessionEvent::ModelStepRetryScheduled { schedule },
        )
        .await?;
        self.observe_commit(&scheduled.0, &scheduled.1).await;
        Ok(scheduled.1)
    }

    async fn recover_failed_model_round(
        self: &Arc<Self>,
        owner: SessionOwner,
        session_id: String,
        mut state: SessionState,
        attempt: crate::domain::ModelAttemptRecord,
    ) -> Result<SessionState, &'static str> {
        let Some(request) = state
            .active_model_round
            .as_ref()
            .and_then(|round| round.request.clone())
        else {
            return Ok(state);
        };
        let failure = read_model_failure_fact(
            self.store.clone(),
            owner.clone(),
            session_id.clone(),
            &attempt,
        )
        .await?
        .unwrap_or_else(|| RecoveredModelFailure {
            error_class: "model_attempt_failed".to_owned(),
            retryable: attempt.attempt_number < request.maximum_attempts,
        });
        let terminal = !failure.retryable || attempt.attempt_number >= request.maximum_attempts;
        if terminal {
            if attempt.attempt_number >= request.maximum_attempts {
                let identity = PreparedRequestIdentity {
                    activation_id: attempt.activation_id.clone(),
                    round_id: attempt.round_id.clone(),
                    request_id: attempt.request_id.clone(),
                    maximum_attempts: request.maximum_attempts,
                    attempt_id: attempt.attempt_id.clone(),
                    attempt_number: attempt.attempt_number,
                };
                let exhausted = append_model_attempts_exhausted(
                    self.store.clone(),
                    owner.clone(),
                    session_id.clone(),
                    &identity,
                    &attempt.attempt_id,
                    attempt.attempt_number,
                )
                .await?;
                self.observe_commit(&exhausted.0, &exhausted.1).await;
                state = exhausted.1;
            }
            if state
                .transcript
                .last()
                .is_some_and(|message| message.role == TranscriptRole::User)
            {
                let (error_class, error_message) = terminal_model_error_class(&failure.error_class);
                let terminal = append_model_attempt_failure_with_error(
                    self.store.clone(),
                    owner.clone(),
                    session_id.clone(),
                    state
                        .transcript
                        .last()
                        .map(|message| message.message_id.clone())
                        .unwrap_or_default(),
                    error_class,
                    error_message,
                )
                .await?;
                self.observe_commit(&terminal.0, &terminal.1).await;
                state = terminal.1;
            }
            return self
                .finish_model_failure_activation(&owner, &session_id, state)
                .await;
        }

        let next_attempt_number = attempt.attempt_number.saturating_add(1);
        let next_attempt_id = stable_digest(
            "model-attempt",
            &format!("{}:{next_attempt_number}", attempt.request_id),
        );
        let delay_ms = retry_delay_ms(
            self.options.model_retry_base,
            self.options.model_retry_max,
            next_attempt_number,
        );
        let schedule = ModelRetrySchedule {
            activation_id: attempt.activation_id,
            round_id: attempt.round_id,
            request_id: attempt.request_id,
            failed_attempt_id: attempt.attempt_id,
            next_attempt_id,
            failed_attempt_number: attempt.attempt_number,
            next_attempt_number,
            delay_ms,
            not_before_ms: current_time_ms().saturating_add(delay_ms as i64),
            maximum_attempts: request.maximum_attempts,
            error_class: failure.error_class,
        };
        let scheduled = append_runtime_event(
            self.store.clone(),
            owner,
            session_id,
            format!(
                "model-retry:{}:{}",
                schedule.request_id, schedule.next_attempt_number
            ),
            format!(
                "model-retry-event:{}:{}",
                schedule.request_id, schedule.next_attempt_number
            ),
            SessionEvent::ModelStepRetryScheduled { schedule },
        )
        .await?;
        self.observe_commit(&scheduled.0, &scheduled.1).await;
        Ok(scheduled.1)
    }

    async fn recover_async_tools(
        &self,
        owner: SessionOwner,
        session_id: String,
        mut state: SessionState,
    ) -> Result<SessionState, &'static str> {
        let records = state
            .async_tool_calls
            .values()
            .filter(|record| record.status == AsyncToolStatus::Running)
            .cloned()
            .collect::<Vec<_>>();
        for record in records {
            // External callbacks are durable across process restarts; their
            // adapter invocation must not be replayed or rewritten.  A
            // process-local invocation has an unknown side-effect outcome and
            // therefore enters the explicit unknown-outcome state.
            if record.completion_mode == CompletionMode::ExternalCallback {
                continue;
            }
            let append = append_runtime_event(
                self.store.clone(),
                owner.clone(),
                session_id.clone(),
                format!("tool-unknown-outcome:{}", record.tool_call_id),
                format!("tool-unknown-outcome-event:{}", record.tool_call_id),
                SessionEvent::AsyncToolCallUnknownOutcome {
                    tool_call_id: record.tool_call_id.clone(),
                    reason: "runtime_restarted".to_owned(),
                },
            )
            .await?;
            self.observe_commit(&append.0, &append.1).await;
            state = append.1;
        }
        Ok(state)
    }

    async fn run_model_round(
        self: &Arc<Self>,
        owner: &SessionOwner,
        session_id: &str,
        selection: &SessionModelSelection,
        state: &SessionState,
        round_identity: String,
    ) -> Result<(Vec<(AppendResult, SessionState)>, SessionState), &'static str> {
        let mut tools = self
            .tools
            .definitions(&state.selection.tools)
            .map_err(|_| "tool_selection")?;
        tools.push(ToolDefinition::wait_for());
        let mut request = ModelRequest {
            owner: owner.clone(),
            session_id: session_id.to_owned(),
            activation_id: state
                .active_activation
                .as_ref()
                .map(|activation| activation.activation_id.clone())
                .ok_or("active_activation_missing")?,
            round_id: round_identity.clone(),
            selection: selection.clone(),
            transcript: provider_transcript(state),
            tools: tools.clone(),
            stream_idle_timeout: self.options.model_stream_idle_timeout,
            stream_observer: self.stream_observer.clone(),
        };
        let (prep_commits, _prepared_state, request_identity) = prepare_model_round(
            self.store.clone(),
            owner.clone(),
            session_id.to_owned(),
            ModelRoundInput {
                state,
                selection,
                request: &request,
                round_identity: &round_identity,
                maximum_attempts: self.options.model_step_max_attempts,
            },
        )
        .await?;
        // `prepare_model_round` derives the durable round identity from the
        // committed stream version.  Use that identity for transient browser
        // observations too; the caller's follow-up identity is only the
        // deterministic input to that derivation.
        request.activation_id = request_identity.activation_id.clone();
        request.round_id = request_identity.round_id.clone();
        for (append, commit_state) in &prep_commits {
            self.observe_commit(append, commit_state).await;
        }
        let request_id = request_identity.request_id.clone();
        let mut attempt_number = request_identity.attempt_number;
        let mut attempt_id = request_identity.attempt_id.clone();
        let outcome = loop {
            let completion = self
                .model
                .complete(request.clone())
                .await
                .and_then(|value| {
                    if validate_tool_calls(&value.tool_calls, &tools).is_ok() {
                        Ok(value)
                    } else {
                        Err(ModelError::InvalidToolArguments)
                    }
                });
            match completion {
                Ok(value) => break value,
                Err(ModelError::AuthReplicaUnavailable) => {
                    let failure = append_model_lifecycle_failure(
                        self.store.clone(),
                        owner.clone(),
                        session_id.to_owned(),
                        ModelFailureInput {
                            identity: &request_identity,
                            attempt_id: &attempt_id,
                            attempt_number,
                            error_class: "auth_replica_unavailable",
                            retryable: false,
                        },
                    )
                    .await?;
                    self.observe_commit(&failure.0, &failure.1).await;
                    let mut current_state = failure.1;
                    if attempt_number >= request_identity.maximum_attempts {
                        let exhausted = append_model_attempts_exhausted(
                            self.store.clone(),
                            owner.clone(),
                            session_id.to_owned(),
                            &request_identity,
                            &attempt_id,
                            attempt_number,
                        )
                        .await?;
                        self.observe_commit(&exhausted.0, &exhausted.1).await;
                        current_state = exhausted.1;
                    }
                    if current_state
                        .transcript
                        .last()
                        .is_some_and(|message| message.role == TranscriptRole::User)
                    {
                        let terminal = append_model_attempt_failure(
                            self.store.clone(),
                            owner.clone(),
                            session_id.to_owned(),
                            current_state
                                .transcript
                                .last()
                                .map(|message| message.message_id.clone())
                                .unwrap_or_default(),
                        )
                        .await?;
                        self.observe_commit(&terminal.0, &terminal.1).await;
                        let terminal = self
                            .finish_model_failure_activation(owner, session_id, terminal.1)
                            .await?;
                        return Ok((Vec::new(), terminal));
                    }
                    let terminal = self
                        .finish_model_failure_activation(owner, session_id, current_state)
                        .await?;
                    return Ok((Vec::new(), terminal));
                }
                Err(error) => {
                    let error_class = model_error_class(&error);
                    let failed = append_model_lifecycle_failure(
                        self.store.clone(),
                        owner.clone(),
                        session_id.to_owned(),
                        ModelFailureInput {
                            identity: &request_identity,
                            attempt_id: &attempt_id,
                            attempt_number,
                            error_class,
                            retryable: attempt_number < request_identity.maximum_attempts,
                        },
                    )
                    .await?;
                    self.observe_commit(&failed.0, &failed.1).await;
                    if attempt_number >= request_identity.maximum_attempts {
                        let exhausted = append_model_attempts_exhausted(
                            self.store.clone(),
                            owner.clone(),
                            session_id.to_owned(),
                            &request_identity,
                            &attempt_id,
                            attempt_number,
                        )
                        .await?;
                        self.observe_commit(&exhausted.0, &exhausted.1).await;
                        let current_state = exhausted.1;
                        if current_state
                            .transcript
                            .last()
                            .is_some_and(|message| message.role == TranscriptRole::User)
                        {
                            let (terminal_class, terminal_message) = terminal_model_error(&error);
                            let terminal = append_model_attempt_failure_with_error(
                                self.store.clone(),
                                owner.clone(),
                                session_id.to_owned(),
                                current_state
                                    .transcript
                                    .last()
                                    .map(|message| message.message_id.clone())
                                    .unwrap_or_default(),
                                terminal_class,
                                terminal_message,
                            )
                            .await?;
                            self.observe_commit(&terminal.0, &terminal.1).await;
                            let terminal = self
                                .finish_model_failure_activation(owner, session_id, terminal.1)
                                .await?;
                            return Ok((Vec::new(), terminal));
                        }
                        let terminal = self
                            .finish_model_failure_activation(owner, session_id, current_state)
                            .await?;
                        return Ok((Vec::new(), terminal));
                    }
                    let next_number = attempt_number.saturating_add(1);
                    let next_id =
                        stable_digest("model-attempt", &format!("{}:{next_number}", request_id));
                    let schedule = ModelRetrySchedule {
                        activation_id: request_identity.activation_id.clone(),
                        round_id: request_identity.round_id.clone(),
                        request_id: request_id.clone(),
                        failed_attempt_id: attempt_id.clone(),
                        next_attempt_id: next_id.clone(),
                        failed_attempt_number: attempt_number,
                        next_attempt_number: next_number,
                        delay_ms: retry_delay_ms(
                            self.options.model_retry_base,
                            self.options.model_retry_max,
                            next_number,
                        ),
                        not_before_ms: current_time_ms(),
                        maximum_attempts: request_identity.maximum_attempts,
                        error_class: error_class.to_owned(),
                    };
                    let scheduled = append_runtime_event(
                        self.store.clone(),
                        owner.clone(),
                        session_id.to_owned(),
                        format!("model-retry:{request_id}:{next_number}"),
                        format!("model-retry-event:{request_id}:{next_number}"),
                        SessionEvent::ModelStepRetryScheduled { schedule },
                    )
                    .await?;
                    self.observe_commit(&scheduled.0, &scheduled.1).await;
                    let delay = retry_delay_ms(
                        self.options.model_retry_base,
                        self.options.model_retry_max,
                        next_number,
                    );
                    if delay > 0 {
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                    let started = append_runtime_event(
                        self.store.clone(),
                        owner.clone(),
                        session_id.to_owned(),
                        format!("model-attempt-start:{request_id}:{next_number}"),
                        format!("model-attempt-start-event:{request_id}:{next_number}"),
                        SessionEvent::ModelAttemptStarted {
                            activation_id: request_identity.activation_id.clone(),
                            round_id: request_identity.round_id.clone(),
                            request_id: request_id.clone(),
                            attempt_id: next_id.clone(),
                            attempt_number: next_number,
                            auth_revision: selection.auth_revision,
                            started_at_ms: current_time_ms(),
                        },
                    )
                    .await?;
                    self.observe_commit(&started.0, &started.1).await;
                    attempt_number = next_number;
                    attempt_id = next_id;
                }
            }
        };
        let completed = append_runtime_event(
            self.store.clone(),
            owner.clone(),
            session_id.to_owned(),
            format!("model-request-complete:{request_id}"),
            format!("model-request-complete-event:{request_id}"),
            SessionEvent::ModelRequestCompleted {
                activation_id: request_identity.activation_id.clone(),
                round_id: request_identity.round_id.clone(),
                request_id,
                attempt_id: attempt_id.clone(),
            },
        )
        .await?;
        self.observe_commit(&completed.0, &completed.1).await;
        if outcome.tool_calls.is_empty() {
            let commit = append_assistant(
                self.store.clone(),
                owner.clone(),
                session_id.to_owned(),
                round_identity,
                outcome.text,
            )
            .await?;
            self.observe_commit(&commit.0, &commit.1).await;
            return Ok((Vec::new(), commit.1));
        }

        let batch_identity = assistant_identity(owner, session_id, &round_identity);
        let callback_plans = self
            .prepare_callback_plans(owner, session_id, state, &tools, &outcome.tool_calls)
            .map_err(|_| "callback_plan")?;
        let initial_commit = append_tool_batch(
            self.store.clone(),
            owner.clone(),
            session_id.to_owned(),
            ToolBatchInput {
                round_identity,
                assistant_content: outcome.text.clone(),
                definitions: tools.clone(),
                callback_plans: callback_plans.clone(),
                tool_calls: outcome.tool_calls.clone(),
            },
        )
        .await?;
        self.observe_commit(&initial_commit.0, &initial_commit.1)
            .await;
        let initial_replayed = initial_commit.0.replayed;
        let initial_state = initial_commit.1.clone();
        if initial_replayed {
            let all_results_present = outcome.tool_calls.iter().all(|call| {
                let message_id = tool_result_message_id(&batch_identity, &call.tool_call_id);
                initial_state
                    .transcript
                    .iter()
                    .any(|message| message.message_id == message_id)
            });
            if !all_results_present {
                let pending = outcome.tool_calls.iter().any(|call| {
                    initial_state
                        .async_tool_calls
                        .get(&call.tool_call_id)
                        .is_some_and(|record| !record.status.is_terminal())
                });
                if pending {
                    return Ok((Vec::new(), initial_state));
                }
                return Err("tool_batch_recovery");
            }
            return Ok((Vec::new(), initial_state));
        }
        let results = self
            .execute_tool_calls(
                owner,
                session_id,
                &batch_identity,
                &outcome.tool_calls,
                &state.selection.tools,
                &callback_plans,
            )
            .await;
        let result_commit = append_tool_results(
            self.store.clone(),
            owner.clone(),
            session_id.to_owned(),
            batch_identity,
            outcome.tool_calls,
            results,
        )
        .await?;
        self.observe_commit(&result_commit.0, &result_commit.1)
            .await;
        Ok((Vec::new(), result_commit.1))
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
        state: SessionState,
    ) -> Result<SessionState, &'static str> {
        let Some(activation) = state.active_activation.as_ref() else {
            return Ok(state);
        };
        let Some((append, next_state)) = finish_activation(
            self.store.clone(),
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
        let definitions = self.tools.definitions(selected).unwrap_or_default();
        let definitions = definitions
            .into_iter()
            .map(|definition| (definition.name.clone(), definition))
            .collect::<HashMap<_, _>>();
        let mut tasks = Vec::new();
        let mut immediate = HashMap::new();
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
        let append_owner = owner.clone();
        let append_session_id = session_id.clone();
        let append = tokio::task::spawn_blocking(move || {
            append_background_tool_result_blocking(
                &*store,
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
fn provider_transcript(state: &SessionState) -> Vec<TranscriptMessage> {
    let placeholder_target = failed_round_placeholder_target(state);
    let placeholder = placeholder_target
        .as_ref()
        .map(|trigger_message_id| TranscriptMessage {
            message_id: stable_digest("model-failure-placeholder", trigger_message_id),
            role: TranscriptRole::Assistant,
            content: String::new(),
            tool_call_id: None,
            tool_calls: Vec::new(),
            dedupe_key: None,
            source_queue_id: None,
        });
    let mut projected =
        Vec::with_capacity(state.transcript.len() + usize::from(placeholder.is_some()));
    for original in &state.transcript {
        if placeholder_target
            .as_deref()
            .is_some_and(|target| target == original.message_id)
        {
            if let Some(placeholder) = &placeholder {
                projected.push(placeholder.clone());
            }
        }
        if original.role == TranscriptRole::Runtime {
            continue;
        }
        let mut message = original.clone();
        if message.role == TranscriptRole::Tool
            && message.content == "async_running"
            && message.tool_call_id.is_some()
        {
            let tool_call_id = message.tool_call_id.as_deref().unwrap_or_default();
            if let Some(record) = state.async_tool_calls.get(tool_call_id) {
                if let Some(content) = terminal_tool_content(record) {
                    message.content = content;
                }
            }
        }
        projected.push(message);
    }
    projected
}

/// Return the first queued user that follows an exhausted model attempt which
/// never committed an assistant message.  The empty assistant is provider
/// context only: it preserves the request envelope's round boundary without
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

async fn append_model_attempt_failure(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    trigger_message_id: String,
) -> Result<(AppendResult, SessionState), &'static str> {
    append_model_attempt_failure_with_error(
        store,
        owner,
        session_id,
        trigger_message_id,
        ModelAttemptErrorClass::AuthReplicaUnavailable,
        "credential replica unavailable",
    )
    .await
}

async fn append_model_attempt_failure_with_error(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    trigger_message_id: String,
    error_class: ModelAttemptErrorClass,
    error_message: &'static str,
) -> Result<(AppendResult, SessionState), &'static str> {
    tokio::task::spawn_blocking(move || {
        append_model_attempt_failure_blocking(
            &*store,
            &owner,
            &session_id,
            &trigger_message_id,
            error_class,
            error_message,
        )
    })
    .await
    .map_err(|_| "model_failure_join")?
}

fn append_model_attempt_failure_blocking(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    trigger_message_id: &str,
    error_class: ModelAttemptErrorClass,
    error_message: &str,
) -> Result<(AppendResult, SessionState), &'static str> {
    let failure = ModelAttemptFailure {
        trigger_message_id: trigger_message_id.to_owned(),
        error: ModelAttemptError {
            class: error_class,
            message: error_message.to_owned(),
        },
    };
    let identity = model_failure_identity(owner, session_id, trigger_message_id);
    let command_id = format!("model-attempt-failed-command:v1:{identity}");
    let event_id = format!("model-attempt-failed-event:v1:{identity}");

    for _ in 0..16 {
        let state = store
            .rehydrate_owned(owner, session_id)
            .map_err(|_| "model_failure_rehydrate")?;
        if let Some(existing) = state.terminal_model_failure_for_last_user() {
            if existing == &failure {
                return Ok((
                    AppendResult {
                        stream_id: session_id.to_owned(),
                        command_id,
                        events: Vec::new(),
                        stream_version: state.stream_version,
                        replayed: true,
                    },
                    state,
                ));
            }
            return Err("model_failure_conflict");
        }
        if !state.transcript.last().is_some_and(|message| {
            message.role == TranscriptRole::User && message.message_id == trigger_message_id
        }) {
            return Err("model_failure_trigger");
        }
        match store.append_owned(
            owner,
            session_id,
            state.stream_version,
            &command_id,
            &[EventDraft::new(
                event_id.clone(),
                SessionEvent::ModelAttemptFailed {
                    failure: failure.clone(),
                },
            )],
        ) {
            Ok(append) => {
                let state = store
                    .rehydrate_owned(owner, session_id)
                    .map_err(|_| "model_failure_rehydrate")?;
                return Ok((append, state));
            }
            Err(StoreError::OptimisticConcurrency { .. }) => continue,
            Err(_) => return Err("model_failure_append"),
        }
    }
    Err("model_failure_concurrency")
}

async fn rehydrate(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
) -> Result<crate::domain::SessionState, &'static str> {
    tokio::task::spawn_blocking(move || {
        store
            .rehydrate_owned(&owner, &session_id)
            .map_err(|_| "rehydrate_store")
    })
    .await
    .map_err(|_| "rehydrate_join")?
}

#[derive(Clone, Debug)]
struct RecoveredModelFailure {
    error_class: String,
    retryable: bool,
}

async fn read_model_failure_fact(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    attempt: &crate::domain::ModelAttemptRecord,
) -> Result<Option<RecoveredModelFailure>, &'static str> {
    // This path is only reached for a failed attempt that has no retry or
    // terminal boundary. Read the append-only fact directly so snapshots made
    // before this recovery rule was shipped remain recoverable as well.
    let activation_id = attempt.activation_id.clone();
    let round_id = attempt.round_id.clone();
    let request_id = attempt.request_id.clone();
    let attempt_id = attempt.attempt_id.clone();
    let attempt_number = attempt.attempt_number;
    tokio::task::spawn_blocking(move || {
        let events = store
            .read_stream_owned(&owner, &session_id, 0)
            .map_err(|_| "model_failure_history")?;
        Ok(events
            .into_iter()
            .rev()
            .find_map(|record| match record.event {
                SessionEvent::ModelAttemptFailedFact {
                    activation_id: event_activation_id,
                    round_id: event_round_id,
                    request_id: event_request_id,
                    attempt_id: event_attempt_id,
                    attempt_number: event_attempt_number,
                    error_class,
                    retryable,
                } if event_activation_id == activation_id
                    && event_round_id == round_id
                    && event_request_id == request_id
                    && event_attempt_id == attempt_id
                    && event_attempt_number == attempt_number =>
                {
                    Some(RecoveredModelFailure {
                        error_class,
                        retryable,
                    })
                }
                _ => None,
            }))
    })
    .await
    .map_err(|_| "model_failure_history_join")?
}

#[derive(Clone, Debug)]
struct PreparedRequestIdentity {
    activation_id: String,
    round_id: String,
    request_id: String,
    maximum_attempts: u32,
    attempt_id: String,
    attempt_number: u32,
}

struct ModelRoundInput<'a> {
    state: &'a SessionState,
    selection: &'a SessionModelSelection,
    request: &'a ModelRequest,
    round_identity: &'a str,
    maximum_attempts: u32,
}

struct ModelFailureInput<'a> {
    identity: &'a PreparedRequestIdentity,
    attempt_id: &'a str,
    attempt_number: u32,
    error_class: &'a str,
    retryable: bool,
}

struct ToolBatchInput {
    round_identity: String,
    assistant_content: String,
    definitions: Vec<ToolDefinition>,
    callback_plans: Vec<CallbackPlan>,
    tool_calls: Vec<ToolCall>,
}

async fn append_runtime_event(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    command_id: String,
    event_id: String,
    event: SessionEvent,
) -> Result<(AppendResult, SessionState), &'static str> {
    tokio::task::spawn_blocking(move || {
        for _ in 0..16 {
            let state = store
                .rehydrate_owned(&owner, &session_id)
                .map_err(|_| "runtime_event_rehydrate")?;
            match store.append_owned(
                &owner,
                &session_id,
                state.stream_version,
                &command_id,
                &[EventDraft::new(event_id.clone(), event.clone())],
            ) {
                Ok(append) => {
                    let state = store
                        .rehydrate_owned(&owner, &session_id)
                        .map_err(|_| "runtime_event_rehydrate")?;
                    return Ok((append, state));
                }
                Err(StoreError::OptimisticConcurrency { .. }) => continue,
                Err(_) => {
                    return Err("runtime_event_append");
                }
            }
        }
        Err("runtime_event_concurrency")
    })
    .await
    .map_err(|_| "runtime_event_join")?
}

async fn append_expired_timer(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    now_ms: i64,
) -> Result<Option<(AppendResult, SessionState)>, &'static str> {
    tokio::task::spawn_blocking(move || {
        for _ in 0..16 {
            let state = store
                .rehydrate_owned(&owner, &session_id)
                .map_err(|_| "timer_rehydrate")?;
            let Some(timer) = state.active_timer.clone() else {
                return Ok(None);
            };
            if timer.deadline_ms > now_ms
                || state
                    .active_wait
                    .as_ref()
                    .is_none_or(|wait| wait.wait_id != timer.wait_id)
                || state.wake_pending_wait_id.as_deref() == Some(timer.wait_id.as_str())
            {
                return Ok(None);
            }
            match store.append_owned(
                &owner,
                &session_id,
                state.stream_version,
                &format!("wait-expired:{}", timer.wait_id),
                &[EventDraft::new(
                    format!("wait-expired-event:{}", timer.wait_id),
                    SessionEvent::WaitExpired {
                        wait_id: timer.wait_id,
                    },
                )],
            ) {
                Ok(append) => {
                    let state = store
                        .rehydrate_owned(&owner, &session_id)
                        .map_err(|_| "timer_rehydrate")?;
                    return Ok(Some((append, state)));
                }
                Err(StoreError::OptimisticConcurrency { .. }) => continue,
                Err(_) => return Err("timer_append"),
            }
        }
        Err("timer_concurrency")
    })
    .await
    .map_err(|_| "timer_join")?
}

async fn start_activation(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    state: &SessionState,
    selection: &SessionSelection,
) -> Result<(AppendResult, SessionState), &'static str> {
    let activation_id = stable_digest(
        "activation",
        &format!(
            "{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}",
            owner.authority_id,
            owner.subject,
            session_id,
            state.selection_version,
            state.stream_version,
        ),
    );
    let minimum_auth_revision = selection
        .model
        .as_ref()
        .map(|model| model.auth_revision)
        .ok_or("activation_without_model")?;
    append_runtime_event(
        store,
        owner,
        session_id,
        format!("activation-start:{activation_id}"),
        format!("activation-start-event:{activation_id}"),
        SessionEvent::ActivationStarted {
            activation_id,
            selection: state.selection.clone(),
            selection_version: state.selection_version,
            minimum_auth_revision,
            started_at_ms: current_time_ms(),
        },
    )
    .await
}

async fn finish_activation(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    state: &SessionState,
    activation_id: String,
    outcome: ActivationOutcome,
) -> Result<Option<(AppendResult, SessionState)>, &'static str> {
    if state.active_activation.is_none() {
        return Ok(None);
    }
    Ok(Some(
        append_runtime_event(
            store,
            owner,
            session_id,
            format!("activation-finish:{activation_id}"),
            format!("activation-finish-event:{activation_id}"),
            SessionEvent::ActivationFinished {
                activation_id,
                outcome,
                finished_at_ms: current_time_ms(),
            },
        )
        .await?,
    ))
}

async fn prepare_model_round(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    input: ModelRoundInput<'_>,
) -> Result<
    (
        Vec<(AppendResult, SessionState)>,
        SessionState,
        PreparedRequestIdentity,
    ),
    &'static str,
> {
    let ModelRoundInput {
        state,
        selection,
        request,
        round_identity,
        maximum_attempts,
    } = input;
    let mut commits = Vec::new();
    let mut current = state.clone();
    let activation = current
        .active_activation
        .as_ref()
        .ok_or("model_round_without_activation")?;
    let activation_id = activation.activation_id.clone();
    let needs_new_round = current.active_model_round.as_ref().is_none_or(|round| {
        round
            .attempt
            .as_ref()
            .is_some_and(|attempt| attempt.outcome == crate::domain::ModelAttemptOutcome::Completed)
    });
    if needs_new_round {
        let round_id = stable_digest(
            "model-round",
            &format!(
                "{}:{}:{}",
                activation_id, round_identity, current.stream_version
            ),
        );
        let delivery_through_queue_id = current
            .delivery_ack
            .saturating_add(current.delivery_queue.len() as u64)
            .max(1);
        let append = append_runtime_event(
            store.clone(),
            owner.clone(),
            session_id.clone(),
            format!("model-round:{round_id}"),
            format!("model-round-event:{round_id}"),
            SessionEvent::ModelRoundStarted {
                activation_id: activation_id.clone(),
                round_id: round_id.clone(),
                delivery_through_queue_id,
                started_at_ms: current_time_ms(),
            },
        )
        .await?;
        current = append.1.clone();
        commits.push(append);
    }
    let round = current
        .active_model_round
        .as_ref()
        .ok_or("model_round_missing")?;
    let round_id = round.round_id.clone();
    let request_id = if let Some(prepared) = &round.request {
        prepared.request_id.clone()
    } else {
        let request_id = stable_digest("model-request", &format!("{}:{}", activation_id, round_id));
        let tool_schema = request
            .tools
            .iter()
            .map(|tool| {
                json!({
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                })
            })
            .collect::<Vec<_>>();
        let envelope_json = json!({
            "transcript": request.transcript,
            "tools": tool_schema,
            "provider": selection.provider,
            "model": selection.model,
        });
        let envelope = DurablePayload::inline(envelope_json).map_err(|_| "model_envelope")?;
        let provider_execution_fingerprint = stable_digest(
            "provider-execution",
            &serde_json::to_string(&selection.provider_execution)
                .map_err(|_| "provider_fingerprint")?,
        );
        let prompt_fingerprint = stable_digest(
            "model-prompt",
            &serde_json::to_string(&request.transcript).map_err(|_| "prompt_fingerprint")?,
        );
        let tool_schema_fingerprint = stable_digest(
            "model-tools",
            &serde_json::to_string(&tool_schema).map_err(|_| "tool_fingerprint")?,
        );
        let request_fingerprint = stable_digest(
            "model-request",
            &format!(
                "{provider_execution_fingerprint}:{prompt_fingerprint}:{tool_schema_fingerprint}"
            ),
        );
        let append = append_runtime_event(
            store.clone(),
            owner.clone(),
            session_id.clone(),
            format!("model-request:{request_id}"),
            format!("model-request-event:{request_id}"),
            SessionEvent::ModelRequestPrepared {
                activation_id: activation_id.clone(),
                round_id: round_id.clone(),
                request_id: request_id.clone(),
                request_fingerprint: request_fingerprint.clone(),
                provider_execution_fingerprint,
                prompt_fingerprint,
                tool_schema_fingerprint,
                envelope,
                maximum_attempts,
                minimum_auth_revision: selection.auth_revision,
            },
        )
        .await?;
        current = append.1.clone();
        commits.push(append);
        request_id
    };
    let round = current
        .active_model_round
        .as_ref()
        .ok_or("model_round_missing_after_prepare")?;
    let attempt_number = round
        .retry
        .as_ref()
        .map(|schedule| schedule.next_attempt_number)
        .unwrap_or(1);
    let attempt_id = round
        .retry
        .as_ref()
        .map(|schedule| schedule.next_attempt_id.clone())
        .unwrap_or_else(|| stable_digest("model-attempt", &format!("{request_id}:1")));
    if round.attempt.is_none() {
        let append = append_runtime_event(
            store,
            owner,
            session_id,
            format!("model-attempt-start:{request_id}:{attempt_number}"),
            format!("model-attempt-start-event:{request_id}:{attempt_number}"),
            SessionEvent::ModelAttemptStarted {
                activation_id: activation_id.clone(),
                round_id: round_id.clone(),
                request_id: request_id.clone(),
                attempt_id: attempt_id.clone(),
                attempt_number,
                auth_revision: selection.auth_revision,
                started_at_ms: current_time_ms(),
            },
        )
        .await?;
        current = append.1.clone();
        commits.push(append);
    }
    Ok((
        commits,
        current,
        PreparedRequestIdentity {
            activation_id,
            round_id,
            request_id,
            maximum_attempts,
            attempt_id,
            attempt_number,
        },
    ))
}

async fn append_model_lifecycle_failure(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    input: ModelFailureInput<'_>,
) -> Result<(AppendResult, SessionState), &'static str> {
    let ModelFailureInput {
        identity,
        attempt_id,
        attempt_number,
        error_class,
        retryable,
    } = input;
    let append = append_runtime_event(
        store,
        owner,
        session_id,
        format!(
            "model-attempt-failed:{}:{attempt_number}",
            identity.request_id
        ),
        format!(
            "model-attempt-failed-event:{}:{attempt_number}",
            identity.request_id
        ),
        SessionEvent::ModelAttemptFailedFact {
            activation_id: identity.activation_id.clone(),
            round_id: identity.round_id.clone(),
            request_id: identity.request_id.clone(),
            attempt_id: attempt_id.to_owned(),
            attempt_number,
            error_class: error_class.to_owned(),
            retryable,
        },
    )
    .await?;
    Ok(append)
}

async fn append_model_attempts_exhausted(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    identity: &PreparedRequestIdentity,
    attempt_id: &str,
    attempt_number: u32,
) -> Result<(AppendResult, SessionState), &'static str> {
    let command_id = format!("model-attempts-exhausted:{}", identity.request_id);
    let event_id = format!("model-attempts-exhausted-event:{}", identity.request_id);
    let activation_id = identity.activation_id.clone();
    let round_id = identity.round_id.clone();
    let request_id = identity.request_id.clone();
    let maximum_attempts = identity.maximum_attempts;
    let attempt_id = attempt_id.to_owned();
    tokio::task::spawn_blocking(move || {
        let matches_fact = |state: &SessionState| {
            state
                .last_model_attempts_exhausted
                .as_ref()
                .is_some_and(|fact| {
                    fact.activation_id == activation_id
                        && fact.round_id == round_id
                        && fact.request_id == request_id
                        && fact.attempt_id == attempt_id
                        && fact.attempt_number == attempt_number
                        && fact.maximum_attempts == maximum_attempts
                })
        };
        for _ in 0..16 {
            let state = store
                .rehydrate_owned(&owner, &session_id)
                .map_err(|_| "model_exhaustion_rehydrate")?;
            if matches_fact(&state) {
                return Ok((replayed_append(&session_id, &command_id, &state), state));
            }
            let fact = crate::domain::ModelAttemptsExhaustedFact {
                activation_id: activation_id.clone(),
                round_id: round_id.clone(),
                request_id: request_id.clone(),
                attempt_id: attempt_id.clone(),
                attempt_number,
                maximum_attempts,
                finished_at_ms: current_time_ms(),
            };
            match store.append_owned(
                &owner,
                &session_id,
                state.stream_version,
                &command_id,
                &[EventDraft::new(
                    event_id.clone(),
                    SessionEvent::ModelAttemptsExhausted { fact },
                )],
            ) {
                Ok(append) => {
                    let state = store
                        .rehydrate_owned(&owner, &session_id)
                        .map_err(|_| "model_exhaustion_rehydrate")?;
                    return Ok((append, state));
                }
                Err(StoreError::OptimisticConcurrency { .. }) => continue,
                Err(StoreError::CommandIdempotencyConflict { .. }) => {
                    let state = store
                        .rehydrate_owned(&owner, &session_id)
                        .map_err(|_| "model_exhaustion_rehydrate")?;
                    if matches_fact(&state) {
                        return Ok((replayed_append(&session_id, &command_id, &state), state));
                    }
                    return Err("model_exhaustion_conflict");
                }
                Err(_) => return Err("model_exhaustion_append"),
            }
        }
        Err("model_exhaustion_concurrency")
    })
    .await
    .map_err(|_| "model_exhaustion_join")?
}

fn model_error_class(error: &ModelError) -> &'static str {
    match error {
        ModelError::Unavailable => "provider_unavailable",
        ModelError::InvalidSelection => "invalid_selection",
        ModelError::AuthReplicaUnavailable => "auth_replica_unavailable",
        ModelError::ProviderFailed => "provider_failed",
        ModelError::InvalidToolArguments => "invalid_tool_arguments",
    }
}

fn terminal_model_error(error: &ModelError) -> (ModelAttemptErrorClass, &'static str) {
    match error {
        ModelError::InvalidToolArguments => (
            ModelAttemptErrorClass::InvalidToolArguments,
            "model supplied invalid tool arguments",
        ),
        _ => (
            ModelAttemptErrorClass::AuthReplicaUnavailable,
            "credential replica unavailable",
        ),
    }
}

fn terminal_model_error_class(error_class: &str) -> (ModelAttemptErrorClass, &'static str) {
    match error_class {
        "invalid_tool_arguments" => (
            ModelAttemptErrorClass::InvalidToolArguments,
            "model supplied invalid tool arguments",
        ),
        _ => (
            ModelAttemptErrorClass::AuthReplicaUnavailable,
            "credential replica unavailable",
        ),
    }
}

fn retry_delay_ms(base: Duration, maximum: Duration, attempt_number: u32) -> u64 {
    let exponent = attempt_number.saturating_sub(1).min(16);
    let multiplier = 1u64 << exponent;
    base.as_millis()
        .saturating_mul(multiplier as u128)
        .min(maximum.as_millis())
        .try_into()
        .unwrap_or(u64::MAX)
}

async fn materialize_boundary(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    state: crate::domain::SessionState,
) -> Result<(Option<AppendResult>, crate::domain::SessionState), &'static str> {
    tokio::task::spawn_blocking(move || {
        materialize_boundary_blocking(&*store, &owner, &session_id, state)
    })
    .await
    .map_err(|_| "materialize_join")?
}

fn materialize_boundary_blocking(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    mut state: crate::domain::SessionState,
) -> Result<(Option<AppendResult>, crate::domain::SessionState), &'static str> {
    for _ in 0..16 {
        let Some(last_delivery) = state.delivery_queue.last() else {
            return Ok((None, state));
        };
        let through_queue_id = last_delivery.queue_id;
        let mut drafts = Vec::new();
        for delivery in &state.delivery_queue {
            if delivery.materialized_message_id.is_some() {
                continue;
            }
            let candidate = materialize_message(delivery)?;
            // Callback completion atomically appends its terminal Tool
            // transcript message together with the wakeable delivery.  The
            // delivery acknowledges that existing message; it must not try
            // to materialize a second Runtime row with the same ID.
            let message = state
                .transcript
                .iter()
                .find(|existing| {
                    existing.message_id == candidate.message_id
                        && existing.source_queue_id == Some(delivery.queue_id)
                })
                .cloned()
                .unwrap_or(candidate);
            drafts.push(EventDraft::new(
                materialization_event_id(delivery),
                SessionEvent::DeliveryMaterialized {
                    queue_id: delivery.queue_id,
                    message,
                },
            ));
        }
        drafts.push(EventDraft::new(
            acknowledgement_event_id(through_queue_id),
            SessionEvent::DeliveryAcknowledged { through_queue_id },
        ));
        let command_id = format!("delivery-boundary:v1:{through_queue_id}");
        match store.append_owned(
            owner,
            session_id,
            state.stream_version,
            &command_id,
            &drafts,
        ) {
            Ok(append) => {
                let state = store
                    .rehydrate_owned(owner, session_id)
                    .map_err(|_| "materialize_rehydrate")?;
                return Ok((Some(append), state));
            }
            Err(StoreError::OptimisticConcurrency { .. }) => {
                state = store
                    .rehydrate_owned(owner, session_id)
                    .map_err(|_| "materialize_rehydrate")?;
            }
            Err(error) => {
                tracing::warn!(session_id, ?error, "delivery materialization append failed");
                return Err("materialize_append");
            }
        }
    }
    Err("materialize_concurrency")
}

fn materialize_message(
    delivery: &crate::domain::QueuedDelivery,
) -> Result<TranscriptMessage, &'static str> {
    let role = match delivery.kind {
        DeliveryKind::UserInput => TranscriptRole::User,
        // A background tool completion is a wakeable runtime notification,
        // not a second ordinary `Tool` result for the same model call.  The
        // foreground `async_running` message remains the sole Tool transcript
        // entry; this notification carries the terminal payload into the
        // next activation without duplicating that tool result.
        DeliveryKind::RuntimeNotification => TranscriptRole::Runtime,
    };
    let DurablePayload::Inline(payload) = &delivery.payload else {
        return Err("delivery_payload");
    };
    let object = payload.value().as_object().ok_or("delivery_payload")?;
    let message_id = object
        .get("message_id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("delivery_message_id")?;
    let content = object
        .get("content")
        .and_then(serde_json::Value::as_str)
        .ok_or("delivery_content")?;
    let message_dedupe_key = object
        .get("message_dedupe_key")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| delivery.dedupe_key.clone());
    let tool_call_id = None;
    Ok(TranscriptMessage {
        message_id: message_id.to_owned(),
        role,
        content: content.to_owned(),
        tool_call_id,
        tool_calls: Vec::new(),
        dedupe_key: Some(message_dedupe_key),
        source_queue_id: Some(delivery.queue_id),
    })
}

async fn append_tool_batch(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    input: ToolBatchInput,
) -> Result<(AppendResult, SessionState), &'static str> {
    tokio::task::spawn_blocking(move || {
        append_tool_batch_blocking(&*store, &owner, &session_id, &input)
    })
    .await
    .map_err(|_| "tool_batch_join")?
}

fn append_tool_batch_blocking(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    input: &ToolBatchInput,
) -> Result<(AppendResult, SessionState), &'static str> {
    let ToolBatchInput {
        round_identity,
        assistant_content,
        definitions,
        callback_plans,
        tool_calls,
    } = input;
    let identity = assistant_identity(owner, session_id, round_identity);
    let command_id = format!("model-tool-batch-command:v1:{identity}");
    let assistant_message = TranscriptMessage {
        message_id: format!("assistant-tool:v1:{identity}"),
        role: TranscriptRole::Assistant,
        content: assistant_content.to_owned(),
        tool_call_id: None,
        tool_calls: tool_calls.to_vec(),
        dedupe_key: Some(command_id.clone()),
        source_queue_id: None,
    };
    for _ in 0..16 {
        let state = store
            .rehydrate_owned(owner, session_id)
            .map_err(|_| "tool_batch_rehydrate")?;
        if let Some(existing) = state
            .transcript
            .iter()
            .find(|message| message.message_id == assistant_message.message_id)
        {
            if existing != &assistant_message {
                return Err("tool_batch_conflict");
            }
            for call in tool_calls
                .iter()
                .filter(|call| call.tool_name != WAIT_FOR_TOOL_NAME)
            {
                let Some(record) = state.async_tool_calls.get(&call.tool_call_id) else {
                    return Err("tool_batch_missing_intent");
                };
                if record.tool_name != call.tool_name || record.input != call.input {
                    return Err("tool_batch_conflict");
                }
            }
            return Ok((replayed_append(session_id, &command_id, &state), state));
        }
        let started_at_ms = current_time_ms();
        let definitions = definitions
            .iter()
            .map(|definition| (definition.name.as_str(), definition))
            .collect::<HashMap<_, _>>();
        let callback_plans = callback_plans
            .iter()
            .map(|plan| (plan.tool_call_id.as_str(), plan))
            .collect::<HashMap<_, _>>();
        let mut drafts = vec![EventDraft::new(
            format!("model-tool-batch-assistant-event:v1:{identity}"),
            SessionEvent::MessageAppended {
                message: assistant_message.clone(),
                wake_wait: false,
            },
        )];
        for call in tool_calls
            .iter()
            .filter(|call| call.tool_name != WAIT_FOR_TOOL_NAME)
        {
            let definition = definitions.get(call.tool_name.as_str());
            let record = AsyncToolCallRecord {
                tool_call_id: call.tool_call_id.clone(),
                tool_name: call.tool_name.clone(),
                input: call.input.clone(),
                status: AsyncToolStatus::Planned,
                started_at_ms,
                auto_wait_seconds: definition.and_then(|definition| definition.auto_wait_seconds),
                completion_mode: definition
                    .map(|definition| definition.completion_mode.clone())
                    .unwrap_or(CompletionMode::ProcessLocal),
                progress: None,
                result: None,
                error: None,
                cancel_reason: None,
                completed_at_ms: None,
            };
            drafts.push(EventDraft::new(
                format!(
                    "tool-started:v1:{}",
                    stable_digest("tool-started", &format!("{identity}:{}", call.tool_call_id))
                ),
                SessionEvent::AsyncToolCallStarted { record },
            ));
            if definition.is_some_and(|definition| {
                definition.completion_mode == CompletionMode::ExternalCallback
            }) {
                let Some(plan) = callback_plans.get(call.tool_call_id.as_str()) else {
                    return Err("tool_batch_callback_plan");
                };
                drafts.push(EventDraft::new(
                    format!("tool-callback-planned:v1:{}", plan.callback_id),
                    SessionEvent::AsyncToolCallCallbackPlanned {
                        binding: plan.binding.clone(),
                    },
                ));
            }
            drafts.push(EventDraft::new(
                format!(
                    "tool-running:v1:{}",
                    stable_digest("tool-running", &format!("{identity}:{}", call.tool_call_id))
                ),
                SessionEvent::AsyncToolCallRunning {
                    tool_call_id: call.tool_call_id.clone(),
                },
            ));
        }
        match store.append_owned(
            owner,
            session_id,
            state.stream_version,
            &command_id,
            &drafts,
        ) {
            Ok(append) => {
                let state = store
                    .rehydrate_owned(owner, session_id)
                    .map_err(|_| "tool_batch_rehydrate")?;
                return Ok((append, state));
            }
            Err(StoreError::OptimisticConcurrency { .. }) => continue,
            Err(_) => return Err("tool_batch_append"),
        }
    }
    Err("tool_batch_concurrency")
}

async fn append_tool_results(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    batch_identity: String,
    tool_calls: Vec<ToolCall>,
    results: Vec<Result<ToolExecutionResult, ToolError>>,
) -> Result<(AppendResult, SessionState), &'static str> {
    tokio::task::spawn_blocking(move || {
        append_tool_results_blocking(
            &*store,
            &owner,
            &session_id,
            &batch_identity,
            &tool_calls,
            &results,
        )
    })
    .await
    .map_err(|_| "tool_results_join")?
}

fn append_tool_results_blocking(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    batch_identity: &str,
    tool_calls: &[ToolCall],
    results: &[Result<ToolExecutionResult, ToolError>],
) -> Result<(AppendResult, SessionState), &'static str> {
    let result_message_ids = tool_calls
        .iter()
        .map(|call| tool_result_message_id(batch_identity, &call.tool_call_id))
        .collect::<Vec<_>>();
    for _ in 0..16 {
        let state = store
            .rehydrate_owned(owner, session_id)
            .map_err(|_| "tool_results_rehydrate")?;
        let all_messages_present = result_message_ids.iter().all(|message_id| {
            state
                .transcript
                .iter()
                .any(|message| &message.message_id == message_id)
        });
        if all_messages_present {
            return Ok((
                replayed_append(
                    session_id,
                    &format!("tool-results-command:v1:{batch_identity}"),
                    &state,
                ),
                state,
            ));
        }

        let mut drafts = Vec::with_capacity(tool_calls.len() * 2 + 1);
        let mut final_wait = None;
        let mut saw_wait = false;
        let mut async_tool_ids = Vec::new();
        let mut async_timeout_seconds = None;
        for (index, call) in tool_calls.iter().enumerate() {
            let result = results.get(index).ok_or("tool_results_count")?;
            // External callbacks own the terminal transition.  Even if the
            // adapter HTTP request returned a response inside the foreground
            // window (or completed concurrently with the callback), never
            // turn that response into a second ordinary tool result.  A
            // running callback contributes the one automatic wait; a
            // callback already terminal leaves its durable Tool message to
            // drive the next boundary.
            if call.tool_name != WAIT_FOR_TOOL_NAME
                && state
                    .async_tool_calls
                    .get(&call.tool_call_id)
                    .is_some_and(|record| {
                        record.completion_mode == CompletionMode::ExternalCallback
                    })
            {
                if let Some(record) = state.async_tool_calls.get(&call.tool_call_id) {
                    if !record.status.is_terminal() {
                        async_timeout_seconds =
                            async_timeout_seconds.or(record.auto_wait_seconds.or_else(|| {
                                result
                                    .as_ref()
                                    .ok()
                                    .and_then(|value| value.auto_wait_seconds)
                            }));
                        async_tool_ids.push(call.tool_call_id.clone());
                    }
                }
                continue;
            }
            if call.tool_name != WAIT_FOR_TOOL_NAME
                && matches!(result, Ok(result) if result.completion == ToolExecutionCompletion::AsyncRunning)
            {
                if let Ok(result) = result {
                    async_timeout_seconds = async_timeout_seconds.or(result.auto_wait_seconds);
                    let event_id = format!("tool-result-event:v1:{batch_identity}:{index}");
                    drafts.push(EventDraft::new(
                        event_id.clone(),
                        SessionEvent::MessageAppended {
                            message: TranscriptMessage {
                                message_id: result_message_ids[index].clone(),
                                role: TranscriptRole::Tool,
                                content: result.content.clone(),
                                tool_call_id: Some(call.tool_call_id.clone()),
                                tool_calls: Vec::new(),
                                dedupe_key: Some(event_id),
                                source_queue_id: None,
                            },
                            wake_wait: false,
                        },
                    ));
                }
                async_tool_ids.push(call.tool_call_id.clone());
                continue;
            }
            let content = if call.tool_name == WAIT_FOR_TOOL_NAME {
                saw_wait = true;
                final_wait = parse_wait(call).ok();
                match final_wait {
                    Some(_) => "wait_for accepted".to_owned(),
                    None => "invalid_request: wait_for input is invalid".to_owned(),
                }
            } else {
                match result {
                    Ok(result) => result.content.clone(),
                    Err(_) => "tool execution failed".to_owned(),
                }
            };
            let message_id = &result_message_ids[index];
            let event_id = format!("tool-result-event:v1:{batch_identity}:{index}");
            drafts.push(EventDraft::new(
                event_id.clone(),
                SessionEvent::MessageAppended {
                    message: TranscriptMessage {
                        message_id: message_id.clone(),
                        role: TranscriptRole::Tool,
                        content,
                        tool_call_id: Some(call.tool_call_id.clone()),
                        tool_calls: Vec::new(),
                        dedupe_key: Some(event_id.clone()),
                        source_queue_id: None,
                    },
                    wake_wait: false,
                },
            ));
            if call.tool_name != WAIT_FOR_TOOL_NAME {
                match result {
                    Ok(result) if !result.is_error => {
                        let payload = match result.result.clone() {
                            Some(payload) => payload,
                            None => DurablePayload::inline(json!({
                                "content": result.content,
                            }))
                            .map_err(|_| "tool_result_payload")?,
                        };
                        drafts.push(EventDraft::new(
                            format!("tool-completed:v1:{batch_identity}:{index}"),
                            SessionEvent::AsyncToolCallCompleted {
                                tool_call_id: call.tool_call_id.clone(),
                                result: payload,
                                completed_at_ms: current_time_ms(),
                            },
                        ));
                    }
                    _ => drafts.push(EventDraft::new(
                        format!("tool-failed:v1:{batch_identity}:{index}"),
                        SessionEvent::AsyncToolCallFailed {
                            tool_call_id: call.tool_call_id.clone(),
                            error: DomainToolError {
                                class: "tool_execution_failed".to_owned(),
                                message: "tool execution failed".to_owned(),
                            },
                            completed_at_ms: current_time_ms(),
                        },
                    )),
                }
            }
        }
        if saw_wait {
            if let Some(wait) = final_wait {
                drafts.push(EventDraft::new(
                    format!("wait-set:v1:{batch_identity}"),
                    SessionEvent::WaitSet { wait },
                ));
            }
        }
        if !async_tool_ids.is_empty() {
            if let Some(timeout_seconds) = async_timeout_seconds {
                let wait = ActiveWait {
                    wait_id: stable_digest("auto-wait", batch_identity),
                    reason: "waiting for asynchronous tool completion".to_owned(),
                    timeout_seconds,
                    deadline_ms: current_time_ms()
                        .checked_add(i64::from(timeout_seconds) * 1_000)
                        .ok_or("auto wait deadline")?,
                    source: WaitSource::AutoToolBatch,
                    tool_call_ids: async_tool_ids,
                };
                drafts.push(EventDraft::new(
                    format!("wait-set:auto:v1:{batch_identity}"),
                    SessionEvent::WaitSet { wait: wait.clone() },
                ));
                drafts.push(EventDraft::new(
                    format!("wait-timer:auto:v1:{batch_identity}"),
                    SessionEvent::WaitTimerScheduled {
                        timer: crate::domain::WaitTimerIntent {
                            wait_id: wait.wait_id,
                            deadline_ms: wait.deadline_ms,
                        },
                    },
                ));
            }
        }
        if drafts.is_empty() {
            return Ok((
                replayed_append(
                    session_id,
                    &format!("tool-results-command:v1:{batch_identity}"),
                    &state,
                ),
                state,
            ));
        }
        let command_id = format!("tool-results-command:v1:{batch_identity}");
        match store.append_owned(
            owner,
            session_id,
            state.stream_version,
            &command_id,
            &drafts,
        ) {
            Ok(append) => {
                let state = store
                    .rehydrate_owned(owner, session_id)
                    .map_err(|_| "tool_results_rehydrate")?;
                return Ok((append, state));
            }
            Err(StoreError::OptimisticConcurrency { .. }) => continue,
            Err(_) => return Err("tool_results_append"),
        }
    }
    Err("tool_results_concurrency")
}

fn append_background_tool_result_blocking(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    batch_identity: &str,
    call: &ToolCall,
    result: Result<ToolExecutionResult, ToolError>,
) -> Result<Option<(AppendResult, SessionState)>, &'static str> {
    let (is_failure, content, payload, error) = match result {
        Ok(result) if result.completion == ToolExecutionCompletion::AsyncRunning => {
            return Ok(None)
        }
        Ok(result) if !result.is_error => {
            let payload = match result.result {
                Some(payload) => payload,
                None => DurablePayload::inline(json!({
                    "content": result.content,
                }))
                .map_err(|_| "background_tool_payload")?,
            };
            (false, result.content, payload, None)
        }
        Ok(_) | Err(_) => (
            true,
            "tool execution failed".to_owned(),
            DurablePayload::inline(json!({
                "content": "tool execution failed",
            }))
            .map_err(|_| "background_tool_payload")?,
            Some(DomainToolError {
                class: "tool_execution_failed".to_owned(),
                message: "tool execution failed".to_owned(),
            }),
        ),
    };
    let message_id = format!(
        "tool-async-result:v1:{}",
        stable_digest(
            "tool-async-result",
            &format!("{batch_identity}:{}", call.tool_call_id),
        )
    );
    let delivery_dedupe_key = format!("tool-async-delivery:{batch_identity}:{}", call.tool_call_id);
    let command_id = format!(
        "tool-async-result-command:v1:{batch_identity}:{}",
        call.tool_call_id
    );
    let result_value = serde_json::to_value(&payload).map_err(|_| "background_tool_payload")?;
    for _ in 0..16 {
        let state = store
            .rehydrate_owned(owner, session_id)
            .map_err(|_| "background_tool_rehydrate")?;
        let Some(record) = state.async_tool_calls.get(&call.tool_call_id) else {
            return Ok(None);
        };
        if record.status != AsyncToolStatus::Running {
            return Ok(None);
        }
        let queue_id = state
            .delivery_ack
            .checked_add(state.delivery_queue.len() as u64 + 1)
            .ok_or("background_tool_queue_id")?;
        let completed_at_ms = current_time_ms();
        let mut drafts = Vec::with_capacity(2);
        if is_failure {
            drafts.push(EventDraft::new(
                format!(
                    "tool-async-failed:v1:{batch_identity}:{}",
                    call.tool_call_id
                ),
                SessionEvent::AsyncToolCallFailed {
                    tool_call_id: call.tool_call_id.clone(),
                    error: error.clone().ok_or("background_tool_error")?,
                    completed_at_ms,
                },
            ));
        } else {
            drafts.push(EventDraft::new(
                format!(
                    "tool-async-completed:v1:{batch_identity}:{}",
                    call.tool_call_id
                ),
                SessionEvent::AsyncToolCallCompleted {
                    tool_call_id: call.tool_call_id.clone(),
                    result: payload.clone(),
                    completed_at_ms,
                },
            ));
        }
        let delivery_payload = DurablePayload::inline(json!({
            "message_id": message_id.clone(),
            "content": content.clone(),
            "tool_call_id": call.tool_call_id.clone(),
            "status": if is_failure { "failed" } else { "completed" },
            "result": if is_failure { Value::Null } else { result_value.clone() },
            "error": if is_failure {
                serde_json::to_value(error.clone()).unwrap_or(Value::Null)
            } else {
                Value::Null
            },
        }))
        .map_err(|_| "background_tool_delivery")?;
        drafts.push(EventDraft::new(
            format!(
                "tool-async-delivery:v1:{batch_identity}:{}",
                call.tool_call_id
            ),
            SessionEvent::DeliveryQueued {
                delivery: crate::domain::QueuedDelivery {
                    queue_id,
                    delivery_id: format!(
                        "tool-async-delivery:{batch_identity}:{}",
                        call.tool_call_id
                    ),
                    kind: DeliveryKind::RuntimeNotification,
                    payload: delivery_payload,
                    dedupe_key: delivery_dedupe_key.clone(),
                    wake: true,
                    created_at_ms: Some(completed_at_ms),
                    source_tool_call_id: Some(call.tool_call_id.clone()),
                    materialized_message_id: None,
                },
            },
        ));
        match store.append_owned(
            owner,
            session_id,
            state.stream_version,
            &command_id,
            &drafts,
        ) {
            Ok(append) => {
                let state = store
                    .rehydrate_owned(owner, session_id)
                    .map_err(|_| "background_tool_rehydrate")?;
                return Ok(Some((append, state)));
            }
            Err(StoreError::OptimisticConcurrency { .. }) => continue,
            Err(StoreError::CommandIdempotencyConflict { .. })
            | Err(StoreError::EventIdempotencyConflict { .. }) => continue,
            Err(_) => return Err("background_tool_append"),
        }
    }
    Err("background_tool_concurrency")
}

fn parse_wait(call: &ToolCall) -> Result<ActiveWait, &'static str> {
    let DurablePayload::Inline(payload) = &call.input else {
        return Err("wait input");
    };
    let object = payload.value().as_object().ok_or("wait input")?;
    if object
        .keys()
        .any(|key| key != "reason" && key != "timeout_seconds")
    {
        return Err("wait input");
    }
    let reason = object
        .get("reason")
        .and_then(Value::as_str)
        .filter(|reason| !reason.is_empty())
        .ok_or("wait reason")?;
    let timeout_seconds = object
        .get("timeout_seconds")
        .map(|value| value.as_u64().ok_or("wait timeout"))
        .transpose()?
        .unwrap_or(60);
    let timeout_seconds = u32::try_from(timeout_seconds).map_err(|_| "wait timeout")?;
    if !(WAIT_MIN_SECONDS..=WAIT_MAX_SECONDS).contains(&timeout_seconds) {
        return Err("wait timeout");
    }
    let deadline_ms = current_time_ms()
        .checked_add(i64::from(timeout_seconds) * 1_000)
        .ok_or("wait deadline")?;
    Ok(ActiveWait {
        wait_id: stable_digest("wait", &call.tool_call_id),
        reason: reason.to_owned(),
        timeout_seconds,
        deadline_ms,
        source: WaitSource::WaitFor,
        tool_call_ids: vec![call.tool_call_id.clone()],
    })
}

fn tool_result_message_id(batch_identity: &str, tool_call_id: &str) -> String {
    format!(
        "tool-result:v1:{}",
        stable_digest("tool-result", &format!("{batch_identity}:{tool_call_id}"))
    )
}

fn replayed_append(session_id: &str, command_id: &str, state: &SessionState) -> AppendResult {
    AppendResult {
        stream_id: session_id.to_owned(),
        command_id: command_id.to_owned(),
        events: Vec::new(),
        stream_version: state.stream_version,
        replayed: true,
    }
}

fn materialization_event_id(delivery: &crate::domain::QueuedDelivery) -> String {
    format!(
        "delivery-materialized:v1:{}",
        stable_digest("materialized", &delivery.delivery_id)
    )
}

fn acknowledgement_event_id(queue_id: u64) -> String {
    format!("delivery-acknowledged:v1:{queue_id}")
}

async fn append_assistant(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    trigger_message_id: String,
    content: String,
) -> Result<(AppendResult, SessionState), &'static str> {
    tokio::task::spawn_blocking(move || {
        append_assistant_blocking(&*store, &owner, &session_id, &trigger_message_id, &content)
    })
    .await
    .map_err(|_| "assistant_join")?
}

fn append_assistant_blocking(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    trigger_message_id: &str,
    content: &str,
) -> Result<(AppendResult, SessionState), &'static str> {
    let identity = assistant_identity(owner, session_id, trigger_message_id);
    let command_id = format!("model-assistant-command:v1:{identity}");
    let event_id = format!("model-assistant-event:v1:{identity}");
    let message = TranscriptMessage {
        message_id: format!("assistant:v1:{identity}"),
        role: TranscriptRole::Assistant,
        content: content.to_owned(),
        tool_call_id: None,
        tool_calls: Vec::new(),
        dedupe_key: Some(command_id.clone()),
        source_queue_id: None,
    };

    for _ in 0..16 {
        let state = store
            .rehydrate_owned(owner, session_id)
            .map_err(|_| "assistant_rehydrate")?;
        if let Some(existing) = state
            .transcript
            .iter()
            .find(|existing| existing.message_id == message.message_id)
        {
            if existing != &message {
                return Err("assistant_conflict");
            }
            return Ok((
                AppendResult {
                    stream_id: session_id.to_owned(),
                    command_id,
                    events: Vec::new(),
                    stream_version: state.stream_version,
                    replayed: true,
                },
                state,
            ));
        }
        // A final assistant result with no queued delivery also closes its
        // activation.  Keep that lifecycle fact and the public assistant
        // message in one optimistic transaction, with the assistant event
        // last so its SSE version is the terminal stream version observed by
        // a subsequent GET.  If a delivery races this rehydrate, the OCC
        // retry below re-evaluates the queue and preserves the next-round
        // steering path instead of closing the activation.
        let mut drafts = Vec::with_capacity(2);
        if state.delivery_queue.is_empty() {
            if let Some(activation) = state.active_activation.as_ref() {
                drafts.push(EventDraft::new(
                    format!("model-assistant-finished-event:v1:{identity}"),
                    SessionEvent::ActivationFinished {
                        activation_id: activation.activation_id.clone(),
                        outcome: ActivationOutcome::Finished,
                        finished_at_ms: current_time_ms(),
                    },
                ));
            }
        }
        drafts.push(EventDraft::new(
            event_id.clone(),
            SessionEvent::MessageAppended {
                message: message.clone(),
                wake_wait: false,
            },
        ));
        match store.append_owned(
            owner,
            session_id,
            state.stream_version,
            &command_id,
            &drafts,
        ) {
            Ok(append) => {
                let state = store
                    .rehydrate_owned(owner, session_id)
                    .map_err(|_| "assistant_rehydrate")?;
                return Ok((append, state));
            }
            Err(StoreError::OptimisticConcurrency { .. }) => continue,
            Err(_) => return Err("assistant_append"),
        }
    }
    Err("assistant_concurrency")
}

fn assistant_identity(owner: &SessionOwner, session_id: &str, trigger_message_id: &str) -> String {
    stable_digest(
        "assistant",
        &format!(
            "{}\u{0}{}\u{0}{}\u{0}{}",
            owner.authority_id, owner.subject, session_id, trigger_message_id
        ),
    )
}

fn model_failure_identity(
    owner: &SessionOwner,
    session_id: &str,
    trigger_message_id: &str,
) -> String {
    stable_digest(
        "model-attempt-failed",
        &format!(
            "{}\u{0}{}\u{0}{}\u{0}{}\u{0}auth_replica_unavailable",
            owner.authority_id, owner.subject, session_id, trigger_message_id
        ),
    )
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

fn canonical_callback_payload(payload: &Value) -> Result<String, RuntimeCommandError> {
    let mut bytes = Vec::new();
    write_canonical_callback_json(payload, &mut bytes)?;
    String::from_utf8(bytes).map_err(|_| RuntimeCommandError::Invalid("callback_payload"))
}

fn write_canonical_callback_json(
    value: &Value,
    output: &mut Vec<u8>,
) -> Result<(), RuntimeCommandError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => output.extend_from_slice(
            &serde_json::to_vec(value)
                .map_err(|_| RuntimeCommandError::Invalid("callback_payload"))?,
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_callback_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
            output.push(b'{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    &serde_json::to_vec(key)
                        .map_err(|_| RuntimeCommandError::Invalid("callback_payload"))?,
                );
                output.push(b':');
                write_canonical_callback_json(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn complete_external_callback_blocking(
    store: &dyn EventStore,
    callback_id: &str,
    bearer: &str,
    payload: Value,
) -> Result<CallbackCompletion, RuntimeCommandError> {
    if callback_id.is_empty() || bearer.is_empty() {
        return Err(RuntimeCommandError::NotFound);
    }
    let (is_failure, result, error) = parse_callback_payload(&payload)?;
    let canonical_payload = canonical_callback_payload(&payload)?;
    let payload_fingerprint = stable_digest("callback-payload", &canonical_payload);
    let bearer_fingerprint = stable_digest("callback-bearer", bearer);

    for _ in 0..16 {
        let lookup = store
            .lookup_external_callback(callback_id)
            .map_err(|_| RuntimeCommandError::Backend)?
            .ok_or(RuntimeCommandError::NotFound)?;
        if !constant_time_equal(
            lookup.binding.bearer_fingerprint.as_bytes(),
            bearer_fingerprint.as_bytes(),
        ) {
            return Err(RuntimeCommandError::NotFound);
        }
        if let Some(existing) = &lookup.binding.payload_fingerprint {
            if existing == &payload_fingerprint {
                return Ok(CallbackCompletion::Replayed(callback_public_body(
                    lookup
                        .state
                        .async_tool_calls
                        .get(&lookup.binding.tool_call_id),
                )));
            }
            return Err(RuntimeCommandError::Conflict);
        }
        let Some(record) = lookup
            .state
            .async_tool_calls
            .get(&lookup.binding.tool_call_id)
        else {
            return Err(RuntimeCommandError::NotFound);
        };
        if record.status.is_terminal() {
            return Err(RuntimeCommandError::Conflict);
        }
        let result_payload = DurablePayload::inline(result.clone())
            .map_err(|_| RuntimeCommandError::Invalid("callback_result"))?;
        let event_prefix = format!("callback:{callback_id}:{payload_fingerprint}");
        let mut drafts = Vec::with_capacity(3);
        if is_failure {
            drafts.push(EventDraft::new(
                format!("{event_prefix}:failed"),
                SessionEvent::AsyncToolCallCallbackFailed {
                    callback_id: callback_id.to_owned(),
                    tool_call_id: lookup.binding.tool_call_id.clone(),
                    payload_fingerprint: payload_fingerprint.clone(),
                    error: error
                        .clone()
                        .ok_or(RuntimeCommandError::Invalid("callback_error"))?,
                    completed_at_ms: current_time_ms(),
                },
            ));
        } else {
            drafts.push(EventDraft::new(
                format!("{event_prefix}:completed"),
                SessionEvent::AsyncToolCallCallbackCompleted {
                    callback_id: callback_id.to_owned(),
                    tool_call_id: lookup.binding.tool_call_id.clone(),
                    payload_fingerprint: payload_fingerprint.clone(),
                    result: result_payload.clone(),
                    completed_at_ms: current_time_ms(),
                },
            ));
        }
        let message_id = format!(
            "tool-callback-result:v1:{}",
            stable_digest("callback-message", callback_id)
        );
        let content = if is_failure {
            error
                .as_ref()
                .map(|value| value.message.clone())
                .unwrap_or_else(|| "tool execution failed".to_owned())
        } else {
            result
                .get("content")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| result.to_string())
        };
        let queue_id = lookup
            .state
            .delivery_ack
            .saturating_add(lookup.state.delivery_queue.len() as u64)
            .saturating_add(1);
        let delivery_dedupe_key = format!("callback-delivery:{callback_id}");
        drafts.push(EventDraft::new(
            format!("{event_prefix}:message"),
            SessionEvent::MessageAppended {
                message: TranscriptMessage {
                    message_id,
                    role: TranscriptRole::Tool,
                    content: content.clone(),
                    tool_call_id: Some(lookup.binding.tool_call_id.clone()),
                    tool_calls: Vec::new(),
                    // Transcript and delivery facts have distinct dedupe
                    // identities.  Sharing the delivery key causes the
                    // reducer to treat the queued wakeable delivery as a
                    // duplicate after remembering the transcript message.
                    dedupe_key: Some(format!("callback-message:{callback_id}")),
                    source_queue_id: Some(queue_id),
                },
                wake_wait: true,
            },
        ));
        let delivery_payload = DurablePayload::inline(json!({
            "message_id": format!(
                "tool-callback-result:v1:{}",
                stable_digest("callback-message", callback_id)
            ),
            "message_dedupe_key": format!("callback-message:{callback_id}"),
            "content": content.clone(),
            "tool_call_id": lookup.binding.tool_call_id,
            "status": if is_failure { "failed" } else { "completed" },
            "result": if is_failure { Value::Null } else { result.clone() },
            "error": if is_failure {
                serde_json::to_value(error.clone()).unwrap_or(Value::Null)
            } else {
                Value::Null
            },
        }))
        .map_err(|_| RuntimeCommandError::Invalid("callback_delivery"))?;
        drafts.push(EventDraft::new(
            format!("{event_prefix}:delivery"),
            SessionEvent::DeliveryQueued {
                delivery: crate::domain::QueuedDelivery {
                    queue_id,
                    delivery_id: format!("callback-delivery:{callback_id}"),
                    kind: DeliveryKind::RuntimeNotification,
                    payload: delivery_payload,
                    dedupe_key: delivery_dedupe_key,
                    wake: true,
                    created_at_ms: Some(current_time_ms()),
                    source_tool_call_id: Some(lookup.binding.tool_call_id.clone()),
                    materialized_message_id: None,
                },
            },
        ));
        let command_id = format!("callback-command:{callback_id}:{payload_fingerprint}");
        match store.append_owned(
            &lookup.owner,
            &lookup.session_id,
            lookup.state.stream_version,
            &command_id,
            &drafts,
        ) {
            Ok(_) => {
                return Ok(CallbackCompletion::Admitted(callback_body(
                    is_failure,
                    &result,
                    error.as_ref(),
                )));
            }
            Err(StoreError::OptimisticConcurrency { .. }) => continue,
            Err(StoreError::CommandIdempotencyConflict { .. })
            | Err(StoreError::EventIdempotencyConflict { .. }) => continue,
            Err(error) => {
                tracing::warn!(callback_id, ?error, "external callback append failed");
                return Err(RuntimeCommandError::Backend);
            }
        }
    }
    Err(RuntimeCommandError::Conflict)
}

fn cancel_tool_call_blocking(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    tool_call_id: &str,
    reason: &str,
    command_id: &str,
) -> Result<AsyncToolCallRecord, RuntimeCommandError> {
    if reason.is_empty() || command_id.is_empty() {
        return Err(RuntimeCommandError::Invalid("cancel_request"));
    }
    for _ in 0..16 {
        let state = store
            .rehydrate_owned(owner, session_id)
            .map_err(|_| RuntimeCommandError::NotFound)?;
        let Some(record) = state.async_tool_calls.get(tool_call_id).cloned() else {
            return Err(RuntimeCommandError::NotFound);
        };
        if record.status == AsyncToolStatus::UnknownOutcome {
            return Err(RuntimeCommandError::Conflict);
        }
        if record.status.is_terminal() {
            return Ok(record);
        }
        let event_id = format!("tool-cancelled:{tool_call_id}:{command_id}");
        match store.append_owned(
            owner,
            session_id,
            state.stream_version,
            command_id,
            &[EventDraft::new(
                event_id,
                SessionEvent::AsyncToolCallCancelled {
                    tool_call_id: tool_call_id.to_owned(),
                    reason: reason.to_owned(),
                    completed_at_ms: current_time_ms(),
                },
            )],
        ) {
            Ok(_) => {
                let state = store
                    .rehydrate_owned(owner, session_id)
                    .map_err(|_| RuntimeCommandError::Backend)?;
                return state
                    .async_tool_calls
                    .get(tool_call_id)
                    .cloned()
                    .ok_or(RuntimeCommandError::NotFound);
            }
            Err(StoreError::OptimisticConcurrency { .. }) => continue,
            Err(StoreError::CommandIdempotencyConflict { .. }) => {
                let state = store
                    .rehydrate_owned(owner, session_id)
                    .map_err(|_| RuntimeCommandError::Backend)?;
                if let Some(record) = state.async_tool_calls.get(tool_call_id).cloned() {
                    return Ok(record);
                }
                return Err(RuntimeCommandError::Conflict);
            }
            Err(_) => return Err(RuntimeCommandError::Backend),
        }
    }
    Err(RuntimeCommandError::Conflict)
}

fn reconcile_tool_call_blocking(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    tool_call_id: &str,
    action: &str,
    command_id: &str,
) -> Result<AsyncToolCallRecord, RuntimeCommandError> {
    if action != "retry_dispatch" || command_id.is_empty() {
        return Err(RuntimeCommandError::Invalid("reconcile_action"));
    }
    let state = store
        .rehydrate_owned(owner, session_id)
        .map_err(|_| RuntimeCommandError::NotFound)?;
    let Some(record) = state.async_tool_calls.get(tool_call_id).cloned() else {
        return Err(RuntimeCommandError::NotFound);
    };
    // Unknown outcomes are intentionally not manually rewritable.  A safe
    // retry requires an adapter-declared idempotency policy and is dispatched
    // only by the runtime executor, never by this command seam.
    if record.status == AsyncToolStatus::UnknownOutcome {
        return Err(RuntimeCommandError::Conflict);
    }
    Ok(record)
}

fn parse_callback_payload(
    payload: &Value,
) -> Result<(bool, Value, Option<DomainToolError>), RuntimeCommandError> {
    let object = payload
        .as_object()
        .ok_or(RuntimeCommandError::Invalid("callback_payload"))?;
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .ok_or(RuntimeCommandError::Invalid("callback_status"))?;
    match status {
        "completed" => {
            let result = object
                .get("result")
                .cloned()
                .ok_or(RuntimeCommandError::Invalid("callback_result"))?;
            Ok((false, result, None))
        }
        "failed" => {
            let error = object
                .get("error")
                .and_then(Value::as_object)
                .ok_or(RuntimeCommandError::Invalid("callback_error"))?;
            let class = error
                .get("class")
                .and_then(Value::as_str)
                .unwrap_or("tool_execution_failed")
                .to_owned();
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("tool execution failed")
                .to_owned();
            Ok((true, Value::Null, Some(DomainToolError { class, message })))
        }
        _ => Err(RuntimeCommandError::Invalid("callback_status")),
    }
}

fn callback_public_body(record: Option<&AsyncToolCallRecord>) -> Value {
    let Some(record) = record else {
        return Value::Null;
    };
    match record.status {
        AsyncToolStatus::Completed => json!({
            "status": "completed",
            "result": record
                .result
                .as_ref()
                .and_then(|payload| match payload {
                    DurablePayload::Inline(value) => Some(value.value().clone()),
                    _ => None,
                })
                .unwrap_or(Value::Null),
        }),
        AsyncToolStatus::Failed => json!({
            "status": "failed",
            "error": record.error.as_ref().map(|error| json!({
                "class": error.class,
                "message": error.message,
            })).unwrap_or(Value::Null),
        }),
        _ => Value::Null,
    }
}

fn callback_body(is_failure: bool, result: &Value, error: Option<&DomainToolError>) -> Value {
    if is_failure {
        json!({
            "status": "failed",
            "error": error.map(|error| json!({
                "class": error.class,
                "message": error.message,
            })).unwrap_or(Value::Null),
        })
    } else {
        json!({"status": "completed", "result": result})
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        diff |= usize::from(left.get(index).copied().unwrap_or_default())
            ^ usize::from(right.get(index).copied().unwrap_or_default());
    }
    diff == 0
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

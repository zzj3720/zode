use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use futures_util::future::join_all;
use serde_json::{json, Value};
use tokio::sync::{broadcast, Mutex as AsyncMutex};

use crate::{
    domain::{
        ActiveWait, AsyncToolCallRecord, AsyncToolStatus, CompletionMode, DeliveryKind,
        DurablePayload, EventDraft, EventRecord, ModelAttemptError, ModelAttemptErrorClass,
        ModelAttemptFailure, SessionEvent, SessionModelSelection, SessionOwner, SessionState,
        ToolCall, ToolError as DomainToolError, TranscriptMessage, TranscriptRole, WaitSource,
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
}

pub const WAIT_FOR_TOOL_NAME: &str = "wait_for";

#[derive(Clone, Debug)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
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
        }
    }
}

#[derive(Clone, Debug)]
pub struct ToolInvocation {
    pub tool_call_id: String,
    pub tool_name: String,
    pub input: Value,
}

#[derive(Clone, Debug)]
pub struct ToolExecutionResult {
    pub content: String,
    pub is_error: bool,
}

#[derive(Debug)]
pub enum ToolError {
    InvalidSelection,
    InvalidInvocation,
    Unavailable,
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
    pub selection: SessionModelSelection,
    pub transcript: Vec<TranscriptMessage>,
    pub tools: Vec<ToolDefinition>,
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
    snapshot_every: Option<u64>,
    session_locks: Mutex<HashMap<SessionKey, Arc<AsyncMutex<()>>>>,
}

impl Runtime {
    pub fn new(
        store: Arc<dyn EventStore>,
        model: Arc<dyn ModelExecutor>,
        tools: Arc<dyn ToolExecutor>,
        snapshot_every: Option<u64>,
    ) -> Arc<Self> {
        let (publisher, _) = broadcast::channel(1_024);
        Arc::new(Self {
            store,
            model,
            tools,
            publisher,
            snapshot_every,
            session_locks: Mutex::new(HashMap::new()),
        })
    }

    pub fn publisher(&self) -> broadcast::Sender<EventRecord> {
        self.publisher.clone()
    }

    pub async fn queue_startup_recovery(self: &Arc<Self>) -> Result<(), &'static str> {
        self.scan_startup_refs(false).await?;
        self.scan_startup_refs(true).await
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
                    self.wake(session.owner, session.session_id);
                }
            }
            if page_len < MAX_OWNED_SESSION_SCAN_LIMIT {
                return Ok(());
            }
        }
    }

    pub async fn observe_commit(&self, append: &AppendResult, state: &SessionState) {
        if append.replayed {
            return;
        }
        if self.snapshot_every.is_some_and(|every| {
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
            Err(_) => return,
        };
        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            let _guard = lock.lock().await;
            if let Err(error) = runtime.activate(owner, session_id.clone()).await {
                tracing::warn!(session_id = %session_id, error, "session activation stopped");
            }
        });
    }

    async fn activate(&self, owner: SessionOwner, session_id: String) -> Result<(), &'static str> {
        let mut state = rehydrate(self.store.clone(), owner.clone(), session_id.clone()).await?;
        let Some(selection) = state.selection.model.clone() else {
            return Ok(());
        };

        loop {
            if state.active_wait.is_some() && state.delivery_queue.is_empty() {
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
            } else {
                return Ok(());
            }
        }
    }

    async fn run_model_round(
        &self,
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
        let request = ModelRequest {
            owner: owner.clone(),
            selection: selection.clone(),
            transcript: state.transcript.clone(),
            tools,
        };
        let outcome = match self.model.complete(request).await {
            Ok(outcome) => outcome,
            Err(ModelError::AuthReplicaUnavailable) => {
                if state
                    .transcript
                    .last()
                    .is_none_or(|message| message.role != TranscriptRole::User)
                {
                    return Err("provider");
                }
                let commit = append_model_attempt_failure(
                    self.store.clone(),
                    owner.clone(),
                    session_id.to_owned(),
                    round_identity,
                )
                .await?;
                return Ok((vec![commit.clone()], commit.1));
            }
            Err(_) => return Err("provider"),
        };
        validate_tool_calls(&outcome.tool_calls, &state.selection.tools)?;
        if outcome.tool_calls.is_empty() {
            let commit = append_assistant(
                self.store.clone(),
                owner.clone(),
                session_id.to_owned(),
                round_identity,
                outcome.text,
            )
            .await?;
            return Ok((vec![commit.clone()], commit.1));
        }

        let batch_identity = assistant_identity(owner, session_id, &round_identity);
        let initial_commit = append_tool_batch(
            self.store.clone(),
            owner.clone(),
            session_id.to_owned(),
            round_identity,
            outcome.tool_calls.clone(),
        )
        .await?;
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
                return Err("tool_batch_recovery");
            }
        }
        let results = if initial_replayed {
            Vec::new()
        } else {
            self.execute_tool_calls(&outcome.tool_calls, &state.selection.tools)
                .await
        };
        let result_commit = append_tool_results(
            self.store.clone(),
            owner.clone(),
            session_id.to_owned(),
            batch_identity,
            outcome.tool_calls,
            results,
        )
        .await?;
        Ok((vec![initial_commit, result_commit.clone()], result_commit.1))
    }

    async fn execute_tool_calls(
        &self,
        calls: &[ToolCall],
        selected: &[String],
    ) -> Vec<Result<ToolExecutionResult, ToolError>> {
        let ordinary = calls
            .iter()
            .filter(|call| call.tool_name != WAIT_FOR_TOOL_NAME)
            .map(|call| {
                let invocation = match inline_tool_input(call) {
                    Ok(input) => Ok(ToolInvocation {
                        tool_call_id: call.tool_call_id.clone(),
                        tool_name: call.tool_name.clone(),
                        input,
                    }),
                    Err(_) => Err(ToolError::InvalidInvocation),
                };
                (call.tool_call_id.clone(), invocation)
            })
            .collect::<Vec<_>>();
        let definitions = self
            .tools
            .definitions(selected)
            .unwrap_or_default()
            .into_iter()
            .map(|definition| definition.name)
            .collect::<HashSet<_>>();
        let futures = ordinary.into_iter().map(|(_id, invocation)| {
            let definitions = definitions.clone();
            async move {
                let invocation = invocation?;
                if !definitions.contains(&invocation.tool_name) {
                    return Err(ToolError::InvalidSelection);
                }
                self.tools.execute(invocation).await
            }
        });
        let ordinary_results = join_all(futures).await;
        let mut by_id = ordinary_results
            .into_iter()
            .zip(
                calls
                    .iter()
                    .filter(|call| call.tool_name != WAIT_FOR_TOOL_NAME),
            )
            .map(|(result, call)| (call.tool_call_id.clone(), result))
            .collect::<HashMap<_, _>>();
        calls
            .iter()
            .map(|call| {
                if call.tool_name == WAIT_FOR_TOOL_NAME {
                    Ok(ToolExecutionResult {
                        content: "wait_for accepted".to_owned(),
                        is_error: false,
                    })
                } else {
                    by_id
                        .remove(&call.tool_call_id)
                        .unwrap_or(Err(ToolError::Unavailable))
                }
            })
            .collect()
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

fn model_followup_identity(state: &SessionState) -> Option<String> {
    if state.active_wait.is_some() || state.transcript.last()?.role != TranscriptRole::Tool {
        return None;
    }
    state
        .transcript
        .iter()
        .rev()
        .skip_while(|message| message.role == TranscriptRole::Tool)
        .find(|message| message.role == TranscriptRole::Assistant && !message.tool_calls.is_empty())
        .map(|message| message.message_id.clone())
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

fn validate_tool_calls(calls: &[ToolCall], selected: &[String]) -> Result<(), &'static str> {
    let mut ids = HashSet::new();
    let selected = selected.iter().collect::<HashSet<_>>();
    for call in calls {
        if !ids.insert(call.tool_call_id.as_str()) {
            return Err("duplicate tool call id");
        }
        if call.tool_name != WAIT_FOR_TOOL_NAME && !selected.contains(&call.tool_name) {
            return Err("unselected tool call");
        }
        if call.tool_name != WAIT_FOR_TOOL_NAME {
            inline_tool_input(call)?;
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
    tokio::task::spawn_blocking(move || {
        append_model_attempt_failure_blocking(&*store, &owner, &session_id, &trigger_message_id)
    })
    .await
    .map_err(|_| "model_failure_join")?
}

fn append_model_attempt_failure_blocking(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    trigger_message_id: &str,
) -> Result<(AppendResult, SessionState), &'static str> {
    let failure = ModelAttemptFailure {
        trigger_message_id: trigger_message_id.to_owned(),
        error: ModelAttemptError {
            class: ModelAttemptErrorClass::AuthReplicaUnavailable,
            message: "credential replica unavailable".to_owned(),
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
            let message = materialize_message(delivery)?;
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
            Err(_) => return Err("materialize_append"),
        }
    }
    Err("materialize_concurrency")
}

fn materialize_message(
    delivery: &crate::domain::QueuedDelivery,
) -> Result<TranscriptMessage, &'static str> {
    let role = match delivery.kind {
        DeliveryKind::UserInput => TranscriptRole::User,
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
    Ok(TranscriptMessage {
        message_id: message_id.to_owned(),
        role,
        content: content.to_owned(),
        tool_call_id: None,
        tool_calls: Vec::new(),
        dedupe_key: Some(delivery.dedupe_key.clone()),
        source_queue_id: Some(delivery.queue_id),
    })
}

async fn append_tool_batch(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    round_identity: String,
    tool_calls: Vec<ToolCall>,
) -> Result<(AppendResult, SessionState), &'static str> {
    tokio::task::spawn_blocking(move || {
        append_tool_batch_blocking(&*store, &owner, &session_id, &round_identity, &tool_calls)
    })
    .await
    .map_err(|_| "tool_batch_join")?
}

fn append_tool_batch_blocking(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    round_identity: &str,
    tool_calls: &[ToolCall],
) -> Result<(AppendResult, SessionState), &'static str> {
    let identity = assistant_identity(owner, session_id, round_identity);
    let command_id = format!("model-tool-batch-command:v1:{identity}");
    let assistant_message = TranscriptMessage {
        message_id: format!("assistant-tool:v1:{identity}"),
        role: TranscriptRole::Assistant,
        content: String::new(),
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
            let record = AsyncToolCallRecord {
                tool_call_id: call.tool_call_id.clone(),
                tool_name: call.tool_name.clone(),
                input: call.input.clone(),
                status: AsyncToolStatus::Running,
                started_at_ms,
                auto_wait_seconds: None,
                completion_mode: CompletionMode::ProcessLocal,
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
        for (index, call) in tool_calls.iter().enumerate() {
            let result = results.get(index).ok_or("tool_results_count")?;
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
                        let payload = DurablePayload::inline(json!({
                            "content": result.content,
                        }))
                        .map_err(|_| "tool_result_payload")?;
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
        match store.append_owned(
            owner,
            session_id,
            state.stream_version,
            &command_id,
            &[EventDraft::new(
                event_id.clone(),
                SessionEvent::MessageAppended {
                    message: message.clone(),
                    wake_wait: false,
                },
            )],
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

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

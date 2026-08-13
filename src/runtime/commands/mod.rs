use std::sync::Arc;

use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::domain::{
    DeliveryKind, DurablePayload, EventDraft, QueuedDelivery, SessionEvent, SessionModelSelection,
    SessionOwner, SessionSelection, SessionState, ToolCall, TranscriptMessage, TranscriptRole,
};

use super::{
    AppendResult, EventStore, ExecutionPolicyPort, RehydrateError, ReplicaPort, ReplicaPortError,
    Runtime, RuntimeCommandError, SessionCreate, SessionCreateCommand, SessionCreateResult,
    StoreError, ToolExecutor, VerifiedSessionState,
};

#[derive(Debug, Serialize)]
struct CanonicalCreateRequest<'a> {
    schema: &'static str,
    path: &'static str,
    selection: &'a SessionSelection,
}

struct ModelDeliverySpec {
    command_id: String,
    event_id: String,
    delivery_id: String,
    dedupe_key: String,
    message_id: String,
    content: String,
    created_at_ms: i64,
}

pub fn session_command_id(kind: &str, owner: &SessionOwner, session_id: &str, key: &str) -> String {
    semantic_digest(
        &format!("session.{kind}.command"),
        &format!(
            "{}:{}:{}",
            owner_digest(&owner.authority_id, &owner.subject),
            session_id,
            key
        ),
        key,
    )
}

fn owner_digest(authority_id: &str, subject: &str) -> String {
    digest_fields("zode.session-owner.v1", &[authority_id, subject])
}

fn semantic_digest(kind: &str, scope: &str, value: &str) -> String {
    digest_fields(kind, &[scope, value])
}

fn digest_fields(kind: &str, fields: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(kind.as_bytes());
    digest.update([0]);
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    format!("sha256:v1:{:x}", digest.finalize())
}

fn validate_tools(
    tools: &dyn ToolExecutor,
    selected: &[String],
) -> Result<(), RuntimeCommandError> {
    tools
        .definitions(selected)
        .map(|_| ())
        .map_err(|_| RuntimeCommandError::Invalid("invalid tool selection"))
}

fn store_error(error: StoreError) -> RuntimeCommandError {
    match error {
        StoreError::OptimisticConcurrency { .. }
        | StoreError::CommandIdempotencyConflict { .. }
        | StoreError::EventIdempotencyConflict { .. }
        | StoreError::DuplicateEventIdInBatch { .. } => RuntimeCommandError::Conflict,
        StoreError::SessionNotFound => RuntimeCommandError::NotFound,
        StoreError::EmptyField { .. } | StoreError::Domain(_) => {
            RuntimeCommandError::Invalid("invalid request")
        }
        _ => RuntimeCommandError::Backend,
    }
}

fn rehydrate_error(error: RehydrateError) -> RuntimeCommandError {
    match error {
        RehydrateError::Store(StoreError::SessionNotFound) => RuntimeCommandError::NotFound,
        _ => RuntimeCommandError::Backend,
    }
}

fn read_store_error(error: StoreError) -> RuntimeCommandError {
    match error {
        StoreError::SessionNotFound => RuntimeCommandError::NotFound,
        _ => RuntimeCommandError::Backend,
    }
}

fn domain_error(error: crate::domain::DomainError) -> RuntimeCommandError {
    match error {
        crate::domain::DomainError::DurablePayloadTooLarge { .. }
        | crate::domain::DomainError::TextTooLarge { .. } => {
            RuntimeCommandError::Invalid("payload_too_large")
        }
        _ => RuntimeCommandError::Invalid("invalid message request"),
    }
}

fn map_replica_error(error: ReplicaPortError, unavailable_is_auth: bool) -> RuntimeCommandError {
    match error {
        ReplicaPortError::Disabled | ReplicaPortError::SecretUnavailable => {
            RuntimeCommandError::AuthReplicaUnavailable
        }
        ReplicaPortError::Unavailable if unavailable_is_auth => {
            RuntimeCommandError::AuthReplicaUnavailable
        }
        ReplicaPortError::Invalid => {
            RuntimeCommandError::Invalid("invalid credential replica selection")
        }
        _ => RuntimeCommandError::Backend,
    }
}

fn admit_model_selection(
    policy: &dyn ExecutionPolicyPort,
    replicas: &dyn ReplicaPort,
    model: &SessionModelSelection,
    unavailable_is_auth: bool,
) -> Result<(), RuntimeCommandError> {
    policy
        .validate_descriptor(&model.provider_execution)
        .map_err(|_| RuntimeCommandError::Invalid("invalid provider execution"))?;
    let probe = replicas
        .probe(
            &model.auth_authority_id,
            &model.auth_profile_id,
            &model.provider,
            model.auth_revision,
        )
        .map_err(|error| map_replica_error(error, unavailable_is_auth))?;
    if policy.credential_schema(&model.provider_execution.kind)
        != Some(probe.credential_schema.as_str())
    {
        return Err(RuntimeCommandError::AuthReplicaUnavailable);
    }
    Ok(())
}

fn same_delivery_request(left: &QueuedDelivery, right: &QueuedDelivery) -> bool {
    left.delivery_id == right.delivery_id
        && left.kind == right.kind
        && left.payload == right.payload
        && left.dedupe_key == right.dedupe_key
        && left.wake == right.wake
        && left.source_tool_call_id == right.source_tool_call_id
}

fn lookup_session_command<F>(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    command_id: &str,
    matches_request: F,
) -> Result<Option<(AppendResult, SessionState)>, RuntimeCommandError>
where
    F: Fn(&SessionEvent) -> bool,
{
    let records = match store.read_stream_owned(owner, session_id, 0) {
        Ok(records) => records,
        Err(StoreError::SessionNotFound) => return Ok(None),
        Err(error) => return Err(read_store_error(error)),
    };
    let events = records
        .into_iter()
        .filter(|record| record.command_id == command_id)
        .collect::<Vec<_>>();
    let Some(first) = events.first() else {
        return Ok(None);
    };
    if events.len() != 1 || !matches_request(&first.event) {
        return Err(RuntimeCommandError::Conflict);
    }
    let state = store
        .rehydrate_owned(owner, session_id)
        .map_err(rehydrate_error)?;
    Ok(Some((
        AppendResult {
            stream_id: session_id.to_owned(),
            command_id: command_id.to_owned(),
            stream_version: events
                .last()
                .map(|event| event.stream_version)
                .unwrap_or(state.stream_version),
            events,
            replayed: true,
        },
        state,
    )))
}

fn replay_queued_delivery(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    command_id: &str,
    requested: &QueuedDelivery,
) -> Result<Option<(AppendResult, SessionState)>, RuntimeCommandError> {
    let records = store
        .read_stream_owned(owner, session_id, 0)
        .map_err(read_store_error)?;
    let events = records
        .into_iter()
        .filter(|record| record.command_id == command_id)
        .collect::<Vec<_>>();
    let Some(first) = events.first() else {
        return Ok(None);
    };
    if events.len() != 1 {
        return Err(RuntimeCommandError::Conflict);
    }
    let SessionEvent::DeliveryQueued { delivery } = &first.event else {
        return Err(RuntimeCommandError::Conflict);
    };
    if !same_delivery_request(delivery, requested) {
        return Err(RuntimeCommandError::Conflict);
    }
    let state = store
        .rehydrate_owned(owner, session_id)
        .map_err(rehydrate_error)?;
    let stream_version = events
        .last()
        .map(|record| record.stream_version)
        .unwrap_or(state.stream_version);
    Ok(Some((
        AppendResult {
            stream_id: session_id.to_owned(),
            command_id: command_id.to_owned(),
            events,
            stream_version,
            replayed: true,
        },
        state,
    )))
}

fn replay_message_command(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    command_id: &str,
    expected_message: &TranscriptMessage,
    requested_delivery: Option<&QueuedDelivery>,
) -> Result<Option<(AppendResult, SessionState)>, RuntimeCommandError> {
    let records = match store.read_stream_owned(owner, session_id, 0) {
        Ok(records) => records,
        Err(StoreError::SessionNotFound) => return Ok(None),
        Err(error) => return Err(read_store_error(error)),
    };
    let events = records
        .into_iter()
        .filter(|record| record.command_id == command_id)
        .collect::<Vec<_>>();
    let Some(first) = events.first() else {
        return Ok(None);
    };
    if events.len() != 1 {
        return Err(RuntimeCommandError::Conflict);
    }
    let matches = match &first.event {
        SessionEvent::MessageAppended { message, .. } => message == expected_message,
        SessionEvent::DeliveryQueued { delivery } => {
            requested_delivery.is_some_and(|requested| same_delivery_request(delivery, requested))
        }
        _ => false,
    };
    if !matches {
        return Err(RuntimeCommandError::Conflict);
    }
    let state = store
        .rehydrate_owned(owner, session_id)
        .map_err(rehydrate_error)?;
    let stream_version = events
        .last()
        .map(|record| record.stream_version)
        .unwrap_or(state.stream_version);
    Ok(Some((
        AppendResult {
            stream_id: session_id.to_owned(),
            command_id: command_id.to_owned(),
            events,
            stream_version,
            replayed: true,
        },
        state,
    )))
}

fn enqueue_model_delivery(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    mut current: VerifiedSessionState,
    spec: ModelDeliverySpec,
) -> Result<(AppendResult, SessionState), RuntimeCommandError> {
    let payload = DurablePayload::inline(json!({
        "message_id": &spec.message_id,
        "content": &spec.content,
    }))
    .map_err(domain_error)?;

    for _ in 0..16 {
        let queue_id = current
            .delivery_ack
            .checked_add(current.delivery_queue.len() as u64 + 1)
            .ok_or(RuntimeCommandError::Invalid("delivery queue is full"))?;
        let delivery = QueuedDelivery {
            queue_id,
            delivery_id: spec.delivery_id.clone(),
            kind: DeliveryKind::UserInput,
            payload: payload.clone(),
            dedupe_key: spec.dedupe_key.clone(),
            wake: true,
            created_at_ms: Some(spec.created_at_ms),
            source_tool_call_id: None,
            materialized_message_id: None,
        };
        let event = SessionEvent::DeliveryQueued {
            delivery: delivery.clone(),
        };
        match store.append_verified_owned(
            owner,
            session_id,
            current,
            &spec.command_id,
            &[EventDraft::new(spec.event_id.clone(), event)],
        ) {
            Ok(appended) => return Ok((appended.append, appended.state.into_state())),
            Err(StoreError::OptimisticConcurrency { .. }) => {
                current = store
                    .rehydrate_verified_owned(owner, session_id)
                    .map_err(rehydrate_error)?;
            }
            Err(StoreError::CommandIdempotencyConflict { .. }) => {
                if let Some(replay) =
                    replay_queued_delivery(store, owner, session_id, &spec.command_id, &delivery)?
                {
                    return Ok(replay);
                }
                return Err(RuntimeCommandError::Conflict);
            }
            Err(error) => return Err(store_error(error)),
        }
    }

    Err(RuntimeCommandError::Conflict)
}

fn create_session_blocking(
    runtime: &Runtime,
    owner: SessionOwner,
    idempotency_key: &str,
    selection: SessionSelection,
    replay_only: bool,
) -> Result<SessionCreateResult, RuntimeCommandError> {
    let semantic_request = CanonicalCreateRequest {
        schema: "zode.session-create.v1",
        path: "/v1/sessions",
        selection: &selection,
    };
    let command = SessionCreateCommand::new(&owner, idempotency_key, &semantic_request)
        .map_err(store_error)?;
    let replay = runtime
        .store
        .lookup_session_create(&owner, &command)
        .map_err(store_error)?;
    if replay_only {
        return replay.ok_or(RuntimeCommandError::IdempotencyReceiptNotFound);
    }
    if let Some(replay) = replay {
        return Ok(replay);
    }
    validate_tools(&*runtime.tools, &selection.tools)?;
    if let Some(model) = selection.model.as_ref() {
        admit_model_selection(&*runtime.execution_policy, &*runtime.replicas, model, false)?;
    }
    runtime
        .store
        .create_session(&SessionCreate {
            owner,
            command,
            created_at_ms: runtime.clock.now_ms(),
            selection,
        })
        .map_err(store_error)
}

fn append_message_blocking(
    runtime: &Runtime,
    owner: SessionOwner,
    session_id: &str,
    idempotency_key: &str,
    content: String,
    message_id: Option<String>,
    replay_only: bool,
) -> Result<(AppendResult, SessionState), RuntimeCommandError> {
    let owner_digest = owner_digest(&owner.authority_id, &owner.subject);
    let command_id = format!(
        "message-{}",
        semantic_digest(
            "session.message.key",
            &format!("{owner_digest}:{session_id}"),
            idempotency_key,
        )
    );
    let message_id = message_id.unwrap_or_else(|| {
        format!(
            "message-{}",
            semantic_digest(
                "session.message.id",
                &format!("{owner_digest}:{session_id}"),
                idempotency_key,
            )
        )
    });
    let event_id = format!(
        "message-appended-{}",
        semantic_digest("session.message.event", &command_id, &message_id)
    );
    let delivery_id = format!(
        "delivery-{}",
        semantic_digest("session.message.delivery", &command_id, &message_id)
    );
    let delivery_event_id = format!(
        "delivery-queued-{}",
        semantic_digest("session.message.delivery-event", &command_id, &message_id)
    );
    let delivery_dedupe_key = format!("delivery:{command_id}");
    let expected_message = TranscriptMessage {
        message_id: message_id.clone(),
        role: TranscriptRole::User,
        content: content.clone(),
        tool_call_id: None,
        tool_calls: Vec::<ToolCall>::new(),
        dedupe_key: Some(idempotency_key.to_owned()),
        source_queue_id: None,
    };
    let requested_delivery = DurablePayload::inline(json!({
        "message_id": &message_id,
        "content": &content,
    }))
    .ok()
    .map(|payload| QueuedDelivery {
        queue_id: 0,
        delivery_id: delivery_id.clone(),
        kind: DeliveryKind::UserInput,
        payload,
        dedupe_key: delivery_dedupe_key.clone(),
        wake: true,
        created_at_ms: None,
        source_tool_call_id: None,
        materialized_message_id: None,
    });
    if let Some(replay) = replay_message_command(
        &*runtime.store,
        &owner,
        session_id,
        &command_id,
        &expected_message,
        requested_delivery.as_ref(),
    )? {
        return Ok(replay);
    }
    if replay_only {
        return Err(RuntimeCommandError::IdempotencyReceiptNotFound);
    }
    let current = runtime
        .store
        .rehydrate_verified_owned(&owner, session_id)
        .map_err(rehydrate_error)?;
    let created_at_ms = runtime.clock.now_ms();
    if current.selection.model.is_some() {
        return enqueue_model_delivery(
            &*runtime.store,
            &owner,
            session_id,
            current,
            ModelDeliverySpec {
                command_id,
                event_id: delivery_event_id,
                delivery_id,
                dedupe_key: delivery_dedupe_key,
                message_id,
                content,
                created_at_ms,
            },
        );
    }
    let event = SessionEvent::MessageAppended {
        message: expected_message,
        wake_wait: true,
    };
    let appended = runtime
        .store
        .append_verified_owned(
            &owner,
            session_id,
            current,
            &command_id,
            &[EventDraft::new(event_id, event)],
        )
        .map_err(store_error)?;
    Ok((appended.append, appended.state.into_state()))
}

fn select_model_blocking(
    runtime: &Runtime,
    owner: SessionOwner,
    session_id: &str,
    idempotency_key: &str,
    model: SessionModelSelection,
    replay_only: bool,
) -> Result<(AppendResult, SessionState), RuntimeCommandError> {
    let command_id = session_command_id("model", &owner, session_id, idempotency_key);
    let event_id = format!("model-selection-changed:{command_id}");
    let expected_model = model.clone();
    let replay = lookup_session_command(
        &*runtime.store,
        &owner,
        session_id,
        &command_id,
        |event| match event {
            SessionEvent::ModelSelectionChanged { selection } => {
                selection.model.as_ref() == Some(&expected_model)
            }
            _ => false,
        },
    )?;
    if let Some(replay) = replay {
        return Ok(replay);
    }
    if replay_only {
        return Err(RuntimeCommandError::IdempotencyReceiptNotFound);
    }
    // Resolve ownership/existence before provider policy or replica state
    // so a cross-owner or missing session cannot probe credential status.
    let current = runtime
        .store
        .rehydrate_verified_owned(&owner, session_id)
        .map_err(rehydrate_error)?;
    admit_model_selection(&*runtime.execution_policy, &*runtime.replicas, &model, true)?;
    let mut selection = current.selection.clone();
    selection.model = Some(model);
    let appended = runtime
        .store
        .append_verified_owned(
            &owner,
            session_id,
            current,
            &command_id,
            &[EventDraft::new(
                event_id,
                SessionEvent::ModelSelectionChanged { selection },
            )],
        )
        .map_err(store_error)?;
    Ok((appended.append, appended.state.into_state()))
}

impl Runtime {
    pub async fn create_session(
        self: &Arc<Self>,
        owner: SessionOwner,
        idempotency_key: String,
        selection: SessionSelection,
        replay_only: bool,
    ) -> Result<SessionCreateResult, RuntimeCommandError> {
        let runtime = Arc::clone(self);
        let operation = tokio::task::spawn_blocking(move || {
            create_session_blocking(&runtime, owner, &idempotency_key, selection, replay_only)
        })
        .await
        .map_err(|_| RuntimeCommandError::Backend)??;
        self.observe_commit(&operation.append, &operation.state)
            .await;
        Ok(operation)
    }

    pub async fn append_message(
        self: &Arc<Self>,
        owner: SessionOwner,
        session_id: String,
        idempotency_key: String,
        content: String,
        message_id: Option<String>,
        replay_only: bool,
    ) -> Result<(AppendResult, SessionState), RuntimeCommandError> {
        let runtime = Arc::clone(self);
        let wake_owner = owner.clone();
        let wake_session_id = session_id.clone();
        let operation = tokio::task::spawn_blocking(move || {
            append_message_blocking(
                &runtime,
                owner,
                &session_id,
                &idempotency_key,
                content,
                message_id,
                replay_only,
            )
        })
        .await
        .map_err(|_| RuntimeCommandError::Backend)??;
        self.observe_commit(&operation.0, &operation.1).await;
        if !operation.0.replayed {
            self.wake(wake_owner, wake_session_id);
        }
        Ok(operation)
    }

    pub async fn select_model(
        self: &Arc<Self>,
        owner: SessionOwner,
        session_id: String,
        idempotency_key: String,
        model: SessionModelSelection,
        replay_only: bool,
    ) -> Result<(AppendResult, SessionState), RuntimeCommandError> {
        let runtime = Arc::clone(self);
        let wake_owner = owner.clone();
        let wake_session_id = session_id.clone();
        let operation = tokio::task::spawn_blocking(move || {
            select_model_blocking(
                &runtime,
                owner,
                &session_id,
                &idempotency_key,
                model,
                replay_only,
            )
        })
        .await
        .map_err(|_| RuntimeCommandError::Backend)??;
        self.observe_commit(&operation.0, &operation.1).await;
        if !operation.0.replayed {
            self.wake(wake_owner, wake_session_id);
        }
        Ok(operation)
    }
}

use super::*;

pub(super) async fn append_model_attempt_failure_with_error(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    trigger_message_id: String,
    error_class: ModelAttemptErrorClass,
    error_message: &'static str,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
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

pub(super) fn append_model_attempt_failure_blocking(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    trigger_message_id: &str,
    error_class: ModelAttemptErrorClass,
    error_message: &str,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
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
            .rehydrate_verified_owned(owner, session_id)
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
        match store.append_verified_owned(
            owner,
            session_id,
            state,
            &command_id,
            &[EventDraft::new(
                event_id.clone(),
                SessionEvent::ModelAttemptFailed {
                    failure: failure.clone(),
                },
            )],
        ) {
            Ok(appended) => return Ok((appended.append, appended.state)),
            Err(StoreError::OptimisticConcurrency { .. }) => continue,
            Err(_) => return Err("model_failure_append"),
        }
    }
    Err("model_failure_concurrency")
}

pub(super) async fn rehydrate_verified(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
) -> Result<VerifiedSessionState, &'static str> {
    tokio::task::spawn_blocking(move || {
        store
            .rehydrate_verified_owned(&owner, &session_id)
            .map_err(|_| "rehydrate_store")
    })
    .await
    .map_err(|_| "rehydrate_join")?
}

#[derive(Clone, Debug)]
pub(super) struct RecoveredModelFailure {
    pub(super) error_class: String,
    pub(super) retryable: bool,
}

pub(super) async fn read_model_failure_fact(
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
pub(super) struct PreparedRequestIdentity {
    pub(super) activation_id: String,
    pub(super) round_id: String,
    pub(super) request_id: String,
    pub(super) maximum_attempts: u32,
    pub(super) attempt_id: String,
    pub(super) attempt_number: u32,
}

pub(super) struct PreparedModelExecution {
    pub(super) state: VerifiedSessionState,
    pub(super) completion: PreparedModelCompletion,
}

pub(super) enum PreparedModelCompletion {
    Completed {
        outcome: ModelOutcome,
        attempt_id: String,
    },
    Terminal,
}

pub(super) struct ModelRoundInput<'a> {
    pub(super) state: &'a VerifiedSessionState,
    pub(super) selection: &'a SessionModelSelection,
    pub(super) request: &'a ModelRequest,
    pub(super) round_identity: &'a str,
    pub(super) purpose: ModelRequestPurpose,
    pub(super) maximum_attempts: u32,
}

pub(super) struct ModelFailureInput<'a> {
    pub(super) identity: &'a PreparedRequestIdentity,
    pub(super) attempt_id: &'a str,
    pub(super) attempt_number: u32,
    pub(super) error_class: &'a str,
    pub(super) retryable: bool,
}

pub(super) fn model_request_draft(
    selection: &SessionModelSelection,
    activation_id: &str,
    round_id: &str,
    request: &ModelRequest,
    maximum_attempts: u32,
) -> Result<(String, EventDraft), &'static str> {
    let request_id = stable_digest("model-request", &format!("{activation_id}:{round_id}"));
    let provider_execution_fingerprint = stable_digest(
        "provider-execution",
        &serde_json::to_string(&selection.provider_execution)
            .map_err(|_| "provider_fingerprint")?,
    );
    let prompt_fingerprint = request.prompt_fingerprint.clone();
    let tool_schema_fingerprint = request.tool_schema_fingerprint.clone();
    let stream_idle_timeout_ms = u64::try_from(request.stream_idle_timeout.as_millis())
        .map_err(|_| "model_stream_idle_timeout")?;
    let request_fingerprint = stable_digest(
        "model-request",
        &format!(
            "{provider_execution_fingerprint}:{prompt_fingerprint}:{tool_schema_fingerprint}:{}:{}:{:?}:{:?}:{stream_idle_timeout_ms}",
            selection.provider,
            selection.model,
            request.max_output_tokens,
            request.handoff_document_tokens,
        ),
    );
    Ok((
        request_id.clone(),
        EventDraft::new(
            format!("model-request-event:{request_id}"),
            SessionEvent::ModelRequestDeclared {
                activation_id: activation_id.to_owned(),
                round_id: round_id.to_owned(),
                request_id,
                request_fingerprint,
                provider_execution_fingerprint,
                prompt_fingerprint,
                tool_schema_fingerprint,
                maximum_attempts,
                minimum_auth_revision: selection.auth_revision,
            },
        ),
    ))
}

pub(super) struct ContextHandoffPlanInput<'a> {
    pub(super) state: &'a VerifiedSessionState,
    pub(super) plan: ContextHandoffPlan,
    pub(super) request: &'a ModelRequest,
    pub(super) maximum_attempts: u32,
}

pub(super) async fn append_context_handoff_plan(
    store: Arc<dyn EventStore>,
    clock: Arc<dyn Clock>,
    owner: SessionOwner,
    session_id: String,
    input: ContextHandoffPlanInput<'_>,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
    let ContextHandoffPlanInput {
        state,
        plan,
        request,
        maximum_attempts,
    } = input;
    if state.active_model_round.as_ref().is_some_and(|round| {
        round
            .attempt
            .as_ref()
            .is_none_or(|attempt| attempt.outcome != crate::domain::ModelAttemptOutcome::Completed)
    }) {
        return Err("context_handoff_active_round");
    }
    let activation_id = plan.activation_id.clone();
    let plan_id = plan.plan_id.clone();
    let round_id = stable_digest("context-handoff-round", &plan_id);
    let delivery_through_queue_id = state.delivery_ack.max(1);
    let (request_id, request_draft) = model_request_draft(
        &plan.selection,
        &activation_id,
        &round_id,
        request,
        maximum_attempts,
    )?;
    let started_at_ms = clock.now_ms();
    let command_id = format!("context-handoff-prepare:{plan_id}");
    let drafts = vec![
        EventDraft::new(
            format!("context-handoff-plan-event:{plan_id}"),
            SessionEvent::ContextHandoffPlanned { plan: plan.clone() },
        ),
        EventDraft::new(
            format!("model-round-event:{round_id}"),
            SessionEvent::ModelRoundStarted {
                activation_id: activation_id.clone(),
                round_id: round_id.clone(),
                purpose: ModelRequestPurpose::ContextHandoff,
                delivery_through_queue_id,
                started_at_ms,
            },
        ),
        request_draft,
    ];
    tokio::task::spawn_blocking(move || {
        for _ in 0..16 {
            let current = store
                .rehydrate_verified_owned(&owner, &session_id)
                .map_err(|_| "context_handoff_prepare_rehydrate")?;
            let already_prepared = current.pending_context_handoff.as_ref() == Some(&plan)
                && current.active_model_round.as_ref().is_some_and(|round| {
                    round.round_id == round_id
                        && round.purpose == ModelRequestPurpose::ContextHandoff
                        && round
                            .request
                            .as_ref()
                            .is_some_and(|prepared| prepared.request_id == request_id)
                });
            if already_prepared {
                return Ok((replayed_append(&session_id, &command_id, &current), current));
            }
            match store.append_verified_owned(&owner, &session_id, current, &command_id, &drafts) {
                Ok(appended) => return Ok((appended.append, appended.state)),
                Err(StoreError::OptimisticConcurrency { .. }) => continue,
                Err(StoreError::CommandIdempotencyConflict { .. }) => {
                    return Err("context_handoff_prepare_conflict");
                }
                Err(_) => return Err("context_handoff_prepare_append"),
            }
        }
        Err("context_handoff_prepare_concurrency")
    })
    .await
    .map_err(|_| "context_handoff_prepare_join")?
}

pub(super) struct ToolResultsInput {
    pub(super) batch_identity: String,
    pub(super) tool_calls: Vec<ToolCall>,
    pub(super) results: Vec<Result<ToolExecutionResult, ToolError>>,
}

pub(super) struct ToolBatchInput {
    pub(super) round_identity: String,
    pub(super) assistant_content: String,
    pub(super) definitions: Arc<Vec<ToolDefinition>>,
    pub(super) callback_plans: Vec<CallbackPlan>,
    pub(super) tool_calls: Vec<ToolCall>,
}

pub(super) async fn append_runtime_event(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    command_id: String,
    event_id: String,
    event: SessionEvent,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
    let state = rehydrate_verified(store.clone(), owner.clone(), session_id.clone()).await?;
    append_runtime_event_from_state(store, owner, session_id, state, command_id, event_id, event)
        .await
}

pub(super) async fn append_runtime_event_from_state(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    state: VerifiedSessionState,
    command_id: String,
    event_id: String,
    event: SessionEvent,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
    append_runtime_events_from_state(
        store,
        owner,
        session_id,
        state,
        command_id,
        vec![EventDraft::new(event_id, event)],
    )
    .await
}

pub(super) async fn append_runtime_events(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    command_id: String,
    events: Vec<EventDraft>,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
    let state = rehydrate_verified(store.clone(), owner.clone(), session_id.clone()).await?;
    append_runtime_events_from_state(store, owner, session_id, state, command_id, events).await
}

pub(super) async fn append_runtime_events_from_state(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    mut state: VerifiedSessionState,
    command_id: String,
    events: Vec<EventDraft>,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
    tokio::task::spawn_blocking(move || {
        for _ in 0..16 {
            match store.append_verified_owned(&owner, &session_id, state, &command_id, &events) {
                Ok(appended) => return Ok((appended.append, appended.state)),
                Err(StoreError::OptimisticConcurrency { .. }) => {
                    state = store
                        .rehydrate_verified_owned(&owner, &session_id)
                        .map_err(|_| "runtime_event_rehydrate")?;
                }
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

pub(super) async fn append_expired_timer(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    wait_id: String,
    now_ms: i64,
) -> Result<Option<(AppendResult, VerifiedSessionState)>, &'static str> {
    tokio::task::spawn_blocking(move || {
        for _ in 0..16 {
            let state = store
                .rehydrate_verified_owned(&owner, &session_id)
                .map_err(|_| "timer_rehydrate")?;
            let Some(timer) = state.active_timer.clone() else {
                return Ok(None);
            };
            if timer.wait_id != wait_id
                || timer.deadline_ms > now_ms
                || state
                    .active_wait
                    .as_ref()
                    .is_none_or(|wait| wait.wait_id != timer.wait_id)
                || state.wake_pending_wait_id.as_deref() == Some(timer.wait_id.as_str())
            {
                return Ok(None);
            }
            match store.append_verified_owned(
                &owner,
                &session_id,
                state,
                &format!("wait-expired:{}", timer.wait_id),
                &[EventDraft::new(
                    format!("wait-expired-event:{}", timer.wait_id),
                    SessionEvent::WaitExpired {
                        wait_id: timer.wait_id,
                    },
                )],
            ) {
                Ok(appended) => return Ok(Some((appended.append, appended.state))),
                Err(StoreError::OptimisticConcurrency { .. }) => continue,
                Err(_) => return Err("timer_append"),
            }
        }
        Err("timer_concurrency")
    })
    .await
    .map_err(|_| "timer_join")?
}

pub(super) async fn start_activation(
    store: Arc<dyn EventStore>,
    clock: Arc<dyn Clock>,
    owner: SessionOwner,
    session_id: String,
    state: &VerifiedSessionState,
    selection: &SessionSelection,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
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
    append_runtime_event_from_state(
        store,
        owner,
        session_id,
        state.clone(),
        format!("activation-start:{activation_id}"),
        format!("activation-start-event:{activation_id}"),
        SessionEvent::ActivationStarted {
            activation_id,
            selection: state.selection.clone(),
            selection_version: state.selection_version,
            minimum_auth_revision,
            started_at_ms: clock.now_ms(),
        },
    )
    .await
}

pub(super) async fn finish_activation(
    store: Arc<dyn EventStore>,
    clock: Arc<dyn Clock>,
    owner: SessionOwner,
    session_id: String,
    state: &VerifiedSessionState,
    activation_id: String,
    outcome: ActivationOutcome,
) -> Result<Option<(AppendResult, VerifiedSessionState)>, &'static str> {
    if state.active_activation.is_none() {
        return Ok(None);
    }
    Ok(Some(
        append_runtime_event_from_state(
            store,
            owner,
            session_id,
            state.clone(),
            format!("activation-finish:{activation_id}"),
            format!("activation-finish-event:{activation_id}"),
            SessionEvent::ActivationFinished {
                activation_id,
                outcome,
                finished_at_ms: clock.now_ms(),
            },
        )
        .await?,
    ))
}

pub(super) async fn prepare_model_round(
    store: Arc<dyn EventStore>,
    clock: Arc<dyn Clock>,
    owner: SessionOwner,
    session_id: String,
    input: ModelRoundInput<'_>,
) -> Result<
    (
        Vec<(AppendResult, VerifiedSessionState)>,
        VerifiedSessionState,
        PreparedRequestIdentity,
    ),
    &'static str,
> {
    let ModelRoundInput {
        state,
        selection,
        request,
        round_identity,
        purpose,
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
    let request_id = if needs_new_round {
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
        let (request_id, request_draft) = model_request_draft(
            selection,
            &activation_id,
            &round_id,
            request,
            maximum_attempts,
        )?;
        let append = append_runtime_events_from_state(
            store.clone(),
            owner.clone(),
            session_id.clone(),
            current,
            format!("model-round:{round_id}"),
            vec![
                EventDraft::new(
                    format!("model-round-event:{round_id}"),
                    SessionEvent::ModelRoundStarted {
                        activation_id: activation_id.clone(),
                        round_id: round_id.clone(),
                        purpose: purpose.clone(),
                        delivery_through_queue_id,
                        started_at_ms: clock.now_ms(),
                    },
                ),
                request_draft,
            ],
        )
        .await?;
        current = append.1.clone();
        commits.push(append);
        request_id
    } else {
        let round = current
            .active_model_round
            .as_ref()
            .ok_or("model_round_missing")?;
        if round.purpose != purpose {
            return Err("model_round_purpose");
        }
        if let Some(prepared) = &round.request {
            prepared.request_id.clone()
        } else {
            let (request_id, request_draft) = model_request_draft(
                selection,
                &activation_id,
                &round.round_id,
                request,
                maximum_attempts,
            )?;
            let append = append_runtime_event_from_state(
                store.clone(),
                owner.clone(),
                session_id.clone(),
                current,
                format!("model-request:{request_id}"),
                request_draft.event_id,
                request_draft.event,
            )
            .await?;
            current = append.1.clone();
            commits.push(append);
            request_id
        }
    };
    let round = current
        .active_model_round
        .as_ref()
        .ok_or("model_round_missing_after_prepare")?;
    if round.purpose != purpose {
        return Err("model_round_purpose");
    }
    let round_id = round.round_id.clone();
    let maximum_attempts = round
        .request
        .as_ref()
        .map(|request| request.maximum_attempts)
        .ok_or("model_request_missing_after_prepare")?;
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
        let append = append_runtime_event_from_state(
            store,
            owner,
            session_id,
            current,
            format!("model-attempt-start:{request_id}:{attempt_number}"),
            format!("model-attempt-start-event:{request_id}:{attempt_number}"),
            SessionEvent::ModelAttemptStarted {
                activation_id: activation_id.clone(),
                round_id: round_id.clone(),
                request_id: request_id.clone(),
                attempt_id: attempt_id.clone(),
                attempt_number,
                auth_revision: selection.auth_revision,
                started_at_ms: clock.now_ms(),
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

pub(super) async fn append_context_handoff_document(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    identity: &PreparedRequestIdentity,
    attempt_id: &str,
    handoff: ContextHandoffDocument,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
    let identity = identity.clone();
    let attempt_id = attempt_id.to_owned();
    tokio::task::spawn_blocking(move || {
        let command_id = format!("context-handoff:{}", handoff.handoff_id);
        for _ in 0..16 {
            let state = store
                .rehydrate_verified_owned(&owner, &session_id)
                .map_err(|_| "context_handoff_rehydrate")?;
            if state
                .latest_context_handoff
                .as_ref()
                .is_some_and(|existing| existing == &handoff)
            {
                return Ok((replayed_append(&session_id, &command_id, &state), state));
            }
            let events = [
                EventDraft::new(
                    format!("model-request-complete-event:{}", identity.request_id),
                    SessionEvent::ModelRequestCompleted {
                        activation_id: identity.activation_id.clone(),
                        round_id: identity.round_id.clone(),
                        request_id: identity.request_id.clone(),
                        attempt_id: attempt_id.clone(),
                        usage: None,
                    },
                ),
                EventDraft::new(
                    format!("context-handoff-event:{}", handoff.handoff_id),
                    SessionEvent::ContextHandoffCreated {
                        handoff: handoff.clone(),
                    },
                ),
            ];
            match store.append_verified_owned(&owner, &session_id, state, &command_id, &events) {
                Ok(appended) => return Ok((appended.append, appended.state)),
                Err(StoreError::OptimisticConcurrency { .. }) => continue,
                Err(StoreError::CommandIdempotencyConflict { .. }) => {
                    let state = store
                        .rehydrate_verified_owned(&owner, &session_id)
                        .map_err(|_| "context_handoff_rehydrate")?;
                    if state
                        .latest_context_handoff
                        .as_ref()
                        .is_some_and(|existing| existing == &handoff)
                    {
                        return Ok((replayed_append(&session_id, &command_id, &state), state));
                    }
                    return Err("context_handoff_conflict");
                }
                Err(_) => return Err("context_handoff_append"),
            }
        }
        Err("context_handoff_concurrency")
    })
    .await
    .map_err(|_| "context_handoff_join")?
}

pub(super) async fn append_context_handoff_failure(
    store: Arc<dyn EventStore>,
    clock: Arc<dyn Clock>,
    owner: SessionOwner,
    session_id: String,
    state: &VerifiedSessionState,
    message: &'static str,
    completed_request: Option<(&PreparedRequestIdentity, &str)>,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
    let plan = state
        .pending_context_handoff
        .as_ref()
        .cloned()
        .ok_or("context_handoff_plan_missing")?;
    let plan_id = plan.plan_id;
    let activation_id = plan.activation_id;
    let completed_request =
        completed_request.map(|(identity, attempt_id)| (identity.clone(), attempt_id.to_owned()));
    let error = ModelAttemptError {
        class: ModelAttemptErrorClass::ContextHandoffFailed,
        message: message.to_owned(),
    };
    let finished_at_ms = clock.now_ms();
    tokio::task::spawn_blocking(move || {
        let command_id = format!("context-handoff-failure:{plan_id}");
        for _ in 0..16 {
            let state = store
                .rehydrate_verified_owned(&owner, &session_id)
                .map_err(|_| "context_handoff_failure_rehydrate")?;
            if state.active_activation.is_none()
                && state.pending_context_handoff.is_none()
                && state.last_context_handoff_failure.as_ref() == Some(&error)
            {
                return Ok((replayed_append(&session_id, &command_id, &state), state));
            }
            let mut events = Vec::with_capacity(3);
            if let Some((identity, attempt_id)) = &completed_request {
                events.push(EventDraft::new(
                    format!("model-request-complete-event:{}", identity.request_id),
                    SessionEvent::ModelRequestCompleted {
                        activation_id: identity.activation_id.clone(),
                        round_id: identity.round_id.clone(),
                        request_id: identity.request_id.clone(),
                        attempt_id: attempt_id.clone(),
                        usage: None,
                    },
                ));
            }
            events.push(EventDraft::new(
                format!("context-handoff-failure-event:{plan_id}"),
                SessionEvent::ContextHandoffFailed {
                    plan_id: plan_id.clone(),
                    error: error.clone(),
                    finished_at_ms,
                },
            ));
            events.push(EventDraft::new(
                format!("activation-finish-event:{activation_id}"),
                SessionEvent::ActivationFinished {
                    activation_id: activation_id.clone(),
                    outcome: ActivationOutcome::Failed,
                    finished_at_ms,
                },
            ));
            match store.append_verified_owned(&owner, &session_id, state, &command_id, &events) {
                Ok(appended) => return Ok((appended.append, appended.state)),
                Err(StoreError::OptimisticConcurrency { .. }) => continue,
                Err(StoreError::CommandIdempotencyConflict { .. }) => {
                    let state = store
                        .rehydrate_verified_owned(&owner, &session_id)
                        .map_err(|_| "context_handoff_failure_rehydrate")?;
                    if state.active_activation.is_none()
                        && state.pending_context_handoff.is_none()
                        && state.last_context_handoff_failure.as_ref() == Some(&error)
                    {
                        return Ok((replayed_append(&session_id, &command_id, &state), state));
                    }
                    return Err("context_handoff_failure_conflict");
                }
                Err(_) => return Err("context_handoff_failure_append"),
            }
        }
        Err("context_handoff_failure_concurrency")
    })
    .await
    .map_err(|_| "context_handoff_failure_join")?
}

pub(super) async fn append_model_lifecycle_failure(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    input: ModelFailureInput<'_>,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
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

pub(super) async fn append_model_attempts_exhausted(
    store: Arc<dyn EventStore>,
    clock: Arc<dyn Clock>,
    owner: SessionOwner,
    session_id: String,
    identity: &PreparedRequestIdentity,
    attempt_id: &str,
    attempt_number: u32,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
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
                .rehydrate_verified_owned(&owner, &session_id)
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
                finished_at_ms: clock.now_ms(),
            };
            match store.append_verified_owned(
                &owner,
                &session_id,
                state,
                &command_id,
                &[EventDraft::new(
                    event_id.clone(),
                    SessionEvent::ModelAttemptsExhausted { fact },
                )],
            ) {
                Ok(appended) => return Ok((appended.append, appended.state)),
                Err(StoreError::OptimisticConcurrency { .. }) => continue,
                Err(StoreError::CommandIdempotencyConflict { .. }) => {
                    let state = store
                        .rehydrate_verified_owned(&owner, &session_id)
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

pub(super) fn model_error_class(error: &ModelError) -> &'static str {
    match error {
        ModelError::Unavailable => "provider_unavailable",
        ModelError::InvalidSelection => "invalid_selection",
        ModelError::AuthReplicaUnavailable => "auth_replica_unavailable",
        ModelError::ProviderFailed => "provider_failed",
        ModelError::InvalidToolArguments => "invalid_tool_arguments",
    }
}

pub(super) fn terminal_model_error(error: &ModelError) -> (ModelAttemptErrorClass, &'static str) {
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

pub(super) fn terminal_model_error_class(
    error_class: &str,
) -> (ModelAttemptErrorClass, &'static str) {
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

pub(super) fn retry_delay_ms(base: Duration, maximum: Duration, attempt_number: u32) -> u64 {
    let exponent = attempt_number.saturating_sub(1).min(16);
    let multiplier = 1u64 << exponent;
    base.as_millis()
        .saturating_mul(multiplier as u128)
        .min(maximum.as_millis())
        .try_into()
        .unwrap_or(u64::MAX)
}

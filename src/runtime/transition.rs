use super::*;

pub(super) async fn materialize_boundary(
    store: Arc<dyn EventStore>,
    owner: SessionOwner,
    session_id: String,
    state: VerifiedSessionState,
) -> Result<(Option<AppendResult>, VerifiedSessionState), &'static str> {
    tokio::task::spawn_blocking(move || {
        materialize_boundary_blocking(&*store, &owner, &session_id, state)
    })
    .await
    .map_err(|_| "materialize_join")?
}

pub(super) fn materialize_boundary_blocking(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    mut state: VerifiedSessionState,
) -> Result<(Option<AppendResult>, VerifiedSessionState), &'static str> {
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
        match store.append_verified_owned(owner, session_id, state, &command_id, &drafts) {
            Ok(appended) => return Ok((Some(appended.append), appended.state)),
            Err(StoreError::OptimisticConcurrency { .. }) => {
                state = store
                    .rehydrate_verified_owned(owner, session_id)
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

pub(super) fn materialize_message(
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

pub(super) async fn append_tool_batch(
    store: Arc<dyn EventStore>,
    clock: Arc<dyn Clock>,
    owner: SessionOwner,
    session_id: String,
    state: VerifiedSessionState,
    input: ToolBatchInput,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
    tokio::task::spawn_blocking(move || {
        append_tool_batch_blocking(&*store, &*clock, &owner, &session_id, state, &input)
    })
    .await
    .map_err(|_| "tool_batch_join")?
}

pub(super) fn append_tool_batch_blocking(
    store: &dyn EventStore,
    clock: &dyn Clock,
    owner: &SessionOwner,
    session_id: &str,
    mut state: VerifiedSessionState,
    input: &ToolBatchInput,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
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
    let definitions_by_name = definitions
        .iter()
        .map(|definition| (definition.name.as_str(), definition))
        .collect::<HashMap<_, _>>();
    let callback_plans_by_id = callback_plans
        .iter()
        .map(|plan| (plan.tool_call_id.as_str(), plan))
        .collect::<HashMap<_, _>>();
    for _ in 0..16 {
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
        let started_at_ms = clock.now_ms();
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
            let definition = definitions_by_name.get(call.tool_name.as_str());
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
                retry_dispatch_deduplicated: definition.is_some_and(|definition| {
                    definition.retry_dispatch == RetryDispatchPolicy::SameInvocationKeyDeduplicated
                }),
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
                let Some(plan) = callback_plans_by_id.get(call.tool_call_id.as_str()) else {
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
        match store.append_verified_owned(owner, session_id, state, &command_id, &drafts) {
            Ok(appended) => return Ok((appended.append, appended.state)),
            Err(StoreError::OptimisticConcurrency { .. }) => {
                state = store
                    .rehydrate_verified_owned(owner, session_id)
                    .map_err(|_| "tool_batch_rehydrate")?;
            }
            Err(_) => return Err("tool_batch_append"),
        }
    }
    Err("tool_batch_concurrency")
}

pub(super) async fn append_tool_results(
    store: Arc<dyn EventStore>,
    clock: Arc<dyn Clock>,
    owner: SessionOwner,
    session_id: String,
    state: VerifiedSessionState,
    input: ToolResultsInput,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
    tokio::task::spawn_blocking(move || {
        append_tool_results_blocking(&*store, &*clock, &owner, &session_id, state, &input)
    })
    .await
    .map_err(|_| "tool_results_join")?
}

pub(super) fn append_tool_results_blocking(
    store: &dyn EventStore,
    clock: &dyn Clock,
    owner: &SessionOwner,
    session_id: &str,
    mut state: VerifiedSessionState,
    input: &ToolResultsInput,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
    let batch_identity = input.batch_identity.as_str();
    let tool_calls = input.tool_calls.as_slice();
    let results = input.results.as_slice();
    let result_message_ids = tool_calls
        .iter()
        .map(|call| tool_result_message_id(batch_identity, &call.tool_call_id))
        .collect::<Vec<_>>();
    for _ in 0..16 {
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
                final_wait = parse_wait(call, clock).ok();
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
                                completed_at_ms: clock.now_ms(),
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
                            completed_at_ms: clock.now_ms(),
                        },
                    )),
                }
            }
        }
        if saw_wait {
            if let Some(wait) = final_wait {
                drafts.push(EventDraft::new(
                    format!("wait-set:v1:{batch_identity}"),
                    SessionEvent::WaitSet { wait: wait.clone() },
                ));
                drafts.push(EventDraft::new(
                    format!("wait-timer:v1:{batch_identity}"),
                    SessionEvent::WaitTimerScheduled {
                        timer: crate::domain::WaitTimerIntent {
                            wait_id: wait.wait_id,
                            deadline_ms: wait.deadline_ms,
                        },
                    },
                ));
            }
        }
        if !async_tool_ids.is_empty() {
            if let Some(timeout_seconds) = async_timeout_seconds {
                let wait = ActiveWait {
                    wait_id: stable_digest("auto-wait", batch_identity),
                    reason: "waiting for asynchronous tool completion".to_owned(),
                    timeout_seconds,
                    deadline_ms: clock
                        .now_ms()
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
        match store.append_verified_owned(owner, session_id, state, &command_id, &drafts) {
            Ok(appended) => return Ok((appended.append, appended.state)),
            Err(StoreError::OptimisticConcurrency { .. }) => {
                state = store
                    .rehydrate_verified_owned(owner, session_id)
                    .map_err(|_| "tool_results_rehydrate")?;
            }
            Err(_) => return Err("tool_results_append"),
        }
    }
    Err("tool_results_concurrency")
}

pub(super) fn append_background_tool_result_blocking(
    store: &dyn EventStore,
    clock: &dyn Clock,
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
        let completed_at_ms = clock.now_ms();
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
        // The terminal async-tool event is the sole durable authority for the
        // result, status, and error.  The wakeable delivery carries only the
        // fields needed to materialize the next runtime transcript message;
        // copying the result here can make one otherwise-bounded inline tool
        // response exceed the delivery envelope bound.
        let delivery_payload = DurablePayload::inline(json!({
            "message_id": message_id.clone(),
            "content": content.clone(),
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
        match store.append_owned(owner, session_id, &state, &command_id, &drafts) {
            Ok(appended) => return Ok(Some((appended.append, appended.state.into_state()))),
            Err(StoreError::OptimisticConcurrency { .. }) => continue,
            Err(StoreError::CommandIdempotencyConflict { .. })
            | Err(StoreError::EventIdempotencyConflict { .. }) => continue,
            Err(_) => return Err("background_tool_append"),
        }
    }
    Err("background_tool_concurrency")
}

pub(super) fn parse_wait(call: &ToolCall, clock: &dyn Clock) -> Result<ActiveWait, &'static str> {
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
    let deadline_ms = clock
        .now_ms()
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

pub(super) fn tool_result_message_id(batch_identity: &str, tool_call_id: &str) -> String {
    format!(
        "tool-result:v1:{}",
        stable_digest("tool-result", &format!("{batch_identity}:{tool_call_id}"))
    )
}

pub(super) fn replayed_append(
    session_id: &str,
    command_id: &str,
    state: &SessionState,
) -> AppendResult {
    AppendResult {
        stream_id: session_id.to_owned(),
        command_id: command_id.to_owned(),
        events: Vec::new(),
        stream_version: state.stream_version,
        replayed: true,
    }
}

pub(super) fn materialization_event_id(delivery: &crate::domain::QueuedDelivery) -> String {
    format!(
        "delivery-materialized:v1:{}",
        stable_digest("materialized", &delivery.delivery_id)
    )
}

pub(super) fn acknowledgement_event_id(queue_id: u64) -> String {
    format!("delivery-acknowledged:v1:{queue_id}")
}

pub(super) async fn append_assistant(
    store: Arc<dyn EventStore>,
    clock: Arc<dyn Clock>,
    owner: SessionOwner,
    session_id: String,
    state: VerifiedSessionState,
    trigger_message_id: String,
    content: String,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
    tokio::task::spawn_blocking(move || {
        append_assistant_blocking(
            &*store,
            &*clock,
            &owner,
            &session_id,
            state,
            &trigger_message_id,
            &content,
        )
    })
    .await
    .map_err(|_| "assistant_join")?
}

pub(super) fn append_assistant_blocking(
    store: &dyn EventStore,
    clock: &dyn Clock,
    owner: &SessionOwner,
    session_id: &str,
    mut state: VerifiedSessionState,
    trigger_message_id: &str,
    content: &str,
) -> Result<(AppendResult, VerifiedSessionState), &'static str> {
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
                        finished_at_ms: clock.now_ms(),
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
        match store.append_verified_owned(owner, session_id, state, &command_id, &drafts) {
            Ok(appended) => return Ok((appended.append, appended.state)),
            Err(StoreError::OptimisticConcurrency { .. }) => {
                state = store
                    .rehydrate_verified_owned(owner, session_id)
                    .map_err(|_| "assistant_rehydrate")?;
            }
            Err(_) => return Err("assistant_append"),
        }
    }
    Err("assistant_concurrency")
}

pub(super) fn assistant_identity(
    owner: &SessionOwner,
    session_id: &str,
    trigger_message_id: &str,
) -> String {
    stable_digest(
        "assistant",
        &format!(
            "{}\u{0}{}\u{0}{}\u{0}{}",
            owner.authority_id, owner.subject, session_id, trigger_message_id
        ),
    )
}

pub(super) fn assistant_result_message_id(
    owner: &SessionOwner,
    session_id: &str,
    trigger_message_id: &str,
    has_tool_calls: bool,
) -> String {
    let identity = assistant_identity(owner, session_id, trigger_message_id);
    if has_tool_calls {
        format!("assistant-tool:v1:{identity}")
    } else {
        format!("assistant:v1:{identity}")
    }
}

pub(super) fn model_failure_identity(
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

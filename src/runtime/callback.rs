use super::*;

pub(super) fn canonical_callback_payload(payload: &Value) -> Result<String, RuntimeCommandError> {
    let mut bytes = Vec::new();
    write_canonical_callback_json(payload, &mut bytes)?;
    String::from_utf8(bytes).map_err(|_| RuntimeCommandError::Invalid("callback_payload"))
}

pub(super) fn write_canonical_callback_json(
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

pub(super) fn complete_external_callback_blocking(
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
            &lookup.state,
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

pub(super) fn cancel_tool_call_blocking(
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
            &state,
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
            Ok(appended) => {
                return appended
                    .state
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

pub(super) fn reconcile_tool_call_blocking(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    tool_call_id: &str,
    command_id: &str,
) -> Result<(AsyncToolCallRecord, Option<(AppendResult, SessionState)>), RuntimeCommandError> {
    for _ in 0..16 {
        let state = store
            .rehydrate_owned(owner, session_id)
            .map_err(|_| RuntimeCommandError::NotFound)?;
        let Some(record) = state.async_tool_calls.get(tool_call_id).cloned() else {
            return Err(RuntimeCommandError::NotFound);
        };
        if !record.retry_dispatch_deduplicated
            || record.completion_mode != CompletionMode::ProcessLocal
        {
            return Err(RuntimeCommandError::Conflict);
        }
        let event_id = format!("tool-retry-dispatch:{tool_call_id}:{command_id}");
        match store.append_owned(
            owner,
            session_id,
            &state,
            command_id,
            &[EventDraft::new(
                event_id,
                SessionEvent::AsyncToolCallRunning {
                    tool_call_id: tool_call_id.to_owned(),
                },
            )],
        ) {
            Ok(appended) => {
                let record = appended
                    .state
                    .async_tool_calls
                    .get(tool_call_id)
                    .cloned()
                    .ok_or(RuntimeCommandError::NotFound)?;
                let admitted =
                    (!appended.append.replayed).then_some((appended.append, appended.state));
                return Ok((record, admitted));
            }
            Err(StoreError::OptimisticConcurrency { .. }) => continue,
            Err(StoreError::Domain(_))
            | Err(StoreError::CommandIdempotencyConflict { .. })
            | Err(StoreError::EventIdempotencyConflict { .. }) => {
                return Err(RuntimeCommandError::Conflict)
            }
            Err(_) => return Err(RuntimeCommandError::Backend),
        }
    }
    Err(RuntimeCommandError::Conflict)
}

pub(super) fn append_retry_dispatch_unknown_blocking(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    batch_identity: &str,
    tool_call_id: &str,
) -> Result<Option<(AppendResult, SessionState)>, &'static str> {
    for _ in 0..16 {
        let state = store
            .rehydrate_owned(owner, session_id)
            .map_err(|_| "retry_dispatch_unknown_rehydrate")?;
        let Some(record) = state.async_tool_calls.get(tool_call_id) else {
            return Ok(None);
        };
        if record.status != AsyncToolStatus::Running {
            return Ok(None);
        }
        let command_id = format!("tool-retry-unknown-command:v1:{batch_identity}:{tool_call_id}");
        let event_id = format!("tool-retry-unknown-event:v1:{batch_identity}:{tool_call_id}");
        match store.append_owned(
            owner,
            session_id,
            &state,
            &command_id,
            &[EventDraft::new(
                event_id,
                SessionEvent::AsyncToolCallUnknownOutcome {
                    tool_call_id: tool_call_id.to_owned(),
                    reason: "retry_dispatch_uncertain".to_owned(),
                },
            )],
        ) {
            Ok(appended) => return Ok(Some((appended.append, appended.state))),
            Err(StoreError::OptimisticConcurrency { .. }) => continue,
            Err(StoreError::CommandIdempotencyConflict { .. })
            | Err(StoreError::EventIdempotencyConflict { .. }) => return Ok(None),
            Err(_) => return Err("retry_dispatch_unknown_append"),
        }
    }
    Err("retry_dispatch_unknown_concurrency")
}

pub(super) fn parse_callback_payload(
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

pub(super) fn callback_public_body(record: Option<&AsyncToolCallRecord>) -> Value {
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

pub(super) fn callback_body(
    is_failure: bool,
    result: &Value,
    error: Option<&DomainToolError>,
) -> Value {
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

pub(super) fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        diff |= usize::from(left.get(index).copied().unwrap_or_default())
            ^ usize::from(right.get(index).copied().unwrap_or_default());
    }
    diff == 0
}

use super::*;
use std::collections::{HashMap, HashSet};

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
            pending_context_handoff: None,
            latest_context_handoff: None,
            latest_model_usage: None,
            last_context_handoff_failure: None,
            callback_bindings: BTreeMap::new(),
            last_model_attempts_exhausted: None,
            stream_version: 0,
            dedupe_facts: DedupeFacts::default(),
        }
    }

    pub fn apply_event(&self, event: &SessionEvent) -> Result<Self, DomainError> {
        self.validate()?;
        let next = self.apply_event_from_valid_state(event)?;
        next.validate()?;
        Ok(next)
    }

    /// Apply one event to a projection whose complete invariants were already
    /// verified by the caller.
    ///
    /// Storage uses this only while carrying its opaque verified projection
    /// through one append transaction. Public reducer entry points continue to
    /// validate both the input and the resulting state. Event-local checks stay
    /// here so a verified projection cannot admit an invalid transition merely
    /// because its unchanged history was not scanned again.
    pub(crate) fn apply_event_from_valid_state(
        &self,
        event: &SessionEvent,
    ) -> Result<Self, DomainError> {
        self.clone().apply_event_from_valid_state_owned(event)
    }

    pub(crate) fn apply_event_from_valid_state_owned(
        mut self,
        event: &SessionEvent,
    ) -> Result<Self, DomainError> {
        self.validate_event_position(event)?;
        event.validate()?;
        if !self.apply_payload(event)? {
            return Ok(self);
        }
        // Validate the projected state at the version that the event will
        // occupy. Creation installs owner/timestamp/selection while the
        // input projection still has stream_version zero; validating before
        // advancing would classify that legitimate transition as an
        // uncreated state. No-op transitions return above and retain the
        // caller's version for reducer-level idempotency filtering.
        self.stream_version = self
            .stream_version
            .checked_add(1)
            .ok_or(DomainError::VersionOverflow)?;
        Ok(self)
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
        self.clone().apply_record_from_valid_state_owned(record)
    }

    pub(crate) fn apply_record_from_valid_state_owned(
        mut self,
        record: &EventRecord,
    ) -> Result<Self, DomainError> {
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
        self.apply_payload(&record.event)?;
        self.stream_version = record.stream_version;
        self.dedupe_facts.remember(event_key);
        self.validate()?;
        Ok(self)
    }

    /// Attach the immutable event identity after storage has committed an
    /// event whose semantic payload was already reduced with `apply_event`.
    ///
    /// Storage uses this to carry one batch projection through the append
    /// transaction instead of reducing every event a second time after its
    /// row receives a global position. Global position and command identity
    /// do not participate in the session projection; the event ID is the only
    /// record-level fact retained by `SessionState`.
    pub(crate) fn remember_committed_event_id(
        &mut self,
        event_id: &str,
    ) -> Result<(), DomainError> {
        validate_identifier("event_id", event_id)?;
        let event_key = format!("event:{event_id}");
        if self.dedupe_facts.contains(&event_key) {
            return Err(DomainError::DuplicateEventId(event_id.to_owned()));
        }
        self.dedupe_facts.remember(event_key);
        Ok(())
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
        let mut message_ids = HashSet::with_capacity(self.transcript.len());
        let mut user_message_ids = HashSet::new();
        let mut declared_tool_calls = HashMap::new();
        for message in &self.transcript {
            validate_message(message)?;
            if !message_ids.insert(message.message_id.as_str()) {
                return Err(DomainError::ConflictingTranscriptMessage(
                    message.message_id.clone(),
                ));
            }
            if message.role == TranscriptRole::User {
                user_message_ids.insert(message.message_id.as_str());
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
            if !user_message_ids.contains(failure.trigger_message_id.as_str()) {
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
        if let Some(plan) = &self.pending_context_handoff {
            validate_context_handoff_plan(plan)?;
            let Some(activation) = &self.active_activation else {
                return Err(DomainError::InvalidState(
                    "pending context handoff requires an active activation".into(),
                ));
            };
            if plan.activation_id != activation.activation_id
                || activation.selection.model.as_ref() != Some(&plan.selection)
            {
                return Err(DomainError::InvalidState(
                    "pending context handoff belongs to another activation".into(),
                ));
            }
            if plan.previous_handoff_id.as_deref()
                != self
                    .latest_context_handoff
                    .as_ref()
                    .map(|handoff| handoff.handoff_id.as_str())
            {
                return Err(DomainError::InvalidState(
                    "pending context handoff has a stale parent".into(),
                ));
            }
            let expected_generation = self
                .latest_context_handoff
                .as_ref()
                .map_or(2, |handoff| handoff.next_generation.saturating_add(1));
            if plan.next_generation != expected_generation {
                return Err(DomainError::InvalidState(
                    "pending context handoff has an invalid generation".into(),
                ));
            }
            if !message_ids.contains(plan.covered_through_message_id.as_str()) {
                return Err(DomainError::InvalidState(
                    "pending context handoff boundary is absent from history".into(),
                ));
            }
        }
        if let Some(handoff) = &self.latest_context_handoff {
            validate_context_handoff_document(handoff)?;
            if !message_ids.contains(handoff.covered_through_message_id.as_str()) {
                return Err(DomainError::InvalidState(
                    "context handoff boundary is absent from history".into(),
                ));
            }
        }
        if let Some(usage) = &self.latest_model_usage {
            validate_model_usage_anchor(usage)?;
        }
        if let Some(error) = &self.last_context_handoff_failure {
            validate_model_error(error)?;
        }
        if let Some(round) = &self.active_model_round {
            match round.purpose {
                ModelRequestPurpose::Conversation => {
                    let completed = round
                        .attempt
                        .as_ref()
                        .is_some_and(|attempt| attempt.outcome == ModelAttemptOutcome::Completed);
                    if self.pending_context_handoff.is_some() && !completed {
                        return Err(DomainError::InvalidState(
                            "pending context handoff requires a handoff round".into(),
                        ));
                    }
                }
                ModelRequestPurpose::ContextHandoff => {
                    let completed = round
                        .attempt
                        .as_ref()
                        .is_some_and(|attempt| attempt.outcome == ModelAttemptOutcome::Completed);
                    if self.pending_context_handoff.is_none()
                        && !completed
                        && self.last_context_handoff_failure.is_none()
                    {
                        return Err(DomainError::InvalidState(
                            "active context handoff round has no durable plan".into(),
                        ));
                    }
                }
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
        let mut callback_tool_ids = HashSet::with_capacity(self.callback_bindings.len());
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

    fn apply_payload(&mut self, event: &SessionEvent) -> Result<bool, DomainError> {
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
            SessionEvent::StatusChanged { status } => {
                if self.status == *status {
                    return Ok(false);
                }
                self.status = status.clone();
            }
            SessionEvent::DeliveryQueued { delivery } => {
                if delivery.queue_id <= self.delivery_ack {
                    return Ok(false);
                }
                if let Some(existing) = self
                    .delivery_queue
                    .iter()
                    .find(|queued| queued.queue_id == delivery.queue_id)
                {
                    if existing == delivery {
                        return Ok(false);
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
                    return Ok(false);
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
                    return Ok(false);
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
                        return Ok(false);
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
                        return Ok(false);
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
                    return Ok(false);
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
                    legacy_rounds_started: 0,
                });
                self.active_model_round = None;
            }
            SessionEvent::ModelRoundStarted {
                activation_id,
                round_id,
                purpose,
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
                activation.legacy_rounds_started =
                    activation.legacy_rounds_started.saturating_add(1);
                self.active_model_round = Some(ActiveModelRound {
                    activation_id: activation_id.clone(),
                    round_id: round_id.clone(),
                    purpose: purpose.clone(),
                    delivery_through_queue_id: *delivery_through_queue_id,
                    started_at_ms: *started_at_ms,
                    request: None,
                    attempt: None,
                    retry: None,
                });
            }
            SessionEvent::ContextHandoffPlanned { plan } => {
                let activation = self.active_activation.as_ref().ok_or_else(|| {
                    DomainError::InvalidState(
                        "context handoff plan has no active activation".into(),
                    )
                })?;
                if plan.activation_id != activation.activation_id
                    || activation.selection.model.as_ref() != Some(&plan.selection)
                {
                    return Err(DomainError::InvalidState(
                        "context handoff plan belongs to another activation".into(),
                    ));
                }
                if plan.previous_handoff_id.as_deref()
                    != self
                        .latest_context_handoff
                        .as_ref()
                        .map(|handoff| handoff.handoff_id.as_str())
                {
                    return Err(DomainError::InvalidState(
                        "context handoff plan has a stale parent".into(),
                    ));
                }
                let expected_generation = self
                    .latest_context_handoff
                    .as_ref()
                    .map_or(2, |handoff| handoff.next_generation.saturating_add(1));
                if plan.next_generation != expected_generation {
                    return Err(DomainError::InvalidState(
                        "context handoff plan has an invalid generation".into(),
                    ));
                }
                if !self
                    .transcript
                    .iter()
                    .any(|message| message.message_id == plan.covered_through_message_id)
                {
                    return Err(DomainError::InvalidState(
                        "context handoff plan boundary is absent from history".into(),
                    ));
                }
                if let Some(existing) = &self.pending_context_handoff {
                    if existing == plan {
                        return Ok(false);
                    }
                    return Err(DomainError::InvalidState(
                        "context handoff already has a pending plan".into(),
                    ));
                }
                self.pending_context_handoff = Some(plan.clone());
                self.last_context_handoff_failure = None;
            }
            SessionEvent::ContextHandoffCreated { handoff } => {
                let plan = self.pending_context_handoff.as_ref().ok_or_else(|| {
                    DomainError::InvalidState("context handoff document has no pending plan".into())
                })?;
                if handoff.plan_id != plan.plan_id
                    || handoff.previous_handoff_id != plan.previous_handoff_id
                    || handoff.next_generation != plan.next_generation
                    || handoff.covered_through_message_id != plan.covered_through_message_id
                    || handoff.source_digest != plan.source_digest
                    || handoff.source_tokens != plan.source_tokens
                    || handoff.token_accounting_version != plan.token_accounting_version
                    || handoff.selection != plan.selection
                {
                    return Err(DomainError::InvalidState(
                        "context handoff document conflicts with its durable plan".into(),
                    ));
                }
                if let Some(existing) = &self.latest_context_handoff {
                    if existing.handoff_id == handoff.handoff_id && existing == handoff {
                        self.pending_context_handoff = None;
                        return Ok(true);
                    }
                    if Some(existing.handoff_id.as_str()) != handoff.previous_handoff_id.as_deref()
                    {
                        return Err(DomainError::InvalidState(
                            "context handoff document has a stale parent".into(),
                        ));
                    }
                }
                self.latest_context_handoff = Some(handoff.clone());
                self.latest_model_usage = None;
                self.pending_context_handoff = None;
                self.last_context_handoff_failure = None;
            }
            SessionEvent::ContextHandoffFailed { plan_id, error, .. } => {
                let plan = self.pending_context_handoff.as_ref().ok_or_else(|| {
                    DomainError::InvalidState("context handoff failure has no pending plan".into())
                })?;
                if plan.plan_id != *plan_id {
                    return Err(DomainError::InvalidState(
                        "context handoff failure belongs to another plan".into(),
                    ));
                }
                self.pending_context_handoff = None;
                self.last_context_handoff_failure = Some(error.clone());
            }
            SessionEvent::ModelRequestDeclared {
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
            | SessionEvent::ModelRequestPrepared {
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
                round.request = Some(ModelRequestFact {
                    activation_id: activation_id.clone(),
                    round_id: round_id.clone(),
                    request_id: request_id.clone(),
                    request_fingerprint: request_fingerprint.clone(),
                    provider_execution_fingerprint: provider_execution_fingerprint.clone(),
                    prompt_fingerprint: prompt_fingerprint.clone(),
                    tool_schema_fingerprint: tool_schema_fingerprint.clone(),
                    legacy_envelope: match event {
                        SessionEvent::ModelRequestPrepared { envelope, .. } => {
                            Some(envelope.clone())
                        }
                        SessionEvent::ModelRequestDeclared { .. } => None,
                        _ => unreachable!("model request declaration arm"),
                    },
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
                    DomainError::InvalidState("model attempt has no declared request".into())
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
                        "model attempt exceeds declared request budget".into(),
                    ));
                }
                if let Some(existing) = &round.attempt {
                    if existing.attempt_id == *attempt_id
                        && existing.attempt_number == *attempt_number
                    {
                        return Ok(false);
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
                    ModelAttemptOutcome::Failed => return Ok(false),
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
                    ModelAttemptOutcome::Interrupted => return Ok(false),
                    _ => {
                        return Err(DomainError::InvalidState(
                            "model attempt interruption is not first-wins".into(),
                        ))
                    }
                }
            }
            SessionEvent::ModelRequestAbandoned {
                activation_id,
                round_id,
                request_id,
                attempt_id,
                ..
            } => {
                let round = self.active_model_round.as_ref().ok_or_else(|| {
                    DomainError::InvalidState("abandonment has no active model round".into())
                })?;
                let request = round.request.as_ref().ok_or_else(|| {
                    DomainError::InvalidState("abandonment has no declared request".into())
                })?;
                let attempt = round.attempt.as_ref().ok_or_else(|| {
                    DomainError::InvalidState("abandonment has no model attempt".into())
                })?;
                if round.activation_id != *activation_id
                    || round.round_id != *round_id
                    || request.request_id != *request_id
                    || attempt.attempt_id != *attempt_id
                {
                    return Err(DomainError::InvalidState(
                        "abandonment belongs to another model request".into(),
                    ));
                }
                if !matches!(
                    attempt.outcome,
                    ModelAttemptOutcome::Failed | ModelAttemptOutcome::Interrupted
                ) {
                    return Err(DomainError::InvalidState(
                        "only a failed or interrupted model request can be abandoned".into(),
                    ));
                }
                self.active_model_round = None;
            }
            SessionEvent::ModelAttemptsExhausted { fact } => {
                if let Some(existing) = &self.last_model_attempts_exhausted {
                    if existing == fact {
                        return Ok(false);
                    }
                    if existing.activation_id == fact.activation_id {
                        return Err(DomainError::InvalidState(
                            "model exhaustion has conflicting semantics".into(),
                        ));
                    }
                }
                let round = self.active_model_round.as_ref().ok_or_else(|| {
                    DomainError::InvalidState("model exhaustion has no active round".into())
                })?;
                let request = round.request.as_ref().ok_or_else(|| {
                    DomainError::InvalidState("model exhaustion has no declared request".into())
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
                        return Ok(false);
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
                usage,
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
                    ModelAttemptOutcome::Completed => return Ok(false),
                    _ => {
                        return Err(DomainError::InvalidState(
                            "model completion requires a running attempt".into(),
                        ))
                    }
                }
                if round.purpose == ModelRequestPurpose::Conversation {
                    if let Some(usage) = usage {
                        self.latest_model_usage = Some(usage.clone());
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
                            return Ok(false);
                        }
                        return Err(DomainError::InvalidState(
                            "current user message has conflicting terminal model failures".into(),
                        ));
                    }
                }
                self.last_model_attempt_failure = Some(failure.clone());
            }
            SessionEvent::WaitSet { wait } => {
                if self.active_wait.as_ref() == Some(wait)
                    && self.active_timer.is_none()
                    && self.wake_pending_wait_id.is_none()
                {
                    return Ok(false);
                }
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
                if self.active_timer.as_ref() == Some(timer) {
                    return Ok(false);
                }
                self.active_timer = Some(timer.clone());
            }
            SessionEvent::WaitCleared { wait_id } | SessionEvent::WaitExpired { wait_id } => {
                if self.wake_pending_wait_id.as_deref() == Some(wait_id.as_str()) {
                    return Ok(false);
                }
                if self
                    .active_wait
                    .as_ref()
                    .is_some_and(|wait| wait.wait_id == *wait_id)
                {
                    self.active_wait = None;
                    self.active_timer = None;
                    self.wake_pending_wait_id = None;
                } else {
                    return Ok(false);
                }
            }
            SessionEvent::AsyncToolCallStarted { record } => {
                if let Some(existing) = self.async_tool_calls.get(&record.tool_call_id) {
                    if existing == record {
                        return Ok(false);
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
                    AsyncToolStatus::Running => return Ok(false),
                    AsyncToolStatus::UnknownOutcome if record.retry_dispatch_deduplicated => {
                        record.status = AsyncToolStatus::Running
                    }
                    _ => {
                        return Err(DomainError::InvalidState(
                            "only a planned or safely reconcilable tool call can become running"
                                .into(),
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
                    AsyncToolStatus::UnknownOutcome => return Ok(false),
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
                    return Ok(false);
                }
                if record.status.is_terminal() {
                    return Ok(false);
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
                        return Ok(false);
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
                        return Ok(false);
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
                        return Ok(false);
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
                    return Ok(false);
                }
                if record.progress.as_ref() == Some(progress) {
                    return Ok(false);
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
                    return Ok(false);
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
                    return Ok(false);
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
                    return Ok(false);
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
            SessionEvent::DedupeRecorded { key } => {
                let changed = self.dedupe_facts.recent_keys.back() != Some(key);
                self.dedupe_facts.remember(key.clone());
                if !changed {
                    return Ok(false);
                }
            }
        }
        Ok(true)
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

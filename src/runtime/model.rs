use super::*;

#[derive(Debug)]
pub struct ModelRequest {
    pub owner: SessionOwner,
    pub session_id: String,
    pub activation_id: String,
    pub round_id: String,
    pub selection: SessionModelSelection,
    pub transcript: Arc<Vec<TranscriptMessage>>,
    pub tools: Arc<Vec<ToolDefinition>>,
    pub(crate) prompt_fingerprint: String,
    pub(crate) tool_schema_fingerprint: String,
    pub max_output_tokens: Option<u32>,
    pub handoff_document_tokens: Option<u32>,
    pub stream_idle_timeout: Duration,
    pub stream_observer: Arc<dyn ModelStreamObserver>,
}

pub(super) struct PreparedConversationContext {
    transcript: Arc<Vec<TranscriptMessage>>,
    tools: Arc<Vec<ToolDefinition>>,
    local_input_estimate_tokens: u64,
    estimated_input_tokens: u64,
    selection_fingerprint: String,
    prompt_fingerprint: String,
    tool_schema_fingerprint: String,
}

pub(super) const MAX_CONTEXT_HANDOFF_DOCUMENT_TOKENS: u32 = 60 * 1024;
const CONTEXT_HANDOFF_DOCUMENT_SCHEMA: &str = "zode.context-handoff-document.v1";
pub(super) const MAX_CONTEXT_HANDOFF_GENERATION_TOKENS: u32 = 256 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextHandoffModelDocument {
    schema: String,
    document: String,
}

#[derive(Clone, Debug)]
pub struct ModelOutcome {
    pub text: String,
    pub tool_calls: Vec<ToolCall>,
    pub usage: Option<ModelTokenUsage>,
}

#[derive(Clone, Debug)]
pub struct ModelTokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

struct PreparedModelRequestInput<'a> {
    owner: &'a SessionOwner,
    session_id: &'a str,
    auth_revision: u64,
    state: VerifiedSessionState,
    request: ModelRequest,
    identity: &'a PreparedRequestIdentity,
    purpose: ModelRequestPurpose,
}

impl Runtime {
    pub(super) async fn recover_model_round(
        self: &Arc<Self>,
        owner: SessionOwner,
        session_id: String,
        state: VerifiedSessionState,
    ) -> Result<VerifiedSessionState, &'static str> {
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
        let abandoned_at_ms = current_time_ms();
        let recovered = append_runtime_events(
            self.store.clone(),
            owner,
            session_id,
            format!("model-request-abandon-after-restart:{}", attempt.attempt_id),
            vec![
                EventDraft::new(
                    format!("model-attempt-interrupted-event:{}", attempt.attempt_id),
                    SessionEvent::ModelAttemptInterrupted {
                        activation_id: attempt.activation_id.clone(),
                        round_id: attempt.round_id.clone(),
                        request_id: attempt.request_id.clone(),
                        attempt_id: attempt.attempt_id.clone(),
                        attempt_number: attempt.attempt_number,
                        reason: "runtime_restarted".to_owned(),
                    },
                ),
                EventDraft::new(
                    format!("model-request-abandoned-event:{}", attempt.attempt_id),
                    SessionEvent::ModelRequestAbandoned {
                        activation_id: attempt.activation_id,
                        round_id: attempt.round_id,
                        request_id: attempt.request_id,
                        attempt_id: attempt.attempt_id,
                        reason: "runtime_restarted".to_owned(),
                        abandoned_at_ms,
                    },
                ),
            ],
        )
        .await?;
        self.observe_commit(&recovered.0, &recovered.1).await;
        Ok(recovered.1)
    }

    async fn recover_failed_model_round(
        self: &Arc<Self>,
        owner: SessionOwner,
        session_id: String,
        mut state: VerifiedSessionState,
        attempt: crate::domain::ModelAttemptRecord,
    ) -> Result<VerifiedSessionState, &'static str> {
        let Some(request) = state
            .active_model_round
            .as_ref()
            .and_then(|round| round.request.clone())
        else {
            return Ok(state);
        };
        let purpose = state
            .active_model_round
            .as_ref()
            .map(|round| round.purpose.clone())
            .ok_or("model_round_missing")?;
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
            let (error_class, error_message) = terminal_model_error_class(&failure.error_class);
            return self
                .finish_model_execution_failure(
                    &owner,
                    &session_id,
                    state,
                    purpose,
                    error_class,
                    error_message,
                )
                .await;
        }

        let abandoned = append_runtime_event(
            self.store.clone(),
            owner,
            session_id,
            format!("model-request-abandon-after-restart:{}", attempt.attempt_id),
            format!("model-request-abandoned-event:{}", attempt.attempt_id),
            SessionEvent::ModelRequestAbandoned {
                activation_id: attempt.activation_id,
                round_id: attempt.round_id,
                request_id: attempt.request_id,
                attempt_id: attempt.attempt_id,
                reason: "runtime_restarted_after_retryable_failure".to_owned(),
                abandoned_at_ms: current_time_ms(),
            },
        )
        .await?;
        self.observe_commit(&abandoned.0, &abandoned.1).await;
        Ok(abandoned.1)
    }

    pub(super) async fn recover_async_tools(
        self: &Arc<Self>,
        owner: SessionOwner,
        session_id: String,
        mut state: VerifiedSessionState,
    ) -> Result<VerifiedSessionState, &'static str> {
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

    async fn execute_prepared_model_request(
        self: &Arc<Self>,
        input: PreparedModelRequestInput<'_>,
    ) -> Result<PreparedModelExecution, &'static str> {
        let PreparedModelRequestInput {
            owner,
            session_id,
            auth_revision,
            mut state,
            request,
            identity: request_identity,
            purpose,
        } = input;
        let request_id = request_identity.request_id.clone();
        let mut attempt_number = request_identity.attempt_number;
        let mut attempt_id = request_identity.attempt_id.clone();
        loop {
            let completion = self.model.complete(&request).await.and_then(|value| {
                if validate_tool_calls(&value.tool_calls, &request.tools).is_ok() {
                    Ok(value)
                } else {
                    Err(ModelError::InvalidToolArguments)
                }
            });
            match completion {
                Ok(outcome) => {
                    return Ok(PreparedModelExecution {
                        state,
                        completion: PreparedModelCompletion::Completed {
                            outcome,
                            attempt_id,
                        },
                    });
                }
                Err(ModelError::AuthReplicaUnavailable) => {
                    let failure = append_model_lifecycle_failure(
                        self.store.clone(),
                        owner.clone(),
                        session_id.to_owned(),
                        ModelFailureInput {
                            identity: request_identity,
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
                            request_identity,
                            &attempt_id,
                            attempt_number,
                        )
                        .await?;
                        self.observe_commit(&exhausted.0, &exhausted.1).await;
                        current_state = exhausted.1;
                    }
                    let terminal = self
                        .finish_model_execution_failure(
                            owner,
                            session_id,
                            current_state,
                            purpose,
                            ModelAttemptErrorClass::AuthReplicaUnavailable,
                            "credential replica unavailable",
                        )
                        .await?;
                    return Ok(PreparedModelExecution {
                        state: terminal,
                        completion: PreparedModelCompletion::Terminal,
                    });
                }
                Err(error) => {
                    let error_class = model_error_class(&error);
                    let failed = append_model_lifecycle_failure(
                        self.store.clone(),
                        owner.clone(),
                        session_id.to_owned(),
                        ModelFailureInput {
                            identity: request_identity,
                            attempt_id: &attempt_id,
                            attempt_number,
                            error_class,
                            retryable: attempt_number < request_identity.maximum_attempts,
                        },
                    )
                    .await?;
                    self.observe_commit(&failed.0, &failed.1).await;
                    state = failed.1.clone();
                    if attempt_number >= request_identity.maximum_attempts {
                        let exhausted = append_model_attempts_exhausted(
                            self.store.clone(),
                            owner.clone(),
                            session_id.to_owned(),
                            request_identity,
                            &attempt_id,
                            attempt_number,
                        )
                        .await?;
                        self.observe_commit(&exhausted.0, &exhausted.1).await;
                        let (terminal_class, terminal_message) = terminal_model_error(&error);
                        let terminal = self
                            .finish_model_execution_failure(
                                owner,
                                session_id,
                                exhausted.1,
                                purpose,
                                terminal_class,
                                terminal_message,
                            )
                            .await?;
                        return Ok(PreparedModelExecution {
                            state: terminal,
                            completion: PreparedModelCompletion::Terminal,
                        });
                    }
                    let next_number = attempt_number.saturating_add(1);
                    let next_id =
                        stable_digest("model-attempt", &format!("{request_id}:{next_number}"));
                    let delay = retry_delay_ms(
                        self.options.model_retry_base,
                        self.options.model_retry_max,
                        next_number,
                    );
                    let schedule = ModelRetrySchedule {
                        activation_id: request_identity.activation_id.clone(),
                        round_id: request_identity.round_id.clone(),
                        request_id: request_id.clone(),
                        failed_attempt_id: attempt_id.clone(),
                        next_attempt_id: next_id.clone(),
                        failed_attempt_number: attempt_number,
                        next_attempt_number: next_number,
                        delay_ms: delay,
                        not_before_ms: current_time_ms(),
                        maximum_attempts: request_identity.maximum_attempts,
                        error_class: error_class.to_owned(),
                    };
                    let scheduled = append_runtime_event_from_state(
                        self.store.clone(),
                        owner.clone(),
                        session_id.to_owned(),
                        state,
                        format!("model-retry:{request_id}:{next_number}"),
                        format!("model-retry-event:{request_id}:{next_number}"),
                        SessionEvent::ModelStepRetryScheduled { schedule },
                    )
                    .await?;
                    self.observe_commit(&scheduled.0, &scheduled.1).await;
                    state = scheduled.1;
                    if delay > 0 {
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                    let started = append_runtime_event_from_state(
                        self.store.clone(),
                        owner.clone(),
                        session_id.to_owned(),
                        state,
                        format!("model-attempt-start:{request_id}:{next_number}"),
                        format!("model-attempt-start-event:{request_id}:{next_number}"),
                        SessionEvent::ModelAttemptStarted {
                            activation_id: request_identity.activation_id.clone(),
                            round_id: request_identity.round_id.clone(),
                            request_id: request_id.clone(),
                            attempt_id: next_id.clone(),
                            attempt_number: next_number,
                            auth_revision,
                            started_at_ms: current_time_ms(),
                        },
                    )
                    .await?;
                    self.observe_commit(&started.0, &started.1).await;
                    state = started.1;
                    attempt_number = next_number;
                    attempt_id = next_id;
                }
            }
        }
    }

    async fn finish_model_execution_failure(
        self: &Arc<Self>,
        owner: &SessionOwner,
        session_id: &str,
        mut state: VerifiedSessionState,
        purpose: ModelRequestPurpose,
        error_class: ModelAttemptErrorClass,
        error_message: &'static str,
    ) -> Result<VerifiedSessionState, &'static str> {
        match purpose {
            ModelRequestPurpose::Conversation => {
                if state
                    .transcript
                    .last()
                    .is_some_and(|message| message.role == TranscriptRole::User)
                {
                    let terminal = append_model_attempt_failure_with_error(
                        self.store.clone(),
                        owner.clone(),
                        session_id.to_owned(),
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
            }
            ModelRequestPurpose::ContextHandoff => {
                let failed = append_context_handoff_failure(
                    self.store.clone(),
                    owner.clone(),
                    session_id.to_owned(),
                    &state,
                    error_message,
                    None,
                )
                .await?;
                self.observe_commit(&failed.0, &failed.1).await;
                return Ok(failed.1);
            }
        }
        self.finish_model_failure_activation(owner, session_id, state)
            .await
    }

    fn prepare_conversation_context(
        &self,
        state: &VerifiedSessionState,
        selection: &SessionModelSelection,
        cache: &mut ProviderContextCache,
    ) -> Result<PreparedConversationContext, &'static str> {
        let mut tools = self
            .tools
            .definitions(&state.selection.tools)
            .map_err(|_| "tool_selection")?;
        tools.extend(provider_runtime_tool_definitions(state));
        let tools = Arc::new(tools);
        let (transcript, transcript_json) = cache.prepare(state)?;
        let metrics = model_context_metrics_from_serialized_transcript(
            transcript_json,
            transcript.len(),
            &tools,
        )?;
        let selection_fingerprint = model_selection_fingerprint(selection)?;
        let estimated_input_tokens = estimated_model_input_tokens_from_metrics(
            state,
            &transcript,
            &selection_fingerprint,
            &metrics.tool_schema_fingerprint,
            metrics.local_input_estimate_tokens,
        )?;
        Ok(PreparedConversationContext {
            transcript,
            tools,
            local_input_estimate_tokens: metrics.local_input_estimate_tokens,
            estimated_input_tokens,
            selection_fingerprint,
            prompt_fingerprint: metrics.prompt_fingerprint,
            tool_schema_fingerprint: metrics.tool_schema_fingerprint,
        })
    }

    pub(super) async fn ensure_model_context(
        self: &Arc<Self>,
        owner: &SessionOwner,
        session_id: &str,
        selection: &SessionModelSelection,
        mut state: VerifiedSessionState,
        cache: &mut ProviderContextCache,
    ) -> Result<(VerifiedSessionState, Option<PreparedConversationContext>), &'static str> {
        let Some(limits) = selection.limits.as_ref() else {
            // Historical selections predate durable model capabilities. They
            // remain executable, but the runtime must not invent a context
            // window and trigger a destructive early handoff from a guess.
            let prepared = self.prepare_conversation_context(&state, selection, cache)?;
            return Ok((state, Some(prepared)));
        };
        let normal_output_tokens = self
            .options
            .model_request_max_output_tokens
            .min(limits.max_output_tokens);
        let Some(normal_input_budget) = model_input_budget(
            selection,
            normal_output_tokens,
            self.options.model_context_buffer_tokens,
        ) else {
            let state = self
                .finish_unhandoffable_model_context(owner, session_id, state)
                .await?;
            return Ok((state, None));
        };
        let handoff_output_tokens = self
            .options
            .model_context_handoff_generation_tokens
            .min(limits.max_output_tokens);
        let Some(handoff_input_budget) = model_input_budget(selection, handoff_output_tokens, 0)
        else {
            let state = self
                .finish_unhandoffable_model_context(owner, session_id, state)
                .await?;
            return Ok((state, None));
        };
        let mut completed_handoff = false;
        loop {
            if state.active_activation.is_none() {
                return Ok((state, None));
            }
            if state.pending_context_handoff.is_some() {
                let previous_handoff_id = state
                    .latest_context_handoff
                    .as_ref()
                    .map(|handoff| handoff.handoff_id.clone());
                state = self
                    .run_context_handoff(owner, session_id, selection, &state)
                    .await?;
                completed_handoff |= state
                    .latest_context_handoff
                    .as_ref()
                    .map(|handoff| &handoff.handoff_id)
                    != previous_handoff_id.as_ref();
                continue;
            }

            let prepared = self.prepare_conversation_context(&state, selection, cache)?;
            if prepared.estimated_input_tokens <= normal_input_budget {
                if completed_handoff && !state.delivery_queue.is_empty() {
                    let (append, next_state) = materialize_boundary(
                        self.store.clone(),
                        owner.clone(),
                        session_id.to_owned(),
                        state,
                    )
                    .await?;
                    if let Some(append) = append {
                        self.observe_commit(&append, &next_state).await;
                    }
                    state = next_state;
                    completed_handoff = false;
                    continue;
                }
                return Ok((state, Some(prepared)));
            }

            let Some(plan) = build_context_handoff_plan(
                &state,
                selection,
                handoff_input_budget,
                self.options.model_context_handoff_document_tokens,
            )?
            else {
                let state = self
                    .finish_unhandoffable_model_context(owner, session_id, state)
                    .await?;
                return Ok((state, None));
            };
            if plan.source_tokens > handoff_input_budget {
                let state = self
                    .finish_unhandoffable_model_context(owner, session_id, state)
                    .await?;
                return Ok((state, None));
            }
            let transcript = context_handoff_source(
                &state,
                &plan,
                self.options.model_context_handoff_document_tokens,
            )?;
            let metrics = model_context_metrics(&transcript, &[])?;
            let request = ModelRequest {
                owner: owner.clone(),
                session_id: session_id.to_owned(),
                activation_id: plan.activation_id.clone(),
                round_id: plan.plan_id.clone(),
                selection: selection.clone(),
                transcript: Arc::new(transcript),
                tools: Arc::new(Vec::new()),
                prompt_fingerprint: metrics.prompt_fingerprint,
                tool_schema_fingerprint: metrics.tool_schema_fingerprint,
                max_output_tokens: Some(handoff_output_tokens),
                handoff_document_tokens: Some(self.options.model_context_handoff_document_tokens),
                stream_idle_timeout: self.options.model_stream_idle_timeout,
                stream_observer: Arc::new(SilentModelStreamObserver),
            };
            let planned = append_context_handoff_plan(
                self.store.clone(),
                owner.clone(),
                session_id.to_owned(),
                &state,
                plan,
                &request,
                self.options.model_step_max_attempts,
            )
            .await?;
            self.observe_commit(&planned.0, &planned.1).await;
            state = planned.1;
        }
    }

    async fn run_context_handoff(
        self: &Arc<Self>,
        owner: &SessionOwner,
        session_id: &str,
        selection: &SessionModelSelection,
        state: &VerifiedSessionState,
    ) -> Result<VerifiedSessionState, &'static str> {
        let plan = state
            .pending_context_handoff
            .clone()
            .ok_or("context_handoff_plan_missing")?;
        if &plan.selection != selection {
            return Err("context_handoff_selection_changed");
        }
        let limits = selection
            .limits
            .as_ref()
            .ok_or("context_handoff_model_limits_missing")?;
        let handoff_output_tokens = self
            .options
            .model_context_handoff_generation_tokens
            .min(limits.max_output_tokens);
        let handoff_input_budget = model_input_budget(selection, handoff_output_tokens, 0)
            .ok_or("context_handoff_model_budget")?;
        let transcript = context_handoff_source(
            state,
            &plan,
            self.options.model_context_handoff_document_tokens,
        )?;
        let metrics = model_context_metrics(&transcript, &[])?;
        let mut request = ModelRequest {
            owner: owner.clone(),
            session_id: session_id.to_owned(),
            activation_id: plan.activation_id.clone(),
            round_id: plan.plan_id.clone(),
            selection: selection.clone(),
            transcript: Arc::new(transcript),
            tools: Arc::new(Vec::new()),
            prompt_fingerprint: metrics.prompt_fingerprint,
            tool_schema_fingerprint: metrics.tool_schema_fingerprint,
            max_output_tokens: Some(handoff_output_tokens),
            handoff_document_tokens: Some(self.options.model_context_handoff_document_tokens),
            stream_idle_timeout: self.options.model_stream_idle_timeout,
            stream_observer: Arc::new(SilentModelStreamObserver),
        };
        let (prep_commits, prepared_state, request_identity) = prepare_model_round(
            self.store.clone(),
            owner.clone(),
            session_id.to_owned(),
            ModelRoundInput {
                state,
                selection,
                request: &request,
                round_identity: &plan.plan_id,
                purpose: ModelRequestPurpose::ContextHandoff,
                maximum_attempts: self.options.model_step_max_attempts,
            },
        )
        .await?;
        for (append, commit_state) in &prep_commits {
            self.observe_commit(append, commit_state).await;
        }
        request.activation_id = request_identity.activation_id.clone();
        request.round_id = request_identity.round_id.clone();
        let source_digest = stable_digest(
            "context-handoff-source-facts",
            &serde_json::to_string(&context_handoff_source_facts(
                state,
                &plan.covered_through_message_id,
            )?)
            .map_err(|_| "context_handoff_source_encode")?,
        );
        let request_tokens = estimated_full_model_input_tokens(
            state,
            selection,
            request.transcript.as_slice(),
            request.tools.as_slice(),
        )?;
        if source_digest != plan.source_digest
            || request_tokens > handoff_input_budget
            || !request.tools.is_empty()
        {
            return self
                .finish_context_handoff_plan_failure(
                    owner,
                    session_id,
                    prepared_state,
                    "context handoff source conflicts with its durable plan",
                    None,
                )
                .await;
        }
        let document_token_limit = request
            .handoff_document_tokens
            .or(request.max_output_tokens)
            .ok_or("context_handoff_output_limit_missing")?;
        let execution = self
            .execute_prepared_model_request(PreparedModelRequestInput {
                owner,
                session_id,
                auth_revision: selection.auth_revision,
                state: prepared_state,
                request,
                identity: &request_identity,
                purpose: ModelRequestPurpose::ContextHandoff,
            })
            .await?;
        let (outcome, attempt_id) = match execution.completion {
            PreparedModelCompletion::Completed {
                outcome,
                attempt_id,
            } => (outcome, attempt_id),
            PreparedModelCompletion::Terminal => return Ok(execution.state),
        };
        let completed_state = execution.state;
        let encoded_document = outcome.text.trim();
        let decoded_document =
            serde_json::from_str::<ContextHandoffModelDocument>(encoded_document);
        let document = decoded_document
            .as_ref()
            .map(|decoded| decoded.document.trim().to_owned())
            .unwrap_or_default();
        let document_tokens = model_context_text_tokens(&document);
        if !outcome.tool_calls.is_empty()
            || !matches!(
                decoded_document.as_ref(),
                Ok(decoded) if decoded.schema == CONTEXT_HANDOFF_DOCUMENT_SCHEMA
            )
            || document.is_empty()
            || document_tokens > u64::from(document_token_limit)
        {
            return self
                .finish_context_handoff_plan_failure(
                    owner,
                    session_id,
                    completed_state,
                    "context handoff returned an invalid bounded document",
                    Some((&request_identity, &attempt_id)),
                )
                .await;
        }
        let document_digest = stable_digest("context-handoff-document", &document);
        let handoff = ContextHandoffDocument {
            handoff_id: stable_digest(
                "context-handoff",
                &format!("{}:{document_digest}", plan.plan_id),
            ),
            plan_id: plan.plan_id.clone(),
            previous_handoff_id: plan.previous_handoff_id.clone(),
            next_generation: plan.next_generation,
            covered_through_message_id: plan.covered_through_message_id.clone(),
            source_digest: plan.source_digest.clone(),
            document,
            document_digest,
            source_tokens: plan.source_tokens,
            document_tokens,
            token_accounting_version: plan.token_accounting_version,
            selection: plan.selection.clone(),
        };
        let completed = append_context_handoff_document(
            self.store.clone(),
            owner.clone(),
            session_id.to_owned(),
            &request_identity,
            &attempt_id,
            handoff,
        )
        .await?;
        self.observe_commit(&completed.0, &completed.1).await;
        Ok(completed.1)
    }

    async fn finish_context_handoff_plan_failure(
        self: &Arc<Self>,
        owner: &SessionOwner,
        session_id: &str,
        state: VerifiedSessionState,
        message: &'static str,
        completed_request: Option<(&PreparedRequestIdentity, &str)>,
    ) -> Result<VerifiedSessionState, &'static str> {
        let failed = append_context_handoff_failure(
            self.store.clone(),
            owner.clone(),
            session_id.to_owned(),
            &state,
            message,
            completed_request,
        )
        .await?;
        self.observe_commit(&failed.0, &failed.1).await;
        Ok(failed.1)
    }

    async fn finish_unhandoffable_model_context(
        self: &Arc<Self>,
        owner: &SessionOwner,
        session_id: &str,
        mut state: VerifiedSessionState,
    ) -> Result<VerifiedSessionState, &'static str> {
        let trigger_message_id = state
            .transcript
            .iter()
            .rev()
            .find(|message| message.role == TranscriptRole::User)
            .map(|message| message.message_id.clone())
            .ok_or("model_context_trigger_missing")?;
        let failed = append_model_attempt_failure_with_error(
            self.store.clone(),
            owner.clone(),
            session_id.to_owned(),
            trigger_message_id,
            ModelAttemptErrorClass::ContextHandoffFailed,
            "model context exceeds its input budget and has no durable handoff boundary",
        )
        .await?;
        self.observe_commit(&failed.0, &failed.1).await;
        state = failed.1;
        self.finish_model_failure_activation(owner, session_id, state)
            .await
    }

    pub(super) async fn run_model_round(
        self: &Arc<Self>,
        owner: &SessionOwner,
        session_id: &str,
        selection: &SessionModelSelection,
        state: &VerifiedSessionState,
        prepared: PreparedConversationContext,
        round_identity: String,
    ) -> Result<
        (
            Vec<(AppendResult, VerifiedSessionState)>,
            VerifiedSessionState,
        ),
        &'static str,
    > {
        let PreparedConversationContext {
            transcript,
            tools,
            local_input_estimate_tokens,
            estimated_input_tokens: _,
            selection_fingerprint,
            prompt_fingerprint,
            tool_schema_fingerprint,
        } = prepared;
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
            transcript,
            tools: tools.clone(),
            prompt_fingerprint,
            tool_schema_fingerprint: tool_schema_fingerprint.clone(),
            max_output_tokens: selection.limits.as_ref().map(|limits| {
                self.options
                    .model_request_max_output_tokens
                    .min(limits.max_output_tokens)
            }),
            handoff_document_tokens: None,
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
                purpose: ModelRequestPurpose::Conversation,
                maximum_attempts: self.options.model_step_max_attempts,
            },
        )
        .await?;
        for (append, commit_state) in &prep_commits {
            self.observe_commit(append, commit_state).await;
        }
        // `prepare_model_round` derives the durable round identity from the
        // committed stream version. Use that identity for transient browser
        // observations too; the caller's follow-up identity is only the
        // deterministic input to that derivation.
        request.activation_id = request_identity.activation_id.clone();
        request.round_id = request_identity.round_id.clone();
        let tools = request.tools.clone();
        let execution = self
            .execute_prepared_model_request(PreparedModelRequestInput {
                owner,
                session_id,
                auth_revision: selection.auth_revision,
                state: _prepared_state,
                request,
                identity: &request_identity,
                purpose: ModelRequestPurpose::Conversation,
            })
            .await?;
        let (outcome, attempt_id) = match execution.completion {
            PreparedModelCompletion::Completed {
                outcome,
                attempt_id,
            } => (outcome, attempt_id),
            PreparedModelCompletion::Terminal => return Ok((Vec::new(), execution.state)),
        };
        let completed_state = execution.state;
        let request_id = request_identity.request_id.clone();
        let usage = match outcome.usage.as_ref() {
            Some(usage) => {
                let context_generation = model_context_generation(state);
                let observed_scale = token_estimate_scale_millionths(
                    usage.input_tokens,
                    local_input_estimate_tokens,
                );
                let prior_scale = state.latest_model_usage.as_ref().and_then(|anchor| {
                    (anchor.context_generation == context_generation
                        && anchor.selection_fingerprint == selection_fingerprint
                        && anchor.tool_schema_fingerprint == tool_schema_fingerprint)
                        .then_some(anchor.input_estimate_scale_millionths)
                        .flatten()
                });
                Some(ModelUsageAnchor {
                    context_generation,
                    selection_fingerprint,
                    tool_schema_fingerprint,
                    result_message_id: assistant_result_message_id(
                        owner,
                        session_id,
                        &round_identity,
                        !outcome.tool_calls.is_empty(),
                    ),
                    input_tokens: usage.input_tokens,
                    output_tokens: usage.output_tokens,
                    local_input_estimate_tokens: Some(local_input_estimate_tokens),
                    input_estimate_scale_millionths: Some(
                        prior_scale.map_or(observed_scale, |prior| prior.max(observed_scale)),
                    ),
                })
            }
            None => None,
        };
        let completed = append_runtime_event_from_state(
            self.store.clone(),
            owner.clone(),
            session_id.to_owned(),
            completed_state,
            format!("model-request-complete:{request_id}"),
            format!("model-request-complete-event:{request_id}"),
            SessionEvent::ModelRequestCompleted {
                activation_id: request_identity.activation_id.clone(),
                round_id: request_identity.round_id.clone(),
                request_id,
                attempt_id: attempt_id.clone(),
                usage,
            },
        )
        .await?;
        self.observe_commit(&completed.0, &completed.1).await;
        if outcome.tool_calls.is_empty() {
            let commit = append_assistant(
                self.store.clone(),
                owner.clone(),
                session_id.to_owned(),
                completed.1,
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
            completed.1,
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
        if initial_commit.0.replayed {
            let initial_state = initial_commit.1;
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
            initial_commit.1,
            batch_identity,
            outcome.tool_calls,
            results,
        )
        .await?;
        self.observe_commit(&result_commit.0, &result_commit.1)
            .await;
        Ok((Vec::new(), result_commit.1))
    }
}

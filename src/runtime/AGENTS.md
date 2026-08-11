# Runtime module rules

`src/runtime` is the application layer. It coordinates durable session
activations and declares the ports needed from storage, models, tools, timers,
blobs, and event publication. It depends on the domain, never on concrete
SQLite, aimux provider, HTTP, filesystem, management Server, or process types.

## Authority and activation

- The durable session projection is authoritative. In-memory actors, futures,
  task handles, subscribers, and timer handles are disposable accelerators.
- At most one activation may execute for a session. Different sessions may run
  independently.
- User input, async completion, external callback, and timer expiry are first
  admitted as durable ordered deliveries. An active model request keeps a
  frozen context because an already-sent HTTP request cannot be changed. New
  deliveries are never injected into it, but they may steer a later model
  round in the same activation.
- Claim the session, commit activation start, and materialize deliveries
  eligible at the first round boundary in one expected-version transaction;
  capture the concrete provider/model/profile selection, provider-execution
  descriptor revision/fingerprint, selection version, credential authority,
  and required minimum auth-replica revision; only then construct the request.
  Before every later model round, atomically materialize deliveries committed
  since the preceding boundary in durable order. If no later round occurs, they
  wake the next activation. Model/descriptor selection changes never retarget
  that activation; credential revision changes may affect only a provider
  request not yet sent.
- HTTP/SSE connection lifetime never owns or cancels an activation.

## Atomic lifecycle boundaries

- Commit `WaitSet`, its durable timer intent, and required outbox/index changes
  in one storage transaction.
- Commit an async terminal transition, bounded result or immutable blob
  reference, and its deduplicated wakeable delivery in one transaction.
- First terminal outcome wins. Duplicate completion, cancellation, callback,
  and stale timer commands append no second terminal transition or wake.
- A timer carries the original `wait_id`; expiry has an effect only while that
  wait is still active and no earlier wakeable delivery is pending. Commit
  order decides timer-versus-input races: earlier wakeable input makes the
  later timer stale even before activation materializes the input and emits
  `WaitCleared`.
- The reducer never reads the clock. Runtime effects calculate timestamps,
  deadlines, retry decisions, and generated IDs before committing typed facts.

## Round behavior and recovery

- Assemble each provider request transiently in memory from the latest
  committed session projection and current round boundary. Never serialize the
  assembled provider request or a second request-owned copy of its transcript,
  tool definitions, prompt, or controls into an event, storage snapshot, or
  blob. A normal storage snapshot may represent the one authoritative
  `SessionState` projection, but it is never provider-request authority. Before every dispatch,
  commit only lifecycle facts: request/round identity, selected execution facts
  or fingerprints, fresh attempt ID, concrete credential revision, and
  monotonic attempt number.
- Bytes already sent in one HTTP request cannot be changed, but that transport
  fact is not a durable frozen-request abstraction. New deliveries remain
  durable and enter the next model round.
- Keep aimux's bounded pre-stream transport retries enabled. They are adapter
  tracing/metrics, not session events. If aimux returns a retryable terminal or
  mid-stream error, discard every partial candidate and optionally retry the
  current in-memory model step under the configured zode budget, committing the
  classified retry decision and delay. The request object may be reused only
  while that process and model round remain alive; it is not recoverable after
  a crash. Runtime publication preserves that
  durable retry boundary ahead of every transient delta from the next attempt;
  transport backpressure cannot concatenate failed-attempt and retry text.
  Retry attempts do not absorb newer deliveries because they are not a new
  model round.
- Apply the configured model stream idle timeout to the first provider chunk
  and every later chunk. A dead or silent provider must become a typed bounded
  model-attempt failure and terminal activation, never an indefinitely Working
  session; a progressing long stream is not limited by a total wall-clock
  deadline.
- Resolve credentials only from the exact installed profile/authority and a
  ready revision satisfying the session minimum immediately before each aimux
  call. Commit the concrete revision in `ModelAttemptStarted`. Never use a
  management default, environment fallback, another profile, a stale secret,
  or a tombstoned revision. Replica bytes remain behind the credential port and
  out of session events.
- Do not commit an assistant outcome or execute any tool until the complete
  stream ends normally with a valid finish and all completed tool calls pass
  validation for configured ordinary adapter tools. The runtime-owned
  `wait_for` call keeps its existing session-control/result contract and is
  outside this adapter-schema validation boundary. Incremental tool-input parts
  are never executable.

- An ordinary tool batch may create at most one automatic wait. If a model
  batch also contains explicit `wait_for`, ordinary tools still execute and
  the explicit wait is the final wait intent, replacing automatic wait.
  Multiple explicit waits are resolved in provider call order; the last one
  wins. Resolve that precedence before the batch commit: one model batch emits
  at most one `WaitSet`, so an earlier explicit wait is never a publicly
  observable intermediate state.
- A wait ends the current round. Wakeable input or notification starts a later
  activation; it does not resume an old model HTTP stream.
- Preserve a configurable consecutive-timeout activation budget so repeated
  waits cannot create an unbounded self-wake loop without external input.
- Do not impose a numeric model-round ceiling on an activation or user task.
  Continue legitimate model/tool rounds until model final, durable wait,
  explicit supported cancellation, or typed execution failure. Bound provider
  attempts, idle time, tools, waits, context, storage, and other concrete
  resources independently; never turn an unfinished tool loop into `Finished`
  because a counter reached an arbitrary value.
- Keep complete public transcript history append-only while bounding each
  provider context generation by tokens. Keep the selected model's advertised
  context/output capabilities separate from the actual request output limit
  and the runtime safety reserve; subtract both actual request output and the
  independent safety buffer from the context window, never the model's full
  output capability by default. Ordinary rounds stop before that buffer; the
  handoff request may consume the reserved headroom while still reserving its
  own output allowance and staying inside the absolute context window. Anchor
  accounting on provider-reported input
  usage and estimate only the newly appended durable tail. Calibrate that tail
  with the highest observed provider-input/local-estimate ratio. Do not add
  private reasoning output wholesale to the next input; visible committed
  output is already in the tail. Before a valid anchor, use exactly four
  UTF-8 bytes/token as a coarse local baseline plus explicit framing, with no
  second multiplier; the independent context buffer is the safety reserve.
  Before a normal request exceeds that budget,
  ask the current agent through the same selected
  aimux/provider path to write a bounded durable handoff document from an inert
  source input; prior operational prompts and tool roles are evidence, not
  executable roles in the handoff request. Accept only a versioned plain
  document in its first-class text field, never a generic inline JSON payload
  or tool-call wire syntax. Keep provider-generation and durable-
  document token limits separate so reasoning allowance cannot enlarge the
  stored handoff. Atomically advance the context
  generation and continue the same activation/task. The
  fresh generation receives no implicit old transcript or handoff body; it uses
  runtime-owned read-only tools to open the handoff and page or chunk original
  history as needed. Restart reuses the committed handoff. Never delete history,
  inject a hidden summary, use a storage snapshot as model context, count
  messages/bytes as a substitute for tokens, or let Server/UI own a handoff or
  history mirror.
- `planned` is strictly pre-dispatch: a durable transition to `running` must
  commit before side effects start, so recovery may dispatch an unclaimed plan
  once. On restart, process-bound running tools become terminal
  `runtime_restarted`; remote response tools become `unknown_outcome`; tools
  declared `external_callback` may remain running and complete later. Runtime
  applies the tool's validated recovery declaration and never guesses from its
  name or transport.
- Recovery derives runnable work, waits, and async status from durable facts;
  an orphaned in-memory handle is never evidence that work is still running.
- A persisted `ModelAttemptFailedFact` is itself an unfinished recovery
  boundary: after restart, finish its exhaustion/terminal/activation batch (or
  schedule its recorded retry) before claiming the session is reconciled. Do
  not treat a failed attempt with no retry/exhaustion fact as already done.
- `last_model_attempts_exhausted` is a current projection of the latest
  activation, not a session-wide singleton. A later activation may append its
  own exhaustion fact after the prior activation has finished; conflicting
  facts within one activation remain fail-closed.
- Recovery marks an unterminated model attempt interrupted and discards its
  uncommitted partial candidate. If durable work remains, materialize every
  committed delivery and build a new model round from the latest facts. Never
  reconstruct or replay the pre-crash provider request, reuse its content as
  authority, or rerun a committed assistant/tool batch.

## Acceptance

Only real-process HTTP/SSE E2Es may exercise runtime behavior. Cover queued
input during an active request steering the next round, fallback to a later
activation when no next round exists, deferred completion during an active turn,
wait/input/timer commit-order races, timeout without tool cancellation, one
auto wait for a mixed batch, explicit-wait precedence, duplicate terminal
commands, partial-stream retry without partial tool effects, interrupted-model
recovery, two-session isolation, restart reconciliation, and SSE reconnect
without duplicated wake effects.
Long-task acceptance additionally requires one session to perform repeated
model/tool work, create a durable agent-authored handoff, enter a fresh context
that actively reads the handoff and required paginated history, restart Endpoint
before and after a handoff request, preserve its complete public transcript,
materialize input admitted during the handoff before the first fresh-context
request, reconstruct a new handoff request from the durable plan after restart, avoid
duplicate external effects, and reach one durable final without another user
command.

Stable executable anchors are:

- round/activation boundaries:
  `e2e_golden_assembled_model_tool_loop_survives_restart`,
  `e2e_round_boundary_steering_waits_for_the_next_model_round`, and
  `e2e_round_boundary_final_defers_steering_to_next_activation`, with
  `e2e_concurrent_inputs_preserve_both_assistant_rounds` fixing the complete
  `input A -> assistant A -> input B -> assistant B` durable and provider-wire
  order when B arrives during A's model request, and
  `e2e_restart_rebuilds_conversation_from_latest_durable_facts` requiring the
  same order after A is interrupted, B is queued, and Endpoint restarts with
  no new client command, plus
  `e2e_long_task_continues_until_final`,
  `e2e_recorded_deepswe_long_run_replays_through_real_endpoint`,
  `e2e_model_request_reserves_128k_output_and_independent_context_buffer`,
  `e2e_unanchored_model_input_uses_four_byte_fallback_without_hidden_multiplier`,
  `e2e_provider_usage_anchor_excludes_discarded_reasoning_output_from_next_input`,
  `e2e_long_task_writes_handoff_and_continues_in_fresh_context`, and
  `e2e_context_handoff_source_is_inert_and_document_is_plain_text`,
  `e2e_context_handoff_plain_document_pages_without_generic_payload_limit`,
  `e2e_delivery_admitted_during_handoff_reaches_first_fresh_context`,
  `e2e_handoff_restart_rebuilds_from_durable_plan_and_queued_input`, and
  `e2e_context_handoff_restart_reuses_committed_document`,
  `e2e_large_history_result_crossing_handoff_threshold_continues_in_fresh_context`,
  `e2e_context_handoff_request_never_exceeds_provider_input_budget`,
  `e2e_context_handoff_plan_is_atomic_across_storage_failure`,
  `e2e_model_request_lifecycle_does_not_persist_request_content`, and
  `e2e_restart_rebuilds_conversation_from_latest_durable_facts`
  for autonomous continuation, bounded provider context, atomic planning,
  concurrent input, request non-duplication, and restart;
- model retry/recovery:
  `e2e_model_pre_stream_rate_limit_is_one_logical_request`,
  `e2e_model_partial_stream_retry_has_no_partial_tool_effect`,
  `e2e_provider_process_exit_finishes_activation_without_stuck_working`,
  `e2e_restart_reconciles_failed_model_attempt_before_fresh_request`,
  `e2e_restart_reconciles_failed_model_attempt_before_terminal_finish`,
  `e2e_restart_reconciles_failed_attempt_after_prior_activation_exhaustion`,
  `e2e_tombstoned_replica_never_reaches_provider_before_or_after_restart`,
  `e2e_hard_crash_rebuilds_fresh_request_without_consuming_attempt_budget`,
  and `e2e_restart_after_retry_decision_builds_fresh_request`;
- wait/concurrency/terminal behavior:
  `e2e_mixed_tool_batch_is_concurrent_ordered_and_waits_once`,
  `e2e_explicit_wait_last_wins_without_skipping_ordinary_tool`,
  `e2e_explicit_wait_defaults_to_sixty_seconds_and_survives_restart`,
  `e2e_external_completion_first_wins_and_wakes_one_next_activation`,
  `e2e_auto_wait_timeout_does_not_cancel_running_tool`, and
  `e2e_two_session_waits_do_not_cross`;
- restart classifications:
  `e2e_http_response_tool_rejects_runtime_restarted_recovery`,
  `e2e_restart_remote_response_becomes_unknown_and_cancel_cannot_rewrite_it`,
  `e2e_restart_unknown_response_rejects_unsupported_mark_failed`, and
  `e2e_external_callback_tool_stays_running_and_completes_after_restart`.
- runtime persistence cadence:
  `e2e_runtime_commits_honor_snapshot_cadence_and_restart` requires runtime-
  produced boundary and assistant commits to use the configured snapshot
  cadence just like HTTP-produced commits, followed by an identical restart
  projection.

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

- Before calling aimux, durably prepare the complete bounded credential-free,
  model-neutral request envelope (or immutable blob reference), its
  fingerprints, logical request/round IDs, selection, and maximum zode attempt
  count once. The provider adapter converts that envelope to aimux types.
  Before every dispatch, commit a fresh attempt ID and monotonic attempt number.
- Keep aimux's bounded pre-stream transport retries enabled. They are adapter
  tracing/metrics, not session events. If aimux returns a retryable terminal or
  mid-stream error, discard every partial candidate and optionally retry the
  same prepared model step under the configured zode budget, committing the
  classified retry decision and delay. Retry attempts do not absorb newer
  deliveries because they are not a new model round.
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
  out of prepared envelopes/events.
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
- Stop an activation after its configured model-round budget; a retry of the
  already prepared round remains eligible, while a queued user delivery may
  wake a fresh activation under a new budget.
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
- Recovery marks an unterminated model attempt interrupted and schedules the
  same prepared request as a new zode attempt only while its bounded step
  budget remains. `ModelStepRetryScheduled` preallocates the stable next
  attempt ID/number; starting it is one expected-version claim, so restart
  neither duplicates nor skips it. If budget is exhausted, commit interruption,
  typed `model_attempts_exhausted`, activation terminal, and queued-delivery
  runnable state atomically. Never rerun a committed assistant/tool batch.

## Acceptance

Only real-process HTTP/SSE E2Es may exercise runtime behavior. Cover queued
input during an active request steering the next round, fallback to a later
activation when no next round exists, deferred completion during an active turn,
wait/input/timer commit-order races, timeout without tool cancellation, one
auto wait for a mixed batch, explicit-wait precedence, duplicate terminal
commands, partial-stream retry without partial tool effects, interrupted-model
recovery, two-session isolation, restart reconciliation, and SSE reconnect
without duplicated wake effects.

Stable executable anchors are:

- round/activation boundaries:
  `e2e_golden_assembled_model_tool_loop_survives_restart`,
  `e2e_round_boundary_steering_waits_for_the_next_model_round`, and
  `e2e_round_boundary_final_defers_steering_to_next_activation`, with
  `e2e_concurrent_inputs_preserve_both_assistant_rounds` fixing the complete
  `input A -> assistant A -> input B -> assistant B` durable and provider-wire
  order when B arrives during A's model request, and
  `e2e_restart_recovers_queued_input_without_another_command` requiring the
  same order after A is interrupted, B is queued, and Endpoint restarts with
  no new client command;
- model retry/recovery:
  `e2e_model_pre_stream_rate_limit_is_one_logical_request`,
  `e2e_model_partial_stream_retry_has_no_partial_tool_effect`,
  `e2e_provider_process_exit_finishes_activation_without_stuck_working`,
  `e2e_restart_reconciles_failed_model_attempt_before_retry_schedule`,
  `e2e_restart_reconciles_failed_model_attempt_before_terminal_finish`,
  `e2e_tombstoned_replica_never_reaches_provider_before_or_after_restart`,
  `e2e_hard_crash_recovery_exhausts_one_model_attempt_and_keeps_delivery_runnable`,
  and `e2e_hard_crash_after_retry_fact_claims_one_scheduled_attempt`;
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

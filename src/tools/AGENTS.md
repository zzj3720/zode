# Tool adapter rules

`src/tools` owns tool disclosure, validated invocation dispatch, bounded result
capture, cancellation adapters, and external-callback admission. Session
lifecycle and waiting remain in `src/runtime`; durable transitions remain in
the domain and storage transaction.
Tool configuration and public status/cancel/callback routes are defined in
`docs/http-api.md`.

## Identity and batch execution

- The model's original `tool_call_id` is the only lifecycle identity. Use it
  for invocation, early result, async status, callback, cancellation, result
  lookup, wait membership, and recovery.
- Validate each configured ordinary adapter's disclosed schema and every
  model-supplied argument for that adapter. Never silently omit a tool whose
  JSON schema cannot be represented by aimux, and never start side effects for
  invalid adapter arguments. The runtime-owned `wait_for` call is governed by
  its existing session-control contract and is outside this adapter-schema
  validation rule.
- Every model request discloses exactly the ordinary tools selected by that
  session plus one runtime-owned `wait_for`; it never discloses an unselected
  configured tool. Preserve each selected schema on the provider wire, and
  publish the `wait_for` bounds as an integer from 1 through 600.
- Durably commit the assistant tool call, stable invocation key, and invocation
  intent before dispatching any side effect. A crash can leave a recoverable
  planned/running fact, never an unrecorded external effect.
- `planned` means no dispatcher has claimed the invocation. Commit the
  `running` dispatch claim before starting any side effect. Recovery may send
  an unclaimed plan once; recovery of `running` follows the adapter's declared
  policy.
- Start all ordinary calls from one assistant batch concurrently. They share
  one foreground window, initially three seconds; do not give each call a
  separate serial timeout.
- Commit tool results in original provider call order regardless of completion
  order. Calls completed inside the window use their real result. Remaining
  calls return a non-error `async_running` result and emit
  `AsyncToolCallStarted`.
- Background completion is a runtime notification, not a second ordinary tool
  result for the same call. Cancelling one call must not cancel siblings.

## `wait_for`

- `wait_for` is an internal session-control tool, not a blocking runner task.
- Its input has required `reason` and optional `timeout_seconds`. The default is
  60 seconds and the valid range is 1 through 600 seconds.
- It emits an ordinary tool result plus durable wait intent and ends the round.
  A session has at most one active wait; a later wait replaces the earlier one.
  Within one model batch, resolve all explicit waits in provider order before
  committing and emit only the last call's `WaitSet`; do not publish transient
  waits for earlier calls in that batch.
- Automatic wait uses the same durable representation. The initial normal-tool
  auto wait is 20 seconds; user-interaction tools may declare 120 seconds in
  tool metadata. Never infer this from tool names or business timeout fields.
- Wait timeout never cancels a tool. Tool execution has its own watchdog and
  explicit unknown-outcome semantics.

## Results, callbacks, and side effects

- Bound inline result size. Store larger output in immutable blob storage and
  persist only a stable, secret-safe reference.
- External callbacks authenticate the invocation, bind idempotency to the
  canonical semantic payload, and cannot overwrite an existing terminal
  outcome.
- Generate a non-secret opaque callback ID separately from the secret bearer.
  Persist the callback ID mapping and only a keyed bearer fingerprint; put the
  ID in the URL and the bearer only in a redacted authorization header. A
  controller-supplied callback base is execution configuration, not Endpoint
  manager discovery.
- External-callback dispatch has a durable outbox/intention and a reproducible
  or secret-stored bearer so restart retries use the same original
  `tool_call_id` invocation identity. The raw bearer never enters events.
- Exactly-once external side effects are not promised by the event store. Use
  stable invocation keys, provider idempotency where available, execution
  fencing, and an explicit unknown-outcome result after ambiguous failure.
- `unknown_outcome` is nonterminal reconciliation state. Do not retry
  automatically. A callback may resolve it; an explicit retry is legal only
  when the adapter contract deduplicates/fences the same invocation key.
- Ordinary cancel is invalid for `unknown_outcome`: return conflict and keep
  the state so a later authenticated callback can resolve it. V0 exposes no
  public manual `mark_failed`; without adapter-verifiable evidence it would
  convert uncertainty into a false fact. Unsupported reconciliation is
  rejected without changing state.
- Process-bound tools are not automatically resumed after restart. A remote
  response tool may have outlived zode but remains `unknown_outcome`; only a
  durable external-callback contract may remain normally `running`.
- Tool configuration declares the running-restart outcome and whether dispatch
  retry is forbidden or safe under same-invocation-key deduplication/fencing.
  Reject missing or incompatible declarations at startup; never infer retry
  safety from HTTP, a tool name, or callback support.

## Acceptance

Only real-process HTTP/SSE E2Es are allowed. Cover synchronous completion,
slow-call early result and later wake, mixed fast/slow/failing batches with
provider-order results, shared foreground-window timing, cancellation without
sibling cancellation, late and duplicate callbacks, callback JSON canonical
idempotency, oversized output via blob reference, and restart outcomes for
process-bound, ambiguous remote-response, and external-callback tools.

Existing executable anchors are
`e2e_invalid_model_tool_arguments_are_rejected_before_side_effect`,
`e2e_long_task_continues_until_final`,
`e2e_long_task_writes_handoff_and_continues_in_fresh_context`,
`e2e_mixed_tool_batch_is_concurrent_ordered_and_waits_once`,
`e2e_explicit_wait_last_wins_without_skipping_ordinary_tool`,
`e2e_explicit_wait_defaults_to_sixty_seconds_and_survives_restart`,
`e2e_two_session_waits_do_not_cross`,
`e2e_external_completion_first_wins_and_wakes_one_next_activation`,
`e2e_auto_wait_timeout_does_not_cancel_running_tool`,
`e2e_http_response_tool_rejects_runtime_restarted_recovery`,
`e2e_restart_remote_response_becomes_unknown_and_cancel_cannot_rewrite_it`,
and `e2e_external_callback_tool_stays_running_and_completes_after_restart`.
The remaining independent decisions require the stable anchors
`e2e_cancel_one_tool_does_not_cancel_siblings`,
`e2e_callback_payload_idempotency_is_canonical`, and
`e2e_oversized_tool_output_uses_secret_safe_blob_reference` before their
production slices are complete.

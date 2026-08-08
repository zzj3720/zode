# Endpoint HTTP and SSE adapter rules

`src/api` is the passive device Endpoint adapter. It admits controller
commands, renders Endpoint projections, and exposes durable session events. It
is not the agent runtime, management Server, UI API, provider-auth authority, or
a second domain service. `docs/http-api.md` is the authoritative Endpoint
contract.

## HTTP contract

- Validate transport shape, authenticate/authorize when introduced, translate
  into one runtime command, and return only after durable admission/commit.
- Derive controller authority from control authentication and accept a bounded
  opaque subject only in that trusted context. Bind session ownership and
  command receipt scope to authority/subject; list/read/mutate/SSE must not leak
  another subject's session existence.
- Bind every idempotency key to the canonical semantic request. Reuse with an
  equivalent request replays the original status and body; reuse with different
  semantics returns conflict and creates no additional session or event.
- Session create rejects a caller-supplied ID. Endpoint generates a ULID and
  commits it atomically with the collection-scoped command receipt and initial
  session event; replay returns the same ULID.
- Authenticated replay-only mode on every session mutation checks the
  authority/subject/command-scoped receipt before current state: hit returns the
  original response, changed fingerprint conflicts, and miss is typed and
  mutation-free. It cannot allocate, append, wake, issue an effect, or bypass
  normal admission for a new key.
- Session-create receipt lookup also precedes current tool-catalog and
  provider/profile admission on the normal path: an equivalent replay is
  returned unchanged, while a receipt miss validates the current selection
  before allocating a new session.
- Persist only a versioned one-way fingerprint. Secret-bearing control
  commands use a restart-stable Endpoint-keyed HMAC; never persist their raw
  canonical request bytes.
- Keep storage/domain/provider details out of public errors. Log classified
  internal context without secrets; return stable versioned error codes and a
  neutral message for internal failures.
- Do not expose raw event payloads or storage records. Maintain explicit,
  versioned public session and event mappings with secret-safe fields.
- All blocking adapter work crosses `spawn_blocking` or a dedicated worker.
- Expose bounded identity/health/capability reads and authenticated,
  idempotent credential-replica install/tombstone commands. Never expose OAuth,
  provider defaults, sharing policy, endpoint registration, or UI routes.
- Require `Zode-Subject` only for session ownership and session-command receipt
  scope. Identity, health, capabilities, controller-auth, and auth-replica
  routes authenticate the controller bearer without requiring or consuming a
  subject; management probes and credential distribution must not manufacture
  a session owner.
- Health is the fixed `zode.endpoint-health.v1` readiness projection capped at
  4 KiB. Capabilities use the exact `zode.endpoint-capabilities.v1` minimum
  shape in `docs/http-api.md`, are sorted and pre-serialized before READY, and
  are capped at 1 MiB. Never build either response by scanning session state or
  expose configured origins, URLs, paths, descriptions, input schemas, profile/
  model instances, replica metadata, or secret-store state.
- Capability classes describe the effective production composition, not merely
  accepted configuration fields. In particular, advertise `external_callback`
  only when its callback policy, tool, public route, and runtime lifecycle are
  all active; otherwise omit it even if dormant callback-shaped config exists.
- Keep controller authority identity independent from bearer bytes. Its
  authenticated, idempotent rotation advances a credential revision,
  atomically fences the old secret, and preserves authority/subject-owned
  sessions and receipts across restart.
- Endpoint never opens a connection to management Server. API code contains no
  reverse registration, heartbeat, manager discovery, or reconnect loop.

## SSE contract

- SSE IDs are durable global event positions. Replay and live publication form
  one strictly increasing, lossless sequence of that session's public events.
  Numeric IDs may skip positions belonging to other sessions or private facts.
- Commit order, not handler completion order, controls publication. Recover a
  lagged receiver from storage without leaking debug errors into the stream.
- Subscribe before replay, deduplicate by durable cursor, and support
  `Last-Event-ID`. A disconnect never cancels runtime work.
- Token deltas may eventually be transient; lifecycle transitions and final
  messages remain durable and reconnectable.
- Public model retry/interruption events expose only zode attempt counters,
  bounded delay, round identity, and safe error classification. Prepared model
  envelopes, partial stream content/tool input, aimux HTTP attempts, and raw
  provider errors remain private.
- A management Server may proxy session SSE, but Endpoint emits no
  Server-specific cursor or callback. The controller resumes with the same
  public `Last-Event-ID` contract as any standalone client.

## Acceptance

API behavior is tested only by spawning the real binary and issuing network
requests. No handler tests, router service calls, in-process stores, hidden
test routes, or library imports from `tests/` are allowed.

Maintain positive E2Es for semantic idempotency conflicts, neutral internal
errors, durable admission before acceptance, concurrent commit-order SSE,
`Last-Event-ID` replay/live handoff without gaps or duplicates, lag recovery,
disconnect without runtime cancellation, bounded identity/health/capabilities,
credential-replica revision/tombstone idempotency without secrets, and
duplicate tool callback commands producing one public terminal event. The
`e2e_session_list_reflects_current_model_selection_after_update` anchor also
keeps the list's current selection consistent with session GET and the
`model_selection_changed` SSE event.

The identity/health/capability anchors are
`e2e_identity_is_endpoint_owned_and_restart_stable`,
`e2e_endpoint_health_is_controller_authenticated_and_independent_of_active_session_work`,
and `e2e_endpoint_capabilities_are_restart_stable_bounded_and_non_secret`.
Missing routes are shallow evidence; capture the first mismatch after the
smallest real route bootstrap before completing either handler.

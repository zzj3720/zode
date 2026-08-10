# zode Endpoint v0 HTTP and configuration contract

Status: authoritative Endpoint contract for v0 E2Es. System and Server/UI
contracts live in `docs/architecture.md` and `docs/server-api.md`. Routes not
implemented yet are introduced only with a red real-process E2E. Additional
response fields are allowed; removing or changing documented fields requires a
design change.

## 1. Common rules

- All product use is through HTTP and SSE. Command bodies and normal responses
  are UTF-8 JSON.
- Every mutating command requires `Idempotency-Key` except the external
  callback route whose opaque callback ID is its one-invocation identity.
- Normal session routes require authenticated controller context containing a
  stable opaque subject. Endpoint derives `controller_authority_id` from the
  control credential and accepts a bounded `Zode-Subject` claim only from that
  authenticated controller. It stores the authority/subject ownership scope,
  not a Server or Cloudflare Access actor object. Controller-scoped identity,
  health, capabilities, controller-auth, and auth-replica routes authenticate
  the bearer but neither require nor consume `Zode-Subject`; a catalog probe or
  credential distribution operation is not a session owner. Callback bearer
  routes are separate capabilities.
- An authenticated controller may add
  `Zode-Idempotency-Mode: replay-only` to any session mutation. Endpoint checks
  only the authority/subject/command-scoped receipt: a matching fingerprint
  returns the original status/body, a changed fingerprint conflicts, and no
  receipt returns `404 idempotency_receipt_not_found`. Replay-only never runs
  current semantic validation, allocates identity, appends, wakes, or issues an
  effect.
- An idempotency replay returns the original status and body. Reuse with a
  different canonical semantic body returns `409 conflict` and performs no
  mutation.
- Canonical identity includes controller authority, the opaque subject for a
  session command, the command kind, and path resource IDs; JSON object key
  order and whitespace do not change it, while array order and schema-defined
  semantic values do. Only a versioned one-way digest is durable. Commands
  containing secret material use a restart-stable Endpoint-keyed HMAC; raw
  canonical request bytes never enter SQLite or operation journals.
- Generated IDs are opaque strings. Clients must not parse timestamps,
  provider names, or database positions from them.
- Unknown or invalid public input is rejected before effects begin. Durable
  text, JSON, and binary-reference fields have explicit implementation limits;
  exceeding one returns `413 payload_too_large` or `422 invalid_request`.
- For a session command, `202 Accepted` means the command and any associated
  wake intent are durable, not that an activation or external effect has
  finished. For an auth-replica command, success means the requested revision
  is durably installed or tombstoned; it does not imply a session wake.

The public error shape is:

```json
{
  "error": {
    "code": "stable_machine_code",
    "message": "safe public message",
    "retryable": false
  }
}
```

Required classes are:

| HTTP    | Code family                     | Meaning                                                                                        |
| ------- | ------------------------------- | ---------------------------------------------------------------------------------------------- |
| 400     | `malformed_request`             | Invalid JSON, header encoding, or SSE cursor                                                   |
| 401/403 | `unauthenticated` / `forbidden` | Missing or invalid control/callback authorization                                              |
| 404     | resource-specific `*_not_found` | Public resource does not exist                                                                 |
| 409     | `conflict`                      | Idempotency mismatch, optimistic conflict, or losing terminal race                             |
| 413     | `payload_too_large`             | A public bound was exceeded                                                                    |
| 422     | `invalid_request`               | Current request violates a public semantic rule                                                |
| 500     | `internal_error`                | Storage, replay, reducer-history, adapter, or unexpected failure                               |
| 503     | `auth_replica_unavailable`      | The exact selected replica/revision is not ready, is tombstoned, or has no valid active secret |
| 503     | `provider_unavailable`          | The selected provider adapter or destination is unavailable before a model request             |

`500` and SSE error events use neutral text. Internal error strings, SQL,
paths, provider bodies, tool stderr, credentials, and authorization headers are
never copied into public output.

## 2. Endpoint configuration

Endpoint accepts `--config <json-path>`. Existing `--listen` and `--database`
flags may remain explicit development overrides. Configuration contains
non-secret adapter wiring. Credentials arrive through the authenticated
auth-replica provisioning API or an explicit standalone controller bootstrap;
they are never embedded in configuration examples, session commands, or
session events.

The v0 configuration shape is conceptually:

```json
{
  "schema": "zode.config.v1",
  "listen": "127.0.0.1:0",
  "runtime_store": { "kind": "sqlite", "path": "runtime.sqlite" },
  "credential_replica_store": { "kind": "files", "directory": "credentials" },
  "blob_store": { "kind": "files", "directory": "blobs" },
  "controller_auth": [
    {
      "authority_id": "controller-opaque",
      "revision": 1,
      "kind": "bearer_secret_file",
      "secret_file": "controller.secret"
    }
  ],
  "runtime": {
    "tool_foreground_ms": 3000,
    "snapshot_every_events": 100,
    "model_context_input_tokens": 32768,
    "model_context_handoff_at_tokens": 24576,
    "model_context_handoff_document_tokens": 4096,
    "model_step_max_attempts": 3,
    "model_retry_base_ms": 500,
    "model_retry_max_ms": 5000,
    "model_stream_idle_timeout_ms": 30000
  },
  "provider_execution": {
    "adapter_kinds": ["openai_compatible"],
    "allowed_base_url_origins": ["http://127.0.0.1"]
  },
  "callback": {
    "allowed_public_origins": ["https://controller.example.test"]
  },
  "tools": [
    {
      "name": "fixture_tool",
      "description": "controlled HTTP fixture",
      "input_schema": { "type": "object" },
      "completion_mode": "response",
      "auto_wait_timeout_seconds": 20,
      "recovery": {
        "on_running_restart": "unknown_outcome",
        "retry_dispatch": "never"
      },
      "adapter": {
        "kind": "http",
        "url": "http://127.0.0.1:42000/invoke"
      }
    }
  ]
}
```

Exact config parsing may use typed version fields, but E2Es rely only on the
documented semantics. Endpoint configuration enables provider adapter kinds
(`openai_compatible` and the native `anthropic` Messages adapter in this
release) and enforces outbound policy; users do not repeat provider base URLs, models, auth
profiles, or defaults on every device. A controller supplies the concrete
non-secret execution descriptor in session selection. Aimux retains its bounded
transport retry before a stream is established. `model_step_max_attempts`
separately bounds how many times Endpoint may call aimux for one prepared model
step after aimux surfaces a retryable failure; it includes the first call and
must be at least one. Retry delay uses bounded jitter between the configured
base and maximum and honors a shorter valid provider hint.

There is no model-round-count setting: an activation is not stopped after an
arbitrary number of model/tool rounds. `model_context_input_tokens` is the
maximum provider input budget after the deployment has reserved output
capacity for its enabled models.
`model_context_handoff_at_tokens` triggers an agent-authored durable handoff
before that ceiling, and `model_context_handoff_document_tokens` bounds the
handoff response. All counts include message framing and selected tool schemas
through the runtime's versioned token accountant. V0 conservatively treats
every serialized UTF-8 byte as at most one token and adds explicit
message/tool framing reserves, so it can trigger early but cannot undercount
the configured provider input budget. Invalid relationships fail startup. The
next context generation starts without implicit old transcript or handoff-body
injection and uses the built-in read-only handoff/history tools.
These limits affect only provider context: public transcript history remains
complete.

Each controller credential maps to one immutable `authority_id`; a caller
cannot select another authority in a header. Secret file contents are outside
the JSON and never returned. Rotating transport authentication while retaining
the same authority preserves owned sessions; changing authority does not adopt
them.

A response-mode HTTP tool uses the HTTP response
as its result, but a restart after its durable dispatch claim is ambiguous and
therefore defaults to `unknown_outcome`. A genuinely process-bound adapter
declares `on_running_restart: runtime_restarted`; only adapters whose work
necessarily dies with zode may use it. A tool with `external_callback` receives
a callback URL and one invocation bearer token and declares
`on_running_restart: await_callback`. `retry_dispatch` is either `never` or
`same_invocation_key_deduplicated`; the latter is accepted only when the tool
contract guarantees deduplication/fencing for the original `tool_call_id`.
Invalid adapter/recovery combinations fail Endpoint startup. An unclaimed
`planned` invocation is pre-dispatch by definition and may be dispatched once
after restart; a durable transition to `running` always precedes outbound side
effects.

`wait_for` is an internal tool supplied by the runtime and is not configured as
an HTTP tool.

## 3. Sessions

### Create

`POST /v1/sessions`

```json
{
  "model": {
    "provider": "fixture-compatible",
    "provider_execution": {
      "schema": "zode.provider-execution.v1",
      "revision": 2,
      "kind": "openai_compatible",
      "base_url": "http://127.0.0.1:41000/v1",
      "options": {}
    },
    "model": "fixture-model",
    "auth_authority_id": "authority-opaque",
    "auth_profile_id": "profile-opaque",
    "minimum_auth_revision": 3
  },
  "tools": ["fixture_tool"],
  "callback_base_url": "https://controller.example.test/callbacks"
}
```

`session_id` is not accepted in the request. Endpoint generates a ULID while
admitting the create command and atomically stores it with the command's
idempotency receipt; replay of the same `Idempotency-Key` returns the same ULID
and response. `model` and `tools` are optional. A supplied model requires an
explicit bounded `provider_execution` descriptor, `auth_authority_id`, and
`auth_profile_id`; Endpoint never resolves a management default or per-device
user configuration. The descriptor kind must be enabled and its destination
allowed by Endpoint outbound policy. `options` is a bounded, credential-free
map persisted as part of the exact session selection and passed to aimux as
provider options. Existing explicit `options: {}` selections remain unchanged.
`minimum_auth_revision` is optional and otherwise resolves to the newest ready
installed revision at admission. A controller that distributed credentials
should send the revision it verified. Omitting `model` creates a durable session
that accepts and exposes messages but is not runnable until model selection is
set; it does not silently choose an ambient provider or profile.
`callback_base_url` is optional unless a selected external-callback tool needs
it. It is concrete execution configuration supplied by the controller, must
match Endpoint callback-origin policy, and does not cause Endpoint to connect
to or discover that controller.

First success is `201 Created`; replay returns the same `201` and body:

```json
{
  "schema": "zode.command.v1",
  "session_id": "01JAZODE6Y7Q3FKM8N2S4V0WXC",
  "accepted": true,
  "version": 1
}
```

For create, the common replay-only mode performs the
authority/subject-scoped collection receipt lookup:

- a matching key and fingerprint returns the original status/body;
- the same key with a different fingerprint returns `409 conflict`;
- no receipt returns `404 idempotency_receipt_not_found`;
- no branch allocates an ID, checks current model credentials, or mutates state.

This lets a stateless controller recover an unknown create outcome before
applying mutable current policy. The normal create path still validates current
tool-catalog and model/profile/replica state on a receipt miss. Other mutation
routes use the same ordering for their own command scopes.

The ULID is unique only within this Endpoint's resource namespace. Controllers
must treat it as opaque and pair it with their own Endpoint identity; they must
not derive creation order, time, or cross-Endpoint identity from its bytes. V0
emits the canonical 26-character uppercase Crockford representation; Endpoint
enforces a unique constraint and regenerates on the vanishingly unlikely local
collision before committing the first event/receipt.

### List and read

`GET /v1/sessions?limit=...&cursor=...` returns a bounded, stably ordered page
of non-secret session summaries owned by the authenticated controller subject.
Ordering uses durable creation position, not ULID lexical order; `cursor` is
opaque. The list is derived from Endpoint events and a rebuildable index, never
a second mutable session authority. The `model` summary is the current
event-replayed selection: after a committed `model_selection_changed` event,
session GET, its SSE frame, and the list item expose the same selection.

```json
{
  "schema": "zode.session-list.v1",
  "items": [
    {
      "session_id": "01JAZODE6Y7Q3FKM8N2S4V0WXC",
      "version": 7,
      "status": "idle",
      "created_at_ms": 1234567890,
      "updated_at_ms": 1234567999,
      "model": {
        "provider": "fixture-compatible",
        "model": "fixture-model",
        "auth_profile_id": "profile-opaque"
      }
    }
  ],
  "next_cursor": null
}
```

`limit` defaults to 50 and is bounded to 1 through 200. Pages are ordered by
durable creation position descending with `session_id` as a deterministic tie
breaker. `next_cursor` is `null` at the end. A cursor is bound to this route,
sort version, and filter; malformed or mismatched cursors return a typed `400`
rather than silently restarting pagination.

`GET /v1/sessions/{session_id}` returns `zode.session.v1` with at least:

```json
{
  "schema": "zode.session.v1",
  "session_id": "session-id",
  "version": 7,
  "status": "idle",
  "model": {
    "provider": "fixture-compatible",
    "provider_execution_schema": "zode.provider-execution.v1",
    "provider_execution_revision": 2,
    "provider_execution_kind": "openai_compatible",
    "provider_execution_base_url": "http://127.0.0.1:41000/v1",
    "provider_execution_options": {},
    "model": "fixture-model",
    "auth_authority_id": "authority-opaque",
    "auth_profile_id": "profile-opaque",
    "auth_revision": 3
  },
  "transcript": [],
  "delivery": { "acknowledged_through": 0, "pending": [] },
  "wait": null,
  "tool_calls": [],
  "active_activation": null,
  "active_model_round": null,
  "context_handoff": null
}
```

After a handoff, `context_handoff` exposes only its stable ID, parent ID,
generation, covered transcript message ID, and token-accounting metadata. The
handoff body is not injected as projection metadata; the successor agent reads
it through the session-bound `read_context_handoff` runtime tool. That bounded
tool result then becomes part of the ordinary append-only transcript like any
other tool result.

List, read, mutation, and tool routes return the same safe not-found result for
a missing session and a session owned by another authority/subject. The
Endpoint-wide SSE omits every event outside the authenticated owner scope and
never reveals whether another subject's session exists. Together these rules
prevent an Endpoint-shared user from probing another subject's session IDs.

Secret tool inputs/results and provider continuation bytes are never exposed
accidentally by this summary. Dedicated result routes return only explicitly
public bounded values or blob references.

### Append user input

`POST /v1/sessions/{session_id}/messages`

```json
{
  "message_id": "optional-client-message-id",
  "content": "hello"
}
```

Success is `202 Accepted` with `zode.command.v1`. Admission durably queues the
message and marks an eligible session runnable. A concurrent expected-version
conflict returns retryable `409`; retrying with the same idempotency key cannot
duplicate the message.

### Select or change model

`PUT /v1/sessions/{session_id}/model`

```json
{
  "provider": "fixture-compatible",
  "provider_execution": {
    "schema": "zode.provider-execution.v1",
    "revision": 2,
    "kind": "openai_compatible",
    "base_url": "http://127.0.0.1:41000/v1",
    "options": {}
  },
  "model": "fixture-model",
  "auth_authority_id": "authority-opaque",
  "auth_profile_id": "profile-opaque",
  "minimum_auth_revision": 3
}
```

This is an idempotent session command. It validates the configured provider,
model, explicit installed profile, and minimum ready revision, commits the
stable next selection, and makes a session with pending user input runnable.
Endpoint never substitutes a local default. If an activation is already
running, that activation continues using the concrete selection and auth
revision captured in its `ActivationStarted` fact; every later activation
captures the latest eligible installed revision. Changing a selection or
installing a new credential revision never retargets an in-flight request or
rewrites historical transcript or provider continuation facts. While active,
the session representation exposes the captured selection under
`active_activation.model` separately from the next `model` selection.

The selection is activation-scoped, but external deliveries are model-round
scoped. A message/completion committed after one model request starts cannot
alter that request; if the activation performs another model round, it is
materialized before that next request. Otherwise it makes the session runnable
for a later activation.

## 4. Endpoint events

`GET /v1/events` returns the one Endpoint-wide `text/event-stream`. The route
requires the same trusted controller authority and opaque `Zode-Subject` used
for session reads and commands. It multiplexes public events for every session
owned by that authority/subject; it is not opened for, filtered by, or owned by
one session.

`Last-Event-ID` is an optional Endpoint-scoped durable global position. Every
durable public frame identifies its owning session:

```text
id: 42
event: assistant_message_committed
data: {"schema":"zode.event.v1","id":"42","session_id":"...","version":7,"kind":"assistant_message_committed","data":{...}}
```

IDs can skip positions used by private storage facts or sessions outside the
authenticated subject. Every eligible public event after the cursor appears
exactly once and in increasing Endpoint-global order. Subscribe/replay handoff
and live publication cannot lose an event. Keepalive comments have no `id` and
carry no state.

Durable catch-up is streamed in bounded batches rather than accumulated in
memory before the first frame. Opening a stream and recovering from receiver
lag each establish one Endpoint-wide handoff fence: durable events through the
fence are replayed in global order, and later durable frames join that same
ordered catch-up. No-ID transient progress is outside the durable cursor order:
it may overtake an older durable replay tail so current work remains visible.
A durable retry boundary still fences transient text from the next attempt
until that boundary has been delivered, and a pre-fence transient is never
emitted after a retry, terminal, or committed-assistant boundary already
covered by catch-up. Catch-up therefore cannot turn old provisional text into
apparently new progress or delay all current progress until an unbounded
history finishes loading.

`context_handoff_created` and `context_handoff_failed` are durable public
metadata events. The created event carries the same bounded metadata as the
session projection, never the handoff document body or a provider request.

The cursor and connection belong to the Endpoint stream, not to a session.
Creating, opening, closing, or navigating among sessions does not create or
reset an SSE stream. A client uses the frame's `session_id` to dispatch the
event to its canonical session projection. A fresh stream without
`Last-Event-ID` replays all eligible public events from the beginning; clients
may reconcile current session snapshots through bounded HTTP reads while the
single stream remains attached.

The former session-scoped `/v1/sessions/{session_id}/events` route is absent;
there is no compatibility stream or second cursor authority. The public
real-process anchor
`e2e_endpoint_event_stream_multiplexes_owned_sessions_and_reconnects_once`
creates two owned sessions plus an unowned session, proves one stream emits only
the two owned sequences in Endpoint-global order, reconnects once with the last
consumed ID, and observes no missed or duplicated durable terminal event.

While a model stream is attached to a live client, Endpoint may also emit
best-effort transient text frames. They have no `id`, are never persisted, and
are not replayed after reconnect:

```text
event: assistant_message_delta
data: {"schema":"zode.transient-event.v1","session_id":"...","activation_id":"...","round_id":"...","text":"partial"}
```

Transient text is provisional display state only and is dispatched by its
`session_id`. A durable
`assistant_message_committed` event replaces it; a reconnect must rely on the
durable stream and must not duplicate or promote a transient candidate. On a
live stream, a durable `model_step_retrying` boundary precedes every transient
delta from the next attempt even when durable replay is backpressured; failed-
attempt text and retry text can never be presented as one candidate.

Durable public kinds include session/message, activation final outcome,
model-step retry/interruption, wait, and async tool lifecycle facts. A
`model_step_retrying` payload exposes only round ID, failed/next/max zode
attempt numbers, bounded delay, and a safe classified error code. Raw prepared
model envelopes, credentials, raw tool result bodies, provider wire parts,
aimux-internal HTTP attempts, internal ignored facts, snapshot operations, and
mutable projection repair are not public event payloads. A transient text frame
contains only bounded display text and the session/activation identity above;
provider metadata and raw wire parts remain private.

The configured `model_step_max_attempts` includes the first zode call to aimux.
Aimux may independently perform its bounded pre-stream transport retries inside
one such call. A retry of the zode model step keeps the prepared request
fingerprint and does not absorb deliveries that arrived after the round
boundary. A stream that ends without a valid finish, contains invalid completed
tool input, or emits an error has no assistant/tool side effect. If retry budget
remains, the public retry event precedes the next attempt; otherwise the
activation ends with safe typed `model_attempts_exhausted` and queued deliveries
remain runnable. A retry event preallocates its stable next attempt ID/number.
Starting that attempt is an expected-version claim; restart resumes an
unclaimed schedule once and never appends a duplicate retry fact.

If durable catch-up fails after headers were sent, emit one neutral
`event: error` with a stable public code, then close the stream.

## 5. Async tool calls

### Read status/result

`GET /v1/sessions/{session_id}/tool-calls/{tool_call_id}` returns:

```json
{
  "schema": "zode.tool-call.v1",
  "session_id": "session-id",
  "tool_call_id": "provider-call-id",
  "tool_name": "fixture_tool",
  "status": "running",
  "completion_mode": "response",
  "allowed_actions": ["cancel"],
  "result": null,
  "error": null,
  "reconciliation": null
}
```

Terminal `result` is either a bounded public value or
`{"blob":{"id":"opaque","media_type":"...","bytes":123}}`. Error output is
classified and redacted.

Public status is `planned`, `running`, `unknown_outcome`, `completed`, `failed`,
or `cancelled`. `allowed_actions` is the complete current public action set:
`planned`/`running` may expose `cancel`; `unknown_outcome` may expose
`retry_dispatch` only for a tool whose contract guarantees the original
invocation identity is deduplicated or fenced; terminal and unsupported states
expose an empty array. Clients never infer actions from status.
`unknown_outcome` is nonterminal: automatic dispatch is paused, an
authenticated callback may still resolve it, and `reconciliation` explains the
safe reason without creating a second action authority.

### Cancel

`POST /v1/sessions/{session_id}/tool-calls/{tool_call_id}/cancel`

```json
{ "reason": "user requested cancellation" }
```

The first terminal transition wins. Success returns the current terminal
public record. Losing a race returns `409` with that same winning status and
does not append another terminal event or wake delivery.

Cancellation while status is `unknown_outcome` returns `409 conflict`, leaves
the state unchanged, and does not send a cancellation that could misrepresent
an already-executed side effect. A later authenticated callback may still win;
operators use the explicit reconciliation route only when retry is guaranteed
to reuse a deduplicated/fenced invocation identity.

### Reconcile an unknown outcome

`POST /v1/sessions/{session_id}/tool-calls/{tool_call_id}/reconcile`

```json
{ "action": "retry_dispatch" }
```

The only v0 action is `retry_dispatch`. It is accepted only when the tool
catalog declares
`recovery.retry_dispatch: same_invocation_key_deduplicated`; otherwise it
returns a stable conflict and sends no request. It never creates another tool
identity. Zode v0 intentionally has no public `mark_failed`: without an
adapter-verifiable evidence protocol it could falsely classify an external
side effect. Such a call returns `422` and leaves the outcome unknown. The
retry command is idempotent, is first-terminal-aware, and produces a durable
SSE lifecycle event.

### External completion

For callback-mode tools, Endpoint generates a stable opaque `callback_id`,
stores its mapping to the original session/tool call plus only a keyed bearer
fingerprint, and sends the external tool:

- `{callback_base_url}/{callback_id}`;
- the raw one-invocation bearer for a secret authorization header.

Management Server supplies its stable Endpoint-scoped relay base; a standalone
controller supplies its own reachable base. This is execution configuration,
not Endpoint manager discovery.

`POST /v1/callbacks/{callback_id}` is the only Endpoint external completion
route. It accepts the bearer in the callback authorization header and this
bounded body:

```json
{
  "status": "completed",
  "result": { "content": "done" }
}
```

`status` is `completed` or `failed`. Callback ID, bearer fingerprint, canonical
body fingerprint, and terminal result make retries idempotent without a
separate header key. Missing and unauthorized IDs return the same safe
not-found result. The callback bearer is never placed in a URL or returned by
status, session, SSE, or error endpoints; callback ID is likewise omitted from
those unrelated views, and only the bearer's keyed fingerprint may be durable.
Canonical JSON means object key order does not change identity. A
duplicate completion replays; a different or later terminal body cannot
overwrite the winner. There is no session/tool-ID completion route.

## 6. Identity, health, and capabilities

- `GET /v1/identity` returns the stable opaque Endpoint-owned `endpoint_id`, protocol
  version, and the authenticated controller's non-secret authority ID and
  credential revision. It never lists other controller authorities.
- `GET /v1/health` performs a bounded readiness check and never scans session
  history or acquires an unnecessary writer lock.
- `GET /v1/capabilities` lists non-secret provider adapter kinds, outbound
  policy capabilities, configured tools, limits, and supported auth-replica
  credential schemas. Provider instances/models configured by Server are not
  Endpoint capabilities.

`GET /v1/health` returns exactly the bounded controller-scoped readiness view:

```json
{
  "schema": "zode.endpoint-health.v1",
  "protocol_version": "zode.endpoint.v1",
  "endpoint_id": "endpoint-opaque",
  "status": "ready"
}
```

Its encoded body is at most 4 KiB. Once the public listener is available,
`ready` means configuration, controller state, credential-replica state,
runtime storage, and startup recovery all completed. It does not perform a new
store scan or wait for active session/provider/tool work on each request.

`GET /v1/capabilities` returns this exact minimum shape; additional fields
require another reviewed contract rather than leaking adapter configuration:

```json
{
  "schema": "zode.endpoint-capabilities.v1",
  "protocol_version": "zode.endpoint.v1",
  "endpoint_id": "endpoint-opaque",
  "provider_adapter_kinds": ["openai_compatible"],
  "auth_replica_credential_schemas": ["openai-compatible.api-key.v1"],
  "outbound_capabilities": ["provider_http", "tool_http"],
  "built_in_tools": ["wait_for"],
  "tools": [
    {
      "name": "fixture_tool",
      "completion_mode": "response"
    }
  ],
  "limits": {
    "max_session_request_bytes": 262144,
    "max_auth_replica_request_bytes": 131072,
    "max_inline_tool_output_bytes": 65536,
    "wait_for_min_seconds": 1,
    "wait_for_default_seconds": 60,
    "wait_for_max_seconds": 600
  }
}
```

When `anthropic` is enabled, the capability projection includes
`"anthropic"` and `"anthropic.api-key.v1"`. An Anthropic session selection
uses `provider_execution.kind: "anthropic"`, an origin-only `base_url` (the
adapter appends `/v1/messages`), and an explicitly installed replica whose
credential schema is `anthropic.api-key.v1`; the native request uses
`x-api-key` and Anthropic SSE rather than the OpenAI-compatible wire shape.

All arrays use ascending UTF-8 byte order. The values above illustrate an
Endpoint whose effective composition has one response-mode HTTP tool and no
public external-callback route. `outbound_capabilities` reports only enabled
capability classes, never allowlisted origins: `external_callback` is present
only when callback policy, a configured external-callback tool, the public
callback route, and its runtime lifecycle are all composed. `tools` exposes
only a bounded configured name and completion mode; descriptions, input schemas,
adapter URLs, recovery internals, and callback origins remain private. The
encoded capability body is at most 1 MiB and is constructed, sorted, and
validated once before READY from the same effective configuration used by the
production adapters. An oversized projection fails startup instead of
truncating or changing order at request time.

These routes do not register Endpoint with a controller and do not expose
filesystem paths, provider credentials, local process details, or session
history. Their arrays are deterministically ordered and their response sizes
are bounded independently of session/event count. `GET /v1/health` returns a
versioned `ready` response without waiting for active provider/tool work or
rebuilding session projections. `GET /v1/capabilities` is restart-stable for
the same effective Endpoint configuration and never returns configured
provider origins, tool URLs, callback origins, model/profile instances, or
secret-store metadata. A management Server records its own health observation.

### Controller credential rotation

`controller_authority_id` is a stable logical identity stored independently of
its bearer secret. Rotation advances a monotonic credential revision without
changing that identity or any session/receipt ownership scope:

```http
PUT /v1/controller-auth
Idempotency-Key: controller-rotation-operation
Authorization: Bearer current-controller-secret
```

```json
{
  "schema": "zode.controller-auth.rotate.v1",
  "authority_id": "controller-opaque",
  "revision": 2,
  "secret": {
    "encoding": "application/zode-secret-envelope",
    "payload": "transport-protected-secret"
  }
}
```

The authenticated authority must match the body. Endpoint stages the secret,
persists a keyed request fingerprint, atomically promotes revision 2, fences the
older credential, and acknowledges only after revision 2 authenticates the
same authority. Lower revisions are stale; same revision/different fingerprint
conflicts. If the response is lost, the controller probes with the staged new
secret first and otherwise retries the same operation with the old secret.
Session list/read/mutation, Endpoint SSE, and same-key receipt replay remain
accessible under the unchanged authority/subject after rotation and restart.

The active authority manifest is the durable promotion fact. Its publication
is also the authentication linearization point: a request admitted after that
publication cannot authenticate with the previous secret, even if persisting a
safe receipt or returning the rotation response later fails. Endpoint preserves
each completed rotation's bounded, non-secret fingerprint and exact response as
an immutable operation receipt scoped by controller authority, opaque subject,
rotation command, and idempotency key. The current authority secret can
therefore replay an older operation exactly and detect a same-key/different-body
conflict after later rotations and restarts without re-running the mutation.
The same key in another authority, subject, or command scope is independent and
cannot discover, replay, or conflict with that receipt.

Completed receipts do not accumulate in the recovery journal. That journal is
a bounded recovery tail containing unresolved intents and, at most, the current
promotion receipt. Older completed receipts move to their immutable
direct-lookup facts after the active manifest and receipt are durable. Startup
reconciles the manifest, recovery tail, and current receipt before readiness,
but does not scan all historical receipts. Initial configured secrets may
bootstrap only a jointly new runtime/control store; a missing initialization
fact or partial controller state on an existing Endpoint fails closed instead
of restoring an older configured secret.

## 7. Credential replicas

Endpoint exposes a controller-authenticated provisioning surface, not a
user-facing OAuth/profile management API:

- `GET /v1/auth-replicas` lists installed non-secret replica metadata;
- `GET /v1/auth-replicas/{auth_profile_id}` reads one replica;
- `PUT /v1/auth-replicas/{auth_profile_id}` installs a revision or a newer
  tombstone.

Install body:

```json
{
  "schema": "zode.auth-replica.install.v1",
  "authority_id": "authority-opaque",
  "provider": "fixture-compatible",
  "kind": "api_key",
  "revision": 3,
  "credential_schema": "openai-compatible.api-key.v1",
  "expires_at_ms": null,
  "secret": {
    "encoding": "application/zode-secret-envelope",
    "payload": "transport-protected-secret"
  }
}
```

Success returns only authority/profile/provider identity, revision, expiry, and
`ready` status. The same idempotency key and fingerprint replay. A different
body conflicts. Lower revisions are stale; the same revision with a different
keyed fingerprint conflicts; a different authority cannot take over the
profile ID.

Tombstone body:

```json
{
  "schema": "zode.auth-replica.tombstone.v1",
  "authority_id": "authority-opaque",
  "provider": "fixture-compatible",
  "revision": 4
}
```

A tombstone prevents new credential resolution before restart-reconciled
secret cleanup. It does not cancel an already-sent model request. A delayed
install cannot resurrect a newer tombstone.

There is no Endpoint route for provider defaults, OAuth login, refresh, profile
labels/account management, or sharing policy. Those belong to management
Server. Endpoint-local standalone controllers use the same provisioning
protocol under their own authority identity.

Full atomicity, security, refresh, and recovery semantics are in
`docs/auth-replication.md`.

## 8. E2E fixture boundary

Tests may start local HTTP servers that emulate model, tool, and callback
counterpart systems. They write an ordinary product config pointing Endpoint
at those URLs, provision credentials through the public replica route, and then
use the real Endpoint binary. Fixture control happens on the fixture's own test
port; no hidden Endpoint route, in-process model, fake storage, or `cfg(test)`
production branch is allowed.

A fixture may expose barriers that hold a provider stream or tool request,
release it, record received native wire requests, or rotate an accepted token.
E2E assertions still observe Endpoint only through the public routes above and
may inspect a stopped test-owned database/secret directory solely for recovery
or secret-leak setup/evidence. OAuth fixtures belong to Server E2Es.

Required create/list identity E2Es prove Endpoint returns a valid ULID, a
same-key create replay returns exactly that ULID and one initial event, a
different-body same-key create conflicts, a caller-supplied `session_id` is
rejected, list pagination survives restart without relying on ULID order, and
two authenticated subjects can reuse a key while neither can list/read/stream/
mutate the other's session. Replay-only lookup must return hit/conflict/miss
without consulting current credential/readiness state or issuing a mutation.

Executable anchors are
`e2e_create_generates_ulid_and_binds_idempotency_payload`,
`e2e_create_receipt_lookup_precedes_current_admission`,
`e2e_create_receipt_projection_rebuilds_from_verified_creation_event`,
`e2e_conflicting_create_receipt_projection_fails_closed`,
`e2e_concurrent_create_receipt_and_event_are_atomic`, and
`e2e_session_ownership_safe_not_found_and_ordered_sse`, with the independent
single-page list assertion in `e2e_session_list_is_subject_scoped`. Authority-
scoped create receipts are anchored by
`e2e_authority_subject_create_receipts_are_scoped`; the cross-authority access
case `e2e_session_authority_ownership_isolates_list_read_message_and_sse` must
be added and demonstrated red. The complete multi-page keyset/restart case must
also be added and demonstrated red before list production is considered
complete; a single-page ownership assertion does not cover that separate
ordering decision.

A controller-auth rotation E2E creates a session, loses the rotation response,
recovers with the staged new secret, restarts Endpoint, and proves the unchanged
authority/subject can list/read/message, resume the Endpoint SSE, and replay the
original create key while the old secret is fenced.

The executable anchor is
`e2e_controller_auth_rotation_lost_response_fences_old_secret_and_survives_restart`;
the adjacent control-store fault cases in `endpoint_control_e2e` freeze its
filesystem authority, promotion, collision, receipt, and recovery boundaries.

Endpoint identity E2E proves the same Endpoint-owned `endpoint_id` is returned
before and after process restart on the same stores and cannot be changed by a
controller request.

The executable anchor is `e2e_identity_is_endpoint_owned_and_restart_stable`.

Endpoint health is anchored by
`e2e_endpoint_health_is_controller_authenticated_and_independent_of_active_session_work`:
with a real provider/tool request held at a fixture barrier, a bearer-authenticated
health request without `Zode-Subject` returns the bounded versioned ready response
before that work is released, while missing or invalid controller authentication
fails safely.

Endpoint capabilities are anchored by
`e2e_endpoint_capabilities_are_restart_stable_bounded_and_non_secret`: a real
Endpoint configured with known adapters and a response-mode HTTP tool returns
the deterministic controller-authenticated capability projection without
`Zode-Subject`, remains identical across restart, matches the exact schema and
the sorted values implied by that effective composition, omits
`external_callback` while no real callback route/lifecycle is composed, stays
within its public bound, and omits every fixture secret, path, URL, provider
instance/model/profile, session ID, and history fact.
An initial missing-route 404 is only shallow evidence. The E2E owner must retain
the first mismatch after the smallest real health/capabilities route bootstrap
and freeze that behavioral red before the complete handlers are implemented.

# zode management Server API

Status: authoritative v0 contract for Server and the web UI. Endpoint protocol
details live in `docs/http-api.md`; cross-version admission is frozen in
[`docs/protocol-compatibility.md`](protocol-compatibility.md). Routes may be introduced incrementally only
with a failing real-process E2E.

## 1. Boundary

The browser and API clients call Server only through the Cloudflare Access-
protected management origin. Server validates the Access application assertion,
resolves Endpoint and auth-profile semantics, and proxies Endpoint session
HTTP/SSE. Session data passes through Server but is never persisted there.
`docs/access.md` is authoritative for ingress, actor derivation, origin
separation, key rotation, and authentication E2Es.

Session proxy observability records only the route template, authorized
Endpoint record, status class, latency, and bounded counters. It must not log or
label metrics with raw URI/query values, `session_id`, response bodies, SSE
frames, `Location`, or callback bearer headers.

Server never returns Endpoint control credentials, provider credentials,
secret distribution payloads, OAuth state/PKCE, internal URLs, filesystem
paths, or raw Endpoint/provider errors.

The management API has no release, stage, promote, rollback, install, or
process-supervisor resource. V0 release switching is an operator deployment
action performed by the release driver/CLI outside this HTTP API. A real
browser may verify the running product after that action, but it cannot trigger
or authorize the switch through Server.

Every Endpoint record, provider descriptor, profile, and default belongs to one
Server authority. V0 has no Zode user, workspace, membership, role, or grant
resource. Every human or service actor admitted by the configured Access
application has the same management capabilities and sees the same management
resources. Provider profiles are deployment-shared, not personal.

Sessions are the deliberate exception to shared visibility. Server derives one
opaque subject from the validated Access actor; Endpoint records and enforces
that subject. Two admitted actors can manage the same Endpoint and profiles but
cannot list, read, stream, or mutate each other's sessions. Server has no
session ACL or session-owner row.

### Ingress authentication

V0 uses the application JWT placed in `Cf-Access-Jwt-Assertion`. Server verifies
its RS256 signature against the configured Access JWKS, exact issuer, accepted
AUD, `type=app`, required expiry, optional not-before, and supported actor shape
before resource lookup or Endpoint contact. It never authenticates from `CF_Authorization`,
email/custom headers, unsigned claims, a Zode bearer credential, or a test-only
bypass. Missing or invalid assertions return one safe authentication error.

Human actors use a non-empty Access `sub`; service-token actors use non-empty
`common_name` with an empty `sub`. A versioned keyed derivation produces an
`access_actor_key` for receipt/OAuth-attempt scope and a separately domain-
separated Endpoint subject. Raw JWTs, Access cookies, subjects, service-token
IDs, and email are never persisted or logged. `server_authority_id` remains the
stable Server/controller and provider-replica writer identity. AUD is validated
but excluded from subject derivation so recreating the Access application does
not silently orphan sessions.

Zode exposes no login, logout, current-user, workspace, principal, role, grant,
invite, or account-management route. Cloudflare owns browser login/session
cookies and service-token admission. Human browser mutations still require the
configured same-origin `Origin`/Fetch-Metadata checks. Long-lived SSE is closed
no later than assertion expiry so reconnect re-enters Access policy evaluation.

Real-process E2Es use a network Access edge/JWKS fixture that emits real signed
application JWTs into the production verifier. Hidden login routes, direct
database insertion, trusted test headers, and `cfg(test)` auth behavior are
forbidden.

All normal bodies are UTF-8 JSON under `/v1`. Every mutation requires
`Idempotency-Key`, except OAuth authorize-ticket redemption, a protected OAuth
callback whose state is its one-time identity, and an Endpoint callback relay
whose opaque callback ID is its one-invocation identity. Responses include a
versioned `schema` field.

Server-owned management mutations bind receipts only after Access validation,
request bounds, and concrete path-identity parsing. Their key is
`(server_authority_id, access_actor_key,
command_kind, concrete_parent_ids, concrete_resource_ids, Idempotency-Key)`.
Command kind is versioned; every concrete path identity participates, not only the route
template. A collection create uses its concrete parent plus collection action
as scope.

The receipt stores a versioned canonical request fingerprint and redacted
status/body: same scope/key/fingerprint replays it, while same scope/key with a
different fingerprint returns `409 idempotency_conflict`. Different Access
actors or scopes never collide. Secret-bearing requests fingerprint with a
restart-stable keyed HMAC and never store canonical secret bytes.

Receipt lookup precedes mutable resource existence/state checks. A hit replays
the original safe response even if the operation deleted or changed that
resource. A miss then resolves the current resource and applies all product
semantics before starting an operation. Because receipt scope includes the
pseudonymous Access actor and every concrete path ID, this replay rule does not
allow another actor or path to probe or reuse an outcome.

Each Server-owned management mutation also has one stable operation identity.
For a database-only mutation, its append-only control facts, final receipt, and
original safe status/body commit in one transaction. A mutation with external
steps first journals its phase and every identity Server owns; secret staging
and bounded probes are replayable phases. Endpoint's own ID is learned from its
repeatable authenticated identity probe, not allocated by Server. The final
resource facts plus receipt commit atomically. Recovery resumes the same
operation and never allocates a second Server-owned resource after an unknown
response.

Endpoint session mutations are the exception to Server receipt storage: Server
validates and forwards `Idempotency-Key` unchanged. Endpoint owns the
receipt and replay, so Server never stores a session command or its result.
Server also forwards a stable opaque subject derived from the validated Access
actor under its configured controller authority. Browser input cannot
override this value; Endpoint owns the resulting session ACL check. The subject
is a bounded pseudonymous keyed derivation, not an email, display name, raw
Access subject, or service-token ID. Its derivation key/version is durable
across restart; rotating it requires an
explicit Endpoint ownership-migration design rather than silently abandoning
existing sessions.

For every session mutation, Server validates the Access actor, resolves the
Endpoint record, then performs Endpoint's replay-only lookup with the exact
body/key. A hit returns the original result even if profile or action state
changed after commit. A miss must pass all current product semantics before
normal Endpoint admission. This ordering applies to create, message, model
selection, cancel, and reconciliation; it never creates a Server receipt.

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

Server distinguishes malformed input, authentication/authorization, missing
resources, idempotency/optimistic conflict, Endpoint unavailable, provider
unavailable, semantic validation, and neutral internal failure. It does not
copy downstream response text into the public message.

## 2. Server capabilities and deployment

`GET /v1/system` returns non-secret product and deployment information:

```json
{
  "schema": "zode.system.v1",
  "deployment": "all_in_one",
  "local_endpoint_id": "endpoint-local",
  "ingress": {
    "management_auth": "cloudflare_access",
    "callback_origin": "separate"
  },
  "features": {
    "remote_endpoints": true,
    "provider_auth": true
  }
}
```

`deployment` is `server_only` or `all_in_one`. Endpoint-only has no Server API.
The built-in Endpoint appears in every normal Endpoint route and is not exposed
through special local-only APIs. In `server_only`, `local_endpoint_id` is
explicitly `null`; it is never omitted or filled with a placeholder. `ingress`
reports only the fixed product mode, never issuer, AUD, JWKS, hostnames, raw
claims, cookies, or callback credentials.

## 3. Endpoints

### List and read

- `GET /v1/endpoints`
- `GET /v1/endpoints/{endpoint_id}`

An Endpoint representation contains:

```json
{
  "schema": "zode.endpoint.v1",
  "endpoint_id": "endpoint-opaque",
  "label": "Studio Mac",
  "kind": "local",
  "status": "online",
  "disabled": false,
  "controller_authority_id": "controller-opaque",
  "controller_credential_revision": 2,
  "capabilities": {
    "providers": ["provider-type"],
    "tools": ["shell", "workspace"],
    "protocol_version": "zode.endpoint.v1"
  },
  "last_observed_at_ms": 1234567890,
  "auth_replica_summary": {
    "ready": 2,
    "pending": 0,
    "stale": 1
  }
}
```

`kind` is `local` or `remote`. `status` is `online`, `degraded`,
`unreachable`, or `disabled`. Status is a bounded Server observation and never
pretends to be a heartbeat emitted by Endpoint.

### Add or update a remote Endpoint

`POST /v1/endpoints` creates a remote Endpoint record:

```json
{
  "label": "Laptop",
  "base_url": "https://endpoint.example.test",
  "control_auth": {
    "kind": "bearer",
    "secret": "secret input"
  }
}
```

Server stages the control secret outside SQLite and probes the authenticated
Endpoint identity/capability route. Endpoint returns its own stable
`endpoint_id`; the final catalog record keyed by that ID, safe response, and
receipt commit atomically. Crash recovery resumes the same staged secret and
probe, which returns the same ID; it cannot create a second Endpoint. An ID
already present under the Server authority must use the explicit update route and cannot
create a second catalog row. Public responses omit `base_url` details that
policy marks sensitive and always omit the secret.

`PUT /v1/endpoints/{endpoint_id}` changes label, address, or disabled state.
Address change must revalidate the same Endpoint-owned ID and stable controller
authority. It cannot retarget the catalog record to another device.

`POST /v1/endpoints/{endpoint_id}/control-auth-rotations` stages a new Server
secret, invokes Endpoint's controller-auth rotation with the current secret,
probes the new credential for the same Endpoint-owned ID and
`controller_authority_id`, then atomically promotes the Server secret reference.
The durable operation retains both safe secret references until recovery knows
which revision won; a lost response probes new first, then resumes with the
same operation. Rotation never changes Endpoint ID, controller authority,
delegated subject, session ownership, or Endpoint idempotency scope.

V0 has no `DELETE` for an Endpoint record. `PUT` may disable it reversibly, but
the stable `endpoint_id` remains reserved so session bookmarks and callback
routes cannot be rebound to another device. A future retirement protocol must
append a durable record tombstone, preserve the ID forever, handle outstanding
auth-replica removals, and explicitly warn that Endpoint-owned sessions are not
deleted. It cannot be added as ordinary row deletion.

### Refresh health

`POST /v1/endpoints/{endpoint_id}/probe` performs one bounded Server-initiated
health/capability observation. It does not cause Endpoint to register or open a
reverse connection.

## 4. Provider types and auth profiles

`GET /v1/providers` lists Server-managed provider types, their versioned
non-secret Endpoint execution descriptor (safe base URL/model/catalog/options),
explicit default profile, and aggregate non-secret auth status. It is configured
once on Server; Server supplies the descriptor to every selected Endpoint
session, while Endpoint supplies the actual adapter/aimux logic.

The response shape is exact and versioned:

```json
{
  "schema": "zode.providers.v1",
  "providers": [
    {
      "provider": "models-example",
      "descriptor": {
        "revision": 3,
        "kind": "openai_compatible",
        "base_url": "https://models.example.test/v1",
        "models": ["model-a"],
        "options": {}
      },
      "default_profile_id": "01JPROFILEEXAMPLE0000000000",
      "auth_status": "ready",
      "auth_profile_count": 2
    }
  ]
}
```

`providers` is sorted by `provider`. `default_profile_id` is nullable and, when
present, identifies one profile of that provider. `auth_status` is
`unconfigured` when no profile exists, `ready` when at least one current usable
profile exists, and `unavailable` when profile records exist but none is currently
usable. The count and status are deployment-shared authority projections, never
filtered by Access actor. The response cannot contain secret bytes, raw account
subjects, OAuth attempt/ticket state, replica credentials, or provider headers.
An authority with no configured providers returns the same schema with an empty
`providers` array; it does not return 404 or invent a built-in provider.

`PUT /v1/providers/{provider}` creates or updates that provider type's
non-secret execution descriptor:

```json
{
  "kind": "openai_compatible",
  "base_url": "https://models.example.test/v1",
  "models": ["model-a"],
  "options": {}
}
```

Server assigns a monotonic immutable descriptor revision. Existing active
requests keep their captured descriptor; UI normally selects the latest, while
session create/model selection carries one explicit revision and same-key retry
keeps it. Server validates bounds and safe URL schemes, while the target
Endpoint independently enforces adapter support and outbound policy. Secret
headers are auth-profile material and are rejected from this descriptor.

One provider type may have any number of OAuth and API-key profiles. Profile
routes are:

- `GET /v1/providers/{provider}/auth-profiles`
- `POST /v1/providers/{provider}/auth-profiles`
- `DELETE /v1/providers/{provider}/auth-profiles/{profile_id}`
- `PUT /v1/providers/{provider}/default-auth-profile`
- `GET /v1/auth-profiles/{profile_id}/replicas`
- `PUT /v1/auth-profiles/{profile_id}/sharing`
- `POST /v1/auth-profiles/{profile_id}/refresh-operations`
- `GET /v1/auth-refresh-operations/{operation_id}`
- `GET /v1/auth-refresh-operations/{operation_id}/events`

An API-key create body is:

```json
{
  "kind": "api_key",
  "label": "work key",
  "api_key": "secret input",
  "make_default": false,
  "sharing": {
    "mode": "selected",
    "endpoint_ids": ["endpoint-local"]
  }
}
```

The response contains profile ID, provider, kind, label, safe account hint,
status, revision, expiry when known, default flag, sharing policy, and
distribution summary. It never returns secret material.

Provider default is one Server-owned versioned pointer. Endpoint has no
independent default for Server-proxied session creation. Deleting the current
default atomically clears it and never chooses another profile.

Sharing policy is `none`, `selected`, or `all_current`. `all_current` does not
silently authorize future Endpoints; adding a new Endpoint creates an explicit
distribution plan visible to the user before secret transfer. A future
`all_including_future` policy requires a separate user-approved design.

Deleting a profile or removing an Endpoint from sharing atomically appends the
higher per-Endpoint tombstone operations defined in `docs/auth-replication.md`.
Those operations outlive the visible profile/sharing row and remain
restart-recoverable until acknowledged; removing the current row is never
treated as replica revocation by itself.

`GET /v1/auth-profiles/{profile_id}/replicas` exposes only non-secret
distribution state per Endpoint: requested/installed revision, status, last
attempt, acknowledgement time, and safe error code. Full semantics are in
`docs/auth-replication.md`.

## 5. OAuth attempts

OAuth is owned by Server. The durable attempt routes are:

- `POST /v1/providers/{provider}/auth-attempts`
- `GET /v1/auth-attempts/{attempt_id}`
- `GET /v1/auth-attempts/{attempt_id}/events`
- `POST /v1/auth-attempts/{attempt_id}/answers`
- `POST /v1/auth-attempts/{attempt_id}/cancel`
- `GET /v1/auth-attempts/{attempt_id}/authorize?ticket=...`
- `POST /v1/auth-attempts/{attempt_id}/authorize-tickets`
- `GET /v1/oauth/callback?state=...&code=...`

Starting an attempt accepts label, `make_default`, and initial sharing policy.
It fixes the eventual profile ID before secret promotion. Attempt state is an
append-only Server control stream and reaches exactly one of `succeeded`,
`failed`, or `cancelled`.

The attempt is bound to the initiating pseudonymous `access_actor_key`. Every
read, answer, cancel, event stream, authorize-ticket mint/redemption, and OAuth
callback requires that same actor. A successful credential/profile becomes
deployment-shared; another Access actor cannot take over an in-progress attempt.

The redirect ticket is a single-use five-minute capability bound to the attempt
and initiating `access_actor_key`. Redeeming it atomically records consumption
and allocates the provider state/PKCE before returning a redirect. A second
request with the same ticket returns one safe consumed response and cannot
redirect, allocate another state, or contact the provider. Expiry or consumption
does not end the login attempt; an active attempt can explicitly mint a new
ticket through `authorize-tickets`. Attempt expiry is terminal
`failed/auth_attempt_expired`. Callback, expiry, cancel, and prompt answer-
delivery failure use one first-terminal compare-and-set. Ticket redemption is a
one-time-identity exception to `Idempotency-Key`; the ticket value and its raw
URL never enter logs, events, receipts, or SQLite.

`authorize-tickets` responses and redemption redirects use `Cache-Control:
no-store`; the redirect also uses `Referrer-Policy: no-referrer`. Cross-site
Fetch-Metadata cannot redeem a ticket—the UI initiates it only from the
management origin. The provider must never receive the ticket in `Referer` or
another forwarded header.

Prompt answers are one-shot by `(attempt_id, prompt_id)`. Server stages answer
bytes in its protected secret store, journals only a keyed fingerprint and
phase, durably claims `accepted -> dispatching` before provider delivery, and
uses the provider adapter's recorded same-prompt idempotency capability for
crash recovery. Unknown delivery becomes
`failed/auth_answer_delivery_unknown` unless idempotent replay is guaranteed.

On OAuth success, Server promotes the credential as the profile's first
revision and creates distribution operations from the requested sharing
policy. Login success does not claim an Endpoint replica is ready.

For relogin after expiry or refresh-unknown, attempt create may include an
explicit `replace_auth_profile_id`. On success it advances that same logical
profile at a revision above every ready/reserved/tombstone revision; it does not
create a competing profile authority. Refresh operation status exposes only
`prepared`, `dispatching`, `succeeded`, `refresh_unknown`, or safe terminal
failure plus revision numbers and adapter recovery capability—never token
material or provider response bodies. Full crash semantics are in
`docs/auth-replication.md`.

Explicit refresh returns `202` with the stable operation ID after durable
admission; scheduled pre-expiry refresh creates the same public operation shape.
Its event stream is operation-local and resumable. Neither path retries or
re-admits an Endpoint session command automatically.

Once a profile reaches `refresh_unknown/reauth_required`, a durable profile-
level refresh fence rejects every new explicit or scheduled refresh admission
with `409 reauth_required`, regardless of a new `Idempotency-Key`, before any
provider request or revision reservation. The original operation remains
queryable/replayable. Only successful replacement through an auth attempt with
`replace_auth_profile_id` atomically advances the profile above the fenced
revision and removes the fence.

## 6. Sessions

### Create

`POST /v1/endpoints/{endpoint_id}/sessions` accepts:

```json
{
  "model": {
    "provider": "provider-type",
    "model": "model-id",
    "provider_execution": {
      "schema": "zode.provider-execution.v1",
      "revision": 4,
      "kind": "openai_compatible",
      "base_url": "https://models.example.test/v1",
      "options": {}
    },
    "auth_profile_id": "profile-opaque",
    "minimum_auth_revision": 7
  },
  "tools": ["shell"]
}
```

The model selection in the create body is fully concrete. UI copies the full
displayed immutable non-secret provider-execution descriptor and selects an
explicit profile before its first submission, then reuses the exact body and
key on every retry. Server never resolves a mutable default during admission.
On a new admission, Server validates the Access assertion, Endpoint capability,
model/profile compatibility, sharing policy, and that the full descriptor
exactly matches its immutable revision before forwarding it with the concrete
authority/profile/minimum replica revision. Operators still configure these
resources once on Server rather than on each Endpoint. Server additionally
injects its stable Endpoint-scoped `callback_base_url`; that configured value
cannot vary across a same-key retry.

Create admission is replay-aware and ordered:

1. Server validates the Access actor, resolves the Endpoint, bounds the request,
   and constructs the exact forwarded body from
   the client-frozen descriptor plus stable Server authority/callback fields.
2. It sends an authenticated replay-only create lookup to Endpoint with the
   same authority, subject, body, and `Idempotency-Key`. Endpoint returns the
   original response on a matching receipt, conflict on a changed fingerprint,
   or a typed receipt miss without creating anything.
3. A receipt hit is returned immediately even if the profile was subsequently
   deleted, unshared, rotated, or tombstoned. This recovers the identity of an
   already-created session; it does not make that session's next model request
   usable after revocation.
4. Only a receipt miss enters current profile, sharing, replica-readiness, and
   capability checks. Server holds the relevant policy serialization guard
   through Endpoint's durable create admission, then forwards normal create.

No replay path reads or restores deleted credential bytes or trusts the
descriptor for execution; a receipt miss must validate it against current
Server policy. An invalid Access assertion never reaches Endpoint receipt
lookup.

Server does not generate or reserve a session ID. It forwards the request and
`Idempotency-Key` to the Endpoint, which generates a ULID and atomically admits
the session. If the response is lost, the client retries this same
Endpoint-scoped route with the same key and Endpoint returns the original ULID.
Server keeps no session receipt, mapping, or pending route.

The Endpoint is always explicit in the URL; v0 never selects a device
implicitly. `auth_profile_id`, `provider_execution`, and
`minimum_auth_revision` are required whenever `model` is present; omitting one
returns `422` and never resolves a default. Omitting the entire model follows
Endpoint's explicit non-runnable-session contract. The provider default is a UI
selection convenience, not hidden create-time resolution.

Success is the Endpoint's authoritative create response:

```json
{
  "schema": "zode.command.v1",
  "session_id": "01JAZODE6Y7Q3FKM8N2S4V0WXC",
  "accepted": true,
  "version": 1
}
```

The browser identifies it by `(endpoint_id, session_id)`. `session_id` is
opaque outside Endpoint even though its v0 representation is a ULID.

### Read, messages, model, tools, callbacks

- `GET /v1/endpoints/{endpoint_id}/sessions`
- `GET /v1/endpoints/{endpoint_id}/sessions/{session_id}`
- `POST /v1/endpoints/{endpoint_id}/sessions/{session_id}/messages`
- `PUT /v1/endpoints/{endpoint_id}/sessions/{session_id}/model`
- `GET /v1/endpoints/{endpoint_id}/sessions/{session_id}/tool-calls/{tool_call_id}`
- `POST /v1/endpoints/{endpoint_id}/sessions/{session_id}/tool-calls/{tool_call_id}/cancel`
- `POST /v1/endpoints/{endpoint_id}/sessions/{session_id}/tool-calls/{tool_call_id}/reconcile`

Server validates and forwards session mutations with the caller's stable
idempotency key. It maps public responses without exposing Endpoint address,
control auth, internal errors, provider credential revision fingerprints, or
private tool callback bearers. It treats `session_id` only as an opaque URL
segment and does not persist or index it. It derives the same opaque subject for
every request by that Access actor; Endpoint returns not-found for another
subject's session.

The common replay-aware ordering is applied before mutable provider, profile,
model, or action gates. Thus a lost admitted message/model/tool-command
response remains replayable after a policy change, while a new key is judged by
current policy.

`GET` is a live Endpoint read. When Endpoint is unreachable, Server returns
`endpoint_unavailable`; it has no session projection to fall back to and does
not turn loss of contact into a runtime terminal event.

### Routing and migration

A v0 session remains on its creating Endpoint. There is no automatic failover
or `move` route. The Endpoint-scoped identity makes that ownership explicit.
Disabling or losing an Endpoint does not silently run the session on the
built-in Endpoint.

## 7. Session events

`GET /v1/endpoints/{endpoint_id}/sessions/{session_id}/events` proxies Endpoint
SSE. Event IDs remain durable Endpoint event positions and support
`Last-Event-ID`.

Server forwards the Endpoint public event schema without allocating a second
event identity. The route already supplies `endpoint_id`; each frame contains
the Endpoint-generated `session_id`, session version, kind, and data.

For each attached client, Server opens the matching Endpoint stream and forwards
the client's `Last-Event-ID`. Endpoint owns replay/live handoff and
deduplication. Server stores neither events nor cursors. If Endpoint is
unreachable, the proxy returns or closes with a safe Endpoint-unavailable
condition and cannot invent missing session facts.

Transient model token deltas may be proxied live. Final messages, activation
outcomes, tool lifecycle, and waits are published as durable frames only after
the Endpoint commits them.

## 8. Callback ingress

External tools may need an Internet-reachable callback while Endpoint is only
reachable from Server. Server has one stable configured public callback origin
that is distinct from the Access-protected management origin. It serves only
this callback surface; management, UI, OAuth, health, and session routes are
absent on that host. When proxying session create, Server injects that
deterministic Endpoint-scoped callback base as non-secret execution
configuration. Endpoint later creates an opaque callback ID and a separate
bearer and gives the external tool this route:

`POST /v1/endpoints/{endpoint_id}/callbacks/{callback_id}`

The callback bearer travels in a secret header, never the URL. Interactive
Cloudflare Access is not required on this origin and an Access assertion never
replaces the callback bearer. Server validates the callback Host/origin,
rate-limits, and forwards `callback_id`, the redacted bearer header, and the
bounded body to Endpoint's callback route without resolving or storing a
session ID or tool-call identity. Endpoint validates the bearer, resolves its
durable callback mapping, and owns idempotent first-terminal admission. Server
reports success only after Endpoint acknowledges it. If Endpoint is
unreachable, v0 returns a retryable failure; Server does not persist or queue
the callback. The stable callback origin cannot silently change on restart;
origin migration must keep old URLs routable until their Endpoint callbacks are
terminal.

## 9. UI bootstrap

After Cloudflare Access admits the browser, the UI may fetch these resources in
parallel:

- `/v1/system`;
- `/v1/endpoints`;
- `/v1/providers`;
- `/v1/endpoints/{endpoint_id}/sessions?limit=...&cursor=...` for each reachable
  Endpoint the current screen needs.

Endpoint session list routes preserve Endpoint opaque cursor pagination and
stable ordering. Server does not combine or retain them. UI must not derive
state by joining secret or Endpoint-internal resources.

## 10. Required E2Es

Only real-process tests are allowed. Server tests start a real Server, real
Endpoint processes, real temporary SQLite/secret stores, and network
provider/tool/OAuth fixtures.

- all-in-one first run: configure one profile, distribute to local Endpoint,
  create a session, receive a final assistant event, restart, and continue;
- add a remote Endpoint and run sessions on local and remote devices through
  the same Server routes;
- Endpoint identity survives restart; adding the same Endpoint again with a
  different key cannot allocate a second Server/device ID or catalog row;
- prove Endpoint creates the ULID, duplicate create with one idempotency key
  returns it, and Server stores no session ID or event;
- prove no global session lookup exists: two Endpoint-created sessions are
  addressed only by `(endpoint_id, session_id)` and an ID-only route is absent;
- two Access human actors sharing an Endpoint can reuse an idempotency key yet
  cannot list, read, stream, mutate, or collide receipts for each other's
  Endpoint-owned session;
- human and service-token assertions both use the shared management resources
  but derive distinct actor keys and Endpoint subjects;
- missing, forged, expired, wrong-issuer/audience/type, and malformed Access
  assertions fail before Endpoint contact; rotated JWKS succeeds without Server
  restart and no raw assertion/identity enters logs or databases;
- browser entry occurs through Access with no Zode login/logout, user,
  workspace, role, grant, token input, or application login cookie;
- restart Server after an unknown create response and retry without duplicating
  the Endpoint session;
- rotate Endpoint control authentication, restart/probe, and continue the same
  session GET/SSE/message and same-key create replay under unchanged authority;
- after Endpoint commits create but Server loses the response, delete/unshare
  the profile and prove same-key retry replays the original ULID while a new key
  is rejected by current policy;
- after Endpoint admits a message/model/tool mutation but Server loses the
  response, change the profile/action state and prove same-key replay returns
  the original result while a new key follows current policy;
- a model selection missing profile/descriptor/minimum revision returns `422`
  and creates no Endpoint session; Server never fills a mutable default;
- proxied SSE reconnect has no missing/duplicate durable Endpoint event and no
  Server event cursor;
- Endpoint unreachable returns typed unavailability and never silently
  reroutes or serves invented stale session state;
- OAuth/profile/default/distribution lifecycle with multiple profiles for one
  provider;
- redeem one OAuth authorize ticket twice and concurrently; exactly one request
  produces one redirect/provider state, every replay is consumed, and an
  explicit new ticket is required for another redirect; the provider observes
  no ticket in `Referer` or any forwarded header;
- rotate and revoke across reachable and unreachable Endpoints;
- idempotent refresh survives response loss/Server crash with one revision and
  distribution; non-idempotent unknown refresh fences new-key explicit and
  scheduled refresh with no second provider call until successful relogin, and
  never blindly retries or reuses a revision;
- Endpoint-scoped callback relay completes exactly once when reachable and
  returns retryable unavailability without a Server queue when offline; its
  bearer never appears in a URL, log, event, or database; the same callback URL
  remains valid across Server restart; the callback origin serves no management
  route and the OAuth callback stays Access-protected;
- Server-owned mutation idempotency is isolated by Access actor and command scope,
  conflicts on a changed body, and never stores secret request bytes;
- the same actor/key/body on two concrete Endpoint/profile path resources
  acts independently on both and can never replay one resource's response for
  the other;
- crash/retry each external-phase Server mutation after resource commit but
  before response and replay one original resource ID/status/body;
- `server_only` reports `local_endpoint_id: null` and exposes no phantom local
  Endpoint in API or UI;
- kill all-in-one Server while local Endpoint work is held, then restart and
  prove it adopts or fences the same Endpoint ID before any duplicate provider/
  tool effect can occur;
- start Server A and Server B on the same control/secret stores; B fails
  readiness and performs no Endpoint/management effect until A exits and B
  acquires the Server process lock;
- secret markers absent from Server/Endpoint HTTP, SSE, logs, databases,
  snapshots, session events, and UI assets;
- browser E2E covers the same all-in-one happy path through the real UI rather
  than a mock transport.

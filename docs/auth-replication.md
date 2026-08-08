# Auth-profile authority and Endpoint replication

Status: authoritative credential-distribution design. This document covers
Server-managed profiles shared to Endpoints. Provider execution remains in
Endpoint; OAuth and profile management remain in Server.

## 1. Goals

- An Access-admitted actor configures an API key or completes provider OAuth
  once on Server.
- The same profile can be authorized for any number of Endpoints.
- An authorized Endpoint persists enough credential material to call the
  provider directly through its local aimux adapter and to recover after
  restart.
- Rotation, refresh, deletion, retry, and crash recovery cannot create two
  credential authorities or silently restore an older credential.
- Secret bytes never enter ordinary databases, events, snapshots, logs, SSE,
  command receipts, or UI responses.

Distribution means the receiving Endpoint becomes a credential trust
boundary. Server must expose which Endpoints hold each profile, and it must not
claim cryptographic revocation of a static API key after that key has been
copied. Provider-side key revocation or rotation remains the only complete
revocation for such credentials.

## 2. Identity model

A Server-managed auth profile has stable non-secret identity:

```json
{
  "auth_profile_id": "profile-opaque",
  "authority_id": "server-installation-opaque",
  "provider": "provider-type",
  "kind": "oauth",
  "label": "work account",
  "revision": 7,
  "credential_schema": "provider.credential.v2",
  "expires_at_ms": 1234567890,
  "secret_fingerprint": "hmac-sha256:v1:..."
}
```

- `auth_profile_id` identifies the logical login across Server and Endpoints.
- `authority_id` identifies the only writer allowed to advance that profile.
- `revision` is monotonically increasing within `(authority_id,
  auth_profile_id)` and changes whenever execution-relevant secret material or
  expiry metadata changes.
- `credential_schema` selects the Endpoint provider adapter's versioned secret
  decoder.
- `secret_fingerprint` is a keyed, versioned digest used only for idempotency
  and comparison. It cannot be a plain hash of a low-entropy API key.

Endpoint-local profiles use a different `authority_id`. An Endpoint rejects a
Server replica that collides with a local profile ID under another authority.
There is no last-write-wins merge between authorities.

## 3. Stores and records

### Server

Server keeps:

- append-only non-secret profile/control events;
- one encrypted secret authority record per profile revision or an atomic
  current-secret record plus immutable operation journal;
- sharing policy identifying authorized Endpoints;
- one distribution operation per `(endpoint_id, profile_id, revision)`;
- acknowledgement and last-observed replica metadata.

The default pointer is provider-scoped and belongs only to Server. It is never
replicated as an Endpoint default. UI may resolve it as a selection convenience,
but Server-proxied session creation always carries a concrete profile ID and
minimum revision selected before first submission.

### Endpoint

Endpoint keeps:

- a restrictive encrypted or `0600` secret file for each installed replica;
- non-secret replica metadata containing authority, profile ID, provider,
  schema, revision, expiry, fingerprint, and status;
- an append-only provisioning-operation receipt sufficient for idempotent
  restart recovery.

Endpoint session events may contain profile ID and resolved revision. They may
not contain credential payload, authorization headers, refresh tokens, API
keys, raw fingerprints without a key-version tag, staging paths, or provider
login state.

## 4. Distribution protocol

Server always initiates distribution. Endpoint never polls Server and never
opens a reverse connection.

Conceptual Endpoint command:

```http
PUT /v1/auth-replicas/profile-opaque
Idempotency-Key: distribution-operation-opaque
Authorization: Bearer endpoint-control-secret
Content-Type: application/json
```

```json
{
  "schema": "zode.auth-replica.install.v1",
  "authority_id": "server-installation-opaque",
  "provider": "provider-type",
  "kind": "oauth",
  "revision": 7,
  "credential_schema": "provider.credential.v2",
  "expires_at_ms": 1234567890,
  "secret": {
    "encoding": "application/zode-secret-envelope",
    "payload": "transport-protected-secret"
  }
}
```

The request is protected by authenticated TLS. An additional envelope
encrypted to the Endpoint identity key is recommended when traffic may
cross a terminating relay. The raw request body is never logged or retained as
an idempotency receipt.

The authenticated authority plus `profile-opaque` path identifies one replica
resource. Its first accepted install binds the profile to the request's
provider type. A later request cannot rebind that profile by changing
`provider`, whether it reuses the original `Idempotency-Key` or supplies a new
one. Receipts are looked up by authority, profile resource, and operation key;
provider remains inside the keyed request fingerprint so an altered replay
conflicts.

Endpoint processes an install as one staged operation:

1. authenticate the controller and require its stable controller authority to
   equal the profile `authority_id`; the opaque session subject is not a
   profile owner or operation scope;
2. validate provider support, credential schema, limits, revision, and secret
   envelope without exposing the secret in an error;
3. stage the secret under the operation-derived protected path;
4. append the non-secret pending operation and keyed request fingerprint;
5. atomically promote the staged secret;
6. atomically mark replica revision `ready` and persist the original redacted
   response metadata;
7. acknowledge only after the active secret exists.

Success returns non-secret metadata:

```json
{
  "schema": "zode.auth-replica.v1",
  "auth_profile_id": "profile-opaque",
  "authority_id": "server-installation-opaque",
  "provider": "provider-type",
  "revision": 7,
  "status": "ready",
  "expires_at_ms": 1234567890
}
```

The same operation and fingerprint replays the original status/body. The same
operation with different semantics conflicts. A lower revision is stale and
cannot mutate the replica. The same revision with a different secret
fingerprint conflicts. A higher revision may replace only the same authority
and provider/profile identity.

## 5. Deletion and revocation

Server distributes a monotonically newer tombstone rather than an unversioned
DELETE:

```http
PUT /v1/auth-replicas/profile-opaque
```

```json
{
  "schema": "zode.auth-replica.tombstone.v1",
  "authority_id": "server-installation-opaque",
  "provider": "provider-type",
  "revision": 8
}
```

Endpoint atomically marks the replica unavailable, prevents new resolution,
and removes active/staged secret material through restart-reconciled cleanup.
An already-sent provider request keeps the credential bytes it resolved; the
tombstone controls later requests. A delayed revision 7 install cannot
resurrect revision 8.

Removing one Endpoint from sharing atomically allocates a profile sequence
revision greater than every credential or prior tombstone revision and appends
a durable tombstone operation for that Endpoint. Deleting a profile does the
same for every Endpoint that may hold it. These operations retain the profile
identity after its secret and visible profile are removed. They remain pending
through Server restart until acknowledged. `unreachable` is a visible pending
condition, never permission to discard a tombstone; current sharing policy is
not used as a substitute for this journal.

Because a per-Endpoint tombstone may be newer than the credential still used by
other Endpoints, every later credential rotation or re-share allocates above
all tombstones. Re-sharing never sends an older credential revision over a
newer tombstone.

Server UI distinguishes:

- `pending`: distribution has not been acknowledged;
- `ready`: Endpoint durably installed the requested revision;
- `stale`: Endpoint reports an older revision;
- `removing`: tombstone sent but not acknowledged;
- `removed`: tombstone acknowledged;
- `unreachable`: current Endpoint state is unknown.

For static API keys, local deletion is best-effort secret erasure, not proof
that a compromised Endpoint forgot the key. Server communicates that security
limit instead of claiming immediate revocation.

## 6. Refresh and rotation

Every profile revision has one refresh authority. For Server-managed profiles
in v0, Server is that authority. Explicit UI refresh and scheduled pre-expiry
refresh enter the same durable Server operation:

1. under the profile lock, Server fixes `refresh_operation_id`, source
   credential revision, provider adapter/capability, and reserves one monotonic
   next revision before any provider request; a reserved revision is never
   reused;
2. it appends `prepared`, then durably advances to `dispatching` before sending
   the refresh secret/request;
3. the auth adapter declares exactly one recovery capability:
   `same_operation_id_idempotent`, `exact_result_reconcile`, or `none`;
4. on a successful response, Server stages the returned secret, then completes
   its phase protocol so the new profile revision, safe final receipt, and all
   authorized Endpoint distribution operations become visible exactly once;
5. Endpoint replicas install that revision normally and acknowledge.

If Server loses the provider response while `dispatching`, it may resend only
when the provider adapter guarantees the same operation ID returns the same
refresh result. An `exact_result_reconcile` adapter may instead read back the
exact credential material needed for execution. Merely learning that a refresh
token was consumed is not reconciliation because it cannot recover a rotated
secret.

With capability `none`, unknown dispatch appends
`refresh_unknown/reauth_required`, keeps the last known revision as current,
never publishes the reserved revision, and never blindly reuses the old refresh
token. The same transaction establishes a durable profile-level refresh fence.
While fenced, every new explicit or scheduled refresh request—including one
with a new idempotency key—is rejected as `reauth_required` before allocating a
revision or contacting the provider. The original operation may only be read or
replayed. The next successful relogin/replacement allocates above every ready,
reserved, or tombstone revision and atomically removes the fence while promoting
the replacement. A failed/cancelled relogin leaves it fenced. Provider/model
calls may continue only while the last known credential still works; otherwise
Endpoint exposes its normal typed auth failure. No Server process invents or
silently retries session input.

Endpoint never refreshes a Server-managed profile or writes a competing
revision. If a provider request reports expired/invalid auth before the update
arrives, Endpoint commits a typed safe failure for the concrete revision and
does not fall back to environment credentials, another profile, or an older
secret. Server can complete distribution and explicitly re-admit work.

Future delegated offline refresh must transfer a fenced refresh lease to one
Endpoint and suspend Server refresh for that profile. Bidirectional
last-write-wins token synchronization is forbidden.

## 7. Session resolution

UI may present Server's default, but before first submission it freezes one
explicit profile and minimum revision. Server validates that concrete choice
against sharing policy and Endpoint readiness, then sends a concrete model
selection. The same rule applies when changing a session:

```json
{
  "provider": "provider-type",
  "model": "model-id",
  "provider_execution": {
    "schema": "zode.provider-execution.v1",
    "revision": 4,
    "kind": "openai_compatible",
    "base_url": "https://models.example.test/v1",
    "options": {}
  },
  "auth_authority_id": "server-installation-opaque",
  "auth_profile_id": "profile-opaque",
  "minimum_auth_revision": 7
}
```

Endpoint does not choose a default profile. Activation captures the exact
authority/profile and minimum revision. Immediately before each aimux call,
Endpoint resolves the newest ready revision satisfying that minimum and records
the concrete revision in `ModelAttemptStarted`. The resolved secret remains
outside the event store.

A revision installed during an active provider request cannot change that
request. A later provider request resolves the newest ready revision. Profile
rotation therefore does not rewrite the session's logical profile selection.

## 8. Startup reconciliation

Before Endpoint readiness:

- finish or fail every staged install deterministically;
- verify each `ready` metadata record has its matching active secret;
- remove orphaned staged material;
- preserve the highest accepted revision and tombstone;
- report typed non-secret health for irrecoverable replicas.

Before Server readiness:

- reconcile profile/OAuth operations and secret promotion;
- rebuild distribution jobs from sharing policy and acknowledged revisions;
- never mark an Endpoint ready for a revision based only on a sent request;
- retry uncertain operations with their original idempotency identity;
- rebuild pending removal tombstones from their append-only operations even
  when the current sharing set or visible profile no longer contains the target.

## 9. Security requirements

- Endpoint control routes require a distinct administrative credential from
  callback bearers and Cloudflare Access ingress.
- Server authorizes profile sharing per Endpoint. Possession of an Endpoint URL
  alone grants no profile access.
- Server-managed profiles are deployment-shared resources in v0. Every actor
  admitted by the configured Access application may enroll, use, default,
  refresh, delete, and change sharing. Zode has no per-actor provider grants or
  personal profile copies.
- Secret-bearing bodies are size-bounded and redacted before tracing.
- Secret fingerprints use a restart-stable keyed HMAC and rotate by explicit
  key version.
- Secret files are atomically replaced, restrictive, and never served as
  blobs.
- Crash dumps, debug endpoints, metrics labels, panic messages, and fixture
  output must not contain secret material.
- Non-secret listing may expose provider, kind, label supplied by Server,
  revision, expiry, and status, but never account tokens, API keys, auth
  headers, OAuth state, PKCE, authorization codes, or raw provider payloads.

## 10. Required E2Es

All cases start real Server and Endpoint processes, use public HTTP/SSE, real
temporary SQLite and secret directories, and network provider fixtures through
Endpoint aimux.

- configure one API-key profile on Server, share it to two Endpoints, and prove
  both Endpoints call the provider directly without per-Endpoint setup;
- `e2e_browser_provider_profile_default_action_updates_server_pointer` creates
  two profiles through the real management UI, changes the provider-scoped
  default, and verifies the Server-owned pointer and non-secret projection;
- complete one OAuth profile on Server, distribute the execution credential,
  restart both Endpoints, and run sessions without another login;
- crash Endpoint before and after secret promotion and prove one revision and
  no secret leakage;
- race revisions N and N+1 and prove N cannot overwrite or resurrect N+1;
- rotate during an active model stream and prove old-in-flight/new-next-request
  revision behavior;
- with an idempotent refresh fixture, consume the refresh and drop the response,
  kill/restart Server, retry the same operation, and prove one new revision, one
  distribution per Endpoint, replay of the original safe result, and a direct
  Endpoint model request using the refreshed credential;
- with a non-idempotent rotating refresh fixture, consume and drop the response,
  then prove `refresh_unknown/reauth_required`, no blind retry or guessed
  revision; submit a new refresh key and prove `409 reauth_required` with no
  second provider request; then prove a relogin succeeds at a strictly higher
  revision, clears the fence, and restores a direct Endpoint model request;
- tombstone while Endpoint is offline, reconnect, reconcile once, and prevent
  future provider calls without fallback;
- delete a profile or remove one Endpoint from sharing while it is offline,
  restart Server, race the retained tombstone with an older install, and prove
  the older credential cannot resurrect;
- retry after Server crashes before distribution acknowledgement and replay the
  original outcome;
- `e2e_browser_provider_profile_delete_replays_original_result_after_response_loss`
  proves a committed profile tombstone keeps a safe response receipt: a lost
  browser response can be retried with the same idempotency key and cannot turn
  into a new-key `not_found` after the UI confirmation remains open;
- corrupt only a stopped test-owned replica secret, restart, and expose a safe
  typed unavailable state rather than credential content;
- verify Server UI/API lists every Endpoint holding a profile and accurately
  distinguishes pending, stale, unreachable, and removed;
- scan Server/Endpoint HTTP, SSE, logs, databases, snapshots, and session events
  for credential markers after every scenario.

Current Endpoint executable anchors include
`e2e_auth_replica_revision_tombstone_and_restart_are_secret_free`,
`e2e_auth_replica_history_receipt_binds_original_revision`, and
`e2e_auth_replica_expiry_and_historical_receipt_survive_restart`. The last case
fixes both current expiry metadata and the exact historical status/body replay
across a newer revision and Endpoint restart; replay may not roll the active
replica backward. The independent execution anchor
`e2e_tombstoned_replica_never_reaches_provider_before_or_after_restart`
requires a durable typed `auth_replica_unavailable` terminal and zero provider
requests for work admitted after the tombstone, both before and after restart.

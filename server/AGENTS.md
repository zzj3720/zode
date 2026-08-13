# Management Server and all-in-one rules

The root `AGENTS.md` and `docs/architecture.md` are authoritative. `server/`
owns the management Server, Cloudflare Access assertion verifier, Endpoint
client, provider-auth authority and distribution, stateless session proxy,
callback relay, and
all-in-one composition. Its public contract is `docs/server-api.md`; credential
replication is `docs/auth-replication.md`; ingress identity is
`docs/access.md`.

## Hard boundaries

- Server initiates every Endpoint connection. Do not add Endpoint registration,
  reverse WebSocket, heartbeat callback, polling agent, or Server discovery to
  Endpoint to simplify Server.
- Consume Endpoint only through its versioned HTTP/SSE protocol. Do not import
  Endpoint domain reducers, SQLite rows, actor handles, or private handlers to
  make runtime decisions.
- Server owns Access assertion verification, Endpoint catalog records,
  provider execution descriptors, provider login/profile/default/
  refresh authority, sharing policy, distribution operations, Endpoint-scoped
  proxying, and UI API. It does not store an Endpoint control bearer.
- Server does not execute provider model streams. Endpoint runs aimux and calls
  providers directly. Server may contain provider-specific auth/login/refresh
  adapters, but not a competing model-execution adapter.
- One Server-managed auth profile has one writer: Server. Endpoint replicas are
  versioned read-only copies. Never resolve conflicts with last-write-wins or
  merge independently refreshed credentials.
- Endpoint alone creates and stores sessions. Server has no session resource,
  route table, event mirror, projection, or cursor. No automatic failover,
  silent local fallback, or migration shortcut is allowed.
- Raw Endpoint/provider/storage errors are classified and redacted before
  public HTTP/SSE. Never proxy downstream response bodies directly.
- Scope Endpoint/provider/profile/OAuth IDs to the stable Server authority
  before lookup. Missing resources use safe public errors; cross-resource IDs
  and receipts never collide or leak.
- V0 is one shared management trust domain. Every actor admitted by the
  configured Cloudflare Access application may use and manage all Endpoint and
  provider resources. Do not add Zode user/workspace/membership/role/grant,
  login/logout, invite, account, or login-cookie resources.
- Validate only `Cf-Access-Jwt-Assertion` using configured JWKS, exact issuer,
  accepted audience, `RS256`, `type=app`, time claims, and the actor shapes in
  `docs/access.md`. Never trust `CF_Authorization`, email/custom headers,
  unsigned claims, a local bearer fallback, or a test-only auth bypass.
- Cache keys boundedly; an unknown `kid` performs one single-flight refresh and
  failures close access. Never discover issuer/JWKS from token claims. Human
  actors use `sub`; service actors use `common_name` only with empty `sub`.
- Persist only versioned keyed pseudonyms where receipt/OAuth ownership needs
  identity. Never persist or log raw Access JWTs/cookies, human subjects,
  service-token client IDs, email, or arbitrary identity claims. Human browser
  mutations also enforce the documented same-origin checks.
- Bind the actor-derivation key version/fingerprint to
  `server_authority_id`. An unexpected key change fails readiness before public
  bind or Endpoint contact; it never silently changes Server-owned receipts.

## Endpoint client and session proxy

- Forward each session mutation's `Idempotency-Key` unchanged. Endpoint owns the
  command receipt; Server must not create a second session-command journal.
  Crash/retry obtains the original Endpoint result through that receipt.
- Do not derive or forward an Endpoint subject. Do not send an Endpoint
  control bearer. Server stores no session ACL. Every admitted Access actor
  sees every session on an Endpoint the Server can reach.
- Endpoint owns `endpoint_id`; Server uses that exact value as its catalog key
  and never allocates a second device ID. Verify it and required capabilities
  before create. Address updates cannot bind an existing record to another
  Endpoint.
- Resolve Server's versioned non-secret provider execution descriptor once and
  forward it in the concrete session model selection. Endpoint reports adapter
  support and outbound policy; do not require users to duplicate provider base
  URL/model configuration on every device.
- `e2e_remote_server_configure_once_distributes_and_runs_session_without_session_storage`
  exercises the public Server→Endpoint model-selection route with a real
  model-less session, same-key replay, durable projection, Server restart, and
  replay after the current profile is deleted; it uses only a test-owned local
  provider fixture and remains in the ordinary CI gate.
- Health is a bounded Server observation from Server-initiated reads. Endpoint
  never supplies a reverse heartbeat.
- V0 Endpoint removal is reversible disablement, not row deletion. Never reuse
  an `endpoint_id` or silently break/rebind session and callback URLs; a future
  retirement flow requires its own tombstone contract and red E2Es.
- Session URLs always contain `(endpoint_id, session_id)`. Endpoint generates
  the ULID during create; Server forwards it later only as an opaque path value
  and never persists, indexes, logs, or maps it.
- Proxy telemetry uses route templates and bounded status/latency fields. Never
  capture raw URI/query, session path parameters, response/`Location` bodies,
  SSE frames, or callback authorization headers in logs, traces, or metrics.
- Do not preallocate a session ID or create a pending route. A lost create
  response is retried against the same Endpoint with the same key, and Endpoint
  returns its original ULID.
- Session create requires the explicit profile, full immutable non-secret
  provider-execution descriptor/revision, and minimum auth revision selected
  before first submission. Never re-resolve a mutable default during retry.
- After Access validation and Endpoint resolution, perform Endpoint replay-only
  receipt lookup for every session mutation before mutable profile/state checks.
  A hit returns the original response; a miss must pass current policy under its
  serialization guard before normal admission. Never add a Server session
  receipt.
- Keep Endpoint unavailable distinct from runtime failure. Return typed
  unavailability; never invent cached session state or an Endpoint terminal
  event.

## SSE proxy

- Open one downstream Endpoint-wide SSE for each attached client Endpoint
  stream, forward `Last-Event-ID`, and preserve Endpoint event IDs and public
  frames. Never open or filter a downstream stream per session.
- Close every management SSE no later than the validated Access assertion's
  expiry so reconnect must re-enter current Access policy.
- Do not store session events, session projections, or resume cursors and do not
  allocate a Server session-event ID. Endpoint owns replay/live handoff and
  durable deduplication. Server-owned OAuth/control streams remain separate and
  may use resource-local cursors.
- Expose only `/v1/endpoints/{endpoint_id}/events` for Endpoint runtime events.
  The former session-scoped event proxy is absent; do not retain a compatibility
  route or a second cursor path.
- Transient token deltas may be proxied, but final messages and lifecycle facts
  are durable only after Endpoint commit.

## Auth authority and distribution

- Server-owned management receipts are scoped by Server authority,
  pseudonymous Access actor key, versioned command kind, and every concrete
  parent/path resource ID. Validate Access, bounds, and path identity, then
  lookup the receipt before mutable resource existence/state. Canonical same-
  body replay is stable after deletion/change, changed-body reuse conflicts,
  and a miss alone enters current semantics. Secret-bearing fingerprints use a
  restart-stable keyed HMAC. Session proxy commands are not stored here.
- Give every management mutation a stable operation identity. Commit pure
  control facts, final receipt, and original safe response atomically. Journal
  every Server-owned resource/revision identity before secret staging, probe,
  OAuth, or distribution phases; Endpoint-owned ID comes only from a replayable
  authenticated identity probe. Recovery resumes the same phase and never
  allocates a duplicate resource after an unknown response.
- Keep profile/OAuth non-secret control facts append-only and secrets in a
  replaceable protected store. Default pointer, refresh, delete, sharing, and
  recovery serialize under the owning profile/provider locks and transactions.
- Load OAuth capability only from the validated Server
  `provider_auth_adapters` catalog. Bind one adapter to one provider identity;
  keep authorization/token endpoints, client configuration, PKCE/state and
  refresh recovery out of Endpoint execution descriptors, browser input and
  test-only environment overrides. Public provider projections expose only the
  sorted supported auth methods.
- Distribute only to explicitly authorized Endpoint IDs. `all_current` expands
  to a durable explicit plan; it does not auto-authorize future Endpoints.
- Allocate stable operation/profile/revision identity before secret staging.
  Journal only keyed fingerprints, phase, and redacted result metadata.
- A distribution is ready only after Endpoint durably acknowledges the exact
  revision. Request sent is not acknowledgement.
- Serialize every Server-managed profile refresh under one profile lock and use
  the durable operation below. Endpoint never races or performs Server refresh.
- Before provider refresh dispatch, persist one operation, source revision,
  adapter recovery capability, and reserved next revision. Retry only with
  proven same-operation idempotency or exact-result reconciliation; otherwise
  commit refresh-unknown/reauth-required and never reuse the reserved revision
  or old refresh token blindly.
- `refresh_unknown/reauth_required` establishes a durable profile refresh fence.
  Reject every new explicit or scheduled refresh before revision allocation or
  provider contact; only a successful same-profile replacement at a higher
  revision clears it. Failed/cancelled relogin leaves it fenced.
- Tombstones are monotonically versioned. UI must represent pending,
  unreachable, stale, ready, removing, and removed accurately.
- Static API-key replacement preserves the same profile identity, default
  pointer, label, and sharing policy. It allocates above every credential,
  reserved, install, and tombstone revision and redistributes only to the
  currently authorized Endpoints; neither request nor response may expose the
  previous or replacement secret.
- Profile deletion and sharing removal atomically allocate a revision above
  every credential/tombstone revision and append durable per-Endpoint tombstone
  operations. Retain and rebuild them across restart until acknowledged;
  current sharing policy alone is not a recovery journal.
- Static API-key deletion from Endpoint is best-effort erasure. Do not claim
  provider-side revocation without evidence.

## All-in-one composition

- Acquire one exclusive process-lifetime lock bound to the stable Server
  authority/control/secret-store identity before opening stores or issuing any
  external phase. A second Server fails readiness. Release the lock last after
  graceful child shutdown; after a crash, only the next lock owner may adopt a
  surviving local Endpoint.
- ControlStore binds one canonical control-database inode and its stable
  `.server.lock`/`.anchor` inode pair for the process lifetime, with durable
  owner markers beside the database and in the protected secret directory;
  missing markers, symlink, inode/path replacement, or multiply-linked
  sidecars fail before READY rather than changing the owned store.
  Existing-store integrity is preflighted before a failed startup can create
  new ownership sidecars. A missing SQLite SHM after a crash is recoverable
  only when the canonical database, stable lock/anchor, both owner markers, and
  a private single-link WAL remain valid. The next exclusive owner may rebuild
  only that disposable SHM, must validate authority metadata through the WAL
  before readiness, and must remove the rebuilt SHM again if validation fails.
  Existing unsafe sidecars or any durable identity mismatch still fail closed.
  The readiness matrix covers database/lock/pair swaps, both-marker removal,
  URI-delimiter restart, corrupt-store cleanup, and WAL/SHM link rejection.
  Its anchors include
  `e2e_server_control_database_path_swap_cannot_cross_catalog_ownership`,
  `e2e_server_control_owner_markers_removal_and_lock_pair_replacement_cannot_allow_second_owner`,
    `e2e_server_corrupt_existing_control_store_failure_removes_new_ownership_sidecars`,
    `e2e_initialized_server_wal_shm_hardlink_is_rejected_before_ready`, and
    `e2e_server_crash_with_committed_wal_and_missing_shm_recovers_same_control_facts`.
- The combined Server starts one built-in local Endpoint on a private loopback
  listener as a supervised standalone `zode` child and treats it as a normal
  Endpoint record/client. Do not link or instantiate Endpoint runtime state in
  the Server process.
- `all_in_one` requires explicit `local_endpoint.executable`, `.config`,
  `.listen` fields as defined in
  `docs/architecture.md`. Resolve paths relative to the Server config; reject
  PATH/sibling executable guessing, non-loopback or port-zero private listeners,
  a missing object in all-in-one, and an object present in server-only. The one
  exception is a relative bootstrap-secret path: resolve it from the referenced
  Endpoint config directory, preflight the Endpoint controller entry, and require
  the same final path, `server_authority_id`, and revision 1 before child start.
- Server and local Endpoint use separate runtime/control databases, secret
  stores, config objects, and lifecycle ownership.
- Bootstrap local controller auth with two private copies: Server authority stays
  under Server `secret_directory`, while Endpoint receives only the separately
  configured bootstrap file. Journal phase/fingerprint, never secret bytes, and
  fail readiness on missing/conflicting authority. Server generates the secret;
  the Endpoint file is a one-time unclaimed-state seed, never an input back into
  Server. Once bootstrap is committed, restart must ignore the seed and Endpoint
  must load its active manifest. Subsequent rotation uses the normal Endpoint
  control API and durable Server operation path, and a stale seed cannot roll it
  back.
- Do not share SQLite connections, credential files, mutable Rust state, call
  private handlers, or skip distribution merely because both components are in
  one process.
- The public Server binds only after configured local Endpoint recovery and
  catalog composition succeed. Shutdown stops admission, drains Server work, then
  signals and waits/reaps a child owned through the supervisor process handle;
  this is not a private handler or an Endpoint shutdown route. Before releasing
  the control-store owner, a normal shutdown checkpoints and truncates its WAL so
  a later startup does not mistake the Server's own missing SQLite SHM sidecar for
  external store damage; external sidecar/link mutations still fail closed during
  preflight. Arm process shutdown signal handling before publishing
  `ZODE_SERVER_READY`, so an immediate signal after the readiness barrier cannot
  bypass that checkpoint and cleanup path. Crash-surviving adoption/handoff
  remains an explicit later lifecycle state, never an accidental orphan.
- Endpoint holds an exclusive process-lifetime lock for its runtime/secret
  identity. On startup, all-in-one first probes the stable loopback address and
  adopts a healthy matching installation. An unresponsive/mismatched probe
  blocks without a spawn. Refusal may launch one candidate, but that candidate
  must acquire the ordinary Endpoint lock before stores/effects; lock failure
  blocks Server readiness. Server never reimplements or bypasses that lock.
- Server-only mode disables built-in Endpoint explicitly; code paths otherwise
  remain the same.

## UI API

- UI calls Server only. Keep resources versioned, paginated, secret-safe, and
  stable independently of Endpoint response shapes.
- Expose Endpoint-scoped session links, Endpoint/model/profile summaries,
  distribution/connection state, and only actions currently allowed by
  Server/Endpoint state.
- OAuth browser redirects and callbacks terminate at Server. Prompt/device
  attempt events are attempt-local durable streams.
- OAuth authorize tickets are actor-bound, short-lived, and atomically single-
  use. A consumed ticket cannot redirect, allocate another provider state, or
  cause provider traffic; re-entry requires explicitly minting a new ticket.
  Mint/redemption responses are non-cacheable and redirects suppress referrers
  so the provider never receives the ticket.
- External callback relay is Endpoint-scoped and stateless. It cannot report
  tool completion until Endpoint acknowledges first-terminal admission; v0
  returns retryable unavailability instead of queueing while Endpoint is down.
- Keep one stable public callback origin distinct from the Access-protected
  management origin. It serves only the callback route and requires the
  Endpoint-issued bearer; an Access assertion cannot replace it. Inject the
  Endpoint-scoped base as session execution configuration, proxy opaque callback
  IDs, and forward the bearer only in a redacted secret header. Never put a
  bearer in a URL or store callback/session/tool routing state on Server.
- Keep provider OAuth callbacks on the Access-protected management origin. Do
  not add a broad Access Bypass policy to management routes for tool callbacks.

## UI artifact delivery

- Production UI assets are the `ui/` component of the same revision-bound
  release artifact as `zode-server` and `zode`; do not embed them into Rust,
  serve Web source, or fall back to a Vite development server.
- Server config always requires `ui_mode: assets | api_only`. `assets` requires
  `ui_assets_directory` and `api_only` forbids it; invalid combinations fail
  before READY. Installed test and production releases use `assets` and point
  the directory at the packaged immutable `ui/` tree. Only explicit API-only
  development/tests may use `api_only`.
- Before READY, validate a bounded regular-file tree with no symlinks or path
  escapes, load `index.html` and only its exact versioned assets into memory,
  then serve that fixed map. Never expose arbitrary paths from the directory.
- Versioned assets use immutable positive caching; HTML uses revalidation/no-
  store semantics. Browser history fallback applies only on the management
  origin to safe GET/HEAD HTML routes and never swallows `/v1`, asset misses,
  callbacks, or non-HTML requests.
- The operator release driver/CLI is the only v0 release-actuation surface.
  `stage` leaves `current` unchanged; `promote` and `rollback` switch the
  complete release directory and restart or adopt the matching Server. Do not
  add Server release-control routes or accept browser commands for these
  operations.
- After each operator switch, a real browser exercises the Access-protected UI
  through the built-in Endpoint while the release harness independently binds
  the served UI tree and observed process executables to the selected manifest.
  Do not add component-digest API fields or hidden DOM constants only for this
  test; no request may combine UI and Server revisions.

## E2E-only acceptance

No Server unit, handler, direct-store, mock-Endpoint, or in-process runtime
tests are allowed. Every E2E starts a real Server and one or more real Endpoint
processes with real temporary SQLite and secret directories. Provider/tool/OAuth
and Access edge/JWKS fixtures are network servers reached through production
boundaries. The Access fixture signs real RS256 application assertions and uses
the ordinary configured verifier; it is not a trusted-header bypass.

Maintain positive E2Es for:

- `e2e_server_provider_list_returns_versioned_empty_authority_projection`,
  proving an Access-protected real Server returns exact
  `zode.providers.v1`/empty-list JSON rather than a fallback or built-in provider;
- `e2e_server_provider_descriptor_round_trips_non_secret_revision`, proving a
  provider descriptor created through the public API appears in deterministic
  list order with its exact revision/default/count/status projection and no
  secret, Access subject, OAuth, replica, or header material;
- `e2e_server_forwards_and_endpoint_persists_provider_execution_options`,
  proving Server forwards the complete validated non-secret descriptor and a
  real Endpoint durably returns the same non-empty options after restart while
  Server retains no session state;
- `e2e_all_in_one_first_run_uses_normal_server_api_and_local_endpoint`, including
  different Server/Endpoint config directories, final-path preflight, separate
  controller-secret copies/stores, authenticated identity/capability probe,
  normal profile distribution/session/SSE/provider path, controller rotation then
  restart without seed rollback, process-handle stop/wait/reap, and Server-store
  absence;
- one provider login/profile distributed to local and remote Endpoints;
- revision/refresh/tombstone races and unreachable reconciliation;
- single-use OAuth authorize-ticket redemption, including concurrent replay
  producing one redirect/state and no second provider effect;
- refresh-unknown fence rejects new-key explicit and scheduled refresh without
  a provider call until successful same-profile replacement;
- profile delete/sharing removal retains a higher tombstone across Server and
  Endpoint restarts and cannot resurrect an older replica;
- `e2e_browser_provider_profile_delete_replays_original_result_after_response_loss`
  drops the first browser response after deletion commit and proves the same
  command key replays its stored safe result while the UI confirmation closes;
- `e2e_browser_provider_profile_delete_tombstone_status_is_monotonic_under_late_failure`
  races one successful and one later failed dispatch of the same tombstone and
  proves the public `removed` projection cannot regress to `unreachable`;
- Endpoint-generated ULID create and stable forwarding across Server crash;
- Endpoint identity/capability mismatch;
- same Endpoint added twice cannot create a second device ID/catalog row;
- two Endpoints create sessions independently, every route requires both IDs,
  and no ID-only Server lookup exists;
- Access edge/JWKS rotation plus valid human and service-token assertions, with
  every invalid claim/signature shape failing closed before Endpoint contact;
- two Access actors on one Endpoint have Endpoint-enforced session isolation
  while same-key commands remain actor-scoped and management resources remain
  shared;
- browser entry through Access has no Zode user/login/logout/grant resource or
  application login cookie;
- SSE replay/live handoff through the stateless proxy;
- callback relay success and retryable Endpoint unavailability on the separate
  callback origin, with no management route exposed there and OAuth callback
  still protected by Access;
- server-only mode with no local fallback;
- `e2e_all_in_one_parent_crash_adopts_local_endpoint_without_duplicate_effect`
  before model/tool work resumes;
- `e2e_all_in_one_startup_fences_unresponsive_or_mismatched_local_endpoint`
  before any public ready signal, candidate authority, distribution, or effect;
  include both no-spawn unresponsive/mismatched-address cases and a
  connection-refused case where a real Endpoint holds the same store lock at a
  different loopback address and the sole candidate exits before runtime effects;
- two Servers on the same stores prove the second cannot become ready or race
  management/Endpoint effects until the first releases its lock;
- proof that Server persists no session IDs/events plus secret absence from
  HTTP/SSE/logs, both databases, snapshots, session events, and UI.
- crash/replay at every management external-phase boundary returns the original
  resource ID/status/body and creates one control resource.

Every new behavioral finding first goes to the fixed E2E owner as a red
real-process scenario. The implementation owner cannot edit that frozen test;
the same independent reviewer re-reviews until convergence.

The root first-occurrence replay gate applies to management HTTP, Access/JWKS,
Server-to-Endpoint, provider login/refresh, replica distribution, proxied SSE,
OAuth, callback, and browser paths. Preserve the first failing exchange before
retry or repair, then replay its secret-safe immutable cassette through real
Server and Endpoint processes. A later reconstructed request is insufficient.
This is test-environment infrastructure only; production Server and Endpoint
must never record bodies, load cassettes, expose replay routes, or enable a
capture proxy.

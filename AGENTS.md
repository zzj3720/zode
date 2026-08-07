# zode Project Instructions

## Project goal

`zode` is a management Server, independently usable device Endpoint, and web UI
for durable agents. Endpoint owns session execution; Server owns Endpoint
inventory, provider-auth authority/distribution, stateless session proxying,
and the UI API. Zode has no application-local user system in v0; Cloudflare
Access protects the management origin.

`docs/architecture.md` is the authoritative system boundary.
`docs/design.md` owns Endpoint runtime semantics, `docs/http-api.md` owns the
Endpoint protocol, `docs/server-api.md` owns Server/UI API behavior,
`docs/auth-replication.md` owns credential distribution, `docs/access.md` owns
management ingress identity, and `docs/ui.md` owns the UI product contract.
`docs/test-recording.md` owns test-only real-request recording, immutable
cassette promotion, and replay; it never authorizes production capture.
This file and module `AGENTS.md` files govern how those designs are changed,
implemented, tested, and reviewed; they do not replace the design documents.

- Endpoint exposes HTTP commands/queries and SSE. It never actively connects,
  registers, or sends heartbeats to management Server; Server initiates every
  Endpoint connection.
- Server exposes the management HTTP/SSE API and may compose one built-in local
  Endpoint using the same Endpoint protocol as remote devices.
- Endpoint runs provider execution locally through aimux. Server manages
  OAuth/API-key profiles and distributes versioned credential replicas that
  Endpoint may persist for direct provider use.
- Web UI talks only to Server and never directly to Endpoint or providers.
- Do not build a TUI or interactive terminal product inside this repository.
- HTTP is the command/query transport and SSE is the default event-stream
  transport at both public boundaries. Add WebSocket only after a concrete
  controller-initiated bidirectional use case exists; it must remain an adapter
  over the same semantics and Endpoint never dials it outward.
- A client connection does not own a turn or tool process. Disconnecting HTTP,
  SSE, or a future WebSocket must not cancel session work.
- Keep the implementation independent from Codex. `codex-reference/` is only a
  reading/reference copy: do not import from it, modify it for zode, copy its
  production implementation, or port its tests.
- The user approved the current Codex Desktop application on 2026-08-07 as the
  v0 Web visual reference only. Reproduce its observable shell and styling in
  zode-owned code and real-browser E2Es; do not copy application source,
  proprietary assets, branding, product text, or tests, and do not let its
  product model alter the Server/Endpoint/runtime architecture.

## Instruction topology and stewardship

This file owns repository-wide architecture and acceptance invariants. A
module-level `AGENTS.md` owns only the additional rules for its subtree. Read
the complete instruction chain before changing a file; the nearest file may
make a rule stricter but may not weaken this root contract.

- Keep one authoritative rule at the highest scope where it is true. Link or
  summarize locally instead of copying long sections into every module.
- Update the nearest `AGENTS.md` when an accepted design decision, red E2E, or
  review finding establishes a durable boundary that future work must retain.
- Do not record transient implementation plans, test run logs, agent status, or
  speculative alternatives in `AGENTS.md`. Keep only the selected architecture,
  invariants, ownership boundaries, and repeatable operating guidance.
- Create a module-level instruction file before delegating a new substantial
  production module. Define its responsibility, forbidden dependencies,
  public seams, persistence ownership, and black-box acceptance path.
- Treat instruction updates as part of the architecture change. They do not
  replace a red E2E or verification evidence.

## Referenced-design approval

Designs derived from any external repository, document, framework, or product
must be reviewed by the user before they enter tracked repository code or
documentation.

- Research and comparison happen outside the repository first.
- Present a review proposal that names the source, the exact semantics proposed
  for adoption, intentional deviations, rejected parts, local tradeoffs, and
  the E2E consequences.
- Do not add the referenced design to production code, tests, module
  instructions, or architecture documents until the user explicitly approves
  that proposal.
- When the user excludes a reference from tracked provenance, do not retain its
  name, path, source notes, fixture or test naming, or code comments anywhere
  in the repository. Record only the independently stated zode behavior.
- After approval, record zode's selected design as its own authoritative rule;
  retain provenance only where it helps future reviewers understand a deliberate
  compatibility or deviation decision.
- Existing user-approved project decisions remain authoritative. A newly found
  external detail that would change them requires a new review rather than a
  silent documentation update.

## Approved-design change control

An authoritative design decision already accepted by the user cannot be
reopened or edited merely because an agent lost conversational context,
re-derived a different preference, or noticed an implementation detail that
was already known when the decision was made.

Before proposing any semantic change to an approved design, the main agent
must present, outside the repository:

1. the current authoritative decision and its tracked document/commit;
2. concrete new evidence that was not part of the accepted review, such as a
   red public E2E, reproduced production behavior, a versioned dependency API
   fact, a security invariant violation, or a demonstrated contradiction
   between authoritative contracts;
3. why the current decision cannot satisfy the goal despite that evidence;
4. the affected public behavior, persistence/migration consequences, E2Es,
   modules, and compatibility boundary;
5. at least the option to retain the current decision, plus the proposed
   alternative and its tradeoffs.

The user must explicitly approve the semantic change before design documents,
module instructions, frozen E2Es, or production code are changed. Reviewer or
subagent preference is not evidence by itself. If context is uncertain, recover
the decision from authoritative documents, git history, and conversation
history; uncertainty is a reason to stop changing semantics, not a reason to
invent a replacement. Pure clarification is allowed without a new approval
only when it provably leaves public behavior, persistence facts, and acceptance
tests unchanged; state that proof in the change review.

## Dependency direction

Keep separate hexagonal graphs rather than a linear monolith:

- Endpoint domain defines durable facts and pure transitions; it imports no
  port or adapter.
- Endpoint application/runtime depends on its domain and declares effect
  ports. It never depends on concrete SQLite, HTTP handlers, management Server,
  provider wire types, or process handles.
- Endpoint SQLite, aimux/provider execution, tool runner, credential-replica,
  blob, and timer modules are adapters. They do not import one another to
  coordinate runtime state.
- Endpoint HTTP/SSE admits runtime and credential-replica commands but does not
  own session lifecycle, provider-profile authority, retries, waits, or tool
  execution.
- Server application owns Cloudflare Access assertion verification, Endpoint
  catalog/client, provider-auth authority, distribution, stateless Endpoint-
  scoped proxying, and UI resources. It consumes Endpoint only through the
  versioned protocol. It neither imports Endpoint storage/domain internals to
  make runtime decisions nor persists session IDs, events, projections, routes,
  or cursors.
- Endpoint persists only a controller authority plus opaque subject as session
  ownership scope. Server derives that subject from the validated Access actor
  on every proxy request; Endpoint does not import an Access or Server identity
  model and Server does not keep a session ACL.
- Web UI consumes only Server API types. It imports no Endpoint client, runtime
  reducer, provider adapter, or credential code.
- Endpoint, Server, and all-in-one `main` functions are composition roots only.
  All-in-one composition keeps separate stores and uses the same Endpoint
  protocol; it cannot add direct-handler or shared-state shortcuts.

## Design authority

Cue is the approved primary reference for runtime semantics. The selected zode
semantics, including deliberate deviations from Cue, are authoritative in
`src/runtime/AGENTS.md` and `src/tools/AGENTS.md`. A newly discovered Cue detail
does not override them without another referenced-design review.

Primary local references:

- `$HOME/Cue/docs/salix/issues/wait-for-async-tool-call-runtime-issue.md`
- `$HOME/Cue/docs/salix/issues/unify-async-tool-call-identity.md`
- `$HOME/Cue/docs/salix/issues/wait-timeout-global-timer-service.md`
- `$HOME/Cue/systems/apps/salix_agent/lib/salix_agent/internal_session/state.ex`
- `$HOME/Cue/systems/apps/salix_agent/lib/salix_agent/internal_session_actor.ex`
- `$HOME/Cue/systems/apps/salix_agent/lib/salix_agent/tools.ex`
- `$HOME/Cue/systems/apps/salix_agent/lib/salix_agent/round.ex`
- `$HOME/Cue/systems/apps/salix_agent/lib/salix_agent/async_tool_results.ex`
- `$HOME/Cue/systems/apps/salix_agent/lib/salix_agent/waits.ex`

Dimi informs only the explicitly reviewed decisions recorded in
`docs/design.md`: bounded model-step retry plus provider/async lifecycle E2Es.
It does not silently override other session-owned, event-driven semantics. The
approved pi-ai/dimi/aimux provider-execution decisions live in
`src/provider/AGENTS.md`. Provider-auth authority and replication are now zode
system decisions in `docs/architecture.md` and `docs/auth-replication.md`;
external references do not override them. Codex does not define zode's runtime
architecture or acceptance tests.

## Runtime ownership model

The durable runtime session is the authority; in-memory actors and task handles
are disposable. Inputs and effect completions become durable deliveries before
they influence a turn. An already-sent model request remains frozen, while
deliveries committed during it may steer the next model round in the same
activation; if no round follows they wake a later activation. Detailed
round-boundary, atomicity, wait, retry, and recovery rules are owned by
`src/runtime/AGENTS.md`.

## Provider execution and authentication boundary

All production LLM requests execute on Endpoint through aimux and go directly
from Endpoint to the configured provider. Do not implement a parallel provider
HTTP client, route every model stream through management Server, or invent a
zode-specific provider wire protocol.

Provider types and login instances are distinct: one provider type may have
many OAuth or API-key auth profiles. Server is management authority for login,
non-secret execution descriptors, defaults, refresh, sharing, and deletion.
Endpoint owns provider adapter/aimux execution and a secure store of versioned
read-only replicas distributed by that authority. Both may persist secret
material, but the same Server-managed profile has only one writer: Server.
Endpoint cannot refresh or mutate it independently.

Endpoint provider execution and complete aimux stream conversion are owned by
`src/provider/AGENTS.md`. Server auth and distribution are owned by
`server/AGENTS.md` and `docs/auth-replication.md`. Secrets remain outside
session/control event stores, snapshots, public HTTP/SSE, and UI.

Server Endpoint-control credentials, Endpoint controller-auth credentials, and
provider credential authority/replicas use their dedicated protected stores;
none may enter ordinary SQLite rows or request/response telemetry.

## Management ingress identity

`docs/access.md` is authoritative. V0 has no Zode user, workspace, membership,
role, grant, login, logout, invite, or application-cookie implementation.
Cloudflare Access is the only admission authority for the management origin;
all admitted actors share one management trust domain. Do not add a local auth
fallback, development bypass, caller-selected identity, or per-route shadow
RBAC.

Server validates the `Cf-Access-Jwt-Assertion` signature, pinned issuer,
configured audience, time claims, token type, and actor shape against the
configured JWKS. Human identity comes only from `sub`; service-token identity
comes only from `common_name` when `sub` is empty. Derive and persist only
versioned pseudonymous actor/Endpoint-subject keys, never raw JWTs, Access
cookies, emails, human subjects, or service-token client IDs.

Keep the Access-protected management origin separate from the public external-
tool callback origin. The callback origin exposes only the bounded Endpoint-
scoped callback route and requires its independent callback bearer; it cannot
serve UI or management routes. Provider OAuth callbacks remain on the Access-
protected management origin.

## Append-only storage

The session event stream is the only source of truth. Current state is a
deterministic projection of semantic events. Do not store a mutable session JSON
record as an alternative authority.

- Use typed semantic events such as `InputQueued`, `WaitSet`,
  `AsyncToolCallStarted`, and `AsyncToolCallCompleted`; do not use generic JSON
  patches as domain deltas.
- Events are immutable after append.
- A command may emit multiple events. Append the complete event batch atomically
  or append none of it.
- Appends use the expected session stream version for optimistic concurrency.
- Every command, event, delivery, and externally completed tool call has stable
  identity suitable for idempotency and deduplication.
- The reducer is a pure deterministic function. It must not read clocks, create
  random IDs, perform I/O, call providers, start timers, or publish events.
  Generate those facts before append and include them in events.
- Publish HTTP/SSE-visible committed events only after the storage transaction
  succeeds.

Storage and runtime are separate through one transactional storage port. Avoid
splitting event append, delivery enqueue, timer mutation, and related result
storage into interfaces that cannot preserve the required atomic commit
boundaries.

Server has no session event mirror. It proxies Endpoint SSE only while a client
is attached, preserves Endpoint event IDs and `Last-Event-ID`, and stores no
session ID, event, projection, route, or cursor. All-in-one keeps Server and
local Endpoint databases separate.

The default backend is SQLite. Configure it for WAL, short transactions, a
busy timeout, and controlled writes. Runtime/domain code must not depend on
SQLite-specific SQL or row shapes. A future backend must pass the same HTTP/SSE
black-box E2E suite.

Mutable operational indexes such as runnable sessions, stream heads, and due
timers are allowed only as rebuildable projections. Deleting them must not lose
domain facts; they must be recoverable from event streams and snapshots.

Do not persist secrets, credentials, authorization tokens, or unredacted
sensitive provider payloads in events, snapshots, or ordinary SQLite control
rows. Server credential authority and Endpoint replicas use
their dedicated secret stores. Store large tool outputs or artifacts in
immutable blob storage and put stable references in events.

## Snapshots and replay

Snapshots optimize replay; they are never an alternative authority.

- Snapshot records are append-only and identify the exact session stream
  version they represent.
- Include state-schema/reducer version and integrity metadata.
- Restore from the newest compatible snapshot, then replay the event tail.
- Ignore an incompatible or invalid snapshot and fall back to an older snapshot
  or full replay.
- Snapshot creation may run asynchronously after a committed version. Snapshot
  failure must not fail or roll back the event append.
- Trigger snapshots by replay cost (event count and/or bytes), not wall-clock
  time alone. Keep the threshold configurable and small in E2E tests.
- Snapshots do not advance the public event cursor and are not emitted as
  normal SSE domain events.
- Storage snapshots and model-context compaction are separate mechanisms.

Every reducer or event-schema change must preserve deterministic full replay
and snapshot-plus-tail replay. Prefer versioned events and explicit upcasters;
never rewrite historical events in place.

## Tool-call lifecycle

The original model `tool_call_id` is the only lifecycle identity. Batch
execution, early async results, callback/cancellation behavior, output bounds,
and side-effect recovery are owned by `src/tools/AGENTS.md`; their durable
atomic transitions are coordinated by `src/runtime/AGENTS.md`.

## Wait lifecycle

`wait_for` is session control, not a blocking function or independent state
service. It defaults to 60 seconds and accepts 1 through 600 seconds. Detailed
replacement, auto-wait, wake, stale-timer, mixed-batch, and timeout-budget
semantics are owned by `src/tools/AGENTS.md` and `src/runtime/AGENTS.md`.

## HTTP and event-stream contract

Use HTTP for commands/queries and SSE for durable event delivery. Asynchronous
commands return after durable admission; they do not keep one request open for
an entire agent run.

Endpoint surface stays execution-focused:

- identity, bounded health, and non-secret capabilities;
- create/read a session, select an explicit provider/model/profile revision,
  append messages, and stream session events;
- read/cancel/reconcile tool calls and accept opaque-ID callback completion;
- install/read/tombstone controller-authenticated credential replicas.

Endpoint has no user-facing OAuth, profile-default, sharing-policy, device
registration, or UI route. Server owns those resources plus Endpoint inventory,
stateless Endpoint-scoped session/callback proxying, and UI delivery as defined
in `docs/server-api.md`.

Endpoint SSE is a durable ordered view of committed runtime events. Server
forwards the UI's `Last-Event-ID` without storing a cursor or allocating a
second event identity. Reconnect may not miss committed events or duplicate
terminal effects. Transient token deltas may be best-effort, but the final
assistant message and all lifecycle transitions are durable.

Do not expose raw storage records as an accidental permanent public API. Map
domain events to an explicitly versioned public event schema.

## E2E acceptance

E2E tests are the only test form allowed in this repository. Do not add unit
tests, module tests, doctests, white-box integration tests, or tests that call
domain, storage, runtime, provider, or HTTP handler functions directly. Remove
rather than preserve such tests when encountered.

### Design-to-E2E traceability

An accepted design is not implementation-ready until its observable contract
is executable. Every authoritative decision that affects public behavior,
durable facts, identity or authorization, ordering, concurrency, recovery,
retry, failure handling, resource bounds, or secret handling must be bound to
at least one named real-process E2E before production implementation begins.

- Record the exact `e2e_*` test name beside the owning design's required-E2E
  matrix or clause. A broad smoke test counts only when its assertions
  independently distinguish the selected behavior from rejected alternatives.
- For a new or changed behavior, the E2E owner must first demonstrate that the
  named scenario is red against the current product for the intended reason.
  A compile error, missing route, timeout without a positive barrier, or an
  assertion unrelated to the decision is not behavioral evidence.
- One scenario may cover several decisions when each has an explicit public
  assertion. One decision may require several scenarios when normal operation,
  concurrency, response loss, restart, or corruption expose different
  obligations.
- Express internal architecture decisions through public composition and
  failure behavior wherever they can affect the running system: use separate
  processes/stores, restart, races, dependency fixtures, and fault injection.
  Static dependency and repository-shape rules may additionally use compiler,
  lint, or search gates, but those gates do not replace an observable E2E for a
  behavioral consequence.
- Every worker handoff names both the authoritative design clause and its
  frozen E2E cases. A module cannot be declared implemented or review-complete
  while an accepted behavioral decision in its scope lacks that trace.
- After the user approves a design change, update the owning design clause and
  its named E2E together. Never change production semantics first and document
  or retrofit the E2E afterward.

Every runtime E2E must:

- start the real Endpoint binary as a separate process on an isolated port;
- use a temporary real SQLite database;
- submit commands through HTTP and observe results through HTTP/SSE;
- use a deterministic local fake model server only at the provider boundary;
- execute tools through the real tool-dispatch path, using controllable local
  fixtures rather than direct runtime calls;
- avoid timing-dependent sleeps where a barrier, notification, or virtual/test
  clock boundary can make the scenario deterministic;
- assert externally observable behavior and persisted restart behavior, not
  private helper calls;
- kill and restart the real Endpoint for recovery scenarios.

An E2E test may control its environment by starting local fake provider and
tool servers, choosing a temporary database and credential directory, holding
fixture requests at explicit barriers, stopping the server, and corrupting or
removing test-owned SQLite rows while Endpoint is stopped. It must still
exercise the product only by spawning the real Endpoint binary and using its
public HTTP/SSE surface. Test code must not import the zode library or expose a
hidden test-only product route.

Server E2Es start real Server and Endpoint processes and observe product
behavior only through Server HTTP/SSE. All-in-one E2Es start the combined
Server binary and prove its built-in Endpoint uses the same protocol and
separate stores. Web E2Es use a real browser, Server, and Endpoint; component,
hook, reducer, mock-router, and DOM snapshot tests are forbidden like every
other unit/white-box form.

The nearest module `AGENTS.md` owns its required behavior matrix. Together the
Endpoint API/storage/runtime/tools/provider, Server/auth-distribution/proxy,
all-in-one, and browser suites must cover normal operation, concurrency races,
idempotency, reconnect, restart/recovery, bounded data, and secret
non-disclosure. A new public route or durable transition must add its positive
path and every discovered regression to that matrix.

Run the same black-box suite against every future storage backend. A backend
does not get a separate white-box test suite.

## Scope and implementation discipline

Start with the smallest complete Endpoint, management Server, built-in local
Endpoint composition, and web UI that pass their E2E suites. Do not add a TUI,
MCP ecosystem, sandbox framework, multi-agent orchestration, plugin marketplace,
generalized workflow engine, automatic session migration, or distributed
cluster logic without an explicit requirement.

Write the public HTTP/event contract and failing E2E path before implementing a
new runtime behavior. Keep one authoritative execution, event, wait, and
recovery path; do not add fallback state machines or duplicate persistence
models.

Deliver in vertical-slice order. First make the normal user path usable through
the real boundaries: Endpoint create/list/message/SSE, one direct aimux model
round, async tool/wait, Server proxy and credential distribution, all-in-one,
then browser UI. Include the authentication, idempotency, durability, and
resource bounds required for that path to work without corrupting ordinary
state. After the vertical slice is green, add adversarial filesystem/link
races, deliberately forged history, exhaustive corruption matrices, extended
secret scanning, and other hardening cases.

This ordering does not weaken or reopen an approved security/recovery decision.
Each deferred hardening behavior still receives its own red E2E before its
production fix, and final release review still requires it. A missing hardening
anchor blocks only that hardening slice, not unrelated happy-path production
work. Do not delay an absent public capability to broaden an adversarial matrix
unless current evidence shows ordinary use would lose, misroute, or disclose
state.

Review findings are regressions, not prose-only cleanup. Before fixing any
behavioral finding discovered during development, construct a black-box E2E
that fails through the owning real process/browser and public HTTP/SSE entry,
then make it pass. If the required process or route does not exist,
implementing that smallest real entry and the red E2E comes before the fix.
Compiler, formatter, lint, and architectural type-boundary failures remain
mandatory static gates; they do not justify adding a non-E2E test.

### First-occurrence replay evidence

This gate applies only to development, E2E, staging, and other explicit test
environments. Production never records request or response bodies, enables a
capture mode, installs a recorder proxy, or exposes a replay endpoint. A
production observation is reproduced first in an isolated test environment;
the first failing exchange of that test reproduction is the one retained.

Every problem exercised on a real user, agent, browser, or network path in a
test environment must preserve that first failing exchange before any retry,
workaround, test rewrite, or production fix changes it.

This requirement is prospective from its adoption. Previously approved and
frozen E2Es do not become invalid merely because their original observation
predated the recorder. An unresolved problem reproduced after adoption must
retain the earliest post-adoption test exchange before further repair. Never
fabricate or relabel a later capture as the historical first occurrence.

- Record the inbound public request and every relevant external-boundary
  request/response needed to reproduce the failure, including status, ordered
  streaming chunks, disconnect point, and relative timing when they affect the
  outcome. A later hand-written approximation is not first-occurrence evidence.
- Raw test-environment captures that may contain credentials are written only
  to a restrictive, ignored local quarantine. Promote an immutable, versioned
  cassette into the repository only after replacing secret values with
  explicit synthetic slots and proving the replacement did not change the
  failing semantics. Never copy a production request into that quarantine.
- The cassette records its owning E2E name, boundary, first observed safe error,
  and canonical request/response fingerprints. Never overwrite it when a later
  occurrence differs; add another cassette instead.
- Before production repair, replay the cassette through the same real process,
  public entry, and production adapters and demonstrate the same behavioral
  red. A direct internal call, mock handler, or reconstructed request does not
  satisfy this gate.
- After repair, the same cassette and E2E must turn green and remain in the
  regression suite. Performance replay may vary only the recorded timing mode;
  it cannot change request or response semantics.
- If the first exchange cannot be retained safely or replayed faithfully, stop
  the repair and report that evidence gap. Never solve it by committing a
  secret-bearing capture or silently substituting a different request.
- Production diagnosis uses bounded secret-safe telemetry only. No production
  adapter, runtime state, Server store, UI code, or configuration may depend on
  test recording or replay support.
- Every test-environment request that reaches a real LLM must traverse the
  test-owned recorder and be durably captured, whether it succeeds, fails,
  retries, or disconnects. Failure to flush the recording fails that live test;
  a direct unrecorded real-LLM test path is forbidden.
- Successful live recordings may remain in ignored test artifacts for
  performance analysis or explicit fixture review. If any recording exposes a
  behavioral problem, promote its secret-safe immutable cassette into the
  repository and add a named real-process replay E2E before production repair.
  The same cassette must be red before the fix and green afterward.

## Delegated implementation and review

- The main agent owns the authoritative design, the major E2E behavior matrix,
  cross-module decisions, and final repository review. It should not become the
  default production implementer after those boundaries are fixed.
- Give each implementation thread or agent one coherent task outcome, normally
  bound to one GitHub issue. Task ownership is behavioral, not directory-based:
  the owner may change any module needed to deliver the complete vertical path
  and must read the full `AGENTS.md` chain for every path it touches. A list of
  likely files or modules is coordination context, never a write prohibition.
- When active tasks overlap in behavior or files, their owners coordinate in
  Chinese before duplicating work, choose one PR to own the shared change, and
  declare the dependency or merge order from the other task. Do not block a
  necessary cross-module change merely because it falls outside a task's
  nominal module; do preserve concurrent changes unrelated to the task.
- Do not cancel, replace, or restart an assigned agent merely because it is
  slow. Let it finish, provide corrective context when needed, and preserve the
  value of the work already performed.
- Use a separate adversarial reviewer for each substantial task or PR. A reviewer
  reports concrete correctness, recovery, security, simplicity, or operability
  findings and does not silently patch the implementation it reviews.
- Every behavioral review finding must state a constructible public red E2E.
  Send it to the assigned E2E owner, who demonstrates that failure before the
  task's implementation owner fixes production code. Production workers and
  reviewers may not rewrite a frozen E2E to fit their preferred implementation.
- Send the fix back to the same reviewer until its findings converge, then use
  an independent final repository review to catch cross-module failures.
- Do not resolve review comments by weakening E2Es, adding parallel fallback
  paths, or changing the accepted architecture without updating the authority
  documents and making the scope change explicit.

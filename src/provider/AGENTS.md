# Endpoint provider execution and credential-replica rules

`src/provider` owns device-side provider execution: provider/model capability
reporting, aimux model construction, complete stream conversion, and secure
consumption/storage of controller-provisioned credential replicas. It does not
own management Server, OAuth login, profile defaults, sharing policy, or user
accounts.

The system boundary is `docs/architecture.md`, the Endpoint API is
`docs/http-api.md`, and replica atomicity is `docs/auth-replication.md`.

## Provider execution boundary

- All production model calls execute on Endpoint through
  `aimux_core::language_model::LanguageModel` constructed with
  `aimux-providers`. Do not add a parallel provider HTTP client or route model
  traffic through management Server.
- Endpoint calls the configured provider directly. Its runtime and provider
  adapters contain no Server URL, registration, heartbeat, reverse connection,
  user, tenant, or UI dependency.
- Preserve native provider protocols. OpenAI-compatible is one explicit
  provider shape, not an intermediate representation imposed on native
  providers.
- The shipped native adapter kind `anthropic` uses the Anthropic Messages
  endpoint and `anthropic.api-key.v1` replicas; it remains a separate wire
  path with `x-api-key` authentication. `openai_compatible` uses
  `openai-compatible.api-key.v1` and the OpenAI chat-completions path.
- Endpoint configuration enables adapter kinds, retry limits, and outbound
  policy. The concrete session carries a controller-supplied, versioned,
  credential-free execution descriptor with provider type, base URL when
  configurable, model/catalog identity, and bounded adapter options. It never
  embeds a user login or ambient-secret fallback.
- A provider type is not a login. Any number of auth-profile replicas can use
  the same provider implementation.

## Credential replicas

- A Server-managed profile is written only by its authority and identified by
  `(authority_id, auth_profile_id, provider, revision)`. Endpoint stores a
  read-only replica so direct provider calls and restart recovery do not require
  configuring each device separately.
- Endpoint-local standalone profiles use a distinct authority identity. Never
  merge, adopt, upload, or last-write-wins between authorities implicitly.
- Install and tombstone are authenticated, idempotent, monotonically versioned
  operations. A lower revision cannot overwrite or resurrect a higher revision;
  the same revision with a different keyed fingerprint conflicts.
- Replica resources and operation receipts are scoped by authenticated
  controller authority plus profile resource, not by a session subject. The
  body authority must match the authenticated authority. The first accepted
  install binds that profile resource to one provider type; neither replaying
  an idempotency key nor using a new key may rebind the same profile to another
  provider. Provider remains part of the keyed request fingerprint, not the
  receipt or active-resource lookup scope. Subjects may share an authority-
  managed profile but cannot use that fact to cross session-owner boundaries.
- Stage secret material under an operation-derived protected path, append only
  non-secret operation identity/phase/fingerprint metadata, atomically promote
  the active secret, then mark the revision ready. Acknowledgement is impossible
  before the active secret exists.
- Active-manifest promotion is the resolution linearization point. New
  resolution sees the promoted revision or tombstone even when safe receipt
  persistence or cleanup subsequently fails. Keep only a bounded recovery
  tail; completed non-secret receipts are direct lookup facts and startup does
  not scan all operation history.
- The default replica store uses a restrictive directory and an encrypted or
  atomically replaced `0600` file per authority/profile. Blocking filesystem
  work crosses a dedicated blocking boundary.
- Listing reads only non-secret metadata. Never expose API keys, access/refresh
  tokens, authorization headers, OAuth state, PKCE, codes, full credential
  payloads, staging paths, or unkeyed secret hashes.
- A tombstone prevents new resolution before restart-reconciled cleanup. It
  does not mutate an already-sent request. Static-key local deletion is
  best-effort erasure, not proof of provider-side revocation.
- Before Endpoint readiness, reconcile every staged install/tombstone, active
  secret, orphaned file, and metadata record. Preserve the highest accepted
  revision even when cleanup failed.
- Expose separate provisioning and resolution ports. Resolution returns a
  non-serializable, non-session-owned secret lease for one provider attempt;
  only its identity and revision may cross into durable runtime facts.

## Selection and refresh

- A model selection names explicit provider, model, authority/profile identity,
  and optional minimum revision. Endpoint never chooses a management default,
  random profile, environment credential, or alternate provider.
- At activation/model request, resolve the newest ready exact replica satisfying
  the minimum and durably record only its identity and revision. Secret bytes
  remain behind the credential port.
- An in-flight provider request retains the revision it resolved. A newly
  installed revision affects a later provider request and does not rewrite
  historical session facts.
- Management Server is the sole refresh authority for Server-managed profiles
  in v0. Endpoint does not refresh or persist a competing token revision. A
  stale/expired/rejected replica produces a typed safe result with no fallback.
- Delegated offline refresh requires a future fenced single-writer protocol.
  Bidirectional token merge is forbidden.

## Aimux stream conversion

- Consume the complete aimux stream: text, reasoning, incremental tool input,
  completed tool calls, usage/response metadata, finish, source/raw parts where
  required, and typed errors. Assemble incremental tool JSON without losing
  provider metadata, thought signatures, or call order.
- Normalize only continuation fields required by a later native request into
  the domain's bounded opaque envelope. Arbitrary raw/debug parts remain
  transient and never enter events, snapshots, or public output.
- Preserve aimux error classification and retry hints; do not use message-text
  heuristics or mutate committed history.
- Keep aimux's bounded transport retry enabled. Its pre-stream wire attempts
  remain secret-safe operational tracing/metrics and do not become session
  events. Once aimux yields a stream, it must never conceal a mid-stream retry.
  Runtime may make a new aimux call as a higher-level model-step retry and
  records only that agent-visible decision.
- Expose incremental `ToolInput*` parts for observation/assembly, but never
  dispatch a tool until the entire stream ends successfully, a valid finish is
  present, and the completed `ToolCall` batch validates.
- Convert Endpoint transcript and tools at this single boundary. Reject an
  invalid conversion explicitly instead of dropping content or tool schemas.
- Resolve authorization only immediately before the aimux call. Prepared model
  envelopes, tracing fields, errors, and retries never retain raw credentials.

## Capability reporting

- Report only installed provider adapter kinds, execution capabilities,
  accepted credential schema versions, outbound-policy capability, and safe
  availability status. Server-configured provider instances/models are not
  Endpoint capability state.
- Capability reads are bounded and do not open every credential or scan session
  history.
- Do not report Server profile defaults, sharing policy, user labels unless
  supplied as non-secret replica metadata, or provider-account secrets.
- A management Server may probe this route, but provider code does not know or
  trust a caller merely because it is named Server; normal Endpoint control
  authentication applies.

## Acceptance

Only real-process HTTP/SSE E2Es are allowed. Fake provider servers are reached
through the real Endpoint aimux adapter. Cover:

- native and OpenAI-compatible wire paths;
- aimux pre-stream retries and mid-stream error propagation;
- incremental tool JSON without early execution;
- provider metadata and continuation preservation;
- two replicas for one provider with exact explicit selection;
- install replay, revision race, tombstone non-resurrection, and startup
  reconciliation;
- restart with a ready persisted replica and no per-Endpoint reconfiguration;
- rotation during an active request: old in-flight and new next request;
- bad/expired/stale stored credential with no environment/profile fallback;
- direct provider traffic from Endpoint without a model-data hop through
  management Server;
- absence of secrets from Endpoint responses, SSE, logs, session SQLite,
  snapshots, blobs, and process error output.

Server OAuth/profile/default/distribution workflows are tested with real Server
plus real Endpoint processes under `server/`; they are not reimplemented as
Endpoint-only OAuth routes.

Existing executable anchors are
`e2e_model_pre_stream_rate_limit_is_one_logical_request`,
`e2e_model_partial_stream_retry_has_no_partial_tool_effect`, and
`e2e_auth_replica_revision_tombstone_and_restart_are_secret_free`.
Descriptor admission is fixed by
`e2e_unknown_provider_execution_schema_is_rejected_and_revision_round_trips`
and `e2e_credential_bearing_model_base_url_is_rejected_without_side_effects`:
the schema is exact, the positive descriptor revision is controller-assigned
and round-trips unchanged, and credential-bearing URLs have no side effects.
`e2e_server_forwards_and_endpoint_persists_provider_execution_options` fixes
the complete descriptor handoff: bounded credential-free options remain part
of the Endpoint-owned selection across a real restart and feed the single
aimux call path rather than a parallel execution adapter.
Replica operation history and expiry metadata are fixed by
`e2e_auth_replica_history_receipt_binds_original_revision` and
`e2e_auth_replica_expiry_and_historical_receipt_survive_restart`; the former
also fixes profile-resource provider binding for both reused and new
idempotency keys.
`e2e_auth_replica_revision_tombstone_and_restart_are_secret_free` fixes the
control-plane tombstone lifecycle, while
`e2e_tombstoned_replica_never_reaches_provider_before_or_after_restart` fixes
the execution consequence: each later attempt commits a typed
`auth_replica_unavailable` terminal and sends no provider request, including
after Endpoint restart. The real direct-provider acceptance path is
`e2e_live_opencode_provider_roundtrip_and_restart`; it is an opt-in live gate
and never replaces deterministic fake-provider cases. Its reviewed,
secret-free provider-wire recording is replayed by
`e2e_recorded_opencode_provider_roundtrip_and_restart` through a network replay
server, the real Endpoint, and aimux. The recording is a test asset rather than
a production provider cache, retry source, or alternate execution path. Every
test-environment request to a real LLM is recorded, including retries and
partial failures. Any problem observed in such a recording must become a
tracked secret-safe cassette and named real-process replay E2E before its fix.

The completed provider execution matrix includes
`e2e_two_profiles_one_provider_resolve_exact_replica`,
`e2e_replica_rotation_keeps_inflight_and_updates_next_request`,
`e2e_bad_replica_never_falls_back_to_environment`, and the reviewed live
direct-provider roundtrip. These cases are real Endpoint-to-network-provider
paths through aimux; a direct aimux test or replica-route-only assertion does
not satisfy them.

The complete public multi-profile lifecycle is fixed by
`e2e_multiple_profiles_selection_isolated_across_replace_tombstone_restart`:
two profiles of one provider are installed and selected explicitly over HTTP,
one profile is replaced and then tombstoned while the other remains usable,
the tombstone and ready state survive Endpoint restart, and every model answer
is observed through the real SSE path. The scenario also proves missing or
tombstoned profile selection fails before provider admission and that profile
secrets never reach HTTP/SSE responses, headers, process output, or session
SQLite.

Native aimux execution is fixed by
`e2e_native_anthropic_messages_stream_uses_exact_replica_and_sse`: an enabled
Anthropic adapter advertises its matching credential schema, resolves the
explicit Anthropic replica, sends the native `/v1/messages` SSE request with
`x-api-key`, and projects the streamed final response through the ordinary
Endpoint HTTP/SSE session path without exposing the secret.

Native tool continuation is fixed by
`e2e_native_anthropic_tool_continuation_preserves_call_and_result`: the same
real Endpoint path dispatches an Anthropic `tool_use`, sends the configured
HTTP tool through the production tool adapter, and the next native request
contains the matching provider-shaped `tool_use` and `tool_result` identities.
The assertion also verifies the final public session remains secret-free.

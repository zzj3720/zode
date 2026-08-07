# Storage module rules

`src/storage` owns the transactional event-store port and the default SQLite
adapter. The event stream is authoritative; all other records are optimizations
or rebuildable operational projections.

## Transaction and replay invariants

- Append a command's complete semantic event batch atomically with optimistic
  stream-version checking and idempotency binding; append none on any failure.
- Session creation atomically appends the version-1 `SessionCreated` event and
  its authority/subject-scoped collection receipt projection. The projection
  stores only versioned command/request digests and event-derived identifiers;
  it is rebuilt from verified creation events and must not become a second
  receipt authority or retain raw idempotency keys/canonical request bytes.
  Create replay reconstructs the canonical fixed `201` response from those
  event facts. The request fingerprint is computed before ULID allocation.
- Empty batches are invalid. Event IDs, stream versions, and public global
  positions are stable and monotonic after commit.
- Snapshots are append-only accelerators. Validate schema, reducer version,
  state identity/version, checksum, and a trusted event-prefix integrity anchor;
  then read and replay only the event tail.
- Every event decode path recomputes its fingerprint from the persisted stream
  identity, version, event/command identity, schema, and original payload bytes
  before trusting that event or extending an integrity digest. HTTP/SSE reads,
  rehydration, command replay, and projection repair cannot bypass this check.
- A non-empty stream requires a valid integrity anchor at its current head.
  Missing, malformed, or mismatched authority metadata is an integrity failure,
  not permission to silently full-replay and bless unverified history.
- Snapshot validation must not turn normal rehydration back into full-history
  replay. Integrity metadata needed to trust the prefix is written atomically
  on the normal append/snapshot path and is not derived by rereading history on
  every query.
- Mutable stream-head, command, runnable-session, and timer indexes are
  disposable. Healthy startup is read-only and proportional to metadata, not
  total history. Repair only a missing/inconsistent projection, preserving
  historical command idempotency bytes rather than reserializing old events
  with current code.
- Owner/list and collection-create indexes are likewise rebuildable
  projections. Rebuild fails closed if verified history maps one scoped create
  digest to multiple streams. Owned read, append, SSE catch-up, and list paths
  share one verified owner gate so missing and cross-owner resources have the
  same public result; list order uses durable creation position, never ULID
  lexical order.
- Initialize the storage schema only when the SQLite catalog is genuinely
  empty. Once any zode fact exists, missing or non-canonical metadata and
  authority tables fail closed; startup may transactionally rebuild only the
  explicitly classified projections and required indexes.
- Storage triggers are a closed canonical set. Preserve harmless caller-added
  ordinary non-unique column indexes, but reject extra unique, partial,
  expression/rowid-key, or custom-collation indexes that can change authority
  semantics or make startup validation ambiguous.
- SQLite uses WAL, busy timeout, short controlled write transactions, and no
  async-worker blocking. Runtime/domain code sees only the storage port.
- Never store provider credentials, OAuth material, raw authorization headers,
  or unbounded inline tool output in events or snapshots.
- Credential replicas use their dedicated protected secret store and
  append-only non-secret provisioning journal. Session storage may retain only
  authority/profile identity and the resolved revision. It never shares a
  SQLite file or secret directory with management Server, including all-in-one
  deployment.

## Acceptance

Storage has no unit or direct integration tests. Tests spawn the real Endpoint,
write through HTTP, observe HTTP/SSE, and restart on the same temporary SQLite
file. A test may inspect or damage its own database only while Endpoint is
stopped to establish recovery conditions. The same E2E contract must apply to
future storage adapters.

Maintain positive E2Es for concurrent reads during append, snapshot-plus-tail
equivalence, invalid snapshot fallback, bounded snapshot rehydration work,
healthy startup without history-wide repair, missing/stale index rebuilding,
historical command-idempotency preservation, snapshot creation leaving the
public cursor unchanged, and oversized/credential-shaped payloads remaining
bounded and secret-free.

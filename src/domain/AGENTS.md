# Domain module rules

`src/domain` owns durable session vocabulary, validated value types, semantic
events, and the deterministic session projection. It does not own effects.

## Hard boundaries

- Reducers are pure and total over valid event sequences. They perform no I/O,
  locking, clock reads, randomness, ID generation, provider calls, tool calls,
  timer scheduling, logging, or publication.
- Persist facts, not handles or instructions to rediscover facts. Time, IDs,
  retry decisions, dedupe keys, deadlines, and terminal outcomes are generated
  outside the reducer and carried by typed events.
- Use semantic events and explicit versioning. Never persist generic JSON
  patches, aimux/provider Rust or wire types, SQLite rows, HTTP request types,
  provider-request snapshots, transcript/tool copies, request controls, or
  secrets. A request already sent to a provider exists only in the live
  process; restart reconstructs a new request from durable semantic facts.
- The original model `tool_call_id` is the lifecycle identity. Do not add a
  parallel async-task identity.
- `SessionCreated` fixes the Endpoint-generated session ID, creation time, and
  initial non-secret selection. It does not record a caller owner. It never
  carries a raw idempotency key. Collection command identity and canonical
  request fingerprint are versioned event-envelope facts computed before ULID
  allocation, so concurrent candidates do not change one logical create
  fingerprint.
- Invalid transitions return a typed invariant error and append nothing.
  Terminal tool transitions are first-wins; stale timers and duplicate
  completions are explicit no-op command outcomes, not second terminal events.
- An activation fact captures its concrete provider/model/profile selection,
  provider-execution descriptor revision/fingerprint, selection version,
  credential authority, and minimum auth-replica revision. Each model-attempt
  fact captures its concrete resolved replica revision. No fact carries secret
  bytes. Later session-selection affects later activations; a later replica
  install may affect only a provider request not yet sent.
- A model-round fact captures the delivery position and transient logical
  request fingerprint used by that round. Deliveries may materialize at later
  round boundaries in the same activation, but retries of one live in-memory
  model step keep its fingerprint and do not consume newer deliveries. An
  interrupted request is abandoned after restart rather than reconstructed.
- A scheduled model retry owns a stable next attempt ID and number while its
  process-local request remains available. Starting it is first-wins. A crash
  abandons that request and builds a fresh round from the latest durable facts;
  it does not turn an interrupted transport into attempt exhaustion.
- Incremental model stream parts are not durable assistant/tool facts. Only a
  complete successful stream can commit its assistant outcome and validated
  tool-call batch.
- Keep bounded durable collections bounded in the projection itself. Large
  outputs use immutable blob references; redacted values never retain their
  original secret bytes.
- Sessions are not owned by a caller. `SessionCreated` does not carry an
  access-control owner. Historical owner fields, if present in old events, are
  not an ACL.

## Acceptance

There are no domain unit tests. Exercise every transition through the real
Endpoint and public HTTP/SSE surface, including restart replay. A new invariant
needs an E2E whose pre-fix behavior is red and whose assertions observe the
public projection/events rather than Rust internals.

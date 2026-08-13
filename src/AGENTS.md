# Endpoint production source rules

The root `AGENTS.md` is authoritative. This file adds rules for all production
Rust code under `src/`, which is the independently deployable device Endpoint.
Management Server code belongs under `server/`; browser code belongs under
`web/`.

## Production boundaries

- Keep one-way dependencies. Domain types and reducers are innermost; the
  application/runtime layer declares effect ports and depends on the domain;
  SQLite, aimux/provider execution, credential-replica, tool, timer, and
  transport code are adapters; `main.rs` only composes them.
- The timer adapter implements a runtime-declared TimerPort. It must not
  append events, rehydrate sessions, cancel tools, or persist wait state.
  Runtime arms it only after the WaitSet/timer-intent transaction commits.
- Session create, append-message, and model-select go through Runtime.
  Credential-replica install, tombstone, list, and get go through Runtime.
  Session list, get, and owned SSE subscribe/catch-up go through Runtime.
  `ProviderExecutionPolicy` implements `ExecutionPolicyPort`; `FileReplicaStore`
  implements `ReplicaPort` and is injected into Runtime only. HTTP does not
  hold EventStore or the replica store, or construct session event drafts.
  Aimux receives a short-lived `SecretLease` at call time, not a store.
- Do not add management Server discovery, registration, reverse connection,
  heartbeat, users, OAuth/profile authority, cross-Endpoint routing, mirror, or
  UI concerns anywhere under `src/`.
- Do not let an adapter type leak into durable events, snapshots, the reducer,
  or another adapter's public seam.
- Prefer deleting duplicate state or control paths over adding synchronization
  between competing authorities.
- Blocking filesystem, SQLite, process, and credential operations must not run
  on Tokio async workers. Move them through an explicit blocking boundary.
- Production code must not contain test-only branches, hidden routes, fixture
  providers, fake clocks selected by build flags, or `#[cfg(test)]` modules.
- Before opening runtime/credential state, acquire one exclusive
  process-lifetime lock bound to the stable Endpoint identity and store
  identity. A second process fails readiness; SQLite locking alone does not
  fence duplicate provider/tool effects.

## Change sequence

For a new behavior or a behavioral defect:

1. Define the externally observable contract in the nearest module instructions
   when it establishes a durable rule.
2. Add a real-process public HTTP/SSE E2E and demonstrate the intended failure.
3. Change the smallest authoritative production path.
4. Re-run the focused E2E, related recovery/reconnect E2Es, formatter, and lint.

Compilation and static architecture failures can be fixed directly, but they
must never be used as a reason to add white-box tests.

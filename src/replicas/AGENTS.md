# Endpoint credential-replica store

`src/replicas` owns the device-side file store for controller-provisioned
credential replicas. It implements the runtime-declared provision and resolve
ports. It is not session authority, an HTTP adapter, or a second event store.

The system boundary is `docs/architecture.md`. Replica atomicity is
`docs/auth-replication.md`. Runtime consume/resolve timing is
`src/runtime/AGENTS.md`. Aimux consumes only a short-lived `SecretLease`.

## Responsibility

- Persist install and tombstone as authenticated, idempotent, monotonically
  versioned operations on a restrictive directory.
- Stage secret material, append only non-secret operation identity/phase/
  fingerprint metadata, atomically promote the active secret, then mark the
  revision ready.
- Resolve a ready replica into a non-serializable, non-session-owned secret
  lease for one provider attempt. Only identity and revision may leave this
  module.
- List and read only non-secret metadata.

## Forbidden dependencies

- Do not import storage session SQLite, HTTP/API, runtime concrete types,
  provider/aimux, or tools.
- Do not append session events, rehydrate sessions, or share a SQLite file
  with the runtime store.
- Do not refresh, merge, or mutate a Server-managed profile independently.
- Do not put secrets in receipts, listings, errors, or logs.

## Public seam

Implement `ReplicaPort` only. Compose `FileReplicaStore` from `main.rs` and
inject it into Runtime. HTTP and aimux must not hold this store.

## Persistence

- Restrictive directory and an atomically replaced `0600` file per
  authority/profile. Blocking filesystem work stays off Tokio async workers.
- Receipts are non-secret idempotency facts. They never contain secret bytes,
  staging paths, or unkeyed secret hashes.
- Active-manifest promotion is the resolution linearization point. A lower
  revision cannot overwrite or resurrect a higher revision.

## Acceptance

No unit tests. Real-process HTTP/SSE E2Es own the contract:

- `e2e_auth_replica_revision_tombstone_and_restart_are_secret_free`
- `e2e_auth_replica_history_receipt_binds_original_revision`
- `e2e_auth_replica_expiry_and_historical_receipt_survive_restart`
- `e2e_tombstoned_replica_never_reaches_provider_before_or_after_restart`

# Endpoint control identity rules

`src/control` owns the device Endpoint's stable identity and exclusive
process lock. It knows nothing about Cloudflare Access, management users,
provider logins, sessions, or UI routes. It does not authenticate HTTP
callers.

## Identity

- Persist one stable opaque `endpoint_id` for the lifetime of the configured
  Endpoint stores. A caller cannot supply or replace it.
- Do not implement controller bearer authentication, `Zode-Subject` admission,
  or controller-auth rotation. Those contracts are removed.
- HTTP admission is unauthenticated. Trust is the listen address.

## Process lock

- Bind the process-lifetime lock and the SQLite adapter to the same verified
  canonical runtime path. Lock and identity sidecars must be regular,
  single-link files opened without following symlinks; runtime hardlinks fail
  closed.
- Create the Endpoint-owned `endpoint_id` only while the runtime store is
  jointly unclaimed. A missing identity sidecar on an existing store is
  corruption, never permission to mint a replacement ID.

## Acceptance

Only real-binary HTTP/SSE E2Es cover this module. Identity and lock anchors
remain. Controller-auth and subject-admission cases are retired.

| Boundary | E2E anchors |
| --- | --- |
| Stable identity and exclusive process lock | `e2e_identity_is_endpoint_owned_and_restart_stable`; `e2e_same_stores_allow_one_endpoint_until_exit_then_preserve_state`; `e2e_runtime_store_path_alias_cannot_split_endpoint_ownership`; `e2e_hardlink_runtime_store_fails_closed_without_state_split`; `e2e_runtime_store_symlink_toctou_cannot_cross_ownership` |
| Protocol has no controller auth | `e2e_endpoint_protocol_has_no_controller_auth` |

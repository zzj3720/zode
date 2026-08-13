# Server--Endpoint protocol compatibility matrix

Status: authoritative compatibility gate for the versioned Server probe of an
independently running Endpoint. The wire fields remain owned by
[`docs/http-api.md`](http-api.md) and the management projection by
[`docs/server-api.md`](server-api.md).

## Handshake matrix

Server admission probes `/v1/identity` and `/v1/capabilities` through the same
HTTP path used for a real Endpoint catalog create. It validates
the two v1 DTOs and negotiates one exact protocol version before writing a
catalog row. Unknown JSON fields are additive metadata and are ignored within
v1; required semantic changes use a new schema/protocol and are rejected
without a catalog row. These metadata probes do not send a controller bearer
or `Zode-Subject`. There is no silent downgrade.

| Wire variant | Expected admission | Durable assertion |
| --- | --- | --- |
| v1 identity + capabilities | accept | one catalog row with the Endpoint identity and v1 projection |
| v1 plus an unknown identity field | accept | same row and identity |
| v1 plus an unknown capabilities field | accept | same row and capabilities |
| v1, credential revision `2` | accept | row records revision `2`; revision is positive and opaque |
| unsupported protocol `zode.endpoint.v2` | reject with `503 endpoint_unavailable` | catalog remains empty |
| unsupported identity schema `zode.identity.v2` | reject with `503 endpoint_unavailable` | catalog remains empty |
| unsupported capabilities schema `zode.endpoint-capabilities.v2` | reject with `503 endpoint_unavailable` | catalog remains empty |
| identity/capabilities endpoint IDs differ | reject with `503 endpoint_unavailable` | catalog remains empty |
| capabilities limits differ from the v1 contract | reject with `503 endpoint_unavailable` | catalog remains empty |
| identity credential revision `0` | reject with `503 endpoint_unavailable` | catalog remains empty |

The real-process gate is
`server/tests/access_ingress_e2e.rs::e2e_server_endpoint_protocol_compatibility_matrix`.
It starts one real Endpoint, places only a test-owned local HTTP compatibility
proxy in front of it, and starts a fresh real Server for every row. The proxy
changes only the selected JSON response. It normalizes connection framing for
the local hop. Each
assertion still traverses the public Server Access/catalog route and the
Endpoint's HTTP identity and capability routes.

The shared Rust negotiation function is the one Server admission path:
`zode_protocol::negotiate_endpoint_protocol`. Server does not maintain a
second hand-written version or limits check.

## Related versioned behavior

Handshake compatibility does not create a second session or event protocol.
The existing black-box E2Es remain the compatibility anchors for the other
versioned boundaries:

- `tests/http_sse_e2e.rs::e2e_create_message_sse_reconnect_get_restart` covers
  durable event IDs, reconnect, and restart replay; SQLite snapshot/cursor
  checks are isolated in `tests/sqlite_storage_e2e.rs`.
- `tests/endpoint_control_e2e.rs::e2e_auth_replica_revision_tombstone_and_restart_are_secret_free`
  covers authenticated credential-replica revision and tombstone behavior.

A future semantic change to either boundary must add a new explicit protocol
version/negotiation row and a real-process red E2E before production behavior
changes. Additive fields within a documented version must remain unknown-field
tolerant and must not alter the durable projection.

# Server-Endpoint protocol rules

Create code under `protocol/` only when shared versioned DTOs or generated
schemas reduce duplication between independently deployable Server and
Endpoint. `docs/http-api.md`, `docs/server-api.md`, and
`docs/auth-replication.md` remain authoritative.

- Protocol types contain wire identities, bounded public payloads,
  compatibility versions, and safe errors only.
- Do not place Endpoint domain state, reducers, storage ports, provider/aimux
  types, Server/Access actor models, database rows, secrets, or process handles
  here.
- Compatibility is additive within a schema version. Required semantic changes
  introduce a new version and explicit negotiation/capability behavior.
- Endpoint remains independently usable without importing Server. Server may
  depend on protocol types but not Endpoint internals.
- Session creation has no caller-supplied ID. Endpoint returns its generated
  ULID; Server proxy routes pair that opaque value with `endpoint_id` and never
  introduce a global session or event identity.
- Controller authority and opaque subject are transport authorization scope,
  not Cloudflare Access claims or Server actor DTOs. Callback ID and bearer are
  distinct: only the ID may appear in a route; bearer fields are secret and
  redacted by default.
- Secret-envelope payload fields are opaque at protocol level and redacted by
  default debug/serialization tooling. Plain secret values never appear in
  generated examples or fixtures.
- Do not create a shared crate for convenience alone. It must reduce final
  duplicated wire code or enforce compatibility more simply than separate
  types.

Protocol behavior is tested only through real Server/Endpoint processes. No
serialization unit tests, golden DTO snapshots, or in-process compatibility
tests are allowed. Version negotiation, unknown fields, bounds, idempotency,
and downgrade rejection use public real-process E2Es.

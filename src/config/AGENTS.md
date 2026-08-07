# Endpoint configuration module rules

`src/config` parses and validates the non-secret device Endpoint configuration
defined by `docs/http-api.md`. It produces bounded composition data for
`main.rs`; it does not execute sessions, resolve management defaults, or own
runtime state.

## Boundary

- Accept only the versioned `zode.config.v1` schema and reject unknown schema
  versions, invalid bounds, unsafe adapter/recovery combinations, and malformed
  outbound-origin policy before readiness.
- Treat the configuration file plus explicit development CLI flags as the only
  composition inputs. Do not read ambient environment variables for listen
  addresses, stores, snapshot policy, credentials, providers, models, users,
  management discovery, or local authentication.
- Deserialize, merge explicit CLI overrides, resolve each path according to its
  source, and then perform one semantic validation pass. An overridden invalid
  lower-priority value cannot veto the explicit CLI value. Configuration-file
  relative paths use the configuration directory; CLI path overrides retain
  process-working-directory semantics.
- Configuration may name secret files and dedicated stores, but secret bytes
  are loaded only by their owning adapters. Never deserialize secret values
  into the general configuration object, log them, or persist them in the
  runtime SQLite database.
- Resolve relative paths against the configuration file directory. Preserve
  explicit command-line `--listen`, `--database`, and snapshot overrides as
  development composition overrides without creating a second configuration
  authority.
- Keep parsing and validation separate from side effects. This module opens no
  database, socket, provider connection, tool process, or credential store.
- Read configuration through a bounded reader that stops after the documented
  maximum plus one byte; checking size after an unbounded read is not a bound.
  Complete blocking configuration I/O before creating the async runtime or use
  an explicit blocking boundary.
- Reject runtime-reserved tool names, including `wait_for`, before readiness.
  Configuration cannot create a second registry entry for an internal tool.
- Prefer typed bounded fields over unstructured JSON passthrough. Adapter
  configuration may remain opaque only behind a versioned kind whose owning
  adapter validates it before Endpoint readiness.
- Keep raw deserialization types private to the binary composition boundary.
  Other modules receive only validated, bounded composition values through the
  smallest required getters; they cannot deserialize an unchecked config DTO.

## Acceptance

Configuration behavior is covered only by real-binary E2Es. They start zode
with a temporary JSON file and assert readiness or a bounded startup failure;
there are no parser unit tests or test-only configuration branches.

# Test-environment request recording and replay

This document is authoritative for request recording and replay used by zode
development, E2E, staging, and other explicit test environments. It is not a
production observability or traffic-capture design.

## 1. Production exclusion

Production Endpoint, Server, provider, tool, OAuth, callback, and web paths
never record request or response bodies, load test cassettes, enable a capture
mode, install a recorder proxy, or expose a replay endpoint. Production
diagnosis uses bounded secret-safe telemetry. A production observation must be
reproduced in an isolated test environment before request recording begins.

No production module, state transition, configuration field, persistence
schema, or runtime branch may depend on this document's test infrastructure.

## 2. Required capture

Every request made from a test environment to a real LLM must traverse a
test-owned recording proxy. Capture every wire attempt, including successful
responses, provider errors, pre-stream retries, partial streams, disconnects,
and requests made before or after Endpoint restart. Failure to flush one
exchange fails the live test; an unrecorded direct real-LLM test is forbidden.

Provider-boundary tests should use
`LlmHttpProxy::record_with_attempt_plan_and_authorization(..., true)` when the
wire contract requires authorization; the flag is authoritative and
independent of the opaque synthetic-slot spelling. The compatibility recorder
may infer the requirement from the provider boundary for existing suites, but
new opaque-slot cases must not rely on that inference. Replay must use
`replay_with_authorization` with the test-only slot value. Authorization is
never serialized into a cassette, and omitting the explicit requirement in a
new case is a test-harness contract error rather than a silent fallback.

For other real-path defects, retain the earliest failing exchange observed in
the test environment after this rule was adopted. Capture the inbound public
request and each external-boundary exchange needed to reproduce the defect
before a retry, workaround, test rewrite, or production repair changes it.
Previously frozen E2Es are not retroactively invalidated, and a later capture
must never be represented as the historical first occurrence.

## 3. Storage classes

Recordings have three storage classes:

1. `target/test-recordings/quarantine/<run-id>/` contains restrictive `0600`
   raw test captures while redaction is being verified. It is ignored and may
   contain test credentials; production traffic must never enter it.
2. `target/test-recordings/live/<run-id>/` contains secret-scanned successful
   live recordings used for local performance analysis or fixture review. It
   remains ignored.
3. `tests/fixtures/provider_recordings/` and the owning suite's
   `fixtures/incidents/` contain reviewed immutable secret-safe cassettes used
   by committed regression E2Es.

Create a new capture path exclusively. Never overwrite an existing raw or
tracked cassette. A different occurrence receives a different recording ID.
Tracked fixture updates are explicit reviewed changes, not output written by
an ordinary test run.

## 4. Recording envelopes

Ordinary HTTP incidents use `zode.http-incident-recording.v1`. Real-LLM wire
recordings use `zode.llm-http-recording.v1`; it has the same exchange shape and
adds non-secret provider/model labels plus logical-round and wire-attempt
numbers.

Each envelope contains:

- a stable recording ID, purpose, owning `e2e_*` case, and boundary label;
- a safe first-observed outcome for incident recordings;
- named synthetic secret slots, never secret values;
- an ordered list of exchanges;
- a whole-envelope integrity digest calculated after redaction.

Each exchange contains:

- sequence, logical round, and wire attempt where applicable;
- request method, path, exact raw body bytes, parsed canonical JSON when valid,
  and body digest;
- an allowlist of semantic headers such as `content-type`; authorization,
  cookies, proxy credentials, trace baggage, and opaque account headers are
  forbidden;
- response status, allowlisted semantic headers, and ordered raw body/SSE
  chunks;
- each chunk's offset from response start in microseconds;
- whether the response completed, disconnected, timed out, or ended with a
  safe classified transport error.

Do not store the upstream credential-bearing URL, DNS result, Authorization
value, cookie, raw Access assertion, OAuth token/code/state, callback bearer,
or unredacted identity. Request bodies that contain a test secret replace the
exact value with a named synthetic slot before promotion.

Startup-rejection incidents use the test-only
`zode.process-incident-recording.v1` envelope. The shared
`tests/support/process_capture.rs` seam records the already slot-substituted
config bytes and each real child observation (bounded stdout, stderr, exit
code, signal, and termination classification). `capture_config` must happen
before the child is spawned; `capture_process` durably seals every observed
child before another startup; `flush` must succeed before the test asserts the
failure or retries. Config and process records are private `0600` files under
the ignored run directory, and the final envelope carries a whole-envelope
digest. This seam records no environment map, JWT, bearer, or live secret.
Natural exits encode `exit_code` as an integer and `signal` as JSON `null`;
signal-terminated children encode the inverse. A successful stop proof must
contain at least one observed and reaped PID, must have no leaked PID, must
not time out, and must report a durable `flush_status` of `ok`; an empty or
placeholder proof is rejected and permanently fails that capture run.
For a tracked startup cassette, the read-only
`ProcessIncidentReplay::load(path, expected_e2e_name, forbidden_markers)` API
is the only loader: it checks the schema/version, recording and E2E identity,
whole-envelope digest, config digest, bounded process observations, and the
`ProcessStopObservation` observed/reaped/leaked/timed-out/flush proof. It also
scans the serialized envelope and decoded config/stdout/stderr against the
forbidden markers before returning a projection. Callers can read only
`config_label()`, `config_bytes()`, `classification()`, `first_observed()`,
and `source_digest()`; no unvalidated JSON or process facts are exposed.
`ProcessIncidentReplay::promote_immutable(destination, proof, forbidden_markers)`
re-reads that existing flushed raw, revalidates schema/version, recording and
E2E identity, envelope/config/process integrity, stop proof, and markers, then
requires the exact `source_digest` plus a non-empty replay fingerprint from the
same public replay. It creates a new `0444` file with create-new semantics and
never overwrites or rewrites the raw source. The public E2E owns the semantic
assertion represented by that fingerprint; this helper only binds it to the
exact flushed source and rejects placeholder or later-occurrence proofs. The
live `ProcessCaptureSet::promote_immutable` path uses the same validation and
promotion primitive before the capture owner exits.
The shared regression anchors are
`e2e_process_capture_replays_natural_exit_with_null_signal`,
`e2e_process_capture_promotes_flushed_raw_after_writer_exit`, and the
malformed-stop, retry-after-failure, exit-code, and recording-identity
rejection cases in `tests/process_capture_e2e.rs`. The recovery case spawns a
writer that exits after durable flush and promotes only from the reloaded raw
source.
It is a test module only and must not be imported by production code.

## 5. Promotion and secret scan

Promotion converts one quarantined capture into a tracked cassette without
changing the behavior that caused the result:

1. replace every secret and sensitive identity with an explicit synthetic
   slot;
2. preserve body shape, stream chunks, ordering, disconnect point, and relevant
   timing;
3. replay once against the still-unfixed product and prove the same public red;
4. scan the cassette, Endpoint/Server output, HTTP/SSE observations, test-owned
   secret directory, and stopped SQLite databases for every live secret and
   sensitive marker;
5. write the tracked cassette only if its destination does not exist.

If redaction changes the failure or a safe replay cannot be produced, stop the
repair and report the evidence gap. Never commit the raw capture.

## 6. Replay modes

Replay always starts the owning real product process and uses its public entry
plus the production adapter under test. Provider replay therefore starts the
real Endpoint and traverses aimux to a network replay server. Server incidents
start real Server and Endpoint processes where the original path did.

The replay server verifies exact exchange order, method, path, semantic
headers, request body bytes or approved synthetic-slot substitution, and total
exchange count. An unexpected, missing, duplicate, or unconsumed request fails
the E2E with a safe diff.

Two timing modes are allowed:

- `immediate` preserves chunk order but emits without recorded delay; it is the
  default deterministic regression mode.
- `captured` preserves recorded relative chunk offsets for opt-in performance
  and race reproduction.

Timing mode may not alter request/response semantics. Performance replay may
report elapsed time and distributions but the canonical correctness suite has
no machine-specific latency threshold.

## 7. Defect workflow

When a recording exposes a problem:

1. stop retries or repair work after the first retained test occurrence;
2. promote its secret-safe immutable cassette;
3. bind the cassette to a named real-process E2E;
4. demonstrate the original public failure red through replay;
5. freeze the E2E through independent review;
6. let the original implementation owner repair production without editing the
   cassette or frozen scenario;
7. run the same replay green and retain it permanently.

A live-only log, manually reconstructed request, direct internal call, mock
handler, or regenerated cassette does not satisfy this workflow.

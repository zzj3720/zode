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

Terminal recorder-flush failures are also bounded at the public SSE boundary.
`e2e_later_test_reproduction_of_terminal_flush_gap_is_bounded_and_captured`
arms the shared process capture before spawning Endpoint, waits at most the
test failure bound for `model_attempt_failed`, and durably flushes the child
stdout/stderr/exit/stop proof before cleanup. Its
`later_test_reproduction_of_gap` observation is a later reproduction and does
not replace an earlier retained full-suite hang.

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

A long agent run may store its reviewed LLM envelope as a Zstandard-compressed
tracked fixture when repeated growing request contexts would make the plain
JSON envelope needlessly large. Compression changes only storage: loading is
bounded independently for compressed and expanded bytes, then validates the
same complete envelope digest, exact ordered requests, chunks, outcomes, and
secret-slot rules before replay. It cannot omit or summarize exchanges.

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
- an allowlist of semantic headers such as `content-type`, canonical `host`,
  `forwarded`, and `x-forwarded-host`; authorization, cookies, proxy
  credentials, trace baggage, and opaque account headers are forbidden;
- response status, allowlisted semantic headers, and ordered raw body/SSE
  chunks;
- each chunk's offset from response start in microseconds;
- whether the response completed, disconnected, timed out, or ended with a
  safe classified transport error.

Reasoning-capable providers may emit one small SSE frame per reasoning token.
The recorder therefore bounds response bytes and frame count independently;
the frame bound must accommodate the configured model output budget while the
byte bound remains authoritative. Crossing either bound fails the live test
and cannot silently combine a later model request with the incomplete
exchange. The positive large-response path is frozen by
`e2e_llm_recorder_accepts_bounded_reasoning_stream_needed_by_handoff_generation`;
`e2e_llm_recorder_stream_capture_bound_fails_closed` retains the upper-bound
failure.

Captured timing is the ordered offset of each frame from response start. The
bounded-delay rule applies to the initial response delay and to each adjacent
frame gap, not to total stream duration. A healthy long reasoning stream may
therefore last longer than one allowed idle gap while every individual gap
remains bounded. `e2e_recorded_provider_replay_accepts_long_total_stream_with_bounded_inter_chunk_delays`
freezes this distinction; `e2e_recorded_provider_replay_rejects_unbounded_captured_timing`
retains the rejection path.

Do not store the upstream credential-bearing URL, DNS result, Authorization
value, cookie, raw Access assertion, OAuth token/code/state, callback bearer,
or unredacted identity. Canonical authority headers are retained exactly so a
management/callback surface cannot be replayed under the other surface or
with forged forwarding headers. Request bodies that contain a test secret
replace the exact value with a named synthetic slot before promotion.

Native HTTP replay uses the shared replay server and compares these authority
headers on every request. Browser replay must use the test-only canonical edge
adapter (`startReplayEdge(cassette, { canonicalOrigin, timingMode })`), which
restores the recorded canonical `Host` before forwarding while preserving the
recorded forwarding headers. The adapter disables recording during replay and
cannot append to a sealed capture set.

The Node journal exposes a crash-safe recovery path for a writer that exited
after flushing but before promotion. `RecordingJournal.openFlushedCaptureRoot`
opens an existing quarantine directory without creating a `promoted` directory,
manifest, or default capture set. The caller must first call
`reloadCaptureSet(captureSetId)`, which revalidates the sealed manifest/anchor,
raw-member digests, source identity, slots, and first-failure member. Then call
`promoteFlushedCaptureSet(captureSetId, { destinationDirectory, replay })` with
an independent destination and a callback that returns the complete results of
`replay` through the same public local edge/base URLs. The helper binds source
manifest digest, first-failure ID, exchange count, and response fingerprint to
that result list, performs the safe scan again, and writes a new `0444`
create-new cassette. A bare `{ ok: true }` proof, a missing callback, a callback
that fabricates or mutates replay results, a changed owner, a symlink
destination, a destination inside the forensic root, or an existing destination
file is rejected without rewriting or deleting the flushed raw evidence. The
callback must return the frozen result list produced by that same journal's
`replay` primitive; the helper revalidates the complete envelope before writing.

All shared HTTP edges call `beginIngress` before URL/authority parsing or body
reading, append bounded chunks and a request-end digest durably, and only then
forward upstream. Body-bound, aborted, malformed-target, and wrong-path
requests therefore retain a partial or terminal raw exchange even when no
upstream request is made. The JWKS fixture uses the same ingress boundary
before its method/path guard.

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

DeepSWE replay is centered on the session's append-only event log. One reviewed,
immutable event trace is the causal manifest for the run; there is no parallel
shell transcript or environment snapshot that can become a second authority.
The trace preserves each ordered semantic event's schema version, type, and
payload. Test-only loading is byte-bounded, checks a whole-trace digest, and
rejects missing, extra, reordered, or changed events.

The replay harness classifies trace entries by their role without importing
them into storage:

- input events describe stimuli that the harness must deliver through the same
  public command or external adapter boundary used in production;
- output and lifecycle events describe facts that the new Endpoint execution
  must commit and are compared as expected results.

For example, a recorded user delivery is replayed as the corresponding public
message command. `AsyncToolCallStarted` supplies the exact tool name and input
that the real HTTP tool adapter must receive, while its matching
`AsyncToolCallCompleted` supplies the recorded external result returned by the
test-owned tool fixture. Endpoint must independently commit both lifecycle
events in the same causal position. Even when an event represents an admitted
input, the harness never appends that event directly.

The provider HTTP cassette is the only supplemental long-run recording. It
retains exact provider request/response bytes because those payloads are
intentionally excluded from session events. Replay still starts the real
Endpoint, sends the user input through public HTTP, traverses aimux, and uses
the production HTTP tool-dispatch adapter. The resulting stopped database's
event trace must match the reviewed manifest after deterministic normalization
of run-local identities and clocks. An unexpected provider request, tool call,
event, duplicate, or unconsumed expected fact fails the E2E.

A separate Pier reconstruction mode may additionally start a fresh official
benchmark environment. It derives each shell command and expected result from
the same event trace, executes the command there for its filesystem side
effects, and requires the recorded exit code while returning the recorded
stdout/stderr so provider replay remains exact. The official verifier then
checks the reconstructed working tree after all provider requests and expected
events are exhausted. This reconstruction does not replace the deterministic
Endpoint replay, and recorded tool output alone cannot produce a passing
benchmark result.

The replay server verifies exact exchange order, method, path, semantic
headers, request body bytes or approved synthetic-slot substitution, and total
exchange count. An unexpected, missing, duplicate, or unconsumed request fails
the E2E with a safe diff. A same-entry replay through a live HTTP hop compares
the complete ordered response bytes and terminal outcome; transport reads may
be coalesced or split by that hop. `startReplayServer` remains the primitive
that re-emits the captured response chunk boundaries exactly.
The replay target's terminal outcome is observed independently; the captured
outcome is never used to relabel a disconnect or transport error. A mismatch
fails with `REPLAY_TERMINATION_MISMATCH` before promotion.

Two timing modes are allowed:

- `immediate` preserves chunk order but emits without recorded delay; it is the
  default deterministic regression mode.
- `captured` preserves recorded relative chunk offsets for opt-in performance
  and race reproduction.

Timing mode may not alter request/response semantics. Performance replay may
report elapsed time and distributions but the canonical correctness suite has
no machine-specific latency threshold.

The opt-in `e2e_live_opencode_provider_roundtrip_and_restart` gate reloads the
newly flushed immutable live recording, then performs three immediate and three
captured replays through the same Endpoint/aimux public path. It writes only
non-secret elapsed time samples and exchange/chunk counts to the ignored
`target/test-recordings/live/<run-id>/replay-benchmark.v1.json`; ordinary CI
never invokes this real-provider gate.

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

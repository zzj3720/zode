# Endpoint E2E suite rules

This repository permits E2E tests only. Files under `tests/` are black-box
clients for the device Endpoint and controllable external fixtures, never
privileged product code. Cross-component Server/all-in-one tests belong under
`server/tests/`; browser tests belong under `web/e2e/`.
`docs/test-recording.md` is authoritative for all test-environment request
recording, fixture promotion, and replay.

## Product boundary

- Every default Endpoint E2E starts the real `CARGO_BIN_EXE_zode` binary on an
  isolated port, uses public HTTP/SSE, and uses a fresh temporary real SQLite
  database. The backend-neutral storage conformance profile may select another
  real Endpoint binary with `ZODE_CONFORMANCE_ENDPOINT_BIN`; it must provide
  the same public contract without making the generic suite depend on SQLite
  internals.
- Never import `zode`, call Rust domain/storage/runtime/API functions, expose a
  hidden test endpoint, or select fake production behavior through `cfg(test)`.
- Local fake model/tool/OAuth servers are allowed only across the same network
  adapter boundary production uses. LLM E2Es must still traverse aimux.
- Direct test-owned SQLite inspection or mutation is allowed only through a
  blocking worker and only while the zode process using that database is fully
  stopped. Use it to establish corruption/recovery conditions, not to invoke
  product behavior.

## Determinism and resource safety

- Prefer positive barriers: a committed public event, held fixture request,
  explicit callback, process readiness line, or persisted row condition. A
  short interval in which nothing happened is not proof of correctness.
- Apply explicit timeouts to readiness, HTTP, SSE frames, fixture barriers, and
  child shutdown so a regression fails instead of hanging the suite.
- Child-process helpers kill and reap on every normal and error path. Temporary
  directories own cleanup through RAII and are removed only after children and
  blocking database workers have finished.
- Concurrency tests must distinguish expected optimistic conflicts from lost
  work: retry through the same public command/idempotency key, then assert the
  final durable order and count.
- Recovery tests stop the process, mutate only the test-owned environment,
  restart the real binary, and finish with a positive HTTP/SSE assertion.
- Credential-replica tests use controller-authenticated public provisioning
  routes to race install revisions and tombstones, then prove lower revisions
  cannot overwrite or resurrect newer state. Endpoint tests do not create
  OAuth attempts, provider defaults, sharing policy, or Server-managed
  profiles; those belong to Server E2Es.
- Model fixtures must separately prove aimux's pre-stream retry and zode's
  higher-level step retry. Hold an active stream while queuing input, then
  prove it enters the next model round when one exists. Emit partial text and
  tool-input fragments before a retryable stream failure and prove no assistant
  or tool side effect survives that attempt. Hard-kill after request dispatch,
  restart, and prove bounded interrupted-attempt recovery. Also kill after a
  public retry fact but before its next provider request; restart must claim
  that stable scheduled attempt exactly once. With one maximum attempt, restart
  must end the activation as `model_attempts_exhausted` and leave queued input
  runnable.
- Preserve field-observed failed-session fixtures when a real installation
  exposes a stuck activation. The immutable, secret-safe version-42 fixture
  must be copied into a test-owned SQLite database and replayed through the
  real Endpoint HTTP/SSE restart path; `e2e_restart_reconciles_failed_attempt_after_prior_activation_exhaustion`
  proves the original event prefix is byte-stable while the terminal recovery
  batch is appended.
- Replica recovery stores sensitive payloads only in the test-owned secret
  directory. Kill before and after secret promotion, restart, and assert one
  ready revision or typed safe failure through public replica/session APIs;
  inspect secret cleanup only after Endpoint stops.

## Live provider recording and replay

- A live-provider recording is captured only by a test-owned HTTP proxy at the
  same network boundary used by Endpoint and aimux. Replay must still start the
  real Endpoint and traverse aimux; it cannot call provider conversion code or
  runtime ports directly.
- Every request sent to a real LLM in a test environment must pass through that
  recorder. Capture every logical round and underlying wire attempt, including
  successful responses, provider errors, retries, partial streams, and client
  disconnects. The live test fails if any exchange cannot be flushed to its
  restricted recording artifact.
- Use the versioned `zode.llm-http-recording.v1` envelope. Retain canonical
  request JSON, response status, an allowlisted content type, raw SSE chunk
  order, and relative chunk timing needed for replay. Never retain upstream or
  downstream authorization, cookies, credential headers, raw API keys, or
  secret-bearing URLs.
- Before a recording enters `tests/fixtures/provider_recordings/`, scan the
  complete artifact, Endpoint output, HTTP/SSE observations, and stopped
  SQLite database for the live credential. A failed scan rejects the artifact;
  redaction after committing a leaked recording is not an acceptable repair.
- Regression replay emits recorded chunks immediately and asserts the complete
  provider request plus durable transcript across restart. Opt-in performance
  replay may preserve recorded relative chunk timing and report elapsed time,
  but it must not impose a machine-specific latency threshold in the canonical
  correctness suite.
- A tracked recording is an immutable, reviewed test input. Re-recording is an
  explicit fixture update with a human-readable request/response diff and the
  same secret scan; live-provider nondeterminism never rewrites it during an
  ordinary test run.
- A long agent replay uses the stopped session's append-only event trace as its
  single causal manifest. User deliveries and tool inputs/results are derived
  from that trace and exercised through public HTTP or the real external
  adapter; produced lifecycle events are compared back to the trace. Do not
  maintain a parallel shell transcript or import recorded events into storage.
  The provider cassette supplements only exact provider HTTP bytes that the
  product intentionally does not persist in events.
- Tool results in that manifest include both successful completions and failed
  external-adapter outcomes. The real replay adapter must reproduce the same
  terminal class, and the new Endpoint must independently project the matching
  durable tool state. The real-process regression anchor is
  `e2e_deepswe_failed_tool_outcome_is_recorded_and_replayed`.
- The canonical DeepSWE correctness replay reports elapsed time without a
  machine-specific limit. Local performance diagnosis may explicitly set
  `ZODE_DEEPSWE_REPLAY_MAX_MS` to turn a measured regression into a typed red;
  the same explicit budget must be used before and after a performance repair.
  `ZODE_DEEPSWE_REPLAY_MAX_LOAD_MS` separately bounds validation and loading of
  the pinned event trace plus provider replay index.
  `ZODE_DEEPSWE_REPLAY_MAX_ORDINARY_BOUNDARY_MS` similarly bounds the aggregate
  ordinary provider/tool transition time while excluding recorded retry
  backoff. `ZODE_DEEPSWE_REPLAY_MAX_FIXTURE_START_MS` isolates duplicate
  cassette validation and fixture startup from both measures.
  `ZODE_DEEPSWE_REPLAY_MAX_RETAINED_REQUEST_BYTES` bounds the replay index's
  retained request-matching representation after cassette validation; response
  bytes are excluded because the fixture must still deliver them.
  `ZODE_DEEPSWE_REPLAY_MAX_DATABASE_BYTES` bounds the stopped Endpoint's SQLite
  file set so a diagnostic snapshot cadence cannot silently duplicate the
  growing long-task state throughout an otherwise-correct replay.
- DeepSWE live and replay runs use the production snapshot policy by default.
  `ZODE_DEEPSWE_SNAPSHOT_EVERY_EVENTS=off|N` is an explicit diagnostic override;
  the generic short-E2E cadence of one snapshot per event must not leak into a
  long benchmark.
- Successful recordings may stay as ignored run artifacts. A recorded problem
  may not remain only in a live log: promote the sanitized cassette under
  `tests/fixtures/provider_recordings/`, bind it to a named real-process E2E,
  replay the original failure red, and use that exact cassette for the green
  regression after repair.
- Ordinary provider recordings keep their existing response-byte and frame
  bounds. DeepSWE's single-session live recorder uses the self-describing
  `long_run` envelope class sized from the approved 128,000-token output
  allowance; `e2e_long_run_llm_recorder_records_and_replays_reasoning_stream_above_ordinary_bound`
  proves a response above both ordinary bounds survives private persistence and
  real Endpoint/aimux replay without weakening the ordinary fail-closed case.
- Terminal recorder-flush failures use
  `e2e_later_test_reproduction_of_terminal_flush_gap_is_bounded_and_captured`:
  arm `ProcessCaptureSet` before Endpoint spawn, bound the public SSE failure
  wait, and durably flush the child observation before assertions or cleanup.
  Its `later_test_reproduction_of_gap` relation is distinct from the retained
  historical full-suite hang; it must never overwrite that first occurrence.

## First-occurrence incident replay

- This gate is prospective. Existing frozen scenarios remain frozen unless new
  evidence changes their assertions; every still-unresolved issue must capture
  its earliest test reproduction after this rule was adopted before repair.
- A real-path failure flushes its first failing exchange to a restrictive
  ignored artifact before the harness retries or cleans up. The tracked
  `zode.http-incident-recording.v1` derivative replaces credentials with named
  synthetic slots while retaining canonical request bytes, response bytes or
  chunks, ordering, disconnects, and relevant relative timing.
- Each incident cassette names one owning `e2e_*` case and the safe first-seen
  failure. That case must replay the cassette through the real Endpoint and the
  same network adapter, fail for the original reason before repair, and pass
  unchanged afterward.
- Do not regenerate an incident cassette during an ordinary test. Do not turn a
  first-occurrence request into a hand-authored fixture, discard an inconvenient
  chunk, or normalize away the condition that caused the failure.

## Red-before-fix workflow

- Name test binaries and cases as E2E (`*_e2e.rs`, `e2e_*`). Support modules
  contain no tests of their own.
- Treat each `e2e_*` case name as a stable executable anchor for an accepted
  design clause. The owning design document must name that case before a
  production worker receives the clause. Renaming, splitting, or deleting an
  anchor requires updating the trace and preserving every covered assertion.
- A design trace is valid only when the scenario makes the chosen contract
  observable and would fail for a rejected implementation. Readiness plus a
  generic success status, an unrelated compiler failure, or a timeout without
  a positive barrier does not count.
- For every behavioral finding, add the smallest public scenario and run it
  against the unfixed implementation. Record the command and failure reason for
  handoff to the implementation owner.
- Do not weaken an assertion, add retries for a product bug, mark a case
  ignored, or replace a public observation with database inspection merely to
  make it green.
- The implementation owner must not rewrite the red scenario to fit its fix.
  The original adversarial reviewer re-runs it and checks adjacent paths.
- During a worker/reviewer loop, new behavioral findings return to the assigned
  E2E owner. Freeze the demonstrated red scenario before production repair;
  implementation workers and reviewers do not edit it for convenience.

## Canonical gates

- `cargo test --test http_sse_e2e`
- `scripts/ci/storage-conformance.sh` (the backend-neutral HTTP/SSE suite with
  an explicit backend label and selectable real Endpoint binary; the SQLite
  profile additionally runs `sqlite_storage_e2e` adapter recovery cases)
- `cargo test --test endpoint_control_e2e`
- `cargo test --test runtime_model_e2e`
- `cargo test --test reviewer_findings_e2e`
- `ZODE_RUN_LIVE_PROVIDER_E2E=1 cargo test --test live_provider_e2e
  e2e_live_opencode_provider_roundtrip_and_restart -- --exact --nocapture` is
  the opt-in real-provider gate when its supported credential exists in the
  caller environment. It supplements, never replaces, deterministic provider
  fixtures and must not print the credential. When enabled, the newly promoted
  immutable recording is reloaded, then replayed three times with immediate
  timing and three times with captured timing; non-secret elapsed samples are written to the ignored
  `replay-benchmark.v1.json` artifact without imposing a machine-specific
  latency threshold.
- `cargo test --test recorded_provider_e2e
  e2e_recorded_opencode_provider_roundtrip_and_restart -- --exact --nocapture`
  is the offline replay gate once the reviewed recording exists. Captured
  timing is opt-in; immediate replay is the default regression mode.
- `cargo test --release --locked --test deepswe_e2e
  e2e_recorded_deepswe_long_run_replays_through_real_endpoint -- --exact
  --nocapture` is the canonical 1,442-event DeepSWE replay gate. The optimized
  profile changes no assertions or replay semantics; it prevents debug-only
  hashing and serialization overhead from dominating the long real-process
  scenario.
- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `rg '#\[cfg\(test\)\]|#\[test\]|#\[tokio::test\]' src --glob '*.rs'` must return no
  production matches.
- `rg 'use zode' tests --glob '*.rs'` must return no matches.

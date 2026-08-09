# Zode browser E2E harness

This directory is the public browser-E2E infrastructure boundary. The smoke
case starts the real `zode` Endpoint and `zode-server` binaries as separate
processes, creates temporary SQLite/secret stores, runs a local fake provider
behind a recording proxy, signs RS256 Access application assertions with a
local JWKS fixture, and sends browser traffic through a local Access-edge
reverse proxy. The browser never calls Endpoint or the provider directly.

Each harness run uses distinct loopback HTTP `management_origin` and
`callback_origin` authorities (`http://127.0.0.1` and `http://127.0.0.2` by
default). The management and callback edges use those canonical Host
authorities while retaining incoming `Forwarded`/`X-Forwarded-Host` unless a
fixture explicitly overrides them. `harness.managementUrl` and
`harness.callbackUrl` remain the actual local edge URLs. The current Server
config schema does not accept those two top-level fields; callers targeting a
Server that has adopted that schema extension pass `includeServerOrigins: true`
to `createWebE2EHarness`. The default keeps the current baseline config
strictly schema-valid and never probes this by spawning a second process.

The harness has no mock router, MSW, imported Zode module, hidden product
route, or retry. Readiness is a positive public `/v1/system` plus Endpoint
identity barrier after process locator readiness; fixture progress is
notification/barrier based and stop/reap is bounded. The browser guard scans
rendered text, accessible attributes, URLs, console/page errors, request
bodies, storage, cookies, and downloads for test secret and identity markers.
`collectBrowserSse` uses a real browser `fetch` stream and the `Last-Event-ID`
header for reconnect scenarios.

## Run the minimum smoke

From `web/e2e`:

```sh
vp install --frozen-lockfile -- --ignore-workspace
vp run test --list
vp run smoke
```

## Run the locked CI gate locally

From the repository root, install the frozen web workspace and the pinned
Chromium once, then use the same entry point as GitHub Actions:

```sh
pnpm --dir web install --frozen-lockfile
pnpm --dir web/e2e exec playwright install chromium
./scripts/ci/verify.sh
```

The gate builds both real Rust binaries, builds the UI with `vp build`, runs the
shared process-capture and Server incident-replay E2Es, and executes the
deterministic shared browser/replay scenarios from
`support/harness_regressions.spec.cjs`. The provider-install failure scenario
and the Management product suites are owned by their respective product jobs;
they are not silently converted to skips or claimed by this shared gate. All
selected fixtures are deterministic and local; the gate never reads real LLM
credentials or enables production recording. A Server startup failure still
fails the command and leaves its bounded process capture under
`target/test-recordings/quarantine` for diagnosis. The CI entry also audits
Playwright's JSON result and fails on any skipped, interrupted, or unrun test;
a readiness error cannot be converted into a green skip.

`@playwright/test` is the only direct Playwright dependency. It is pinned to
the repository-local version in `package.json` and `pnpm-lock.yaml`; the
package scripts call the project-local `playwright` binary and `vp run` supplies
the package bin directory. This keeps the runner and its bundled Chromium at
the same locked version. Set `ZODE_ENDPOINT_BIN` or
`ZODE_SERVER_BIN` to use other already-built real binaries, and set
`ZODE_UI_ASSETS_DIRECTORY` to serve an already-built UI tree. Pointing all
three at one channel-installed immutable release runs the browser scenarios
against that artifact rather than source-tree product outputs. The default
paths are
`target/debug/zode` and `server/target/debug/zode-server`.

The `web` workspace registers `e2e` as this package, so `vp run` resolves the
runner scripts from this directory and never falls back to a parent task. The
install command forwards pnpm's `--ignore-workspace` so this package's own
frozen lockfile is used for its browser dependency installation.

## Collection and visual defaults

The default config uses `testDir: .` and collects `support/smoke.spec.cjs`,
`support/harness_regressions.spec.cjs`, plus `specs/**/*.spec.{cjs,ts}`. Verify
the complete collection before running a classification:

```sh
vp run test --list
vp run smoke
```

The frozen default collection includes both shared harness regression tests;
they are intentionally in the collection and must not be skipped or marked
as shallow route evidence.

The Chromium project is the fixed browser-version entry. Visual E2Es default
to a 1920x1080 viewport, device scale factor 1, dark color scheme, `en-US`,
UTC, and reduced motion. A mobile scenario may explicitly override those
context options in its own test or project.

The shared harness emits an explicit Server configuration mode. Browser
product runs that need the UI use `ui_mode: assets` and a test-owned `vp build`
output named by `ui_assets_directory`; API-only probes use explicit
`ui_mode: api_only` and omit that field. The first-failure and smoke scenarios
opt into the built assets mode; a plain harness defaults to API-only unless an
assets directory/mode is explicitly supplied. The first-failure regression
navigates the real built UI,
retains an explicit harness fixture failure after its successful document
exchange, and replays the exact headers/body/chunks/termination through the
same Server and Access edge. The shared regression injects an explicit harness
fixture failure after the successful UI exchange; its classification is
`HARNESS_FIRST_OCCURRENCE_FIXTURE_FAILURE` with `nonEvidence: true`, never a
product-behavior claim. A shallow 404 is classified as non-evidence and
cannot satisfy that regression. A missing binary or asset build is reported
as a harness failure and does not fabricate an HTTP incident.

Consumers that exercise Server-to-Endpoint authority distribution may pass
`createWebE2EHarness({ authorityId: 'web-e2e-shared-authority' })`. The bounded
test-only value is written to both the Endpoint controller-auth entry and the
Server `server_authority_id`; omitting it preserves the historical defaults
(`web-e2e-controller` and `web-e2e-server`). When supplied, the harness
exposes the selected value as `harness.authorityId` for request payloads;
otherwise that property is undefined because the defaults are intentionally
independent.

Navigation-scoped evidence uses `RecordingJournal.beginCaptureSet` before the
browser action; management HTML/assets, `/v1/system`, and the JWKS fixture are
recorded with that same bounded `captureSetId`. `flushCaptureSet` must complete
before `promoteCaptureSet`, which replays and promotes the complete set
atomically rather than promoting only the HTML response. The set manifest and
each raw member carry the capture-set ID; reload validates member order,
first-failure identity, raw-member digest/schema/bounds, and sealed/late-member
state before promotion. A flushed manifest carries an integrity digest and a
0444 durable anchor, so changing both a raw member and its manifest digest is
also rejected. Cassette request bodies and response chunks use canonical
bounded base64, and synthetic slots are unique safe labels; replay rejects a
digest-valid envelope with malformed bytes or slots before opening the public
endpoint. Completed replay exchanges are counted only after the terminal
response is consumed; recorded disconnects flush their status and partial
chunks before cutting the connection.

Sensitive query parameters are redacted pair-by-pair from the wire request
target. Their original percent escapes, order, and duplicate occurrences are
retained behind distinct safe slots (for example, `query_code_0` and
`query_code_1`), so promotion and public replay restore the exact browser path.

Every capture creates the restrictive quarantine directory before the first
request, fsyncs the request ingress, each response chunk, and the terminal
disconnect/completion marker before forwarding or closing. A flush error is
fatal and prevents the wire request from leaving the recorder. Promotion first
secret-scans and proves red replay, then creates a new immutable `0444`
cassette; existing files are never overwritten.

If the recorder process exits after a capture set is flushed but before
promotion, use the read-only recovery sequence:

```js
const journal = RecordingJournal.openFlushedCaptureRoot({ rootDir, ledger });
journal.reloadCaptureSet(captureSetId);
await journal.promoteFlushedCaptureSet(captureSetId, {
  destinationDirectory,
  replay: (envelope) => journal.replay(envelope, { baseUrl, boundaryBaseUrls }),
});
```

The recovery constructor does not create a child directory, default manifest,
or `promoted/` output under the forensic root. `reloadCaptureSet` rechecks the
sealed anchor, raw-member digests, source/e2e/recording identity, first-failure
member, and secret slots. Promotion requires the complete same-entry replay
result list, binds its source digest/exchange count/response fingerprint, and
uses an existing independent non-symlink directory as a create-new `0444`
destination. Missing or boolean-only proofs, fabricated or mutated replay
results, changed owner metadata, symlink/in-root destinations, and duplicate
targets fail closed while preserving the original raw files.

`proxyHttp` and the JWKS fixture arm a durable ingress record before parsing
the target or applying a method/path guard. Request chunks and the terminal
request digest are fsynced before any upstream forwarding, so body bounds,
client aborts, malformed authorities, and wrong JWKS paths remain recoverable
first occurrences even when the upstream receives no request.

Capture cassettes retain the canonical `host`, `forwarded`, and
`x-forwarded-host` request headers exactly. Replay validates and restores all
three, so a management exchange cannot be replayed on the callback authority
or with spoofed forwarding headers. Authorization, cookie, and Access
assertion headers remain excluded from the safe envelope.

Native HTTP replay uses `RecordingJournal.startReplayServer(cassette)` and
therefore expects the caller to send the recorded authority headers exactly.
Same-entry replay through a live product/edge compares the complete ordered
response bytes and terminal outcome; an HTTP hop may coalesce or split Node
transport reads. The target terminal outcome is observed independently rather
than copied from the cassette; a difference is `REPLAY_TERMINATION_MISMATCH`.
`startReplayServer` remains the exact captured-chunk replay primitive.
Browser replay uses `startReplayEdge(cassette, { canonicalOrigin, timingMode })`;
the local edge restores the canonical `Host` before forwarding to the replay
server and restores recorded `Forwarded`/`X-Forwarded-Host` only when the
browser omits them. Explicit incoming values remain visible to strict replay
validation and produce a typed mismatch when spoofed. Exchange reservations
remain held through request-body read, dispatch, and terminal response, so a
later browser request cannot overtake a held body. The edge is test-only and
runs with recording disabled, so replay cannot append members to a sealed
capture set.

Raw process logs and quarantine captures are test-only artifacts. They are
created with restrictive permissions and are never printed on failure. The
promoted cassette strips authorization/cookie headers and replaces every live
marker with a named synthetic slot. Tracked incident promotion remains an
explicit owner/review action outside an ordinary smoke run.

Startup rejection capture uses `RealProcess.start`'s
`startupCaptureRoot`, `startupConfigBytes`, and `e2eName` options. Before spawn
it durably seals slot-substituted config bytes; readiness/early-exit failure
then records bounded stdout/stderr, exit, termination, and stop/reap/flush
proof in a create-new `zode.process-incident-recording.v1` envelope with the
same `recording_id`, `e2e_name`, `classification`, `first_observed`, config,
`processes` array, and integrity digest as the test process-capture seam.

The config and source files here are deliberately limited to the harness
boundary. Product routes, production code, design documents, and future
browser scenarios belong to their owning agents.

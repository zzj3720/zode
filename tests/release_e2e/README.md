# UI release-pipeline E2E

This directory is an independent black-box harness. It never imports `zode`,
starts no mock router, and does not implement a release manager. The release
driver supplied to it must be the real product release entry that starts the
built Server with its built-in Endpoint.

The executable entry is `run_release_e2e.sh`:

```sh
ZODE_RELEASE_BASELINE_REVISION=<old-commit> \
ZODE_RELEASE_CANDIDATE_REVISION=<candidate-commit> \
ZODE_RELEASE_FAILED_REVISION=<known-health-failing-commit> \
ZODE_RELEASE_DRIVER_RELATIVE_PATH=path/to/the/real-release-entry \
ZODE_RELEASE_UI_URL=http://127.0.0.1:<management-port>/ \
./tests/release_e2e/run_release_e2e.sh --promote-incident
```

The test channel supplies the existing authentication inputs through
`ZODE_RELEASE_ACCESS_ASSERTION` (or `_ACCESS_JWT_ASSERTION`) and
`ZODE_RELEASE_ENDPOINT_CONTROLLER_BEARER` (or `_CONTROLLER_BEARER`). Optional
`ZODE_RELEASE_SERVER_LISTEN` and `ZODE_RELEASE_ENDPOINT_LISTEN` pin the stable
loopback listeners; otherwise the driver allocates isolated loopback ports.
Issuer/JWKS/audience configuration is passed by the corresponding
`ZODE_RELEASE_ACCESS_ISSUER`, `_ACCESS_JWKS_URL`, and `_ACCESS_AUDIENCE`
variable names. Values are never written to manifests, locators, stop reports,
logs, or health JSON.

All three revisions must resolve to immutable commits. The harness archives
each revision into a fresh temporary checkout, builds `web`, `server`, and the
Endpoint there, and writes an immutable `zode.release-artifact.v1` manifest
whose UI/Server/Endpoint component hashes, checkout-selected driver hash, and
`revision` are checked before the immutable driver receives the artifact. A
dirty working tree is not copied into a candidate.

`ZODE_RELEASE_DRIVER_RELATIVE_PATH` selects the real driver from each fresh
immutable checkout. The harness packages the selected executable as
`release-driver`, binds its SHA-256 in the manifest, and invokes that immutable
copy without a shell using this protocol:

```text
<driver> bootstrap --release-root <dir> --artifact <dir> --json
<driver> stage    --release-root <dir> --artifact <dir> --json
<driver> promote  --release-root <dir> --json
<driver> health   --release-root <dir> --json
<driver> rollback --release-root <dir> --json
<driver> teardown --release-root <dir> --json
```

`bootstrap` must install the baseline without a promotion. `stage`
must run the real install/readiness gate and leave `current` untouched until
the driver `promote` action. A failed readiness gate must exit non-zero and
leave `current` and `previous` byte-for-byte unchanged. The driver owns
starting the real Server and built-in Endpoint; it must not use a mock HTTP
handler. The release root is test-owned and must expose `current` and
`previous`, each resolving to a directory containing the checked manifest.
The active `current` process keeps the all-in-one Endpoint runtime store,
Server control store, catalog identity, controller authority, subject key, and
secret directory in one run-owned persistent state directory; each promoted or
rolled-back revision points at those same stores rather than resetting them.
An independently staged `candidate` receives isolated stores and authority so
its SQLite ownership cannot conflict with `current`; promotion adopts the
candidate artifact onto the persistent current stores.

`teardown` must stop and reap every Server/Endpoint child started for the run;
the harness invokes it on success and failure. The harness independently checks
live PIDs, executable digests, HTTP readiness, and post-teardown process reaping;
a non-zero teardown status or leaked process makes an otherwise successful run
exit non-zero too.

`health` must query the live installed Server and built-in Endpoint, not read
the release pointers or a cached manifest. Its successful JSON result contains
`health: { status: "ok", source: "live_process", checks: { ui: "ok",
server: "ok", endpoint: "ok" }, ui_mode: "assets",
ui_assets_directory: "ui", revision, components }`; the installed Server
configuration must resolve that `ui_assets_directory` relative to its config
file and must not use `api_only`. Each component revision and digest must
match the expected immutable artifact. It must also include
`health.probes.server_url` and `health.probes.endpoint_url` on local HTTP
readiness listeners. The harness performs fresh HTTP probes, captures and
parses the real `zode.system.v1` and `zode.endpoint-health.v1` response bodies,
and binds the Server UI listener and `/v1/system` port to the independently
observed live Server PID (and `/v1/health` to the Endpoint PID); it does not
treat the driver's JSON health claim as readiness evidence. The
known health-failing fixture must return non-zero with the same shape but a
non-`ok` status/check, and must identify the failed artifact.
The failed-stage Server/Endpoint PIDs, immutable executables, listener ports,
and HTTP bodies are independently observed before the baseline health check;
all PIDs observed in either successful or failed staging are rechecked after
teardown.
Process identity is consumed from `health.processes.locator_paths`, whose files
must use the exact `zode.e2e.process-locator.v1` contract. Production processes
do not write these files: the driver creates test-owned locators only after
binding the Server PID/parent process group and its one known Endpoint child
by exact installed executable/argv/config/listen, listener ownership, and
authenticated identity/capabilities. The harness never binds a release
instance by scanning unrelated same-name processes. Teardown must return one
or more exact `zode.e2e.process-stop.v1` reports; each `observed_pids` entry
includes the PID, role, process-group/session identity, executable path, and
SHA-256 digest, while `reaped_pids`/`leaked_pids` contain only those observed
PIDs. Every observed instance and PID must be accounted for.

The browser portion only starts after a real management page returns a
successful document response. It verifies the product's existing management
shell and normal Access-protected UI → Server → built-in Endpoint path;
promotion and rollback are operator driver actions, not browser controls.
The browser must receive successful `zode.system.v1`, `zode.endpoints.v1`, and
`zode.providers.v1` responses through the same origin, and the endpoint catalog
must contain the `local_endpoint_id` from `zode.system.v1`; these are existing
management routes, not release metadata APIs.
The product is not required to expose release pointers, component digests, or
test-only DOM markers. The harness independently reads the selected manifest
and `current`/`previous` pointers, hashes the served UI tree, and binds the
observed Server/Endpoint PIDs to their executable digests.
The test first stages the health-failing build and proves that `current` does
not change, then stages the candidate and proves it still does not change.
The operator driver then promotes it. During promotion the harness watches the
real release-root filesystem and requires a positive event showing the
canonical before and after pointer states; a torn or unparsable
`current`/`previous` fails the scenario. Only `rename`/`change` events whose
filename is exactly `pointer-state` (the atomic transaction link) count; a
legacy direct-pointer event is accepted only when its post-event pair is also
canonical. Both pointer names must be observed after the action.
It then invokes operator rollback, reloads the browser entry, and proves that the
baseline is current again, the candidate is previous, and browser runtime
document still loads through the normal path after reload. Packaged UI, Server, and
Endpoint payloads are immutable, hashed before staging, and re-hashed after
teardown so a driver cannot mutate the staged payload in place.

The named acceptance cases are
`e2e_release_artifact_binds_server_endpoint_and_ui_tree` (manifest and
immutable component binding) and
`e2e_release_promotion_never_mixes_server_and_ui_revision` (real health,
browser promotion, torn-pointer observation, rollback, and reload).

Exit codes:

- `0`: the real release/browser path passed;
- `1`: a semantic E2E failure was observed;
- `78`: blocked before a valid public path existed (missing build surface,
  release driver, or a shallow HTTP/compile failure). This is not a behavioral
  red and is never promoted to a cassette.

For a semantic failure, the harness writes the first post-rule exchange to a
`0700` directory under `target/test-recordings/quarantine/<run-id>` (or the
explicit `ZODE_RELEASE_QUARANTINE` test override). `--promote-incident` creates
one new `zode.http-incident-recording.v1` cassette under this suite's
`fixtures/incidents/` (or the explicit `ZODE_RELEASE_CASSETTES` test override)
with exclusive creation,
allowlisted headers, synthetic slots, an exact binding to the first captured
failing browser exchange, a whole-envelope SHA-256, and mode `0444`. Secret
scanning is fail-closed, including configured secret values, headers, all
recorded fields, and decoded bodies. It never overwrites an existing cassette.
`--replay <cassette>` (with `ZODE_RELEASE_REPLAY_EXPECTATION=red` before a
repair or `green` after it) validates its unique exact `exchange_sequence`, passes
that same immutable cassette through a test-owned replay adapter (never to the
production driver), and repeats the same browser entry. Before the production
repair the replay must reproduce the exact sequence and exchange fingerprints,
including the original request query, `requestfailed`, and disconnect markers;
after the repair the same cassette and named E2E must pass. Cassette body values
must be canonical
RFC 4648 base64 before secret scanning. The raw quarantine and cassettes are
never production inputs.

If a failure occurs before the browser entry (for example, a staged payload
mutation), a real-driver semantic failure is RED and the exact raw
release-driver exchange is still retained, but no browser cassette is promoted
for it; replay is reserved for a captured browser-bound failure. A missing
driver or missing public seam remains BLOCKED.

The harness does not make an LLM request. If the real release path adds one,
the release driver must route it through the test-owned recorder mandated by
`docs/test-recording.md`; a direct provider URL is outside this E2E's scope.

Immutable-source premise: the harness obtains every candidate source with
`git archive` of its canonical commit; it never copies a dirty candidate
worktree or fills an archive from uncommitted files. Every revision must carry
the complete tracked build surface, including the release driver path. A
revision missing that surface remains `78` BLOCKED even if the dirty worktree
happens to contain the files; the harness must not copy them or create a
fabricated 404/compile cassette.

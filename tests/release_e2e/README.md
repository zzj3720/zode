# UI release-pipeline E2E

This directory is an independent black-box harness because the repository has
no release-test manifest yet. It never imports `zode`, starts no mock router,
and does not implement a release manager. The release driver supplied to it
must be the real product release entry that starts the built Server and its
built-in Endpoint.

The executable entry is `run_release_e2e.sh`:

```sh
ZODE_RELEASE_BASELINE_REVISION=<old-commit> \
ZODE_RELEASE_CANDIDATE_REVISION=<candidate-commit> \
ZODE_RELEASE_FAILED_REVISION=<known-health-failing-commit> \
ZODE_RELEASE_DRIVER_RELATIVE_PATH=path/to/the/real-release-entry \
ZODE_RELEASE_UI_URL=http://127.0.0.1:<management-port>/ \
./tests/release_e2e/run_release_e2e.sh --promote-incident
```

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
<driver> health   --release-root <dir> --json
<driver> rollback --release-root <dir> --json
<driver> teardown --release-root <dir> --json
```

`bootstrap` must install the baseline without a browser promotion. `stage`
must run the real install/readiness gate and leave `current` untouched until
the browser promotion action. A failed readiness gate must exit non-zero and
leave `current` byte-for-byte unchanged. The driver owns starting the real
Server and built-in Endpoint; it must not use a mock HTTP handler. The release
root is test-owned and must expose `current` and `previous`, each resolving to
a directory containing the checked manifest.

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
Process discovery uses the kernel-reported executable name, resolved executable
path, and observed PIDs; it does not require `releaseRoot` to appear in argv.

The browser portion only starts after a real management page returns a
successful document response. It verifies the product shell (`Sessions`,
`Endpoints`, and `Providers`) before treating absent release controls as a
behavioral failure. The release UI must expose these black-box DOM semantics:

- `[data-zode-release-current-revision]`
- `[data-zode-release-previous-revision]`
- `[data-zode-release-staged-revision]`
- `[data-zode-release-runtime-revision]`
- `[data-zode-release-ui-revision]`
- `[data-zode-release-server-revision]`
- `[data-zode-release-endpoint-revision]`
- `[data-zode-release-ui-tree-sha256]`
- `[data-zode-release-server-binary-sha256]`
- `[data-zode-release-endpoint-binary-sha256]`
- an accessible `Promote staged release` button;
- an accessible `Rollback current release` button.

The test first stages the health-failing build and proves that `current` does
not change, then stages the candidate and proves it still does not change.
Only a real browser click may promote it. During promotion the harness watches
the real release-root filesystem and requires a positive event showing the
canonical before and after pointer states; a torn or unparsable
`current`/`previous` fails the scenario. Only `rename`/`change` events whose
filename is exactly `current` or `previous` count, and both pointer names
must be observed after the action.
It then clicks rollback, reloads the browser entry, and proves that the
baseline is current again, the candidate is previous, and browser runtime
markers still agree with live health after reload. Packaged UI, Server, and
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
`0700` quarantine directory under this directory. `--promote-incident` creates
one new `zode.http-incident-recording.v1` cassette with exclusive creation,
allowlisted headers, synthetic slots, an exact binding to the first captured
failing browser exchange, a whole-envelope SHA-256, and mode `0444`. Secret
scanning is fail-closed, including configured secret values, headers, all
recorded fields, and decoded bodies. It never overwrites an existing cassette.
`--replay <cassette>` validates its unique exact `exchange_sequence`, passes
that same immutable cassette to the real driver, and repeats the same browser
entry; replay must reproduce that exact sequence and exchange fingerprints,
including the original request query, `requestfailed`, and disconnect markers,
and remain red for the recorded safe reason. Cassette body values must be canonical
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

Immutable-source premise: the current frozen `HEAD` has only 39 tracked
files. The harness obtains every candidate source with `git archive` of its
canonical commit; it never copies a dirty candidate worktree or fills an
archive from uncommitted files. The candidate worktree currently contains
many uncommitted files, but the current `HEAD` archive lacks the real driver,
build manifests, UI entry, and current/previous release store
(`web/package.json`, `server/Cargo.toml`, and related tracked inputs). The
command must remain `78` BLOCKED on that missing immutable source surface,
even if the dirty worktree happens to contain those files; it must not copy
them and must not create a fabricated 404/compile cassette.

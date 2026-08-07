# Zode browser E2E harness

This directory is the public browser-E2E infrastructure boundary. The smoke
case starts the real `zode` Endpoint and `zode-server` binaries as separate
processes, creates temporary SQLite/secret stores, runs a local fake provider
behind a recording proxy, signs RS256 Access application assertions with a
local JWKS fixture, and sends browser traffic through a local Access-edge
reverse proxy. The browser never calls Endpoint or the provider directly.

The harness has no mock router, MSW, imported Zode module, hidden product
route, or retry. Readiness is a process stdout barrier and fixture progress is
notification/barrier based; timers are only bounded failure guards. The
browser guard scans rendered text, accessible attributes, URLs, console/page
errors, request bodies, storage, cookies, and downloads for test secret and
identity markers. `collectBrowserSse` uses a real browser `fetch` stream and
the `Last-Event-ID` header for reconnect scenarios.

## Run the minimum smoke

From `web/e2e`:

```sh
vp install --frozen-lockfile -- --ignore-workspace
vp run test --list
vp run smoke
```

`@playwright/test` is the only direct Playwright dependency. It is pinned to
the repository-local version in `package.json` and `pnpm-lock.yaml`; the
package scripts call the project-local `playwright` binary and `vp run` supplies
the package bin directory. This keeps the runner and its bundled Chromium at
the same locked version. Set `ZODE_ENDPOINT_BIN` or
`ZODE_SERVER_BIN` to use other already-built real binaries. The default paths
are
`target/debug/zode` and `server/target/debug/zode-server`.

The `web` workspace registers `e2e` as this package, so `vp run` resolves the
runner scripts from this directory and never falls back to a parent task. The
install command forwards pnpm's `--ignore-workspace` so this package's own
frozen lockfile is used for its browser dependency installation.

## Collection and visual defaults

The default config uses `testDir: .` and collects
`support/smoke.spec.cjs` plus `specs/**/*.spec.{cjs,ts}`. Verify the complete
collection before running a classification:

```sh
vp run test --list
vp run smoke
```

The frozen default collection is 26 tests in 10 files: the support smoke plus
the named `specs/**/*.spec.{cjs,ts}` files.

The Chromium project is the fixed browser-version entry. Visual E2Es default
to a 1920x1080 viewport, device scale factor 1, dark color scheme, `en-US`,
UTC, and reduced motion. A mobile scenario may explicitly override those
context options in its own test or project.

The current Server binary binds an empty router. Therefore the first real
browser request to `/v1/system` is expected to produce the classified
`PRODUCT_ROUTE_MISSING_SHALLOW_404` failure. The harness retains that exact
first exchange in a restrictive
`target/test-recordings/quarantine/<run-id>/` directory, promotes a
secret-safe immutable cassette beside it, replays it through the same real
Server and Access edge, and reports the replay status. This is explicitly
non-evidence for final UI behavior; a 404 is never converted into a passing
product assertion. A missing binary is reported separately as a harness
failure and does not fabricate an HTTP incident.

Raw process logs and quarantine captures are test-only artifacts. They are
created with restrictive permissions and are never printed on failure. The
promoted cassette strips authorization/cookie headers and replaces every live
marker with a named synthetic slot. Tracked incident promotion remains an
explicit owner/review action outside an ordinary smoke run.

The config and source files here are deliberately limited to the harness
boundary. Product routes, production code, design documents, and future
browser scenarios belong to their owning agents.

# Web UI rules

The root `AGENTS.md`, `docs/ui.md`, and `docs/server-api.md` are authoritative.
`web/` owns the browser application served by management Server.

## Boundary

- Call only management Server HTTP/SSE. Never call Endpoint/provider URLs,
  discover devices, attach provider authorization, or import Endpoint runtime
  code.
- Keep the Endpoint-owned `(endpoint_id, session_id)` pair together in every
  session URL and query key. Resume with Endpoint event cursors proxied by
  Server; no Server-global session or session-event identity exists.
- Use `/endpoints/{endpoint_id}/sessions/{session_id}` as the canonical browser
  route. Never implement an ID-only search/fallback across Endpoints.
- Browser storage and client caches contain non-secret query state only. API
  keys, OAuth values, Endpoint control credentials, callback bearers, and
  secret-bearing command bodies are never persisted or logged.
- Keep OAuth authorize tickets in memory and start redemption only from an
  explicit action with `location.replace`. Do not render a prefetchable link or
  expose the ticket to analytics, history state, logs, or caches.
- Cloudflare Access runs before the app. Do not implement a Zode login/logout,
  token input, account/user/role/grant UI, application login cookie, local-
  storage auth, or development auth bypass. On Access re-entry, use full-page
  navigation through the management origin rather than collecting credentials.
- Generated API types may come from the versioned Server schema; do not edit
  generated files by hand or duplicate wire types ad hoc.
- Do not add release staging, promotion, rollback, install, or process-control
  UI. V0 release actuation belongs to the operator driver/CLI; browser E2Es
  observe the real product only after those actions.
- HTTP command acceptance is distinct from runtime completion. Durable UI state
  follows Server responses/events; transient token text remains provisional.

## Product behavior

- Treat built-in local and remote Endpoints with the same components and state
  model. Do not hardcode that local Endpoint exists.
- Provider configuration is centralized. One provider may have many profiles
  and each profile exposes explicit per-Endpoint distribution progress.
- Profiles and Endpoint management are shared by every actor admitted through
  the configured Access application. Present profiles as deployment resources,
  not personal accounts; session lists remain isolated by the actor-derived
  Endpoint subject.
- Already rendered state may stay visible while disconnected, but Server has no
  durable session mirror. Label it non-authoritative and never render loss of
  Endpoint contact as a fabricated agent failure.
- Expose destructive or reconciliation actions only when the Server contract
  says they are valid. Unknown tool outcome is not ordinary failure.
- Use stable idempotency keys per user mutation and reuse them after an unknown
  response. Multiple tabs must not duplicate the same action.
- Initialize same-session execution recovery from the Endpoint-owned current
  provider/model/profile when they remain available. Provider list order may
  not silently change that selection, and a no-op submission must preserve the
  current execution across refresh and legal process restart. The real-browser
  anchor is
  `e2e_browser_bad_session_retains_history_and_offers_same_session_execution_recovery`.
- Render stable safe error codes. Never display raw downstream bodies, SQL,
  paths, stderr, authorization headers, or debug chains.
- Meet keyboard, focus, screen-reader, contrast, status-without-color, and
  responsive requirements in `docs/ui.md`.

## Approved visual baseline

- The current Codex Desktop application captured and approved by the user on
  2026-08-07 is the v0 visual reference only. `docs/ui.md` owns the measured
  desktop geometry, palette, typography, semantic mapping, deviations, and
  named browser E2Es.
- Reproduce observable styling with zode-owned components and CSS. Do not copy
  application source, tests, branded text, logos, proprietary assets, or
  unsupported controls, and do not import anything from `codex-reference/`.
- The private source capture stays outside the repository. Commit only a
  zode-rendered golden after a real Server/Endpoint browser path is independently
  compared with the source and accepted.
- Source calibration is an explicit local-only mode with its path supplied from
  outside tracked files. It writes only to ignored restricted quarantine and
  may not persist the source path or digest. Default/CI visual E2Es require only
  the accepted zode-rendered golden.
- A 404, blank page, fake data page, component render, or mock router is not a
  visual red. The first valid visual mismatch is retained only after the real
  management Server successfully serves the browser application.

## Tooling and structure

- Use Vite Plus as the sole Web task entry through `vp`: `vp build`, `vp
  check`, `vp lint`, and `vp fmt` where applicable. Do not add a direct `vite
  build`, esbuild CLI, or package-script recursion as a parallel build path.
  Keep any required Vite peer compatible with the pinned Vite Plus toolchain
  and regenerate the frozen lockfile after changing it.
- A clean non-interactive `vp install --frozen-lockfile` must succeed without a
  broad allow-all build-script policy. A transitive install script is allowed
  only when the pinned Vite Plus graph demonstrably requires that exact
  package; it does not become Zode's build implementation.
- Keep one Server API client, one SSE reconnection/cursor path, and one query
  cache authority. Do not add parallel fetch wrappers or local runtime reducers.
- Do not add a WebSocket merely for token streaming while HTTP plus SSE meets
  the contract.
- Production builds are served by Server; development may use a proxy to a real
  local Server, never a mock-only product mode.
- Serve UI and provider OAuth navigation only on the Access-protected management
  origin. The public external-tool callback origin never serves app assets or
  browser routes.

## E2E-only acceptance

UI tests live under `web/e2e/` and drive a real browser against real Server and
Endpoint processes. Unit, component, hook, reducer, DOM snapshot, mock-router,
mock-service-worker, and visual tests against fake product state are forbidden.

Every real user path needs a positive browser E2E. Every discovered UI behavior
bug first receives a red browser E2E through the real Server boundary before a
fix. Use semantic barriers and explicit timeouts, not sleeps as proof. Capture
screenshots/traces on failure without secrets.

Required paths are the all-in-one first run, remote Endpoint addition, provider
profile login/sharing/rotation/removal, Access entry/re-entry with no Zode
login screen, two-actor session isolation, Endpoint-generated session create/
chat/reconnect, async tool/wait/unknown-outcome states, Endpoint disconnect,
accessibility, and secret non-disclosure listed in `docs/ui.md`.

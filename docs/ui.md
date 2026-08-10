# zode web UI product contract

Status: authoritative handoff for UI implementation. The UI consumes only the
management Server contract in `docs/server-api.md`. Visual design may evolve,
but it must preserve these information and action boundaries.
`docs/access.md` owns the Cloudflare Access boundary.

## 1. Purpose

The UI lets a user:

- configure or log in to a provider once;
- see which Endpoints may use each auth profile;
- use the built-in local Endpoint without setup;
- add and inspect remote Endpoints;
- create a session on a selected Endpoint;
- converse with the agent and observe durable runtime progress;
- inspect, cancel, or reconcile tool work when the public contract allows it;
- understand offline, stale-credential, waiting, retrying, and recovery states
  without reading logs or internal identifiers.

The first UI is a management application, not an Endpoint dashboard pasted on
top of raw routes. Every session link carries the Endpoint-owned pair
`(endpoint_id, session_id)`. Each browser application graph opens at most one
SSE connection per Endpoint and keeps one Endpoint event cursor proxied by
Server; sessions consume frames dispatched by `session_id` and never own a
connection or cursor.

The canonical browser route is
`/endpoints/{endpoint_id}/sessions/{session_id}`. There is no ID-only session
route or client-side fallback lookup across devices.

## 2. Approved v0 visual baseline

The user explicitly approved the current Codex Desktop application on
2026-08-07 as zode's first-release, pixel-level visual reference. This approval
is visual only. It does not import Codex product semantics, runtime behavior,
source code, assets, tests, session model, or storage decisions.

The reference evidence is a private 1920 by 1080 full-screen capture of the
user's current macOS application. It remains outside the repository because it
contains local project and conversation data. Do not copy that capture, the
Codex or OpenAI names, logos, product copy, proprietary icons, or other branded
assets into tracked fixtures or production. Zode's first accepted render
becomes the tracked zode-owned visual baseline after independent comparison
with that private source.

At the 1920 by 1080 desktop reference viewport, the required shell is:

- a fixed 274 px left navigation pane separated from the main surface by a
  single-pixel boundary;
- navigation background `#27363b`, selected-row background `#38464b`, main
  background `#181818`, secondary surface `#242424`, and composer surface
  `#2a2a2a`;
- primary text near `#f5f6f6`, secondary text near `#dfe1e1`, subdued text with
  at least AA contrast, and amber `#f39c12` only for the same narrow status or
  attention role visible in the reference;
- a 56 px main header and a 736 px maximum-width thread column centered in the
  space to the right of the navigation pane;
- a 736 px composer aligned to that column, 16 px from the viewport bottom,
  with a 24 px outer radius and content-driven height;
- compact 32 px navigation rows, 8 px row radii, 16 px monochrome icons, quiet
  one-pixel separators, and no decorative gradients, glass, large shadows, or
  marketing surfaces;
- native system sans typography (`-apple-system`, `BlinkMacSystemFont`, then
  `Segoe UI`), with 15 px body text and 24 px line height at the reference
  viewport;
- the same restrained hierarchy for selected, hover, pressed, focus, loading,
  streaming, waiting, tool, error, and disconnected states. Keyboard focus is
  still explicit and accessibility requirements may strengthen the source.

The visual mapping is semantic rather than branded: Codex project groups map
to Endpoint groups, threads map to Endpoint-owned sessions, the main chat maps
to the selected session, and the bottom status area maps to safe Server and
Endpoint state. Primary destinations remain Sessions, Endpoints, Providers,
and Settings. Do not render copied controls for worktrees, plugins,
automations, accounts, or other features that zode does not implement.

At narrower widths, preserve the reference's density and component styling but
use zode's responsive navigation and activity-state rules. Mobile is an
intentional responsive adaptation, not a claim that a desktop source has a
mobile reference. A future visual redesign is a deliberate design change; the
first usable release does not mix another visual language into this baseline.

The visual contract is executable through these named browser E2Es:

- `e2e_access_entry_serves_static_ui_without_zode_login_screen` freezes real
  Server delivery on the Access-protected management origin;
- `e2e_browser_codex_desktop_shell_matches_approved_1920x1080_reference`
  freezes desktop geometry, palette, typography, navigation, transcript, and
  composer through a real Server and Endpoint;
- `e2e_browser_codex_desktop_session_states_match_approved_reference` freezes
  the visible streaming, waiting, tool, error, reconnect, and focus states on
  the same shell.

The pixel E2E pins browser version, device scale, fonts, viewport, and product
state. It may mask only dynamic user text, IDs, timestamps, token content, and
carets; it may not mask layout, surfaces, icons, status labels, controls, or
focus state. Measured geometry and palette have a one-CSS-pixel/one-channel
maximum deviation, and the masked full-page screenshot has a maximum changed-
pixel ratio of 0.2%. The source capture itself is never the committed golden.
A missing route or empty Router is classified as blocked shallow evidence; the
first retained visual red is the first real rendered mismatch after static UI
delivery works.

The private source may be read only in an explicit local calibration run whose
path is supplied outside tracked files. That run writes comparison artifacts to
the ignored 0600 quarantine and never records the source path, bytes, or digest
in a tracked fixture. After independent acceptance, promote only the zode-
rendered screenshot as the immutable regression golden. Default and CI browser
runs compare against that zode golden and must work without access to the
private source.

## 3. Navigation

The v0 information architecture has four primary destinations:

1. **Sessions**: Endpoint-grouped live session lists, create action,
   active/offline/waiting status, Endpoint and model summary.
2. **Endpoints**: built-in local device and remote devices, reachability,
   capabilities, assigned sessions, and installed auth-replica health.
3. **Providers**: provider types, multiple auth profiles, default selection,
   provider OAuth/API-key actions, sharing targets, refresh/expiry, and
   revocation.
4. **Settings**: Server deployment information and safe operational settings.

Provider auth is not hidden under each Endpoint. The primary workflow starts
from Providers, then selects the Endpoints allowed to receive that profile.
Profiles are deployment-shared resources in v0: every actor admitted by the
Cloudflare Access application may use and manage them. The UI communicates this
shared trust boundary and does not imply that a profile is personal.

Settings shows only the safe deployment and fixed ingress mode from
`/v1/system`; it never displays issuer, AUD, JWKS, Access claims, callback host,
or credentials. Zode has no user, workspace, role, grant, invite, account, or
membership settings.

Cloudflare Access runs before the application. Zode renders no login screen,
token input, account switcher, password recovery, or logout action and does not
set or inspect a login cookie. If an API/SSE request indicates that Access must
be re-entered, the UI stops mutation retries, preserves only non-secret local
view state, and performs a full-page navigation through the management origin;
it never tries to collect or refresh credentials itself.

## 4. Session workspace

The session page contains:

- transcript and composer;
- Endpoint/model/profile identity in a compact header;
- live connection state and Endpoint reachability;
- current activation state and safe model retry information;
- active wait reason/deadline;
- tool calls in provider order with `planned`, `running`,
  `unknown_outcome`, `completed`, `failed`, or `cancelled` status;
- explicit cancel/retry-dispatch actions only when Server says they are
  allowed;
- reconnectable durable event history.

The composer submits once with a generated idempotency key and disables only
while admission is unknown. A lost response is retried with the same key. The
UI must not infer that `202 Accepted` means the assistant has finished.
Same-session durable or transient rendering preserves an unsent composer draft
in browser memory; accepting the submission or opening another session clears
it. The draft is never persisted as session state or sent before submission.

Before session create, the UI resolves the visible provider default to one
explicit auth profile, full immutable non-secret provider-execution descriptor,
and minimum installed auth revision. It freezes that request body with the
idempotency key for all retries; a changed default or descriptor never mutates
an in-flight create. If Server rejects that frozen create because a provider
descriptor advanced, the logic refreshes the authoritative provider catalog,
keeps the draft and form open on the latest valid selection, and requires a
new explicit submission. That rejected command is not presented as an unknown
admission and is never retried with silently changed bytes.

An existing session's execution recovery form starts from that session's
current provider, model, and auth profile whenever each remains available. A
different provider elsewhere in the catalog cannot become the implicit
selection merely because it sorts first. Refreshing the page or legally
restarting Server and Endpoint preserves the same visible selection, and
submitting it without an explicit change preserves the Endpoint-owned current
execution, session identity, and transcript. If the current profile is no
longer usable, the form keeps the current provider and model while offering a
current shared profile for an explicit same-session recovery. This contract is
frozen by
`e2e_browser_bad_session_retains_history_and_offers_same_session_execution_recovery`.

When Endpoint becomes unreachable, the UI:

- may keep already rendered transcript data visible in the current browser
  view, clearly labeled disconnected and non-authoritative;
- does not claim Server has a durable offline copy;
- does not append a fake failure or assistant message;
- disables session commands because Server does not queue them;
- offers retry/reconnect only through the same Endpoint-scoped Server routes.

Transient token deltas are provisional. On reconnect, the UI replaces any
provisional candidate with the durable final assistant message rather than
duplicating it.

## 5. Endpoint experience

The built-in Endpoint appears first and is labeled as this machine. It uses the
same status and detail components as a remote Endpoint.

The Endpoint list shows:

- user label and local/remote kind;
- online, degraded, unreachable, or disabled state;
- last observation time;
- supported provider/tool capabilities;
- current Access actor's live session count when the Endpoint can answer,
  otherwise unavailable;
- auth-replica ready/pending/stale counts.

Adding a remote Endpoint asks for label, reachable URL, and control credential.
Secret input is write-only. After submission, the UI displays probe progress
and the safe result. It never reads the secret back.

Endpoint detail links to sessions and shows which profiles are installed, but
profile management remains in Providers. An unreachable Endpoint is not
presented as deleted and its sessions are not offered automatic migration.

## 6. Provider and auth-profile experience

One provider type can contain many OAuth or API-key profiles. Cards/rows show:

- the centrally configured execution endpoint/model catalog and descriptor
  revision;
- label and safe account hint;
- kind, readiness, expiry, and explicit default;
- profile revision;
- sharing scope and per-Endpoint distribution summary;
- actions to set default, edit sharing, refresh/relogin, or delete.

Adding an API key uses a write-only secret field. OAuth opens the protected
Server redirect and follows attempt events for redirect, device code, prompt,
progress, success, failure, or cancellation.

An OAuth redirect ticket stays in memory only. An explicit button navigates
with `location.replace`; it is not rendered as a prefetchable anchor, copied to
analytics, cached, or stored in history state/browser storage. A consumed or
expired ticket causes the UI to mint a new one rather than replay it.

Refresh shows its durable operation state. `refresh_unknown` is not displayed
as an ordinary retryable error: the UI offers relogin for the same logical
profile and explains that the provider may have consumed the old refresh token.
It never offers blind refresh retry when the adapter lacks idempotent or exact
reconcile capability. Once the profile is refresh-fenced, the refresh action is
absent; only same-profile relogin is offered, and a failed/cancelled relogin does
not clear the warning.

Changing sharing is an operation, not an instantaneous checkbox illusion. The
UI shows pending installation/removal per Endpoint until durable
acknowledgement. Unreachable devices remain visibly unresolved.

Deletion warns that removing a copied static API key from an Endpoint is
best-effort and that complete revocation may require provider-side key
rotation. It never claims a remote secret was erased merely because Server
queued a tombstone.

## 7. Error and status language

UI renders stable Server error codes into concise user language while
preserving a retryable/non-retryable distinction. It does not display raw
provider bodies, SQL, paths, internal error chains, tool stderr, authorization
headers, or Endpoint control details.

At minimum, distinct experiences exist for:

- Access session requires re-entry;
- Server offline;
- Endpoint unreachable;
- Endpoint capability mismatch;
- auth replica pending/stale/unavailable;
- provider unavailable or authentication rejected;
- idempotency conflict;
- model attempts exhausted;
- tool unknown outcome requiring safe reconciliation;
- session waiting or timed out;
- neutral internal error.

## 8. Client state rules

- Server HTTP responses and SSE are authoritative; browser local storage is
  never a second session or credential database.
- Cache only non-secret query data. Do not persist API keys, OAuth values,
  Endpoint control credentials, callback bearers, or secret-bearing request
  bodies.
- Keep `endpoint_id` and Endpoint-generated `session_id` together in links,
  query keys, and open tabs. Never look up a session by `session_id` alone.
- Resume each Endpoint stream with its Endpoint event ID. Opening, closing, or
  switching sessions does not replace that connection or reset its cursor.
  Server has no durable Endpoint/session cursor; Server-owned OAuth attempt
  streams may have their own attempt-local cursor.
- Reconnect SSE with `Last-Event-ID`, deduplicate durable frames, and reconcile
  lists through Server queries after lag/error.
- Optimistic UI may show command submission, but durable state changes only
  after Server acknowledgement/event.
- Multiple tabs must not duplicate a mutation; each user action owns one
  stable idempotency key.

## 9. Accessibility and responsive behavior

- All actions are keyboard reachable and have visible focus.
- Status is expressed with text/icons in addition to color.
- Live updates use appropriate, non-disruptive announcements; token streaming
  must not continuously overwhelm screen readers.
- Dialogs trap/restore focus and destructive actions explain their exact
  scope.
- The session workspace remains usable on a narrow screen; secondary runtime
  detail can collapse without hiding current wait/tool/error state.
- Loading, empty, offline, Access-denied, and partial-data states are
  designed explicitly rather than represented by blank panels.

## 10. Implementation boundary

The UI lives under `web/` and is served by Server in production. It may use a
development proxy to a real local Server. It must not:

- serve or navigate application screens from the public external-tool callback
  origin;
- import Rust runtime/domain implementation details;
- call Endpoint URLs directly;
- implement provider OAuth or credential distribution in the browser;
- expose release staging, promotion, rollback, or process-supervisor controls;
- add mock-only product branches or hidden Server routes;
- hardcode that a built-in Endpoint always exists;
- introduce a second WebSocket protocol when HTTP plus SSE is sufficient.

Provider OAuth redirects return to the Access-protected management origin. The
separate public callback origin is an external-tool protocol surface and never
part of browser navigation.

Generated API types are allowed from the versioned Server schema. Generated
code is not edited by hand.

Vite Plus is the sole Web build/check entry; Zode does not maintain a direct
`vite build` or esbuild CLI path beside it. `vp build` produces the immutable
Web `dist` tree. Release packaging installs
that tree as `ui/` beside the exact Server and Endpoint binaries, configures
Server with `ui_mode: assets` plus that `ui_assets_directory`, and binds all
components in one revision manifest. Server loads only this configured,
validated release tree before readiness; the browser never observes a mix of
UI and Server revisions. Source files, a Vite dev server, and a mutable working
tree are not production asset fallbacks. An explicit API-only development/test
Server uses `ui_mode: api_only` and must omit the directory; it is not a usable
UI release.

The operator release driver/CLI, normally called by continuous test-release
automation, owns `stage`, `promote`, and `rollback`. The browser does not expose
or invoke those actions. Release E2Es open the real Access-protected application
after each operator action and exercise the ordinary UI -> Server -> built-in
Endpoint path. The release harness separately binds the served UI tree and
observed process executables to the selected manifest; Web does not expose
component digests or hidden release markers solely for the test.

## 11. E2E-only acceptance

UI verification uses a real browser against a real Server and real Endpoint
processes. Unit, component, hook, reducer, DOM snapshot, mock-service-worker,
and in-memory-router tests are forbidden by the repository-wide E2E-only rule.

Required browser scenarios:

- first-run all-in-one: create one profile, share it to the built-in Endpoint,
  create a session, send a message, observe a final assistant response;
- Access-admitted entry/reload and expired/invalid assertion re-entry with no
  Zode login screen, token field, user settings, or application login cookie;
- server-only bootstrap exposes no built-in Endpoint and handles
  `local_endpoint_id: null`;
- add one remote Endpoint and deliberately choose local versus remote session
  placement;
- one provider with two profiles, explicit default, and different Endpoint
  sharing;
- a second Access actor sees the shared Endpoint/provider management resources
  but cannot discover or open the first actor's Endpoint-owned sessions;
- OAuth redirect/prompt/cancel/success without exposing secret values in DOM or
  browser storage;
- refresh success, crash recovery, and refresh-unknown relogin states without a
  blind retry action;
- distribution pending, stale, unreachable, ready, and removed states;
- one Endpoint SSE multiplexes at least two sessions across navigation, and
  disconnect/reconnect does not miss or duplicate either session's durable
  final message;
- switching from one session to another clears the previous unsent draft
  without submitting it
  (`e2e_browser_switching_sessions_clears_the_previous_unsent_draft`);
- same-session execution recovery in a multi-provider catalog, including
  current-selection defaults, no-op submission, refresh, and legal
  Server/Endpoint restart without changing session identity or history;
- Endpoint goes unreachable while a session page remains open and the UI keeps
  only its clearly disconnected current view without a fake terminal event;
- async tool completion, wait timeout, cancellation, and unknown-outcome safe
  action gating;
- keyboard-only completion of the primary session and provider workflows;
- secret markers absent from rendered text, accessible names, browser storage,
  URLs, console output, and downloaded artifacts.

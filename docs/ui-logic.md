# Browser logic architecture

Status: authoritative architecture for browser-side product logic.
`docs/ui.md` owns user-visible behavior and visual/product semantics. This
document owns the framework-independent class and signal model consumed by the
visual UI.

## 1. Selected model

Browser logic is one stable object graph whose classes match Zode product
domains. Classes own behavior and private writable signals. The visual UI reads
public `ReadonlySignal<T>` values and invokes semantic operations; it does not
own Server requests, SSE connections, retry policy, idempotency, reconciliation,
or domain workflow state.

The logic layer uses `@preact/signals-core` and imports no React, hooks, Radix,
Emotion, visual component, or component context. A framework adapter may
subscribe to signals, but framework lifecycle never constructs or disposes
domain objects.

```text
visual UI
   | reads signals; invokes semantic operations
   v
domain/workflow classes
   | typed ports
   v
Server HTTP client + one Endpoint SSE transport per Endpoint
```

There is one authority for each piece of browser state. The application does
not retain a parallel global signal bag, callback registry, DTO cache, runtime
reducer, or compatibility SSE path.

## 2. Canonical object graph

```text
ZodeApplication
├── settings: Settings
├── navigation: Navigation
├── endpoints: ReadonlySignal<readonly Endpoint[]>
│   └── Endpoint
│       ├── connection: ReadonlySignal<EndpointConnection>
│       └── sessions: ReadonlySignal<readonly Session[]>
│           └── Session
│               └── toolCalls: ReadonlySignal<readonly ToolCall[]>
└── providers: ReadonlySignal<readonly Provider[]>
    └── Provider
        └── profiles: ReadonlySignal<readonly AuthProfile[]>
```

Identity-bearing resources have one canonical instance:

- `Endpoint` is keyed by `endpoint_id`.
- `Session` is keyed by `(endpoint_id, session_id)` and is owned by its
  `Endpoint`; a session ID alone is never a lookup key.
- `Provider` is keyed by provider identity.
- `AuthProfile` is keyed by Server profile identity and owned by its Provider.
- `ToolCall` is keyed by the original `tool_call_id` and owned by its Session.

List refresh and newer snapshots reconcile those instances in place. A DTO
change or visual rerender does not replace a class instance, its subscribers,
draft, accepted operation, or provisional state.

Pure immutable values may remain value types. A class is required when a
concept owns identity, behavior, asynchronous work, lifecycle, or independently
observable state.

## 3. Class responsibilities

### `ZodeApplication`

`ZodeApplication` is constructed once before the visual root. It owns the
single `ServerClient`, browser ports, canonical Endpoint and Provider
registries, Settings, and Navigation. `start()` bootstraps the object graph.
`dispose()` is used only for real application shutdown or page unload, never a
component unmount, Strict Mode cycle, route replacement, or responsive layout
change.

### `Settings`

`Settings` owns all safe Server-exposed settings and deployment facts, their
freshness/availability/mutation states, and semantic refresh/update operations.
It never exposes Access claims, credentials, callback secrets, or release
actuation.

### `Provider` and `AuthProfile`

`Provider` owns one provider descriptor, model catalog, default selection,
availability, and canonical AuthProfile registry. `AuthProfile` owns profile
readiness, revision, sharing, expiry, distribution state, and safe profile
operations. Secret input is a one-way workflow value and is cleared after
submission; it is never a durable or public signal.

### `Endpoint`

`Endpoint` owns identity, label, kind, reachability, capabilities, replica
summary, loading/error state, its canonical Session registry, and its one
Endpoint-wide SSE connection.

The Endpoint alone owns:

- connection lifecycle and reconnect policy;
- one in-memory durable cursor for that Endpoint;
- ordered durable-frame deduplication;
- demultiplexing frames by `session_id` into canonical Session instances;
- dispatch of no-ID transient frames without advancing the durable cursor;
- bounded HTTP reconciliation after stream gaps or Endpoint recovery.

An Endpoint instance never opens more than one live SSE connection. Opening,
closing, or switching a Session, mounting or unmounting a component, and
changing responsive layout do not start, stop, or replace that connection.
Removing/disposing the Endpoint or shutting down the application closes it.

The connection signal distinguishes at least connecting, live, reconnecting,
unavailable, and stopped. Endpoint loss retains last-rendered Session objects
as explicitly stale/non-authoritative; it does not fabricate deletion,
migration, or a runtime terminal event.

### `Session`

`Session` owns product logic for one `(endpoint_id, session_id)` pair:

- the latest authoritative snapshot and transcript;
- provider/model/profile execution facts and recovery availability;
- activation, wait, retry, tool-call, and unknown-outcome projections;
- provisional assistant text dispatched by its Endpoint;
- the composer draft and frozen admitted operations;
- semantic refresh, send, execution selection, cancel, and reconcile methods.

Session owns no SSE transport, cursor, reconnect timer, or connection lifecycle.
It receives already-validated frames from its Endpoint and updates related
signals atomically. A durable final replaces provisional text exactly once.

### `Navigation`

`Navigation` owns route parsing, browser history actions, current product view,
and active Endpoint/Session selection. It resolves canonical objects from
ZodeApplication. Route components do not fetch resources or construct models.
The canonical route is
`/endpoints/{endpoint_id}/sessions/{session_id}`.

### Pre-admission workflows

State that exists before a durable resource belongs to a domain-named workflow
class, not a component hook. New-session, Endpoint registration,
provider/profile creation, and execution recovery workflows own validation,
frozen request data, mutation status, stable idempotency key, retry eligibility,
and safe error state. UI-local state is limited to presentation with no product
meaning, such as hover or animation progress.

## 4. Signal contract

Writable signals are private. Public state is read-only or computed. Classes:

- expose domain values rather than transport DTO containers;
- expose business decisions as derived signals rather than component logic;
- update related signals in one batch;
- preserve canonical instances and deterministic collection ordering;
- distinguish loading, stale, disconnected, retryable, unknown, and failed;
- expose retry eligibility as data and retry as a named method, never a callback
  stored inside a signal;
- never expose a writable Map or mutable collection.

Signals are disposable projections, not a browser database. They never become
an alternative authority for sessions, events, cursors, profiles, credentials,
or execution.

## 5. Endpoint-wide stream and reconciliation

The browser opens management
`GET /v1/endpoints/{endpoint_id}/events`; Server transparently proxies Endpoint
`GET /v1/events`. Every durable frame carries the Endpoint-global ID and its
owning `session_id`. The Endpoint class applies these rules:

1. Validate the public event schema and Endpoint identity context.
2. Ignore a durable frame whose numeric ID is not newer than the Endpoint
   cursor.
3. Resolve or reconcile the canonical Session named by `session_id`.
4. Dispatch the frame to that Session, then advance the Endpoint cursor.
5. Dispatch no-ID transient frames to the named Session without changing the
   cursor.
6. On reconnect, send the one Endpoint cursor as `Last-Event-ID`.
7. After lag, disconnect, or an event for an unknown Session, reconcile bounded
   HTTP projections without implementing a second runtime reducer.

The v0 cursor is in-memory browser state. A full application reload may open
without `Last-Event-ID` and consume the subject-filtered replay from the
beginning. It must not persist a cursor across an unknown Access actor and
thereby skip that actor's events. A future persisted cursor requires an
explicit actor-scoped public identity contract.

HTTP snapshots and committed SSE events are authoritative. Transient text is
best-effort display state only. Server stores no event, cursor, Session
projection, or Endpoint stream mirror.

## 6. Commands and concurrency

Every mutation is a semantic method on its owning class or workflow. The owner
creates one stable idempotency key and freezes the admitted request for retry.
Unknown response and accepted-but-incomplete are distinct. Retry reuses the
same key and body; it does not rerun component closures or re-read mutable
defaults.

Classes guard stale responses with operation identity/generation and apply a
result only while it belongs to that operation. A confirmed admission remains
confirmed if a later projection refresh fails. Accepted work continues across
HTTP loss, Endpoint SSE reconnect, route changes, component removal, Server
restart, and browser refresh according to the durable product contract.

## 7. UI boundary

Visual components may read class signals, invoke semantic methods, and retain
purely visual state. They may not call `fetch`, construct or close SSE, import
transport DTOs, own domain state in component lifecycle, duplicate validation
or retry policy, assign signals, or reconstruct domain objects.

The logic layer does not prescribe components, layout, styling, interaction
appearance, responsive composition, or visual implementation.

## 8. Required acceptance

The final implementation has one class graph, one Server HTTP client, and one
SSE/cursor implementation per canonical Endpoint. No session SSE route,
Session-owned connection, compatibility stream, duplicate cache, or component
request path remains.

Repository shape gates supplement, but never replace, real-browser E2Es:

- logic classes import no visual framework or components;
- visual code imports no Server transport or writable domain signal;
- only the composition root constructs top-level services;
- Session code contains no SSE construction, cursor storage, or reconnect
  lifecycle.

Named real-browser/real-process acceptance includes:

- `e2e_browser_endpoint_stream_multiplexes_sessions_across_navigation_and_reconnect`:
  one browser application opens exactly one management and one downstream
  Endpoint SSE, receives ordered events for two sessions, navigates between
  them, reconnects with one Endpoint `Last-Event-ID`, and shows one durable final
  per session without a missed or duplicated terminal effect.
- `e2e_browser_session_logic_survives_shell_navigation_without_losing_draft_or_duplicating_effects`:
  an unsent draft and accepted work survive visual route replacement while the
  Endpoint stream remains the same connection authority.
- `e2e_browser_endpoint_reconciles_canonical_sessions_without_duplicate_streams_or_rows`:
  inventory refresh and reopening the same pair preserve one Session instance,
  one row, and the Endpoint's single stream.
- `e2e_browser_provider_endpoint_and_settings_models_follow_server_authority_without_shadow_state`:
  provider, Endpoint, profile, and settings changes reconcile without stale
  client defaults or a local shadow database.

Existing ordinary-chat, same-session recovery, tool/wait/cancel,
unknown-outcome, Access, restart, accessibility, and secret-nondisclosure E2Es
remain mandatory and consume this same object graph.

## 9. Migration boundary

The final migration replaces component-owned and per-session stream logic; it
does not wrap or preserve those paths. Visual UI is a consumer of this public
class/signal contract. File overlap does not change the boundary: product logic
stays in classes, and visual decisions stay outside this document.

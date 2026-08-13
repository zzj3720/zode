# Timer adapter rules

`src/timer` owns in-process wait scheduling for session waits. It implements
the runtime-declared TimerPort. Wait remains session control in runtime and
domain. This adapter is not wait authority, a second event store, or a durable
timer database.

## Responsibility

- Arm, cancel, and shut down process-local sleeps for the current session wait.
- On fire, invoke only the composed callback. Do not append `WaitExpired` or
  inspect session state.
- Cancel is best-effort. A stale fire after cancel or replacement must remain
  harmless.
- Shutdown drops outstanding sleeps and must not invent `WaitExpired`.
- Model-step retry delay and tool foreground windows stay outside TimerPort.

## Forbidden dependencies

- Do not import storage, HTTP/API, runtime concrete types, provider, or tools.
- Do not append events, rehydrate sessions, cancel tools, persist wait state,
  or add a second SQLite.
- Do not become wait authority. Durable `WaitSet`, `WaitTimerScheduled`, and
  `WaitExpired` remain runtime/store facts.

## Public seam

Implement TimerPort only. Compose from `main.rs` with a clock and a channel
into `Runtime::expire_wait`. Do not `register_callback` or `attach(runtime)`.
Runtime arms the adapter after the WaitSet/timer-intent transaction commits.
Crash between commit and arm is recovered by startup re-arm from durable
`active_timer` / outstanding-wait facts.

## Persistence

None. Losing every in-memory arm is always recoverable from the runtime store.

## Acceptance

No unit tests. Later real-process HTTP/SSE E2Es own the contract; this file
does not add them:

- `e2e_auto_wait_timeout_does_not_cancel_running_tool`
- `e2e_two_session_waits_do_not_cross`
- `e2e_explicit_wait_defaults_to_sixty_seconds_and_survives_restart`
- keep-green `e2e_outstanding_wait_expires_after_restart`

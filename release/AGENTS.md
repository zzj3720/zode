# Release driver and local test-channel rules

`release/` owns the immutable artifact installer used by the local test
channel.  The driver is an operator-facing composition boundary: it validates
the harness manifest, installs a complete artifact atomically, starts the
all-in-one Server for its own release instance, binds its one known Endpoint
child, exposes live health metadata, and stops and reaps that instance on
teardown.

The driver does not implement Server or Web release-control resources.  The
operator driver/CLI performs promotion and rollback; the browser only verifies
the ordinary Access-protected UI → Server → built-in Endpoint path afterwards.
The driver must not accept cassettes, replay paths, recorder flags, or
unauthenticated health fallbacks.  Test-only recording and replay belong to
`tests/release_e2e/**` and the shared recorder seam.

Every artifact is immutable and binds one source revision to the UI tree,
Server binary, Endpoint binary, protocol inputs, and driver digest.  Staging
starts and observes the candidate on isolated listeners without changing
`current` or `previous`; only a separately approved promotion operation may
change those pointers.  Process identity is scoped to a run-owned instance
locator and is independently checked by the release E2E with OS executable,
listener, HTTP, and digest evidence.

All mutating driver operations serialize through one release-root operation
lock.  A stale lock is reclaimed only when its recorded owner PID is no longer
alive; a live or malformed lock fails closed.

Release-instance directories are disposable process/config state only.  The
active `current` instance uses one run-owned persistent Endpoint runtime store,
Server control database, subject key, controller authority secret, and Server
secret directory; promotion and rollback point the replacement process at
those same paths, so Endpoint identity, catalog, sessions, and credentials do
not reset.  A `candidate` instance deliberately receives an isolated store,
authority, and secret directory while it is staged, otherwise its SQLite
ownership locks and catalog would conflict with the active release.  The
candidate's persistent state is discarded with that instance after promotion
or failed staging.

The driver may use the existing Access assertion and Endpoint controller-auth
configuration supplied by the local test channel.  It must never emit their
values or persist them in manifests, release pointers, ordinary logs, or
health JSON.  Production Server/Endpoint processes do not import the test
process seam or write locator files; the driver derives a test-owned Endpoint
locator only after validating the Server's known direct child by PID/parent,
exact installed argv/config/listen, executable digest, listener, and
authenticated identity/capabilities evidence.

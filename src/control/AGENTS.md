# Endpoint control identity and authentication rules

`src/control` owns the device Endpoint's stable identity and controller
authentication boundary. It converts a valid control credential plus bounded
`Zode-Subject` header into an opaque `ControlContext`; it knows nothing about
Cloudflare Access, management users, provider logins, sessions, or UI routes.

## Identity and authorization

- Persist one stable opaque `endpoint_id` for the lifetime of the configured
  Endpoint stores. A controller cannot supply or replace it.
- A controller authority is the configured stable `authority_id` plus a
  monotonic credential revision. Bearer bytes are replaceable authentication
  material and never define session ownership.
- Authenticate the bearer before parsing or accepting `Zode-Subject`. Reject a
  missing, duplicate, empty, malformed, or oversized authorization/subject
  header with a safe typed result and no resource lookup.
- `ControlContext` contains only bounded non-secret authority/revision/subject
  values. It never contains the raw bearer, a Server actor, Access claims, an
  email, or a provider credential.
- Use constant-time secret comparison. Do not log or persist raw bearer bytes,
  authorization headers, failed secret candidates, or unkeyed secret hashes.
- Distinct authorities cannot adopt one another's sessions, command receipts,
  auth replicas, or rotation operations even if their opaque subjects match.

## Secret storage and rotation

- Read initial bearer material only from the configured secret file. General
  configuration, environment variables, session SQLite, events, snapshots,
  blobs, responses, and SSE contain no control secret.
- Bootstrap controller state only while the runtime and its control sidecars
  are jointly unclaimed. Persist an initialization fact binding the configured
  authorities and revisions; after that point a missing identity, authority
  state, manifest, journal fact, or initialization fact is corruption, never
  permission to fall back to the original configured secret.
- Bind the process-lifetime lock and the SQLite adapter to the same verified
  canonical runtime path. Lock and state sidecars must be regular, single-link
  files opened without following symlinks; runtime hardlinks fail closed.
- Rotation keeps `authority_id` unchanged, stages the new secret, records a
  restart-stable keyed request fingerprint, atomically promotes the higher
  revision, and fences the old secret before acknowledgement.
- The active authority manifest is the promotion fact and the authentication
  linearization boundary. Once it is visible, no newly admitted request may
  authenticate with the previous secret, even while receipt persistence or
  response delivery is still in progress.
- Preserve every completed operation's bounded non-secret fingerprint and
  exact response as an immutable receipt scoped by authority, opaque subject,
  rotation command, and idempotency key. Historical receipts remain replayable
  only in that same scope under the current authority secret; cross-scope keys
  never replay or conflict with one another. The bounded recovery journal
  contains unresolved intents and at most the current promotion receipt; older
  completed receipts move to their immutable direct-lookup facts instead of
  growing the journal. Startup and ordinary authentication never scan all
  receipts.
- Lower revisions are stale; the same revision with different semantics
  conflicts. Startup reconciles staged promotion before readiness.
- Blocking filesystem and secret-store work uses an explicit blocking
  boundary. Files are restrictive and atomically replaced; deletion is
  best-effort erasure, never an authorization fact.

## Acceptance

Only real-binary HTTP/SSE E2Es cover this module. Maintain cases for missing or
wrong credentials, subject isolation, stable Endpoint identity, lost-response
rotation recovery, old-secret fencing at manifest promotion, partial-sidecar
deletion, runtime-path swap and unsafe-link rejection, bounded pending-journal
growth with historical receipt replay, restart persistence, and absence of
secret markers from public output, logs, runtime SQLite, snapshots, and blobs.

The design is executable through these stable anchors:

| Boundary | E2E anchors |
| --- | --- |
| Stable identity, single owner, canonical runtime path | `e2e_identity_is_endpoint_owned_and_restart_stable`; `e2e_same_stores_allow_one_endpoint_until_exit_then_preserve_state`; `e2e_runtime_store_path_alias_cannot_split_endpoint_ownership`; `e2e_hardlink_runtime_store_fails_closed_without_state_split`; `e2e_runtime_store_symlink_toctou_cannot_cross_ownership` |
| Authentication and bounded subject admission | `e2e_invalid_controller_auth_and_subject_fail_before_lookup`; `e2e_oversized_subject_is_rejected_as_payload_too_large`; `e2e_empty_controller_auth_is_rejected_before_ready`; `e2e_world_readable_controller_secret_is_rejected_before_ready` |
| Bootstrap and missing/corrupt durable facts fail closed | `e2e_missing_endpoint_identity_sidecar_is_rejected_before_ready`; `e2e_missing_controller_auth_state_is_rejected_before_ready`; `e2e_partial_controller_rotation_state_is_rejected_before_ready`; `e2e_unknown_controller_operation_phase_is_rejected_before_ready`; `e2e_file_backend_manifest_authority_binding_corruption_is_rejected_before_ready` |
| Rotation linearization, replay, collision, recovery, and bounds | `e2e_controller_auth_rotation_lost_response_fences_old_secret_and_survives_restart`; `e2e_manifest_promotion_fences_old_secret_before_public_completion`; `e2e_controller_authority_secret_collision_is_rejected_without_mutation`; `e2e_historical_controller_rotation_receipts_survive_restart`; `e2e_completed_rotations_bound_journal_and_preserve_historical_receipts` |
| Sidecar authority cannot move after readiness | `e2e_controller_auth_directory_swap_cannot_acknowledge_split_state` |

Each case must observe the real Endpoint through public HTTP and use filesystem
mutation only on its test-owned paths. A path/link check performed only at
startup does not satisfy the process-lifetime authority decision.

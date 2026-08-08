# Approved common-user E2E matrix

Status: approved Zode behavior map, current protected main `2beff070a6cdbe67c2422f564c285264c5d7c496`.

This document turns the approved outside-repository adoption baseline into
Zode-owned black-box anchors. It is a traceability document, not a claim that
the current installation is usable. A row is complete only when its named
real-browser or real-process E2E is red against the unfixed behavior, green
after the owning product fix, and (where applicable) green after an exact-main
installation and restart. Existing lower-level E2Es provide useful evidence,
but do not substitute for the installed browser path.

The adopted source is `openai/codex` revision
`a17da5e6e4a5a9b45396f0693b0a4d5b9df06318`, recorded outside the repository in
the approved baseline. Zode deliberately keeps its own Web -> Access-protected Server ->
Endpoint -> aimux/provider path, HTTP plus SSE transport, Endpoint-owned
durable session authority, and Server-managed versioned provider profiles. No
reference implementation, fixture, asset, brand, or internal transport is
copied here.

## Status vocabulary

- **ANCHOR**: a named real-process/browser scenario exists and is owned by the
  relevant suite; its assertions still need to be evaluated in the complete
  installed matrix.
- **PARTIAL**: lower-level or narrower browser coverage exists, but one or more
  approved user boundaries (usually restart, re-attachment, or exact install)
  are not covered by the same scenario.
- **BLOCKED**: a current public run has an observed behavioral red; do not turn
  it into a skip or call the row green. If the run was not durably captured,
  no repair may be claimed from it until a later test-only reproduction records
  the public boundary safely.
- **GATED**: the behavior is intentionally excluded from this adoption and
  requires a separate public-semantics proposal.
- **REJECTED**: outside Zode's product boundary.

## Adopted scenario map

| Approved common behavior | Zode public behavior and deliberate difference | Stable real E2E anchors | Current state |
| --- | --- | --- | --- |
| Session create/list/read/continue | The `(endpoint_id, session_id)` pair is the browser identity; Endpoint owns history and Server stores no session mirror. | `e2e_browser_sessions_home_is_endpoint_grouped_without_server_session_mirror`; `e2e_create_generates_ulid_and_binds_idempotency_payload`; `e2e_session_ownership_safe_not_found_and_ordered_sse` | PARTIAL: browser and Endpoint anchors exist; exact installed continuation still belongs to the product matrix. |
| Simplest chat | Select an explicit Endpoint/provider/model/profile, send one text message, stream progress, and render exactly one durable assistant final after reload. | `e2e_all_in_one_first_run_uses_normal_server_api_and_local_endpoint`; `e2e_golden_assembled_model_tool_loop_survives_restart`; `e2e_recorded_opencode_provider_roundtrip_and_restart` | **BLOCKED**: the latest real Chromium/all-in-one run crossed the public-entry prerequisite and failed at `local_endpoint_catalog_committed` with `control_store_integrity`; fixed-channel ordinary chat remains a separate red. The observed run was not made into a new first-occurrence cassette, so this row is a blocker/handoff rather than authorization to repair from an unretained exchange. |
| Consecutive and concurrent input | An already-dispatched model round is frozen; queued/steered input enters the next allowed round without loss, duplication, or stale active state. | `e2e_concurrent_inputs_preserve_both_assistant_rounds`; `e2e_round_boundary_steering_waits_for_the_next_model_round`; `e2e_round_boundary_final_defers_steering_to_next_activation`; `e2e_browser_session_admission_is_separate_from_completion_and_last_event_id_reconnect_replaces_provisional_final` | PARTIAL: Endpoint round-boundary coverage exists; one complete browser/install path is still required. |
| Long-running work and re-attachment | Closing a browser, navigating, refreshing, losing SSE, or restarting Server must not cancel Endpoint work; re-attachment observes progress, tools/waits, and the final. | `e2e_browser_session_admission_is_separate_from_completion_and_last_event_id_reconnect_replaces_provisional_final`; `e2e_external_callback_tool_stays_running_and_completes_after_restart`; `e2e_http_response_tool_rejects_runtime_restarted_recovery`; `e2e_hard_crash_recovery_exhausts_one_model_attempt_and_keeps_delivery_runnable` | PARTIAL: each boundary has a real anchor, but the adopted single browser journey across disconnect, reload, Server restart, and Endpoint restart is not yet green. |
| Provider failure and recovery | Unavailable/auth-rejected/early-close/partial/retry-exhausted outcomes become durable terminal facts; after repair, the same session can continue and never stays falsely active. | `e2e_model_pre_stream_rate_limit_is_one_logical_request`; `e2e_model_partial_stream_retry_has_no_partial_tool_effect`; `e2e_tombstoned_replica_never_reaches_provider_before_or_after_restart`; `e2e_llm_recorder_preserves_failure_outcomes` | PARTIAL: deterministic Endpoint/provider failure anchors exist; the fixed installed provider path and browser recovery remain required. |
| Durable model-attempt recovery | If the process stops after `model_attempt_failed` but before `model_attempts_exhausted`, the typed activation terminal, and `activation_finished`, restart must reconcile the same session/history in place and never leave the activation permanently active. | `e2e_hard_crash_recovery_exhausts_one_model_attempt_and_keeps_delivery_runnable`; `e2e_hard_crash_after_retry_fact_claims_one_scheduled_attempt` (related crash anchors; the observed pre-terminal window still needs a dedicated named red E2E) | **BLOCKED**: the current product observation has `model_attempt_failed` durable but no terminal/exhaustion/activation-finished facts; restart skips the non-running attempt and leaves the original session `Working`. This is a current product red, not permission to create a replacement session or to relabel an unretained capture. |
| Provider/model/profile selection | Server owns descriptors, profiles, defaults, and revisions; Endpoint executes the explicit revision and a later rotation does not rewrite an in-flight request or history. | `e2e_provider_profiles_two_profiles_same_provider_have_explicit_default_and_distinct_endpoint_sharing`; `e2e_browser_provider_profiles_are_shared_deployment_resources`; `e2e_server_forwards_and_endpoint_persists_provider_execution_options`; `e2e_unknown_provider_execution_schema_is_rejected_and_revision_round_trips` | ANCHOR/PARTIAL: management and Endpoint anchors are present; include the selected profile in the same simple-chat/install journey. |
| Tools, waits, and long tasks | Ordinary adapter tools use the real HTTP boundary; concurrent results retain provider order; `wait_for`, external callbacks, cancellation, unknown outcomes, and restart recovery retain their approved Zode semantics. | `e2e_browser_async_tool_wait_timeout_cancel_and_unknown_outcome_gate_safe_actions`; `e2e_mixed_tool_batch_is_concurrent_ordered_and_waits_once`; `e2e_external_completion_first_wins_and_wakes_one_next_activation`; `e2e_external_callback_tool_stays_running_and_completes_after_restart` | PARTIAL: Endpoint and browser state coverage exists; long-task browser re-attachment still needs a single positive matrix row. |
| Interruption and cancellation | Existing tool/callback cancellation and reconciliation remain first-wins and restart-safe. Whole-activation cancellation is not inferred from this row. | `e2e_restart_remote_response_becomes_unknown_and_cancel_cannot_rewrite_it`; `e2e_restart_unknown_response_rejects_unsupported_mark_failed`; `e2e_browser_async_tool_wait_timeout_cancel_and_unknown_outcome_gate_safe_actions` | ANCHOR for currently exposed tool/callback behavior; whole activation cancel is GATED below. |
| History, pagination, and recovery | Bounded list/read and stable cursors expose the complete Endpoint transcript; invalid snapshots/indexes fall back without changing events. | `e2e_browser_sessions_home_is_endpoint_grouped_without_server_session_mirror`; `e2e_create_message_sse_reconnect_get_restart`; `e2e_corrupt_latest_snapshot_falls_back`; `e2e_sqlite_restart_rebuilds_derived_indexes_and_allows_harmless_extra_index` | PARTIAL: storage and browser anchors exist; exact installed history continuation is not yet accepted. |
| SSE reconnect and multiple clients | Server forwards Endpoint event IDs and `Last-Event-ID`; it stores no cursor, and reconnect does not duplicate a durable final. | `e2e_browser_session_admission_is_separate_from_completion_and_last_event_id_reconnect_replaces_provisional_final`; `e2e_browser_two_actor_session_isolation`; `e2e_create_message_sse_reconnect_get_restart` | ANCHOR/PARTIAL: public reconnect and isolation are covered; combine with long-task restart before declaring complete. |
| Context growth and resource bounds | Adopt bounded input/output and continued history availability; storage snapshots remain distinct from model-context policy. | `e2e_oversized_tool_output_uses_secret_safe_blob_reference`; `e2e_max_rounds_per_activation_stops_tool_feedback_loop`; `e2e_public_500_redaction` | PARTIAL: bounds are anchored. Context compaction itself is GATED and must not be added by this matrix. |
| Access and security failures | Access admission/re-entry is separate from Zode login; safe error classes distinguish Access, Server, and Endpoint failures; credentials never enter DOM, storage, URLs, logs, or ordinary DB. | `e2e_access_entry_reentry_through_real_access_edge`; `e2e_access_reload_keeps_the_access_admitted_ui_without_zode_auth`; `e2e_browser_access_reentry_stops_mutations_and_uses_management_origin`; `e2e_browser_write_only_secrets_and_oauth_ticket_non_disclosure`; `e2e_callback_origin_never_serves_management_ui_or_api` | ANCHOR/PARTIAL: real browser security paths exist; the full matrix must retain genuine readiness failures rather than skip them. |
| Exact-main persistent install | A selected merged artifact is installed to the fixed channel; fixtures do not become persistent provider/session state, and repeated smoke leaves a usable channel. | `e2e_web_harness_real_process_smoke`; release-driver install/restart evidence outside the browser spec | **BLOCKED**: shell/health evidence is insufficient while ordinary chat and the long-running browser journey are red. |

## Separately gated public semantics

These behaviors may be common elsewhere but are not implied by the approved
Zode contract. Do not add them through a test migration:

1. archive, unarchive, delete, or fork;
2. whole-activation cancel (beyond the currently exposed tool/callback
   cancellation contract);
3. model-context compaction and its public lifecycle;
4. request-user-input or permission approval as a new public interaction;
5. image or attachment input.

Each requires a separate behavior proposal, red real-process/browser E2E, and
explicit approval before any production or UI route is added.

## Explicitly rejected reference scope

Zode does not adopt a TUI/CLI product, JSON-RPC or WebSocket transport,
rollout-file or reference SQLite ownership, MCP/plugins/skills/cloud tasks,
multi-agent/plan/review workflows, Git/workspace trust or shell approval,
account/login/rate-limit semantics, telemetry/feature flags, or reference
branding/assets/copy/tests. These are not missing rows in this matrix.

## Completion gate

The matrix is complete only when each non-GATED row has a named red-to-green
E2E through the real public composition, the exact-main install row has a
repeatable browser smoke, and the long-running row proves browser close,
navigation, reload, SSE reconnect, Server restart, and Endpoint restart before
observing the same durable final. A build, health page, test count, or lower-
level fixture alone cannot change a row from PARTIAL/BLOCKED to complete.

## CI signal contract

`locked-build-and-e2e` is the shared protocol/recorder/process evidence job. Its
green result is deliberately not a product-acceptance result. The separate
`approved-common-browser-e2e` job checks out the exact merge revision, builds
the Endpoint, Server, and UI from that checkout, and executes every tracked
file under `web/e2e/specs/` through Chromium and real child processes. Its
collection audit is pinned by
`scripts/ci/approved-product-playwright-manifest.json` to 24 files and 53 test
identities; any missing/extra file or test, failure, skip, or unrun test fails
the job. It never reads live-provider credentials. `approved-product-merge-gate`
requires both jobs, so a shared-only green cannot make a product merge appear
green. Repository protection must require that aggregate context after its
first run; the workflow cannot make an unconfigured GitHub branch-protection
rule required by itself. The product job also uploads a line-progress log next
to its JSON report; a timeout therefore retains the last real test boundary
even when Playwright has not reached its final JSON flush.

The current exact-main product gate is expected to expose real fixture or
product blockers rather than hide them. For example, the session-reconnect
fixture currently reaches the Endpoint public startup boundary and fails closed
on the typed HTTP-tool recovery configuration error
`Invalid("HTTP tools cannot claim deduplicated retry dispatch")`; that is a
test-fixture drift to repair in the owning E2E, not permission to change the
approved HTTP recovery contract or production behavior.

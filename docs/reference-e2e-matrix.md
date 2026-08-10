# Approved common-user E2E matrix

Status: approved Zode behavior map, current protected main `999e6aea9150609c6912317ec944c059c6ca8ea0`.

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
| Confirmed message admission versus projection freshness | Once the browser has received `202` for one message, a later session or session-list projection failure may mark the projection stale or reconnecting, but cannot relabel the already admitted mutation as failed or unknown. The browser keeps one idempotency key; Endpoint keeps one user message and one durable assistant final; Server keeps no session mirror. | Pending owner candidate `e2e_browser_confirmed_message_admission_is_not_downgraded_by_projection_failure` (not yet an exact-main/stable anchor and therefore excluded from the stable-anchor count). | **BLOCKED**: a real browser -> management Access edge -> Server -> test-owned Endpoint proxy -> Endpoint run received one message `202`, then one session projection `503` and one session-list `503`. Endpoint work continued, the provider fixture returned `200`, later public reads returned `200`, and the durable transcript ended with exactly one user and one assistant message, but the page still rendered the admission-failure alert “The Endpoint is unavailable. Existing content is not an offline Server copy.” The valid relation-labeled later reproduction records both management and Server-to-Endpoint boundaries, is durably flushed with 14 members/14 digests and no active exchange, and binds its first failure to the completed management session `GET 503`. An earlier five-member attempt short-circuited the fault in a Playwright browser route and did not record the public fault boundary; it is explicitly ineligible for promotion or any first/replay pointer. The 14-member capture is still a later reproduction, never the historical first occurrence. The owning logic candidate must merge before this identity enters the pinned manifest and aggregate. |
| Consecutive and concurrent input | An already-dispatched model round is frozen; queued/steered input enters the next allowed round without loss, duplication, or stale active state. | `e2e_concurrent_inputs_preserve_both_assistant_rounds`; `e2e_round_boundary_steering_waits_for_the_next_model_round`; `e2e_round_boundary_final_defers_steering_to_next_activation`; `e2e_browser_session_admission_is_separate_from_completion_and_last_event_id_reconnect_replaces_provisional_final` | PARTIAL: Endpoint round-boundary coverage exists; one complete browser/install path is still required. |
| Long-running work and re-attachment | Closing a browser, navigating, refreshing, losing SSE, or restarting Server must not cancel Endpoint work; re-attachment observes progress, tools/waits, and the final. | `e2e_browser_session_admission_is_separate_from_completion_and_last_event_id_reconnect_replaces_provisional_final`; `e2e_external_callback_tool_stays_running_and_completes_after_restart`; `e2e_http_response_tool_rejects_runtime_restarted_recovery`; `e2e_hard_crash_recovery_exhausts_one_model_attempt_and_keeps_delivery_runnable` | PARTIAL: each boundary has a real anchor, but the adopted single browser journey is not yet green. The reconnect candidate no longer treats a Server-emitted SSE ID or a later projection render as browser consumption: its test-owned page pass-through records the exact SSE frames read by the production fetch consumer, separately records each production session-cursor write, requires the target durable ID itself, and compares both complete ordered browser prefixes with the Endpoint prefix. Immediately before each refresh or process restart, the test-owned boundary freezes only that response's browser-facing bytes, snapshots and validates the actual last processed cursor, continues observing withheld Endpoint frames, then requires the next connection to carry that exact cursor and replay every withheld durable ID. Its current exact-main stability run is blocked earlier by the composer draft/rerender red, so this corrected barrier has static review evidence but not yet a downstream behavioral green. The owning logic candidate has one real-browser green run but is not merged, so neither that candidate nor the downstream reconnect result counts as exact-main acceptance yet. |
| Provider failure and recovery | Unavailable/auth-rejected/early-close/partial/retry-exhausted outcomes become durable terminal facts; after repair, the same session can continue and never stays falsely active. | `e2e_model_pre_stream_rate_limit_is_one_logical_request`; `e2e_model_partial_stream_retry_has_no_partial_tool_effect`; `e2e_tombstoned_replica_never_reaches_provider_before_or_after_restart`; `e2e_llm_recorder_preserves_failure_outcomes` | PARTIAL: deterministic Endpoint/provider failure anchors exist; the fixed installed provider path and browser recovery remain required. |
| Durable model-attempt recovery | If the process stops after `model_attempt_failed` but before `model_attempts_exhausted`, the typed activation terminal, and `activation_finished`, restart must reconcile the same session/history in place and never leave the activation permanently active. | `e2e_hard_crash_recovery_exhausts_one_model_attempt_and_keeps_delivery_runnable`; `e2e_hard_crash_after_retry_fact_claims_one_scheduled_attempt` (related crash anchors; the observed pre-terminal window still needs a dedicated named red E2E) | **BLOCKED**: the current product observation has `model_attempt_failed` durable but no terminal/exhaustion/activation-finished facts; restart skips the non-running attempt and leaves the original session `Working`. This is a current product red, not permission to create a replacement session or to relabel an unretained capture. |
| Provider/model/profile selection | Server owns descriptors, profiles, defaults, and revisions; Endpoint executes the explicit revision and a later rotation does not rewrite an in-flight request or history. | `e2e_provider_profiles_two_profiles_same_provider_have_explicit_default_and_distinct_endpoint_sharing`; `e2e_browser_provider_profiles_are_shared_deployment_resources`; `e2e_server_forwards_and_endpoint_persists_provider_execution_options`; `e2e_unknown_provider_execution_schema_is_rejected_and_revision_round_trips` | **BLOCKED**: API-key distribution now reaches durable pending→unreachable→ready through the public browser path, but the same two-profile scenario stops at the absent OAuth action (`addOAuthProfile`); Server/UI OAuth attempt and authorize-ticket routes are not implemented. Keep the browser red; do not replace the OAuth profile with another API-key profile. |
| Tools, waits, and long tasks | Ordinary adapter tools use the real HTTP boundary; concurrent results retain provider order; `wait_for`, external callbacks, cancellation, unknown outcomes, and restart recovery retain their approved Zode semantics. The UI renders only actions explicitly authorized by the public projection; it never infers an action from status alone. | `e2e_browser_async_tool_wait_timeout_cancel_and_unknown_outcome_gate_safe_actions`; `e2e_mixed_tool_batch_is_concurrent_ordered_and_waits_once`; `e2e_external_completion_first_wins_and_wakes_one_next_activation`; `e2e_external_callback_tool_stays_running_and_completes_after_restart` | **BLOCKED**: exact-main Chromium reaches a real running tool, but its runtime row is anonymous and has no accessible tool identity. The existing fixture also declares `recovery.retry_dispatch=never` while expecting an enabled Reconcile button; that expectation conflicts with the approved HTTP contract and is test drift, not a missing product action. The owning vertical slice must separately prove a `never` branch with understandable `unknown_outcome` and no Cancel/Reconcile/Mark-failed controls, plus a `same_invocation_key_deduplicated` branch where the authoritative projection permits Reconcile and the public action reuses the original tool-call/invocation identity. The first safe-deduplicated suite attempt exited with a typed configuration error before the public bind and before any process capture was armed, so it is only a startup evidence gap: it is neither a product red nor first-occurrence replay evidence. The later public journey has an earlier real HTTP `409` raw for `ASYNC_TOOL_SAFE_RECONCILE_REJECTED`; that raw remains the earliest public product red and an evidence gap, never an eligible cassette. The authorized test-only boundary/topology correction used a new recording ID with `relation=later_test_reproduction_of_gap` and reproduced the same public result at both boundaries: Server -> Endpoint Reconcile `409`, then management-browser POST `409`, without changing safe-retry runtime or the original raw. Exact-authority replay is still invalid: it replays the nested Endpoint exchange independently and then replays the public Server exchange, which invokes Endpoint a second time and changes the response bytes (`REPLAY_MISMATCH`). The slice is therefore frozen with ignored 0600 gap metadata: no rerun, promotion, immutable cassette, or runtime repair is authorized, and the later capture may not be relabeled as replayable regression evidence. The removed startup blanket rejection is not reintroduced. Until both authoritative browser branches and a faithful single-authority replay topology enter the aggregate, narrower Endpoint anchors cannot make this row green. |
| Interruption and cancellation | Existing tool/callback cancellation and reconciliation remain first-wins and restart-safe. Cancel or retry-dispatch appears only when the Server/Endpoint public contract says that exact action is available. Whole-activation cancellation is not inferred from this row. | `e2e_restart_remote_response_becomes_unknown_and_cancel_cannot_rewrite_it`; `e2e_restart_unknown_response_rejects_unsupported_mark_failed`; `e2e_browser_async_tool_wait_timeout_cancel_and_unknown_outcome_gate_safe_actions` | **BLOCKED**: lower-level cancellation and reconciliation anchors remain valid, but the browser journey still needs the two authoritative availability branches above. An `unknown_outcome` with `retry_dispatch=never` must expose no action; only a deduplicated-retry tool may expose Reconcile, and it must retain the original identity. The startup evidence gap, original public `409` raw, relation-labeled two-boundary reproduction, and unresolved exact-authority replay mismatch remain separate layers; none substitutes for another, and the current later capture is explicitly not promotable. Do not preserve the old invalid-button assertion merely to turn the current fixture green. Whole-activation cancel remains GATED below. |
| History, pagination, and recovery | Bounded list/read and stable cursors expose the complete Endpoint transcript; invalid snapshots/indexes fall back without changing events. A broken execution is repaired on the original `(endpoint_id, session_id)` without replacing its history. | `e2e_browser_sessions_home_is_endpoint_grouped_without_server_session_mirror`; `e2e_browser_bad_session_retains_history_and_offers_same_session_execution_recovery`; `e2e_create_message_sse_reconnect_get_restart`; `e2e_corrupt_latest_snapshot_falls_back`; `e2e_sqlite_restart_rebuilds_derived_indexes_and_allows_harmless_extra_index` | ANCHOR/PARTIAL: the bad-session same-ID/history recovery anchor is 1/1 green on protected main `999e6aea9150609c6912317ec944c059c6ca8ea0`; storage and browser anchors remain valid. Final fixed-install history continuation and the unmerged shell-navigation/draft candidate are still not accepted as exact-main product green. |
| SSE reconnect and multiple clients | Server forwards Endpoint event IDs and `Last-Event-ID`; it stores no cursor, and reconnect does not duplicate a durable final. | `e2e_browser_session_admission_is_separate_from_completion_and_last_event_id_reconnect_replaces_provisional_final`; `e2e_browser_two_actor_session_isolation`; `e2e_browser_two_actor_session_isolation_replays_complete_endpoint_transcript`; `e2e_browser_provider_profiles_shared_deployment_replays_complete_endpoint_transcript`; `e2e_create_message_sse_reconnect_get_restart` | **BLOCKED/PARTIAL**: the current exact UI does not complete the two-actor browser contract. After Actor B receives the public safe `404`, the real page fails to render the unique visible safe-unavailable status; the live test fails and the serial replay identities correctly remain unrun rather than producing a partial green. The locally retained v8 isolation/profile files remain immutable evidence inputs, but review proved that their per-body slot numbering collapses distinct IDs across exchanges, so they are not eligible as exact transcript cassettes and cannot make either replay identity green. Capture/replay now keeps one ordered slot relation across the complete transport, but a replacement cassette requires a new recording ID from the same real-browser journey after the UI blocker is removed; v8 must not be rewritten or relabeled. This is a UI product handoff plus a replay-evidence dependency, not permission to weaken the 404/access-isolation assertion. The original shallow incident cassettes remain unchanged as provenance. Public reconnect and lower-level SSE anchors remain valid, but the aggregate must wait for the final UI and long-task restart journey. |
| Context growth and resource bounds | Adopt bounded input/output and continued history availability; storage snapshots remain distinct from model-context policy. | `e2e_oversized_tool_output_uses_secret_safe_blob_reference`; `e2e_max_rounds_per_activation_stops_tool_feedback_loop`; `e2e_public_500_redaction` | PARTIAL: bounds are anchored. Context compaction itself is GATED and must not be added by this matrix. |
| Access and security failures | Access admission/re-entry is separate from Zode login; safe error classes distinguish Access, Server, and Endpoint failures; credentials never enter DOM, storage, URLs, logs, or ordinary DB. Keyboard-only provider/profile actions restore visible focus to their trigger after cancel and after the public mutation succeeds, independent of whether the editor is a dialog or an inline semantic form. | `e2e_access_entry_reentry_through_real_access_edge`; `e2e_access_reload_keeps_the_access_admitted_ui_without_zode_auth`; `e2e_browser_access_reentry_stops_mutations_and_uses_management_origin`; `e2e_browser_write_only_secrets_and_oauth_ticket_non_disclosure`; `e2e_callback_origin_never_serves_management_ui_or_api` | **BLOCKED**: the real browser completed the provider descriptor `PUT` with 200, then lost keyboard focus instead of restoring it to the configuration trigger. Raw exchanges and process observations are durable and restricted, but the capture set remained open because the original native focus assertion was not bound to that public exchange; the gap is recorded locally and a future run must be labeled `later_test_reproduction_of_gap`, never historical first evidence. The corrected gate arms that relation before browser requests, rejects stale mutation matches, and may durably seal HTTP context, but it refuses cassette promotion because HTTP replay alone cannot reproduce keyboard/DOM focus. Same-entry Chromium replay remains required before product repair; final acceptance runs unchanged against the UI that reaches exact-main. |
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
`approved-product-collection` checks out the exact merge revision and derives
one fail-fast-disabled shard per approved spec from the reviewed manifest.
Every `approved-common-browser-e2e (...)` shard builds the Endpoint, Server,
and UI from that same revision and executes its complete spec through Chromium
and real child processes. A hung spec is bounded to its shard and cannot stop
the remaining approved specs from producing evidence. The full collection is
pinned by
`scripts/ci/approved-product-playwright-manifest.json` to 25 files and 58 test
identities; any missing/extra file or test, failed shard, failure, skip, unrun,
or incomplete result report fails the stable aggregate. It never reads
live-provider credentials. `approved-product-merge-gate` requires shared
evidence, collection, and every product shard, so a shared-only green cannot
make a product merge appear green. Repository protection must require that
aggregate context after its first successful run; the workflow cannot make an
unconfigured GitHub branch-protection rule required by itself. Each shard also
uploads a line-progress log next to its JSON report, so a timeout retains the
last real test boundary without suppressing results from the other specs.
CI artifacts contain only the collection matrix, progress/result reports, and
secret-scanned browser evidence. Raw or live recordings under
`target/test-recordings/` remain runner-local ignored evidence and are never
uploaded: quarantine members may contain test credentials until they have been
redacted, replay-verified, and promoted into a reviewed immutable cassette.
The local equivalent remains `./scripts/ci/verify-approved-product.sh`; setting
`ZODE_CI_PRODUCT_SPEC=specs/<name>.spec.<cjs|ts>` runs one manifest-approved
shard through the same build, full-collection audit, browser/process path, and
identity-complete result audit used in CI.

The current exact-main product gate is expected to expose real fixture or
product blockers rather than hide them. The earlier session-reconnect fixture
drift around HTTP-tool recovery metadata has been corrected without changing
the approved recovery contract. The same unchanged browser assertion now
crosses startup and reaches a real running tool, then records the product red
described in the tools and cancellation rows above. That distinction is why
fixture repair does not turn the shard green and why a narrower lower-level
anchor cannot substitute for the complete browser journey.

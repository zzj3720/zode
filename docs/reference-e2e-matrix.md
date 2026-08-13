# Approved common-user E2E matrix

Status: approved Zode behavior map, current protected main
`999e6aea9150609c6912317ec944c059c6ca8ea0`; the current non-visual candidate
is the unmerged `codex/zode-ui-logic` branch. Its current non-visual Chromium
matrix is 86/86 green; the six remaining cases require the separately delivered
visual UI, after which the complete 92-case matrix must run without filtering.

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
- **CANDIDATE GREEN**: the named public real-process/browser behavior has passed
  on the current candidate without skip or filtering of that behavior. It is
  not an exact-main or fixed-install acceptance claim.
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
| Session create/list/read/continue | The `(endpoint_id, session_id)` pair is the browser identity; Endpoint owns history and Server stores no session mirror. | `e2e_browser_sessions_home_is_endpoint_grouped_without_server_session_mirror`; `e2e_create_generates_ulid_and_binds_idempotency_payload`; `e2e_session_ownership_safe_not_found_and_ordered_sse` | CANDIDATE GREEN: browser and Endpoint anchors pass on the current candidate; exact-main and fixed-install continuation remain pending. |
| Simplest chat | Select an explicit Endpoint/provider/model/profile, send one text message, stream progress, and render exactly one durable assistant final after reload. | `e2e_all_in_one_first_run_uses_normal_server_api_and_local_endpoint`; `e2e_golden_assembled_model_tool_loop_survives_restart`; `e2e_recorded_opencode_provider_roundtrip_and_restart` | CANDIDATE GREEN: the former `control_store_integrity` prerequisite failure is stale. Current real-process/browser candidate paths admit one message, show progress, converge to one durable final, and survive reload; visual integration, exact-main, and fixed-install repetition remain pending. |
| Consecutive and concurrent input | An already-dispatched model round is frozen; queued/steered input enters the next allowed round without loss, duplication, or stale active state. | `e2e_concurrent_inputs_preserve_both_assistant_rounds`; `e2e_round_boundary_steering_waits_for_the_next_model_round`; `e2e_round_boundary_final_defers_steering_to_next_activation`; `e2e_browser_session_admission_is_separate_from_completion_and_last_event_id_reconnect_replaces_provisional_final` | CANDIDATE GREEN: Endpoint round-boundary and browser admission/reconnect anchors pass; fixed-install repetition remains pending. |
| Long-running work and re-attachment | Closing a browser, navigating, refreshing, losing SSE, or restarting Server must not cancel Endpoint work; re-attachment observes progress, tools/waits, and the final. | `e2e_browser_session_admission_is_separate_from_completion_and_last_event_id_reconnect_replaces_provisional_final`; `e2e_external_callback_tool_stays_running_and_completes_after_restart`; `e2e_http_response_tool_rejects_runtime_restarted_recovery`; `e2e_hard_crash_rebuilds_fresh_request_without_consuming_attempt_budget` | CANDIDATE GREEN: the current candidate covers navigation/refresh, Endpoint-wide SSE reconnect, Server restart, Endpoint restart, and convergence to one durable final without connection-owned cancellation. Exact-main and fixed-install acceptance remain pending. |
| Provider failure and recovery | Unavailable/auth-rejected/early-close/partial/retry-exhausted outcomes become durable terminal facts; a 200 SSE response that reaches EOF without a provider finish may retry only from its live in-memory request and cannot commit its partial candidate; after restart a new request is rebuilt from current durable facts, and the same session never stays falsely active. | `e2e_model_pre_stream_rate_limit_is_one_logical_request`; `e2e_model_partial_stream_retry_has_no_partial_tool_effect`; `e2e_model_clean_eof_without_finish_retries_in_memory_step`; `e2e_tombstoned_replica_never_reaches_provider_before_or_after_restart`; `e2e_llm_recorder_preserves_failure_outcomes` | CANDIDATE GREEN: the named Endpoint/provider failure and recovery anchors pass; the live DeepSWE run that first exposed missing-finish EOF is retained in its test-only recorder root; exact-main and fixed installed provider paths remain pending. |
| Durable model-attempt recovery | If the process stops with a request in flight or after `model_attempt_failed` but before the next durable boundary, restart must reconcile the same session/history in place, abandon the unavailable in-memory request, and build a fresh round from the latest durable facts without leaving the activation permanently active. | `e2e_restart_reconciles_failed_model_attempt_before_fresh_request`; `e2e_restart_reconciles_failed_model_attempt_before_terminal_finish`; `e2e_hard_crash_rebuilds_fresh_request_without_consuming_attempt_budget`; `e2e_restart_after_retry_decision_builds_fresh_request` | CANDIDATE GREEN: interruption, retry-boundary, and terminal-boundary restart reconciliation pass on the current candidate; restart does not restore request content or leave the session permanently `Working`. Exact-main/fixed product acceptance remains pending. |
| Provider/model/profile selection | Server owns descriptors, profiles, defaults, and revisions; Endpoint executes the explicit revision and a later rotation does not rewrite an in-flight request or history. | `e2e_provider_profiles_two_profiles_same_provider_have_explicit_default_and_distinct_endpoint_sharing`; `e2e_browser_provider_profiles_are_shared_deployment_resources`; `e2e_server_forwards_and_endpoint_persists_provider_execution_options`; `e2e_unknown_provider_execution_schema_is_rejected_and_revision_round_trips` | CANDIDATE GREEN: management, Endpoint, explicit selection, revision, default, and frozen in-flight execution anchors pass; final visual and fixed-install acceptance remain pending. |
| Tools, waits, and long tasks | Ordinary adapter tools use the real HTTP boundary; concurrent results retain provider order; `wait_for`, external callbacks, cancellation, unknown outcomes, and restart recovery retain their approved Zode semantics. | `e2e_browser_async_tool_wait_timeout_cancel_and_unknown_outcome_gate_safe_actions`; `e2e_mixed_tool_batch_is_concurrent_ordered_and_waits_once`; `e2e_external_completion_first_wins_and_wakes_one_next_activation`; `e2e_external_callback_tool_stays_running_and_completes_after_restart` | CANDIDATE GREEN: identity, running Cancel, wait timeout, offline/restart, unsupported unknown without an action, safe deduplicated retry, and final convergence pass in the current browser/process candidate; final visual and fixed-install acceptance remain pending. |
| Interruption and cancellation | Existing tool/callback cancellation and reconciliation remain first-wins and restart-safe. Whole-activation cancellation is not inferred from this row. | `e2e_restart_remote_response_becomes_unknown_and_cancel_cannot_rewrite_it`; `e2e_restart_unknown_response_rejects_unsupported_mark_failed`; `e2e_browser_async_tool_wait_timeout_cancel_and_unknown_outcome_gate_safe_actions` | CANDIDATE GREEN for currently exposed tool/callback behavior; whole-activation cancellation remains GATED below. |
| History, pagination, and recovery | Bounded list/read and stable cursors expose the complete Endpoint transcript; invalid snapshots/indexes fall back without changing events. | `e2e_browser_sessions_home_is_endpoint_grouped_without_server_session_mirror`; `e2e_create_message_sse_reconnect_get_restart`; `e2e_corrupt_latest_snapshot_falls_back`; `e2e_sqlite_restart_rebuilds_derived_indexes_and_allows_harmless_extra_index` | CANDIDATE GREEN: storage, browser history, pagination, snapshot fallback, and restart anchors pass; exact installed continuation remains pending. |
| Endpoint-wide SSE reconnect and multiple sessions | One browser application owns one stream/cursor per Endpoint, receives every session on it, and dispatches by `session_id`; Server forwards Endpoint event IDs and `Last-Event-ID`, stores no cursor, and reconnect does not miss or duplicate either session's durable final. | `e2e_endpoint_event_stream_multiplexes_sessions_and_reconnects_once`; `e2e_browser_endpoint_stream_multiplexes_sessions_across_navigation_and_reconnect`; `e2e_two_actor_sessions_are_shared_on_one_endpoint`; `e2e_endpoint_protocol_has_no_controller_auth`; `e2e_create_message_sse_reconnect_get_restart` | RED: listen-trust docs are accepted; Endpoint still requires controller auth and isolates subjects. |
| Context growth and resource bounds | Keep the complete append-only transcript available while bounding each provider context generation by tokens. The request output allowance and independent safety buffer are both reserved; before the first provider usage anchor the estimate is exactly four UTF-8 bytes per token plus framing, with no hidden multiplier, and later provider input usage calibrates only the newly appended durable tail. Discarded hidden reasoning output is not treated as next-round input. Before the selected model's input budget is exhausted, the current agent writes a versioned plain durable handoff from inert source data; prior operational prompts and tool roles cannot execute in that request and tool-call markup cannot become the document. Provider-generation and durable-document limits remain separate. The handoff is a first-class bounded text field rather than a generic inline JSON payload. Endpoint starts a fresh context for the same task without implicitly injecting old history or the document body; the successor reads the handoff in bounded UTF-8 chunks and paginates original history through runtime-owned read-only tools. Session events never serialize a provider request or duplicate transcript/tools. Input admitted during a handoff reaches the first fresh-context request; after restart Endpoint records the interrupted attempt and rebuilds a new request from the durable plan and current facts. If one completed tool result leaps across the provider ceiling, the handoff covers the newest fitting earlier prefix and the complete self-contained tail enters the fresh generation verbatim. Model/tool rounds have no numeric task or activation ceiling. | `e2e_oversized_tool_output_uses_secret_safe_blob_reference`; `e2e_long_task_continues_until_final`; `e2e_recorded_deepswe_long_run_replays_through_real_endpoint`; `e2e_model_request_reserves_128k_output_and_independent_context_buffer`; `e2e_unanchored_model_input_uses_four_byte_fallback_without_hidden_multiplier`; `e2e_provider_usage_anchor_excludes_discarded_reasoning_output_from_next_input`; `e2e_long_task_writes_handoff_and_continues_in_fresh_context`; `e2e_context_handoff_source_is_inert_and_document_is_plain_text`; `e2e_context_handoff_plain_document_pages_without_generic_payload_limit`; `e2e_large_history_result_crossing_handoff_threshold_continues_in_fresh_context`; `e2e_delivery_admitted_during_handoff_reaches_first_fresh_context`; `e2e_handoff_restart_rebuilds_from_durable_plan_and_queued_input`; `e2e_context_handoff_restart_reuses_committed_document`; `e2e_context_handoff_request_never_exceeds_provider_input_budget`; `e2e_context_handoff_plan_is_atomic_across_storage_failure`; `e2e_model_request_lifecycle_does_not_persist_request_content`; `e2e_restart_rebuilds_conversation_from_latest_durable_facts`; `e2e_public_500_redaction` | CANDIDATE GREEN: the no-request-snapshot restart, provider-calibrated budgets, and fresh-context handoff pass. The first unbiased OpenCode Go `deepseek-v4-flash` DeepSWE run completed 159 logical rounds through Zode Endpoint and received Harbor reward 0 (F2P 1/2, P2P 119/119); its 177 provider exchanges and 1,442-event causal trace replay green through the same real Endpoint with 158 event-derived tool outcomes. Exact-main merge and fixed installation remain pending. |
| Access and security failures | Access admission/re-entry is separate from Zode login; safe error classes distinguish Access, Server, and Endpoint failures; credentials never enter DOM, storage, URLs, logs, or ordinary DB. | `e2e_access_entry_reentry_through_real_access_edge`; `e2e_access_reload_keeps_the_access_admitted_ui_without_zode_auth`; `e2e_browser_access_reentry_stops_mutations_and_uses_management_origin`; `e2e_browser_write_only_secrets_and_oauth_ticket_non_disclosure`; `e2e_callback_origin_never_serves_management_ui_or_api` | ANCHOR/PARTIAL: real browser security paths exist; the full matrix must retain genuine readiness failures rather than skip them. |
| Exact-main persistent install | A selected merged artifact is installed to the fixed channel; fixtures do not become persistent provider/session state, and repeated smoke leaves a usable channel. | `e2e_web_harness_real_process_smoke`; release-driver install/restart evidence outside the browser spec | PARTIAL: the non-visual candidate and complete-matrix gate exist, but no claim is accepted until the delivered visual UI is integrated, the candidate is merged, and that exact revision is installed and repeated on fixed `60903`. |

## Separately gated public semantics

These behaviors may be common elsewhere but are not implied by the approved
Zode contract. Do not add them through a test migration:

1. archive, unarchive, delete, or fork;
2. whole-activation cancel (beyond the currently exposed tool/callback
   cancellation contract);
3. request-user-input or permission approval as a new public interaction;
4. image or attachment input.

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
navigation, reload, one Endpoint-wide SSE reconnect with the browser's last
processed Endpoint event ID, Server restart, and Endpoint restart before
observing the same durable final. A build, health page, test count, or lower-
level fixture alone cannot change a row from PARTIAL/BLOCKED to complete.

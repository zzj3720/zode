#[path = "support/http_sse.rs"]
mod http_sse_support;
pub(crate) mod support;

use std::io::{Error, ErrorKind};

use http_sse_support::*;
use reqwest::StatusCode;
use serde_json::{json, Value};
use support::{
    authenticated, authenticated_as, http_client, install_test_replica, require_ulid,
    response_json, response_text, write_endpoint_config, ConfiguredServer, HttpRequestExt,
};
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_create_message_sse_reconnect_get_restart(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("positive")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;

    let response = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", "create-positive")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let create = json_response(response).await?;
    let session_id = require_ulid(&create)?;
    assert_eq!(create["version"], 1);

    let response =
        authenticated(client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))))
            .header("Idempotency-Key", "message-positive")
            .json(&json!({"content": "hello from e2e"}))
            .send_with_timeout()
            .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let message = json_response(response).await?;
    assert_eq!(message["accepted"], true);
    assert_eq!(message["version"], 2);

    let response =
        authenticated(client.get(server.url(&format!("/v1/sessions/{session_id}/events"))))
            .send_with_timeout()
            .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let events = read_sse_events(response, 2).await?;
    let (_first_id, second_id) = assert_two_ordered_session_events(&events, &session_id)?;
    assert_eq!(events[1].data["schema"], "zode.event.v1");

    let response =
        authenticated(client.get(server.url(&format!("/v1/sessions/{session_id}/events"))))
            .header("Last-Event-ID", &events[0].id)
            .send_with_timeout()
            .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let replay = read_sse_events(response, 1).await?;
    assert_eq!(replay[0].id, events[1].id);
    assert_eq!(replay[0].event, "message_appended");

    let sse_response =
        authenticated(client.get(server.url(&format!("/v1/sessions/{session_id}/events"))))
            .header("Last-Event-ID", &events[1].id)
            .send_with_timeout()
            .await?;
    assert_eq!(sse_response.status(), StatusCode::OK);
    let response =
        authenticated(client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))))
            .header("Idempotency-Key", "message-positive-next")
            .json(&json!({"content": "next after live reconnect"}))
            .send_with_timeout()
            .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let next_message = json_response(response).await?;
    assert_eq!(next_message["accepted"], true);
    assert_eq!(next_message["version"], 3);
    let next_event = read_sse_events(sse_response, 1).await?;
    let next_id = next_event[0].id.parse::<u64>()?;
    assert!(second_id < next_id, "SSE id did not keep increasing");
    assert_eq!(next_event[0].event, "message_appended");
    assert_eq!(next_event[0].data["version"], 3);

    let response = authenticated(client.get(server.url(&format!("/v1/sessions/{session_id}"))))
        .send_with_timeout()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let before_restart = json_response(response).await?;
    assert_eq!(before_restart["version"], 3);
    assert_eq!(before_restart["transcript"][0]["content"], "hello from e2e");
    assert_eq!(
        before_restart["transcript"][1]["content"],
        "next after live reconnect"
    );

    server.stop().await?;
    let restarted = TestServer::start(&database_path).await?;
    let response = authenticated(client.get(restarted.url(&format!("/v1/sessions/{session_id}"))))
        .send_with_timeout()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let after_restart = json_response(response).await?;
    assert_eq!(after_restart["version"], 3);
    assert_eq!(after_restart["transcript"][0]["content"], "hello from e2e");
    assert_eq!(
        after_restart["transcript"][1]["content"],
        "next after live reconnect"
    );
    let mut restarted = restarted;
    restarted.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_create_generates_ulid_and_binds_idempotency_payload(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("session-identity")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;
    let first_response = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", "identity-create")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    assert_eq!(first_response.status(), StatusCode::CREATED);
    let first_body_text = response_text(first_response).await?;
    let first_body: Value = serde_json::from_str(&first_body_text)?;
    let session_id = first_body["session_id"]
        .as_str()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "create response omitted session_id"))?;
    assert_eq!(first_body["version"], 1);

    let replay_response = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", "identity-create")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    assert_eq!(replay_response.status(), StatusCode::CREATED);
    assert_eq!(response_text(replay_response).await?, first_body_text);

    let existing = authenticated(client.get(server.url(&format!("/v1/sessions/{session_id}"))))
        .send_with_timeout()
        .await?;
    assert_eq!(existing.status(), StatusCode::OK);

    let caller_id_response = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", "caller-supplied-id")
        .json(&json!({"session_id": "caller-supplied"}))
        .send_with_timeout()
        .await?;
    let caller_id_status = caller_id_response.status();
    let caller_id_body = response_text(caller_id_response).await?;
    assert_eq!(
        caller_id_status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "caller-supplied session id was accepted: {caller_id_body}"
    );
    let caller_id_json: Value = serde_json::from_str(&caller_id_body)?;
    assert_eq!(caller_id_json["error"]["code"], "invalid_request");
    let caller_id_read = authenticated(client.get(server.url("/v1/sessions/caller-supplied")))
        .send_with_timeout()
        .await?;
    assert_eq!(caller_id_read.status(), StatusCode::NOT_FOUND);

    let conflict_response = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", "identity-create")
        .json(&json!({"tools": ["different"]}))
        .send_with_timeout()
        .await?;
    let conflict_status = conflict_response.status();
    let conflict_body = response_text(conflict_response).await?;
    assert_eq!(conflict_status, StatusCode::CONFLICT, "{conflict_body}");
    let conflict_json: Value = serde_json::from_str(&conflict_body)?;
    assert_eq!(conflict_json["error"]["code"], "conflict");
    require_ulid(&first_body)?;
    server.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_session_list_is_subject_scoped() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let database_path = test_database("session-list-ownership")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;
    let subject_a = "round1-list-subject-a";
    let subject_b = "round1-list-subject-b";
    let (session_a, _) =
        create_subject_session(&client, &server, subject_a, "list-create-a").await?;
    let (session_b, _) =
        create_subject_session(&client, &server, subject_b, "list-create-b").await?;
    let missing = "00000000000000000000000000";

    let (status, body) = list_subject_sessions(&client, &server, subject_a).await?;
    assert_list_contains_only(status, &body, subject_a, &session_a, &session_b, missing)?;
    let (status, body) = list_subject_sessions(&client, &server, subject_b).await?;
    assert_list_contains_only(status, &body, subject_b, &session_b, &session_a, missing)?;

    server.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_caller_supplied_session_id_has_no_list_side_effect(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("caller-session-id-list-side-effect")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;
    let subject = "round1-caller-subject";
    let (existing_id, _) =
        create_subject_session(&client, &server, subject, "caller-list-existing").await?;

    let (before_status, before_body) = list_subject_sessions(&client, &server, subject).await?;
    assert_list_contains_only(
        before_status,
        &before_body,
        subject,
        &existing_id,
        "caller-supplied",
        "00000000000000000000000000",
    )?;

    let caller_response = authenticated_as(client.post(server.url("/v1/sessions")), subject)
        .header("Idempotency-Key", "caller-list-side-effect")
        .json(&json!({"session_id": "caller-supplied"}))
        .send_with_timeout()
        .await?;
    let caller_status = caller_response.status();
    let caller_body = response_text(caller_response).await?;
    assert_eq!(
        caller_status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{caller_body}"
    );
    let caller_json: Value = serde_json::from_str(&caller_body)?;
    assert_eq!(caller_json["error"]["code"], "invalid_request");

    let (after_status, after_body) = list_subject_sessions(&client, &server, subject).await?;
    assert_eq!(after_status, before_status);
    assert_eq!(after_body, before_body);
    assert!(!after_body.contains("caller-supplied"));

    server.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_message_unknown_field_is_rejected_without_effect(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("message-unknown-field")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;
    let subject = "unknown-field-subject";
    let (session_id, _) =
        create_subject_session(&client, &server, subject, "unknown-field-create").await?;

    let initial_response = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}/events"))),
        subject,
    )
    .header("Last-Event-ID", "0")
    .send_with_timeout()
    .await?;
    assert_eq!(initial_response.status(), StatusCode::OK);
    let initial = read_sse_events(initial_response, 1).await?.remove(0);
    let before_response = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}"))),
        subject,
    )
    .send_with_timeout()
    .await?;
    assert_eq!(before_response.status(), StatusCode::OK);
    let before = response_json(before_response).await?;

    let invalid = authenticated_as(
        client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))),
        subject,
    )
    .header("Idempotency-Key", "unknown-field-message")
    .json(&json!({"content": "must not append", "unexpected": 1}))
    .send_with_timeout()
    .await?;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let invalid_body = response_json(invalid).await?;
    assert_eq!(invalid_body["error"]["code"], "invalid_request");

    let after_response = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}"))),
        subject,
    )
    .send_with_timeout()
    .await?;
    assert_eq!(after_response.status(), StatusCode::OK);
    let after = response_json(after_response).await?;
    assert_eq!(after["version"], before["version"]);
    assert_eq!(after["transcript"], before["transcript"]);
    assert_session_replay_has_only_initial_event(&client, &server, subject, &session_id, &initial)
        .await?;

    server.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_malformed_message_json_is_rejected_without_effect(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("message-malformed-json")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;
    let subject = "malformed-message-subject";
    let (session_id, _) =
        create_subject_session(&client, &server, subject, "malformed-message-create").await?;

    let initial_response = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}/events"))),
        subject,
    )
    .header("Last-Event-ID", "0")
    .send_with_timeout()
    .await?;
    assert_eq!(initial_response.status(), StatusCode::OK);
    let initial = read_sse_events(initial_response, 1).await?.remove(0);
    let before_response = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}"))),
        subject,
    )
    .send_with_timeout()
    .await?;
    assert_eq!(before_response.status(), StatusCode::OK);
    let before = response_json(before_response).await?;

    let invalid = authenticated_as(
        client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))),
        subject,
    )
    .header("Idempotency-Key", "malformed-message")
    .header("Content-Type", "application/json")
    .body(r#"{"content":"unterminated"#)
    .send_with_timeout()
    .await?;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    let invalid_body = response_json(invalid).await?;
    assert_eq!(invalid_body["error"]["code"], "malformed_request");

    let after_response = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}"))),
        subject,
    )
    .send_with_timeout()
    .await?;
    assert_eq!(after_response.status(), StatusCode::OK);
    let after = response_json(after_response).await?;
    assert_eq!(after["version"], before["version"]);
    assert_eq!(after["transcript"], before["transcript"]);
    assert_session_replay_has_only_initial_event(&client, &server, subject, &session_id, &initial)
        .await?;

    server.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_callback_unknown_or_unauthorized_is_safe_not_found(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("callback-safe-not-found")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;
    let callback_url = server.url("/v1/callbacks/opaque-callback-id");
    let body = json!({
        "status": "completed",
        "result": {"content": "must not be admitted"}
    });

    let missing_bearer = client
        .post(&callback_url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send_with_timeout()
        .await?;
    let missing_status = missing_bearer.status();
    let missing_body = response_text(missing_bearer).await?;

    let wrong_bearer = client
        .post(&callback_url)
        .header("Authorization", "Bearer wrong-callback-bearer")
        .header("Content-Type", "application/json")
        .json(&body)
        .send_with_timeout()
        .await?;
    let wrong_status = wrong_bearer.status();
    let wrong_body = response_text(wrong_bearer).await?;

    assert_eq!(missing_status, StatusCode::NOT_FOUND, "{missing_body}");
    assert_eq!(wrong_status, StatusCode::NOT_FOUND, "{wrong_body}");
    assert_eq!(missing_body, wrong_body);
    let error: Value = serde_json::from_str(&missing_body)?;
    assert_eq!(error["error"]["code"], "callback_not_found");
    assert!(!missing_body.contains("opaque-callback-id"));
    assert!(!missing_body.contains("wrong-callback-bearer"));

    server.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_message_replay_only_replays_receipt_without_new_event(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("message-replay-only")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;
    let subject = "message-replay-only-subject";
    let (session_id, _) =
        create_subject_session(&client, &server, subject, "message-replay-create").await?;

    let append = |key: &str, content: &str, replay_only: bool| {
        let mut request = authenticated_as(
            client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))),
            subject,
        )
        .header("Idempotency-Key", key)
        .json(&json!({"content": content}));
        if replay_only {
            request = request.header("Zode-Idempotency-Mode", "replay-only");
        }
        request
    };

    let first = append("message-replay-key", "once", false)
        .send_with_timeout()
        .await?;
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let first_body = response_text(first).await?;

    let replay = append("message-replay-key", "once", false)
        .send_with_timeout()
        .await?;
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    assert_eq!(response_text(replay).await?, first_body);

    let replay_only = append("message-replay-key", "once", true)
        .send_with_timeout()
        .await?;
    assert_eq!(replay_only.status(), StatusCode::ACCEPTED);
    assert_eq!(response_text(replay_only).await?, first_body);

    let conflict = append("message-replay-key", "changed", true)
        .send_with_timeout()
        .await?;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(response_json(conflict).await?["error"]["code"], "conflict");

    let miss = append("message-replay-miss", "must not append", true)
        .send_with_timeout()
        .await?;
    assert_eq!(miss.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(miss).await?["error"]["code"],
        "idempotency_receipt_not_found"
    );

    let events = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}/events"))),
        subject,
    )
    .header("Last-Event-ID", "0")
    .send_with_timeout()
    .await?;
    assert_eq!(events.status(), StatusCode::OK);
    let records = read_sse_events(events, 2).await?;
    assert_eq!(records[0].event, "session_created");
    assert_eq!(records[1].event, "message_appended");

    server.stop().await?;
    Ok(())
}

fn receipt_admission_tool(adapter_url: &str) -> Value {
    json!({
        "name": "fixture_tool",
        "description": "receipt admission fixture",
        "input_schema": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "additionalProperties": false
        },
        "completion_mode": "response",
        "auto_wait_timeout_seconds": 20,
        "recovery": {
            "on_running_restart": "unknown_outcome",
            "retry_dispatch": "never"
        },
        "adapter": {"kind": "http", "url": adapter_url}
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_create_receipt_lookup_precedes_current_admission(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database = test_database("create-receipt-admission")?;
    let configured_tool = receipt_admission_tool("http://127.0.0.1:1/invoke");
    let config = write_endpoint_config(&database, vec![configured_tool], 1)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = http_client()?;
    let create_body = json!({"tools": ["fixture_tool"]});

    let first = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", "create-receipt-admission-key")
        .json(&create_body)
        .send_with_timeout()
        .await?;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_body = response_text(first).await?;
    let first_json: Value = serde_json::from_str(&first_body)?;
    let session_id = require_ulid(&first_json)?;
    assert_eq!(first_json["version"], 1);

    let events = authenticated(
        client
            .get(server.url(&format!("/v1/sessions/{session_id}/events")))
            .header("Last-Event-ID", "0"),
    )
    .send_with_timeout()
    .await?;
    assert_eq!(events.status(), StatusCode::OK);
    let events = read_sse_events(events, 1).await?;
    assert_eq!(events[0].event, "session_created");

    server.stop().await?;
    let config = write_endpoint_config(&database, Vec::new(), 1)?;
    let mut restarted = ConfiguredServer::start(&database, &config).await?;

    let replay = authenticated(client.post(restarted.url("/v1/sessions")))
        .header("Idempotency-Key", "create-receipt-admission-key")
        .json(&create_body)
        .send_with_timeout()
        .await?;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(response_text(replay).await?, first_body);

    let replay_only = authenticated(client.post(restarted.url("/v1/sessions")))
        .header("Idempotency-Key", "create-receipt-admission-key")
        .header("Zode-Idempotency-Mode", "replay-only")
        .json(&create_body)
        .send_with_timeout()
        .await?;
    assert_eq!(replay_only.status(), StatusCode::CREATED);
    assert_eq!(response_text(replay_only).await?, first_body);

    let conflict = authenticated(client.post(restarted.url("/v1/sessions")))
        .header("Idempotency-Key", "create-receipt-admission-key")
        .json(&json!({"tools": ["missing_tool"]}))
        .send_with_timeout()
        .await?;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(response_json(conflict).await?["error"]["code"], "conflict");

    let replay_miss = authenticated(client.post(restarted.url("/v1/sessions")))
        .header("Idempotency-Key", "create-receipt-admission-miss")
        .header("Zode-Idempotency-Mode", "replay-only")
        .json(&json!({"tools": ["missing_tool"]}))
        .send_with_timeout()
        .await?;
    assert_eq!(replay_miss.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(replay_miss).await?["error"]["code"],
        "idempotency_receipt_not_found"
    );

    // A new key must consult the restarted, current tool catalog only after
    // receipt lookup; the removed fixture tool is no longer admissible.
    let new_admission = authenticated(client.post(restarted.url("/v1/sessions")))
        .header("Idempotency-Key", "create-receipt-admission-new")
        .json(&create_body)
        .send_with_timeout()
        .await?;
    assert_eq!(new_admission.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response_json(new_admission).await?["error"]["code"],
        "invalid_request"
    );

    let session = authenticated(client.get(restarted.url(&format!("/v1/sessions/{session_id}"))))
        .send_with_timeout()
        .await?;
    assert_eq!(session.status(), StatusCode::OK);
    let session = response_json(session).await?;
    assert_eq!(session["version"], 1);
    assert_eq!(session["transcript"], json!([]));

    restarted.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn e2e_sse_concurrent_commits_are_replayed_in_durable_order(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("sse-commit-order")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;
    let subject = "sse-commit-order-subject";
    let (session_id, _) =
        create_subject_session(&client, &server, subject, "sse-commit-order-create").await?;

    let stream = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}/events"))),
        subject,
    )
    .header("Last-Event-ID", "0")
    .send_with_timeout()
    .await?;
    assert_eq!(stream.status(), StatusCode::OK);

    const MESSAGE_COUNT: usize = 12;
    let mut tasks = Vec::with_capacity(MESSAGE_COUNT);
    for index in 0..MESSAGE_COUNT {
        let client = client.clone();
        let url = server.url(&format!("/v1/sessions/{session_id}/messages"));
        let key = format!("sse-commit-order-{index}");
        tasks.push(tokio::spawn(async move {
            for _attempt in 0..32 {
                let response = authenticated_as(client.post(&url), subject)
                    .header("Idempotency-Key", &key)
                    .json(&json!({"content": format!("concurrent-{index}")}))
                    .send_with_timeout()
                    .await?;
                if response.status() == StatusCode::ACCEPTED {
                    return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
                }
                let status = response.status();
                let body = response_text(response).await?;
                if status != StatusCode::CONFLICT {
                    return Err(Error::other(format!(
                        "concurrent append failed with {status}: {body}"
                    ))
                    .into());
                }
                tokio::task::yield_now().await;
            }
            Err(Error::other("concurrent append did not admit").into())
        }));
    }
    for task in tasks {
        task.await??;
    }

    let records = read_sse_events(stream, MESSAGE_COUNT + 1).await?;
    assert_eq!(records.len(), MESSAGE_COUNT + 1);
    let mut previous = 0_u64;
    for (index, record) in records.iter().enumerate() {
        let id = record.id.parse::<u64>()?;
        assert!(id > previous, "SSE id regressed at {index}: {records:?}");
        previous = id;
        if index == 0 {
            assert_eq!(record.event, "session_created");
        } else {
            assert_eq!(record.event, "message_appended");
        }
    }

    server.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_invalid_last_event_id_is_malformed_request(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("invalid-last-event-id")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;
    let subject = "invalid-cursor-subject";
    let (session_id, _) =
        create_subject_session(&client, &server, subject, "invalid-cursor-create").await?;

    let response = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}/events"))),
        subject,
    )
    .header("Last-Event-ID", "nope")
    .send_with_timeout()
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_json(response).await?;
    assert_eq!(body["error"]["code"], "malformed_request");

    server.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_get_exposes_explicit_durable_model_selection(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("get-model-selection")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;
    let subject = "model-selection-subject";
    install_test_replica(&client, &server.base_url, "model-selection-replica").await?;
    let model = json!({
        "provider": "fixture-provider",
        "provider_execution": {
            "schema": "zode.provider-execution.v1",
            "revision": 1,
            "kind": "openai_compatible",
            "base_url": "http://127.0.0.1/v1"
        },
        "model": "fixture-model",
        "auth_authority_id": support::TEST_CONTROLLER_AUTHORITY,
        "auth_profile_id": support::TEST_AUTH_PROFILE,
        "minimum_auth_revision": 1
    });
    let create = authenticated_as(client.post(server.url("/v1/sessions")), subject)
        .header("Idempotency-Key", "model-selection-create")
        .json(&json!({"model": model}))
        .send_with_timeout()
        .await?;
    assert_eq!(create.status(), StatusCode::CREATED);
    let create_body = response_json(create).await?;
    let session_id = create_body["session_id"]
        .as_str()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "model create omitted session_id"))?;

    let response = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}"))),
        subject,
    )
    .send_with_timeout()
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await?;
    assert_eq!(body["model"]["provider"], "fixture-provider");
    assert_eq!(body["model"]["provider_execution_revision"], 1);
    assert_eq!(body["model"]["model"], "fixture-model");
    assert_eq!(
        body["model"]["auth_authority_id"],
        support::TEST_CONTROLLER_AUTHORITY
    );
    assert_eq!(body["model"]["auth_profile_id"], support::TEST_AUTH_PROFILE);
    assert_eq!(body["model"]["auth_revision"], 1);
    assert!(!body.to_string().contains(support::TEST_PROVIDER_SECRET));

    server.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_concurrent_create_receipt_and_event_are_atomic(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("concurrent-create-receipt")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;
    let create_url = server.url("/v1/sessions");
    let request_a = authenticated(client.clone().post(create_url.clone()))
        .header("Idempotency-Key", "concurrent-create")
        .json(&json!({}));
    let request_b = authenticated(client.clone().post(create_url))
        .header("Idempotency-Key", "concurrent-create")
        .json(&json!({}));
    let (response_a, response_b) =
        tokio::join!(request_a.send_with_timeout(), request_b.send_with_timeout());
    let response_a = response_a?;
    let response_b = response_b?;
    assert_eq!(response_a.status(), StatusCode::CREATED);
    assert_eq!(response_b.status(), StatusCode::CREATED);
    let body_a = response_text(response_a).await?;
    let body_b = response_text(response_b).await?;
    assert_eq!(body_a, body_b);
    let create_body: Value = serde_json::from_str(&body_a)?;
    let session_id = create_body["session_id"]
        .as_str()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "create response omitted session_id"))?;
    assert_eq!(create_body["version"], 1);

    let sse_response = authenticated(
        client
            .get(server.url(&format!("/v1/sessions/{session_id}/events")))
            .header("Last-Event-ID", "0"),
    )
    .send_with_timeout()
    .await?;
    assert_eq!(sse_response.status(), StatusCode::OK);

    let replay = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", "concurrent-create")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(response_text(replay).await?, body_a);

    let conflict = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", "concurrent-create")
        .json(&json!({"tools": ["different"]}))
        .send_with_timeout()
        .await?;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let conflict_body = response_text(conflict).await?;
    let conflict_json: Value = serde_json::from_str(&conflict_body)?;
    assert_eq!(conflict_json["error"]["code"], "conflict");

    let message =
        authenticated(client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))))
            .header("Idempotency-Key", "concurrent-create-message")
            .json(&json!({"content": "after atomic create"}))
            .send_with_timeout()
            .await?;
    assert_eq!(message.status(), StatusCode::ACCEPTED);
    let message_body = response_json(message).await?;
    assert_eq!(message_body["version"], 2);

    let events = read_sse_events(sse_response, 2).await?;
    let _ = assert_two_ordered_session_events(&events, session_id)?;

    let read = authenticated(client.get(server.url(&format!("/v1/sessions/{session_id}"))))
        .send_with_timeout()
        .await?;
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(response_json(read).await?["version"], 2);
    server.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_session_ownership_safe_not_found_and_ordered_sse(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("ownership-safe-not-found")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;
    let subject_a = "round1-subject-a";
    let subject_b = "round1-subject-b";
    let (session_a, _) = create_subject_session(&client, &server, subject_a, "ownership-a").await?;
    let (session_b, _) = create_subject_session(&client, &server, subject_b, "ownership-b").await?;
    let missing = "00000000000000000000000000";
    assert!(support::is_crockford_ulid(missing));
    let database_marker = database_path.path().to_string_lossy().to_string();
    let markers = [
        session_a.as_str(),
        session_b.as_str(),
        missing,
        database_marker.as_str(),
    ];

    for (subject, cross_id) in [
        (subject_a, session_b.as_str()),
        (subject_b, session_a.as_str()),
    ] {
        for resource in [
            OwnershipResource::Read,
            OwnershipResource::Message,
            OwnershipResource::Events,
        ] {
            assert_subject_safe_not_found(
                &client, &server, subject, cross_id, missing, resource, &markers,
            )
            .await?;
        }
    }

    let own_sse = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_a}/events"))),
        subject_a,
    )
    .send_with_timeout()
    .await?;
    assert_eq!(own_sse.status(), StatusCode::OK);

    let own_message = authenticated_as(
        client.post(server.url(&format!("/v1/sessions/{session_a}/messages"))),
        subject_a,
    )
    .header("Idempotency-Key", "ownership-own-message-a")
    .json(&json!({"content": "owned message"}))
    .send_with_timeout()
    .await?;
    assert_eq!(own_message.status(), StatusCode::ACCEPTED);
    let events = read_sse_events(own_sse, 2).await?;
    let _ = assert_two_ordered_session_events(&events, &session_a)?;
    server.stop().await?;
    Ok(())
}

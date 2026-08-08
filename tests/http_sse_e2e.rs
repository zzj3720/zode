#[path = "support/http_sse.rs"]
mod http_sse_support;
pub(crate) mod support;

use std::io::{Error, ErrorKind};

use http_sse_support::*;
use reqwest::StatusCode;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::{
    authenticated, authenticated_as, db_blocking, http_client, install_test_replica, require_ulid,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_create_receipt_projection_rebuilds_from_verified_creation_event(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database = test_database("create-receipt-projection-rebuild")?;
    let mut server = TestServer::start(&database).await?;
    let client = http_client()?;
    let create = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", "create-receipt-projection-key")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    assert_eq!(create.status(), StatusCode::CREATED);
    let first_body = response_text(create).await?;
    let first_json: Value = serde_json::from_str(&first_body)?;
    let session_id = require_ulid(&first_json)?;

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
    let database_file = database.path().to_owned();
    let session_for_db = session_id.clone();
    let session_for_events = session_id.clone();
    let (deleted, remaining_events) = db_blocking(move || {
        let connection = Connection::open(database_file)?;
        let deleted = connection.execute(
            "DELETE FROM session_create_receipts WHERE stream_id = ?1",
            params![session_for_db],
        )?;
        let remaining_events = connection.query_row(
            "SELECT COUNT(*) FROM events WHERE stream_id = ?1",
            params![session_for_events],
            |row| row.get::<_, i64>(0),
        )?;
        Ok((deleted, remaining_events))
    })
    .await?;
    assert_eq!(deleted, 1);
    assert_eq!(remaining_events, 1);

    let mut restarted = TestServer::start(&database).await?;
    let replay = authenticated(client.post(restarted.url("/v1/sessions")))
        .header("Idempotency-Key", "create-receipt-projection-key")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(response_text(replay).await?, first_body);

    let replay_only = authenticated(client.post(restarted.url("/v1/sessions")))
        .header("Idempotency-Key", "create-receipt-projection-key")
        .header("Zode-Idempotency-Mode", "replay-only")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    assert_eq!(replay_only.status(), StatusCode::CREATED);
    assert_eq!(response_text(replay_only).await?, first_body);

    let read = authenticated(client.get(restarted.url(&format!("/v1/sessions/{session_id}"))))
        .send_with_timeout()
        .await?;
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(response_json(read).await?["version"], 1);

    let replay_events = authenticated(
        client
            .get(restarted.url(&format!("/v1/sessions/{session_id}/events")))
            .header("Last-Event-ID", "0"),
    )
    .send_with_timeout()
    .await?;
    assert_eq!(replay_events.status(), StatusCode::OK);
    let replay_events = read_sse_events(replay_events, 1).await?;
    assert_eq!(replay_events[0].event, "session_created");

    restarted.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_conflicting_create_receipt_projection_fails_closed(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database = test_database("create-receipt-conflicting-projection")?;
    let mut server = TestServer::start(&database).await?;
    let client = http_client()?;

    let first = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", "conflicting-receipt-first")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_body: Value = response_json(first).await?;
    let first_session = require_ulid(&first_body)?.to_owned();
    let first_events = authenticated(
        client
            .get(server.url(&format!("/v1/sessions/{first_session}/events")))
            .header("Last-Event-ID", "0"),
    )
    .send_with_timeout()
    .await?;
    assert_eq!(first_events.status(), StatusCode::OK);
    assert_eq!(
        read_sse_events(first_events, 1).await?[0].event,
        "session_created"
    );

    let second = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", "conflicting-receipt-second")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    assert_eq!(second.status(), StatusCode::CREATED);
    let second_body: Value = response_json(second).await?;
    let second_session = require_ulid(&second_body)?.to_owned();
    let second_events = authenticated(
        client
            .get(server.url(&format!("/v1/sessions/{second_session}/events")))
            .header("Last-Event-ID", "0"),
    )
    .send_with_timeout()
    .await?;
    assert_eq!(second_events.status(), StatusCode::OK);
    assert_eq!(
        read_sse_events(second_events, 1).await?[0].event,
        "session_created"
    );

    server.stop().await?;
    let database_file = database.path().to_owned();
    let before_restart = db_blocking(move || {
        let mut connection = Connection::open(database_file)?;
        let transaction = connection.transaction()?;
        let (command_id, command_fingerprint): (String, Vec<u8>) = transaction.query_row(
            "SELECT command_id, command_fingerprint FROM events
             WHERE stream_id = ?1 AND stream_version = 1",
            params![first_session],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let (event_id, event_schema_version, event_type, payload, event_version): (
            String,
            i64,
            String,
            Vec<u8>,
            i64,
        ) = transaction.query_row(
            "SELECT event_id, event_schema_version, event_type, payload, stream_version
             FROM events WHERE stream_id = ?1 AND stream_version = 1",
            params![second_session],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        let event_fingerprint = receipt_event_fingerprint(
            &second_session,
            u64::try_from(event_version)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?,
            &event_id,
            &command_id,
            u32::try_from(event_schema_version)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?,
            &event_type,
            &payload,
        );
        let prefix_digest = receipt_prefix_digest(&second_session, &event_fingerprint);
        transaction.execute(
            "UPDATE events SET command_id = ?1, command_fingerprint = ?2,
                event_fingerprint = ?3
             WHERE stream_id = ?4 AND stream_version = 1",
            params![
                command_id,
                command_fingerprint,
                event_fingerprint,
                second_session
            ],
        )?;
        transaction.execute(
            "UPDATE integrity_anchors SET event_prefix_digest = ?1
             WHERE stream_id = ?2 AND stream_version = 1",
            params![prefix_digest, second_session],
        )?;
        transaction.execute(
            "UPDATE storage_metadata SET projections_dirty = 1 WHERE singleton = 1",
            [],
        )?;
        let duplicate_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM events WHERE stream_version = 1 AND command_id = ?1",
            params![command_id],
            |row| row.get(0),
        )?;
        if duplicate_count != 2 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        transaction.commit()?;
        receipt_recovery_snapshot(&connection)
    })
    .await?;

    let restart = TestServer::start(&database).await;
    assert!(
        restart.is_err(),
        "conflicting verified create receipt projection must fail before READY"
    );
    let expected = before_restart.clone();
    let database_file = database.path().to_owned();
    let after_restart = db_blocking(move || {
        let connection = Connection::open(database_file)?;
        receipt_recovery_snapshot(&connection)
    })
    .await?;
    assert_eq!(
        after_restart, expected,
        "failed repair changed receipt facts"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_ownerless_session_history_fails_closed(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database = test_database("ownerless-session-history")?;
    let mut server = TestServer::start(&database).await?;
    let client = http_client()?;
    let response = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", "ownerless-history-create")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response_json(response).await?;
    let session_id = require_ulid(&body)?.to_owned();
    let events = authenticated(
        client
            .get(server.url(&format!("/v1/sessions/{session_id}/events")))
            .header("Last-Event-ID", "0"),
    )
    .send_with_timeout()
    .await?;
    assert_eq!(events.status(), StatusCode::OK);
    assert_eq!(
        read_sse_events(events, 1).await?[0].event,
        "session_created"
    );

    server.stop().await?;
    let database_file = database.path().to_owned();
    let session_for_db = session_id.clone();
    let before_restart = db_blocking(move || {
        let mut connection = Connection::open(database_file)?;
        let transaction = connection.transaction()?;
        let (event_id, event_schema_version, command_id, event_type, payload, event_version): (
            String,
            i64,
            String,
            String,
            Vec<u8>,
            i64,
        ) = transaction.query_row(
            "SELECT event_id, event_schema_version, command_id, event_type, payload,
                    stream_version
             FROM events WHERE stream_id = ?1 AND stream_version = 1",
            params![session_for_db],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?;
        let mut payload_json: Value =
            serde_json::from_slice(&payload).map_err(|_| rusqlite::Error::InvalidQuery)?;
        payload_json["owner"] = Value::Null;
        let payload =
            serde_json::to_vec(&payload_json).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let event_fingerprint = receipt_event_fingerprint(
            &session_for_db,
            u64::try_from(event_version)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?,
            &event_id,
            &command_id,
            u32::try_from(event_schema_version)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?,
            &event_type,
            &payload,
        );
        let prefix_digest = receipt_prefix_digest(&session_for_db, &event_fingerprint);
        transaction.execute(
            "UPDATE events SET payload = ?1, event_fingerprint = ?2
             WHERE stream_id = ?3 AND stream_version = 1",
            params![payload, event_fingerprint, session_for_db],
        )?;
        transaction.execute(
            "UPDATE integrity_anchors SET event_prefix_digest = ?1
             WHERE stream_id = ?2 AND stream_version = 1",
            params![prefix_digest, session_for_db],
        )?;
        transaction.execute(
            "UPDATE storage_metadata SET projections_dirty = 1 WHERE singleton = 1",
            [],
        )?;
        transaction.commit()?;
        receipt_recovery_snapshot(&connection)
    })
    .await?;

    let restart = TestServer::start(&database).await;
    assert!(
        restart.is_err(),
        "ownerless history must fail before READY rather than guessing an owner"
    );
    let expected = before_restart.clone();
    let database_file = database.path().to_owned();
    let after_restart = db_blocking(move || {
        let connection = Connection::open(database_file)?;
        receipt_recovery_snapshot(&connection)
    })
    .await?;
    assert_eq!(
        after_restart, expected,
        "failed repair changed ownerless facts"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiptEventSnapshot {
    global_position: i64,
    stream_id: String,
    stream_version: i64,
    event_id: String,
    command_id: String,
    command_fingerprint_version: i64,
    command_fingerprint: Vec<u8>,
    event_schema_version: i64,
    event_type: String,
    payload: Vec<u8>,
    event_fingerprint_version: i64,
    event_fingerprint: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiptIndexSnapshot {
    authority_id: String,
    subject: String,
    command_id: String,
    fingerprint_version: i64,
    request_hash: Vec<u8>,
    stream_id: String,
    stream_version: i64,
    creation_global_position: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiptAnchorSnapshot {
    stream_id: String,
    stream_version: i64,
    event_prefix_digest_version: i64,
    event_prefix_digest: Vec<u8>,
    state_schema_version: i64,
    reducer_schema_version: i64,
    state_digest_version: i64,
    state_digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiptRecoverySnapshot {
    events: Vec<ReceiptEventSnapshot>,
    receipts: Vec<ReceiptIndexSnapshot>,
    anchors: Vec<ReceiptAnchorSnapshot>,
}

fn receipt_recovery_snapshot(
    connection: &Connection,
) -> Result<ReceiptRecoverySnapshot, rusqlite::Error> {
    let mut events_statement = connection.prepare(
        "SELECT global_position, stream_id, stream_version, event_id, command_id,
                command_fingerprint_version, command_fingerprint, event_schema_version,
                event_type, payload, event_fingerprint_version, event_fingerprint
         FROM events ORDER BY global_position",
    )?;
    let events = events_statement
        .query_map([], |row| {
            Ok(ReceiptEventSnapshot {
                global_position: row.get(0)?,
                stream_id: row.get(1)?,
                stream_version: row.get(2)?,
                event_id: row.get(3)?,
                command_id: row.get(4)?,
                command_fingerprint_version: row.get(5)?,
                command_fingerprint: row.get(6)?,
                event_schema_version: row.get(7)?,
                event_type: row.get(8)?,
                payload: row.get(9)?,
                event_fingerprint_version: row.get(10)?,
                event_fingerprint: row.get(11)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut receipts_statement = connection.prepare(
        "SELECT authority_id, subject, command_id, fingerprint_version, request_hash,
                stream_id, stream_version, creation_global_position
         FROM session_create_receipts
         ORDER BY authority_id, subject, command_id",
    )?;
    let receipts = receipts_statement
        .query_map([], |row| {
            Ok(ReceiptIndexSnapshot {
                authority_id: row.get(0)?,
                subject: row.get(1)?,
                command_id: row.get(2)?,
                fingerprint_version: row.get(3)?,
                request_hash: row.get(4)?,
                stream_id: row.get(5)?,
                stream_version: row.get(6)?,
                creation_global_position: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut anchors_statement = connection.prepare(
        "SELECT stream_id, stream_version, event_prefix_digest_version,
                event_prefix_digest, state_schema_version, reducer_schema_version,
                state_digest_version, state_digest
         FROM integrity_anchors ORDER BY stream_id, stream_version",
    )?;
    let anchors = anchors_statement
        .query_map([], |row| {
            Ok(ReceiptAnchorSnapshot {
                stream_id: row.get(0)?,
                stream_version: row.get(1)?,
                event_prefix_digest_version: row.get(2)?,
                event_prefix_digest: row.get(3)?,
                state_schema_version: row.get(4)?,
                reducer_schema_version: row.get(5)?,
                state_digest_version: row.get(6)?,
                state_digest: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ReceiptRecoverySnapshot {
        events,
        receipts,
        anchors,
    })
}

fn receipt_hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn receipt_event_fingerprint(
    stream_id: &str,
    stream_version: u64,
    event_id: &str,
    command_id: &str,
    event_schema_version: u32,
    event_type: &str,
    payload: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"zode:event-fingerprint:v1");
    receipt_hash_field(&mut hasher, stream_id.as_bytes());
    hasher.update(stream_version.to_be_bytes());
    receipt_hash_field(&mut hasher, event_id.as_bytes());
    receipt_hash_field(&mut hasher, command_id.as_bytes());
    hasher.update(event_schema_version.to_be_bytes());
    receipt_hash_field(&mut hasher, event_type.as_bytes());
    receipt_hash_field(&mut hasher, payload);
    hasher.finalize().to_vec()
}

fn receipt_prefix_digest(stream_id: &str, event_fingerprint: &[u8]) -> Vec<u8> {
    let mut seed = Sha256::new();
    seed.update(b"zode:event-prefix:v1");
    receipt_hash_field(&mut seed, stream_id.as_bytes());
    let seed = seed.finalize();
    let mut linked = Sha256::new();
    linked.update(b"zode:event-prefix-link:v1");
    receipt_hash_field(&mut linked, &seed);
    receipt_hash_field(&mut linked, event_fingerprint);
    linked.finalize().to_vec()
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_session_list_reflects_current_model_selection_after_update(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("list-current-model-selection")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;
    let subject = "list-current-model-selection-subject";
    install_test_replica(
        &client,
        &server.base_url,
        "list-current-model-selection-replica",
    )
    .await?;
    let initial_model = json!({
        "provider": "fixture-provider",
        "provider_execution": {
            "schema": "zode.provider-execution.v1",
            "revision": 1,
            "kind": "openai_compatible",
            "base_url": "http://127.0.0.1/v1"
        },
        "model": "fixture-model-v1",
        "auth_authority_id": support::TEST_CONTROLLER_AUTHORITY,
        "auth_profile_id": support::TEST_AUTH_PROFILE,
        "minimum_auth_revision": 1
    });
    let create = authenticated_as(client.post(server.url("/v1/sessions")), subject)
        .header("Idempotency-Key", "list-current-model-selection-create")
        .json(&json!({"model": initial_model}))
        .send_with_timeout()
        .await?;
    assert_eq!(create.status(), StatusCode::CREATED);
    let create_body = response_json(create).await?;
    let session_id = create_body["session_id"]
        .as_str()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "model create omitted session_id"))?;

    let sse_response = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}/events"))),
        subject,
    )
    .header("Last-Event-ID", "1")
    .send_with_timeout()
    .await?;
    assert_eq!(sse_response.status(), StatusCode::OK);

    let updated_model = json!({
        "provider": "fixture-provider",
        "provider_execution": {
            "schema": "zode.provider-execution.v1",
            "revision": 1,
            "kind": "openai_compatible",
            "base_url": "http://127.0.0.1/v1"
        },
        "model": "fixture-model-v2",
        "auth_authority_id": support::TEST_CONTROLLER_AUTHORITY,
        "auth_profile_id": support::TEST_AUTH_PROFILE,
        "minimum_auth_revision": 1
    });
    let update = authenticated_as(
        client.put(server.url(&format!("/v1/sessions/{session_id}/model"))),
        subject,
    )
    .header("Idempotency-Key", "list-current-model-selection-update")
    .json(&updated_model)
    .send_with_timeout()
    .await?;
    assert_eq!(update.status(), StatusCode::ACCEPTED);
    let update_body = response_json(update).await?;
    assert_eq!(update_body["version"], 2);

    let events = read_sse_events(sse_response, 1).await?;
    assert_eq!(events[0].event, "model_selection_changed");
    assert_eq!(events[0].data["version"], 2);
    assert_eq!(events[0].data["data"]["model"]["model"], "fixture-model-v2");

    let current = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}"))),
        subject,
    )
    .send_with_timeout()
    .await?;
    assert_eq!(current.status(), StatusCode::OK);
    let current_body = response_json(current).await?;
    assert_eq!(current_body["model"]["model"], "fixture-model-v2");

    let list = authenticated_as(client.get(server.url("/v1/sessions?limit=100")), subject)
        .send_with_timeout()
        .await?;
    assert_eq!(list.status(), StatusCode::OK);
    let list_body = response_json(list).await?;
    let item = list_body["items"]
        .as_array()
        .and_then(|items| items.iter().find(|item| item["session_id"] == session_id))
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "updated session omitted from list"))?;
    assert!(
        item["version"].as_u64().is_some_and(|version| version >= 2),
        "list did not advance after model selection: {item}"
    );
    assert_eq!(item["model"], current_body["model"]);
    assert_eq!(item["model"]["model"], "fixture-model-v2");

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

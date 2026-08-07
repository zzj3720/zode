mod support;

use std::{
    io::{Error, ErrorKind},
    path::Path,
    process::Stdio,
    time::Duration,
};

use futures_util::StreamExt;
use reqwest::{Client, Response, StatusCode};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::{
    authenticated, authenticated_as, db_blocking, http_client, install_test_replica, kill_and_reap,
    reap_child_on_drop, require_ulid, response_bytes, response_json, response_text,
    write_endpoint_config, HttpRequestExt, TempDatabase,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    time::timeout,
};

const READY_PREFIX: &str = "ZODE_READY ";
const SQLITE_DERIVED_INDEX_NAMES: [&str; 3] = [
    "events_by_stream_version",
    "events_by_command",
    "snapshots_by_stream_version",
];
const SQLITE_CANONICAL_TRIGGER_NAMES: [&str; 9] = [
    "events_insert_dirty",
    "event_streams_insert_dirty",
    "event_streams_update_dirty",
    "event_streams_delete_dirty",
    "commands_insert_dirty",
    "commands_update_dirty",
    "commands_delete_dirty",
    "events_update_invalidates_integrity",
    "events_delete_invalidates_integrity",
];
const SQLITE_EXTRA_INDEX_NAME: &str = "e2e_extra_events";

struct TestServer {
    child: Option<Child>,
    base_url: String,
}

impl TestServer {
    async fn start(database_path: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config_path = write_endpoint_config(database_path, Vec::new(), 1)?;
        let mut child = Command::new(env!("CARGO_BIN_EXE_zode"))
            .arg("--config")
            .arg(config_path)
            .arg("--database")
            .arg(database_path)
            .arg("--listen")
            .arg("127.0.0.1:0")
            .env("ZODE_SNAPSHOT_EVERY", "1")
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let error = Error::other("zode stdout was not piped for readiness");
                let _ = kill_and_reap(child).await;
                return Err(Box::new(error));
            }
        };
        let mut lines = BufReader::new(stdout).lines();
        let readiness = async {
            let line = timeout(Duration::from_secs(10), lines.next_line())
                .await
                .map_err(|_| Error::new(ErrorKind::TimedOut, "zode readiness deadline expired"))??
                .ok_or_else(|| {
                    Error::new(ErrorKind::UnexpectedEof, "zode exited before readiness")
                })?;
            let base_url = line
                .strip_prefix(READY_PREFIX)
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidData,
                        format!("unexpected readiness: {line}"),
                    )
                })?
                .trim()
                .to_owned();
            Ok::<String, Box<dyn std::error::Error + Send + Sync>>(base_url)
        }
        .await;
        match readiness {
            Ok(base_url) => Ok(Self {
                child: Some(child),
                base_url,
            }),
            Err(error) => {
                let status = kill_and_reap(child).await?;
                let status_kind = if status.success() { "zero" } else { "non-zero" };
                Err(Error::other(format!(
                    "{error}; zode child exited with {status_kind} process status {status}"
                ))
                .into())
            }
        }
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(child) = self.child.take() {
            let _ = kill_and_reap(child).await?;
        }
        Ok(())
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        reap_child_on_drop(self.child.take());
    }
}

#[derive(Clone, Debug, PartialEq)]
struct SseRecord {
    id: String,
    event: String,
    data: Value,
}

#[derive(Clone, Debug)]
struct SnapshotRow {
    snapshot_id: i64,
    stream_version: i64,
    payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct SqliteCatalogEvidence {
    event_count: i64,
    metadata_clean: bool,
    canonical_trigger_sql: Vec<(String, String)>,
    required_index_sql: Vec<(String, String)>,
}

fn read_sqlite_catalog_evidence(
    connection: &Connection,
    session_id: &str,
) -> rusqlite::Result<SqliteCatalogEvidence> {
    let event_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM events WHERE stream_id = ?1",
        params![session_id],
        |row| row.get(0),
    )?;
    let metadata_clean: bool = connection.query_row(
        "SELECT storage_schema_version = 1
                AND projection_schema_version = 1
                AND projections_dirty = 0
         FROM storage_metadata WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let mut canonical_trigger_sql = Vec::new();
    for trigger_name in SQLITE_CANONICAL_TRIGGER_NAMES {
        let sql: String = connection.query_row(
            "SELECT COALESCE(MAX(sql), '') FROM sqlite_master
             WHERE type = 'trigger' AND name = ?1",
            params![trigger_name],
            |row| row.get(0),
        )?;
        canonical_trigger_sql.push((trigger_name.to_owned(), sql));
    }
    let mut required_index_sql = Vec::new();
    for index_name in SQLITE_DERIVED_INDEX_NAMES {
        let sql: String = connection.query_row(
            "SELECT COALESCE(MAX(sql), '') FROM sqlite_master
             WHERE type = 'index' AND name = ?1",
            params![index_name],
            |row| row.get(0),
        )?;
        required_index_sql.push((index_name.to_owned(), sql));
    }
    Ok(SqliteCatalogEvidence {
        event_count,
        metadata_clean,
        canonical_trigger_sql,
        required_index_sql,
    })
}

fn test_database(label: &str) -> Result<TempDatabase, Box<dyn std::error::Error + Send + Sync>> {
    TempDatabase::new(label)
}

async fn json_response(
    response: Response,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    response_json(response).await
}

async fn read_sse_events(
    response: Response,
    wanted: usize,
) -> Result<Vec<SseRecord>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = response.bytes_stream();
    let mut buffer = Vec::new();
    let mut records = Vec::new();
    while records.len() < wanted {
        let chunk = timeout(Duration::from_secs(5), stream.next())
            .await?
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "SSE stream ended early"))??;
        buffer.extend_from_slice(&chunk);
        while let Some(frame_end) = find_frame_end(&buffer) {
            let frame = buffer.drain(..frame_end).collect::<Vec<_>>();
            if let Some(record) = parse_sse_frame(&frame)? {
                records.push(record);
                if records.len() == wanted {
                    break;
                }
            }
        }
    }
    Ok(records)
}

async fn create_subject_session(
    client: &Client,
    server: &TestServer,
    subject: &str,
    key: &str,
) -> Result<(String, Value), Box<dyn std::error::Error + Send + Sync>> {
    let response = authenticated_as(client.post(server.url("/v1/sessions")), subject)
        .header("Idempotency-Key", key)
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_response(response).await?;
    let session_id = body["session_id"]
        .as_str()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "create response omitted session_id"))?;
    Ok((session_id.to_owned(), body))
}

async fn list_subject_sessions(
    client: &Client,
    server: &TestServer,
    subject: &str,
) -> Result<(StatusCode, String), Box<dyn std::error::Error + Send + Sync>> {
    let response = authenticated_as(client.get(server.url("/v1/sessions?limit=100")), subject)
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_text(response).await?;
    Ok((status, body))
}

fn assert_two_ordered_session_events(
    events: &[SseRecord],
    session_id: &str,
) -> Result<(u64, u64), Box<dyn std::error::Error + Send + Sync>> {
    assert_eq!(events.len(), 2);
    let first_id = events[0].id.parse::<u64>()?;
    let second_id = events[1].id.parse::<u64>()?;
    assert!(
        first_id < second_id,
        "SSE ids were not increasing: {events:?}"
    );
    assert_eq!(events[0].event, "session_created");
    assert_eq!(events[1].event, "message_appended");
    assert_eq!(events[0].data["session_id"], session_id);
    assert_eq!(events[1].data["session_id"], session_id);
    assert_eq!(events[0].data["version"], 1);
    assert_eq!(events[1].data["version"], 2);
    Ok((first_id, second_id))
}

fn assert_list_contains_only(
    status: StatusCode,
    body: &str,
    subject: &str,
    own_session_id: &str,
    other_session_id: &str,
    missing_session_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert_eq!(status, StatusCode::OK, "list for {subject}: {body}");
    let list: Value = serde_json::from_str(body)?;
    assert_eq!(list["schema"], "zode.session-list.v1", "{body}");
    let items = list["items"]
        .as_array()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "session list omitted items"))?;
    assert_eq!(
        items.len(),
        1,
        "{subject} saw an unexpected number of sessions: {body}"
    );
    for item in items {
        item["session_id"].as_str().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "session list item omitted string session_id",
            )
        })?;
    }
    let only_session_id = items[0]["session_id"].as_str().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            "session list item omitted string session_id",
        )
    })?;
    assert_eq!(
        only_session_id, own_session_id,
        "{subject} saw the wrong session: {body}"
    );
    assert!(
        !body.contains(other_session_id),
        "{subject} saw another subject: {body}"
    );
    assert!(
        !body.contains(missing_session_id),
        "{subject} saw missing session: {body}"
    );
    Ok(())
}

fn assert_same_safe_not_found(
    label: &str,
    first: (StatusCode, String),
    second: (StatusCode, String),
    markers: &[&str],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert_eq!(first.0, StatusCode::NOT_FOUND, "{label}: first status");
    assert_eq!(second.0, StatusCode::NOT_FOUND, "{label}: second status");
    assert_eq!(first.0, second.0, "{label}: status differs");
    assert_eq!(first.1, second.1, "{label}: safe envelopes differ");
    let body: Value = serde_json::from_str(&first.1)?;
    assert_eq!(
        body["error"]["code"], "session_not_found",
        "{label}: {body}"
    );
    for marker in markers {
        assert!(!first.1.contains(marker), "{label} disclosed {marker}");
    }
    assert!(!first.1.to_lowercase().contains("sqlite"));
    assert!(!first.1.to_lowercase().contains("database"));
    Ok(())
}

async fn assert_session_replay_has_only_initial_event(
    client: &Client,
    server: &TestServer,
    subject: &str,
    session_id: &str,
    initial: &SseRecord,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let replay_response = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}/events"))),
        subject,
    )
    .header("Last-Event-ID", "0")
    .send_with_timeout()
    .await?;
    assert_eq!(replay_response.status(), StatusCode::OK);
    let replay = read_sse_events(replay_response, 1).await?;
    assert_eq!(replay, vec![initial.clone()]);

    let tail_response = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}/events"))),
        subject,
    )
    .header("Last-Event-ID", &initial.id)
    .send_with_timeout()
    .await?;
    assert_eq!(tail_response.status(), StatusCode::OK);
    match timeout(
        Duration::from_millis(750),
        read_sse_events(tail_response, 1),
    )
    .await
    {
        Err(_) => Ok(()),
        Ok(Ok(events)) => Err(Error::other(format!(
            "unexpected durable session event after cursor {}: {events:?}",
            initial.id
        ))
        .into()),
        Ok(Err(error)) => Err(error),
    }
}

#[derive(Clone, Copy)]
enum OwnershipResource {
    Read,
    Message,
    Events,
}

async fn assert_subject_safe_not_found(
    client: &Client,
    server: &TestServer,
    subject: &str,
    cross_id: &str,
    missing_id: &str,
    resource: OwnershipResource,
    markers: &[&str],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let request = |session_id: &str| match resource {
        OwnershipResource::Read => authenticated_as(
            client.get(server.url(&format!("/v1/sessions/{session_id}"))),
            subject,
        ),
        OwnershipResource::Message => authenticated_as(
            client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))),
            subject,
        )
        .header(
            "Idempotency-Key",
            format!("round1-not-found-{subject}-{session_id}"),
        )
        .json(&json!({"content": "must not cross"})),
        OwnershipResource::Events => authenticated_as(
            client.get(server.url(&format!("/v1/sessions/{session_id}/events"))),
            subject,
        )
        .header("Last-Event-ID", "0"),
    };
    let cross = request(cross_id).send_with_timeout().await?;
    let missing = request(missing_id).send_with_timeout().await?;
    let cross = (cross.status(), response_text(cross).await?);
    let missing = (missing.status(), response_text(missing).await?);
    assert_same_safe_not_found(
        match resource {
            OwnershipResource::Read => "GET",
            OwnershipResource::Message => "message",
            OwnershipResource::Events => "SSE",
        },
        cross,
        missing,
        markers,
    )
}

fn find_frame_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|position| position + 2)
}

fn parse_sse_frame(
    frame: &[u8],
) -> Result<Option<SseRecord>, Box<dyn std::error::Error + Send + Sync>> {
    let text = std::str::from_utf8(frame)?;
    let mut id = None;
    let mut event = None;
    let mut data = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("id: ") {
            id = Some(value.to_owned());
        } else if let Some(value) = line.strip_prefix("event: ") {
            event = Some(value.to_owned());
        } else if let Some(value) = line.strip_prefix("data: ") {
            data = Some(value.to_owned());
        }
    }
    match (id, event, data) {
        (Some(id), Some(event), Some(data)) => Ok(Some(SseRecord {
            id,
            event,
            data: serde_json::from_str(&data)?,
        })),
        _ => Ok(None),
    }
}

fn read_snapshots(path: &Path) -> rusqlite::Result<Vec<SnapshotRow>> {
    let connection = Connection::open(path)?;
    connection.busy_timeout(Duration::from_secs(5))?;
    let mut statement = connection.prepare(
        "SELECT snapshot_id, stream_version, payload
         FROM snapshots ORDER BY snapshot_id ASC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(SnapshotRow {
            snapshot_id: row.get(0)?,
            stream_version: row.get(1)?,
            payload: row.get(2)?,
        })
    })?;
    rows.collect()
}

fn event_cursor(path: &Path) -> rusqlite::Result<i64> {
    let connection = Connection::open(path)?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.query_row(
        "SELECT COALESCE(MAX(global_position), 0) FROM events",
        [],
        |row| row.get(0),
    )
}

async fn snapshots(
    path: &Path,
) -> Result<Vec<SnapshotRow>, Box<dyn std::error::Error + Send + Sync>> {
    let path = path.to_owned();
    db_blocking(move || read_snapshots(&path)).await
}

async fn cursor(path: &Path) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let path = path.to_owned();
    db_blocking(move || event_cursor(&path)).await
}

async fn create_history(
    database_path: &Path,
) -> Result<(TestServer, Client, String), Box<dyn std::error::Error + Send + Sync>> {
    let server = TestServer::start(database_path).await?;
    let client = http_client()?;
    let response = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", "create-history")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let session_id = require_ulid(&json_response(response).await?)?;

    let response =
        authenticated(client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))))
            .header("Idempotency-Key", "message-history")
            .json(&json!({"content": "historical message"}))
            .send_with_timeout()
            .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let _ = response_bytes(response).await?;
    let response = authenticated(client.get(server.url(&format!("/v1/sessions/{session_id}"))))
        .send_with_timeout()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response_bytes(response).await?;
    Ok((server, client, session_id))
}

async fn create_history_opaque(
    database_path: &Path,
) -> Result<(TestServer, Client, String), Box<dyn std::error::Error + Send + Sync>> {
    let server = TestServer::start(database_path).await?;
    let client = http_client()?;
    let response = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", "create-history")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let create_body = json_response(response).await?;
    let session_id = create_body["session_id"]
        .as_str()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "create response has no session_id"))?
        .to_owned();

    let response =
        authenticated(client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))))
            .header("Idempotency-Key", "message-history")
            .json(&json!({"content": "historical message"}))
            .send_with_timeout()
            .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let _ = response_bytes(response).await?;
    let response = authenticated(client.get(server.url(&format!("/v1/sessions/{session_id}"))))
        .send_with_timeout()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response_bytes(response).await?;
    Ok((server, client, session_id))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_create_message_sse_reconnect_get_restart_and_snapshot_cursor(
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

    let cursor_before = second_id as i64;
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
    let snapshots = snapshots(&database_path).await?;
    assert!(snapshots.iter().any(|row| row.stream_version == 1));
    assert!(snapshots.iter().any(|row| row.stream_version == 2));
    assert!(snapshots.iter().any(|row| row.stream_version == 3));
    assert_eq!(cursor(&database_path).await?, cursor_before + 1);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_snapshot_cannot_override_event_stream(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("snapshot-mismatch")?;
    let (mut server, client, session_id) = create_history(&database_path).await?;
    server.stop().await?;

    let snapshots = snapshots(&database_path).await?;
    let latest = snapshots
        .iter()
        .max_by_key(|row| row.snapshot_id)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "no snapshot candidate was created"))?;
    let mut state: Value = serde_json::from_slice(&latest.payload)?;
    state["transcript"] = json!([]);
    let payload = serde_json::to_vec(&state)?;
    let checksum = format!("sha256:{:x}", Sha256::digest(&payload));
    let database_file = database_path.path().to_owned();
    let snapshot_id = latest.snapshot_id;
    db_blocking(move || {
        let connection = Connection::open(database_file)?;
        connection.execute(
            "UPDATE snapshots SET payload = ?1, checksum = ?2 WHERE snapshot_id = ?3",
            params![payload, checksum, snapshot_id],
        )?;
        Ok(())
    })
    .await?;

    let mut restarted = TestServer::start(&database_path).await?;
    let response = authenticated(client.get(restarted.url(&format!("/v1/sessions/{session_id}"))))
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_text(response).await?;
    restarted.stop().await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "full replay should win over a semantically valid but inconsistent snapshot: {body}"
    );
    let body: Value = serde_json::from_str(&body)?;
    assert_eq!(body["version"], 2, "unexpected projection: {body}");
    assert_eq!(
        body["transcript"][0]["content"], "historical message",
        "snapshot contents overrode the event stream: {body}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_corrupt_latest_snapshot_falls_back(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("snapshot-corrupt")?;
    let (mut server, client, session_id) = create_history(&database_path).await?;
    server.stop().await?;

    let snapshots = snapshots(&database_path).await?;
    let latest = snapshots
        .iter()
        .max_by_key(|row| row.snapshot_id)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "no snapshot candidate was created"))?;
    assert!(snapshots
        .iter()
        .any(|row| row.snapshot_id != latest.snapshot_id));
    let database_file = database_path.path().to_owned();
    let snapshot_id = latest.snapshot_id;
    db_blocking(move || {
        let connection = Connection::open(database_file)?;
        connection.execute(
            "UPDATE snapshots SET payload = ?1 WHERE snapshot_id = ?2",
            params![
                "corrupt payload with the wrong SQLite column type",
                snapshot_id
            ],
        )?;
        Ok(())
    })
    .await?;

    let mut restarted = TestServer::start(&database_path).await?;
    let response = authenticated(client.get(restarted.url(&format!("/v1/sessions/{session_id}"))))
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_text(response).await?;
    restarted.stop().await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "corrupt latest snapshot should be skipped in favor of the old snapshot: {body}"
    );
    let body: Value = serde_json::from_str(&body)?;
    assert_eq!(body["version"], 2);
    assert_eq!(body["transcript"][0]["content"], "historical message");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
// SQLite-specific backend contract: dirty projections and missing required
// indexes are repaired, while a harmless extra index remains valid.
async fn e2e_sqlite_restart_rebuilds_derived_indexes_and_allows_harmless_extra_index(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("index-rebuild")?;
    let (mut server, client, session_id) = create_history_opaque(&database_path).await?;
    server.stop().await?;

    // SQLite-specific stage 1: dirty projection rows are repaired first. The
    // subsequent index-only corruption must start from a clean metadata fast path.
    let database_file = database_path.path().to_owned();
    let session_for_db = session_id.clone();
    let (event_count, remaining) = db_blocking(move || {
        let connection = Connection::open(database_file)?;
        let event_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM events WHERE stream_id = ?1",
            params![&session_for_db],
            |row| row.get(0),
        )?;
        connection.execute(
            "DELETE FROM event_streams WHERE stream_id = ?1",
            params![&session_for_db],
        )?;
        connection.execute(
            "DELETE FROM commands WHERE stream_id = ?1",
            params![&session_for_db],
        )?;
        let remaining: i64 = connection.query_row(
            "SELECT COUNT(*) FROM events WHERE stream_id = ?1",
            params![&session_for_db],
            |row| row.get(0),
        )?;
        Ok((event_count, remaining))
    })
    .await?;
    assert_eq!(event_count, 2);
    assert_eq!(remaining, event_count);

    let mut repaired = TestServer::start(&database_path).await?;
    let get_response =
        authenticated(client.get(repaired.url(&format!("/v1/sessions/{session_id}"))))
            .send_with_timeout()
            .await?;
    let get_status = get_response.status();
    let get_body = response_text(get_response).await?;
    let retry_response =
        authenticated(client.post(repaired.url(&format!("/v1/sessions/{session_id}/messages"))))
            .header("Idempotency-Key", "message-history")
            .json(&json!({"content": "historical message"}))
            .send_with_timeout()
            .await?;
    let retry_status = retry_response.status();
    let retry_body = response_text(retry_response).await?;
    repaired.stop().await?;
    assert!(
        get_status == StatusCode::OK && retry_status == StatusCode::ACCEPTED,
        "projection repair restart failed; GET status={get_status} body={get_body}; retry status={retry_status} body={retry_body}"
    );
    let get_body: Value = serde_json::from_str(&get_body)?;
    assert_eq!(get_body["version"], 2);
    assert_eq!(get_body["transcript"][0]["content"], "historical message");
    let retry_body: Value = serde_json::from_str(&retry_body)?;
    assert_eq!(retry_body["version"], 2);

    // SQLite-specific stage 2: remove only catalog indexes while metadata stays
    // clean, then require physical sqlite_master repair after public recovery.
    let database_file = database_path.path().to_owned();
    let (metadata_clean_before, metadata_clean_after) = db_blocking(move || {
        let connection = Connection::open(database_file)?;
        let metadata_clean_before: bool = connection.query_row(
            "SELECT storage_schema_version = 1
                    AND projection_schema_version = 1
                    AND projections_dirty = 0
             FROM storage_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if !metadata_clean_before {
            return Err(rusqlite::Error::InvalidQuery);
        }
        for index_name in SQLITE_DERIVED_INDEX_NAMES {
            let sql: String = connection.query_row(
                "SELECT sql FROM sqlite_master
                 WHERE type = 'index' AND name = ?1 AND sql IS NOT NULL",
                params![index_name],
                |row| row.get(0),
            )?;
            if sql.trim().is_empty() {
                return Err(rusqlite::Error::InvalidQuery);
            }
            connection.execute(&format!("DROP INDEX {index_name}"), [])?;
        }
        let metadata_clean_after: bool = connection.query_row(
            "SELECT storage_schema_version = 1
                    AND projection_schema_version = 1
                    AND projections_dirty = 0
             FROM storage_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        Ok((metadata_clean_before, metadata_clean_after))
    })
    .await?;
    assert!(metadata_clean_before);
    assert!(metadata_clean_after);

    let mut restarted = TestServer::start(&database_path).await?;
    let get_response =
        authenticated(client.get(restarted.url(&format!("/v1/sessions/{session_id}"))))
            .send_with_timeout()
            .await?;
    let get_status = get_response.status();
    let get_body = response_text(get_response).await?;
    let retry_response =
        authenticated(client.post(restarted.url(&format!("/v1/sessions/{session_id}/messages"))))
            .header("Idempotency-Key", "message-history")
            .json(&json!({"content": "historical message"}))
            .send_with_timeout()
            .await?;
    let retry_status = retry_response.status();
    let retry_body = response_text(retry_response).await?;
    restarted.stop().await?;
    assert!(
        get_status == StatusCode::OK && retry_status == StatusCode::ACCEPTED,
        "clean metadata/index-only restart failed; GET status={get_status} body={get_body}; retry status={retry_status} body={retry_body}"
    );
    let get_body: Value = serde_json::from_str(&get_body)?;
    assert_eq!(get_body["version"], 2);
    assert_eq!(get_body["transcript"][0]["content"], "historical message");
    let retry_body: Value = serde_json::from_str(&retry_body)?;
    assert_eq!(retry_body["version"], 2);

    let database_file = database_path.path().to_owned();
    let session_for_db = session_id.clone();
    let repaired_catalog = db_blocking(move || {
        let connection = Connection::open(database_file)?;
        read_sqlite_catalog_evidence(&connection, &session_for_db)
    })
    .await?;
    assert!(repaired_catalog.metadata_clean);
    assert!(repaired_catalog.event_count > 0);
    for (index_name, sql) in &repaired_catalog.required_index_sql {
        assert!(
            !sql.trim().is_empty(),
            "SQLite required index {index_name} was not rebuilt with SQL"
        );
    }
    for (trigger_name, sql) in &repaired_catalog.canonical_trigger_sql {
        assert!(
            !sql.trim().is_empty(),
            "SQLite canonical trigger {trigger_name} disappeared during projection repair"
        );
    }

    // SQLite-specific stage 3: a non-UNIQUE index outside the required set is
    // harmless catalog state. Preserve the clean facts, metadata, canonical
    // triggers, and required indexes while adding it to a stopped database.
    let database_file = database_path.path().to_owned();
    let session_for_db = session_id.clone();
    let (catalog_before_extra, catalog_after_extra, extra_sql) = db_blocking(move || {
        let connection = Connection::open(database_file)?;
        let catalog_before_extra = read_sqlite_catalog_evidence(&connection, &session_for_db)?;
        if !catalog_before_extra.metadata_clean || catalog_before_extra.event_count == 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if catalog_before_extra
            .canonical_trigger_sql
            .iter()
            .any(|(_, sql)| sql.trim().is_empty())
            || catalog_before_extra
                .required_index_sql
                .iter()
                .any(|(_, sql)| sql.trim().is_empty())
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let existing_extra: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
            params![SQLITE_EXTRA_INDEX_NAME],
            |row| row.get(0),
        )?;
        if existing_extra != 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        connection.execute("CREATE INDEX e2e_extra_events ON events(command_id)", [])?;
        let catalog_after_extra = read_sqlite_catalog_evidence(&connection, &session_for_db)?;
        let extra_sql: String = connection.query_row(
            "SELECT COALESCE(MAX(sql), '') FROM sqlite_master
             WHERE type = 'index' AND name = ?1",
            params![SQLITE_EXTRA_INDEX_NAME],
            |row| row.get(0),
        )?;
        if extra_sql.trim().is_empty() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok((catalog_before_extra, catalog_after_extra, extra_sql))
    })
    .await?;
    assert_eq!(
        catalog_before_extra, catalog_after_extra,
        "adding a harmless extra SQLite index changed facts, metadata, canonical triggers, or required indexes"
    );
    assert!(catalog_before_extra.metadata_clean);
    assert!(catalog_before_extra.event_count > 0);
    assert!(!extra_sql.trim().is_empty());

    let mut extra_index_server = match TestServer::start(&database_path).await {
        Ok(server) => server,
        Err(error) => {
            let message = error.to_string();
            if message.contains("readiness deadline expired") {
                return Err(Error::other(format!(
                    "harmless extra-index recovery was inconclusive: readiness timed out: {message}"
                ))
                .into());
            }
            if !message.contains("exited with non-zero process status") {
                return Err(Error::other(format!(
                    "harmless extra-index recovery was inconclusive: child was not proven to exit non-zero: {message}"
                ))
                .into());
            }
            if !message.contains("zode exited before readiness") {
                return Err(Error::other(format!(
                    "harmless extra-index recovery was inconclusive: child failed before a readiness EOF was observed: {message}"
                ))
                .into());
            }
            let database_file = database_path.path().to_owned();
            let session_for_db = session_id.clone();
            let (failure_catalog, failure_extra_sql) = db_blocking(move || {
                let connection = Connection::open(database_file)?;
                let catalog = read_sqlite_catalog_evidence(&connection, &session_for_db)?;
                let extra_sql: String = connection.query_row(
                    "SELECT COALESCE(MAX(sql), '') FROM sqlite_master
                     WHERE type = 'index' AND name = ?1",
                    params![SQLITE_EXTRA_INDEX_NAME],
                    |row| row.get(0),
                )?;
                Ok((catalog, extra_sql))
            })
            .await?;
            assert_eq!(failure_catalog, catalog_before_extra);
            assert_eq!(failure_extra_sql, extra_sql);
            return Err(Error::other(format!(
                "production rejected harmless extra SQLite index before readiness: {message}"
            ))
            .into());
        }
    };

    let response =
        authenticated(client.get(extra_index_server.url(&format!("/v1/sessions/{session_id}"))))
            .send_with_timeout()
            .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_response(response).await?;
    assert_eq!(body["version"], 2);
    assert_eq!(body["transcript"][0]["content"], "historical message");

    let response = authenticated(
        client.get(extra_index_server.url(&format!("/v1/sessions/{session_id}/events"))),
    )
    .send_with_timeout()
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let events = read_sse_events(response, 2).await?;
    let _ = assert_two_ordered_session_events(&events, &session_id)?;

    let response = authenticated(
        client.post(extra_index_server.url(&format!("/v1/sessions/{session_id}/messages"))),
    )
    .header("Idempotency-Key", "message-history")
    .json(&json!({"content": "historical message"}))
    .send_with_timeout()
    .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let replay = json_response(response).await?;
    assert_eq!(replay["version"], 2);

    extra_index_server.stop().await?;
    let database_file = database_path.path().to_owned();
    let session_for_db = session_id.clone();
    let (final_catalog, final_extra_sql) = db_blocking(move || {
        let connection = Connection::open(database_file)?;
        let catalog = read_sqlite_catalog_evidence(&connection, &session_for_db)?;
        let extra_sql: String = connection.query_row(
            "SELECT COALESCE(MAX(sql), '') FROM sqlite_master
             WHERE type = 'index' AND name = ?1",
            params![SQLITE_EXTRA_INDEX_NAME],
            |row| row.get(0),
        )?;
        Ok((catalog, extra_sql))
    })
    .await?;
    assert_eq!(final_catalog, catalog_before_extra);
    assert!(!final_extra_sql.trim().is_empty());
    Ok(())
}

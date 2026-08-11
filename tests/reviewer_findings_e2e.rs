mod support;

use std::{
    io::{Error, ErrorKind},
    path::Path,
    process::Stdio,
    time::Duration,
};

use futures_util::StreamExt;
use reqwest::{Client, Response, StatusCode};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::{
    authenticated, db_blocking, http_client, kill_and_reap, reap_child_on_drop, require_ulid,
    response_bytes, response_json, response_text, spawn_db_blocking, write_endpoint_config,
    ConfiguredServer, HttpRequestExt, TempDatabase, TestResult,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader, Lines},
    process::{Child, ChildStdout, Command},
    time::timeout,
};

const READY_PREFIX: &str = "ZODE_READY ";
const SNAPSHOT_STATE_SCHEMA_VERSION: i64 = 1;
const SNAPSHOT_REDUCER_SCHEMA_VERSION: i64 = 1;
const EVENTS_UPDATE_TRIGGER: &str = "events_update_invalidates_integrity";
const CANONICAL_TRIGGER_NAMES: [&str; 9] = [
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
const REQUIRED_INDEX_NAMES: [&str; 3] = [
    "events_by_stream_version",
    "events_by_command",
    "snapshots_by_stream_version",
];

struct Process {
    child: Option<Child>,
    lines: Lines<BufReader<ChildStdout>>,
    base_url: Option<String>,
    pid: u32,
    exit_status: Option<std::process::ExitStatus>,
}

impl Process {
    async fn spawn(database_path: &Path, snapshot_every: Option<&str>) -> TestResult<Self> {
        let config_path = write_endpoint_config(database_path, Vec::new(), 1)?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_zode"));
        command
            .arg("--config")
            .arg(config_path)
            .arg("--database")
            .arg(database_path)
            .arg("--listen")
            .arg("127.0.0.1:0");
        match snapshot_every {
            Some(value) => {
                command.env("ZODE_SNAPSHOT_EVERY", value);
            }
            None => {
                command.env_remove("ZODE_SNAPSHOT_EVERY");
            }
        }
        let mut child = command
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let pid = match child.id() {
            Some(pid) => pid,
            None => {
                let error = Error::other("zode child has no pid");
                let _ = kill_and_reap(child).await;
                return Err(Box::new(error));
            }
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let error = Error::other("zode stdout was not piped");
                let _ = kill_and_reap(child).await;
                return Err(Box::new(error));
            }
        };
        Ok(Self {
            child: Some(child),
            lines: BufReader::new(stdout).lines(),
            base_url: None,
            pid,
            exit_status: None,
        })
    }

    async fn wait_ready(&mut self, limit: Duration) -> TestResult<Option<String>> {
        let line = match timeout(limit, self.lines.next_line()).await {
            Ok(result) => result?,
            Err(_) => return Ok(None),
        };
        let Some(line) = line else {
            return Ok(None);
        };
        let url = line
            .strip_prefix(READY_PREFIX)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, line.clone()))?
            .trim()
            .to_owned();
        self.base_url = Some(url.clone());
        Ok(Some(url))
    }

    async fn wait_ready_or_reap(&mut self, limit: Duration) -> TestResult<Option<String>> {
        match self.wait_ready(limit).await {
            Ok(Some(url)) => Ok(Some(url)),
            Ok(None) => {
                self.stop().await?;
                Ok(None)
            }
            Err(error) => {
                let _ = self.stop().await;
                Err(error)
            }
        }
    }

    async fn start(database_path: &Path, snapshot_every: Option<&str>) -> TestResult<Self> {
        let mut process = Self::spawn(database_path, snapshot_every).await?;
        match process.wait_ready(Duration::from_secs(10)).await {
            Ok(Some(_)) => Ok(process),
            Ok(None) => {
                let pid = process.pid;
                process.stop().await?;
                Err(Box::new(Error::new(
                    ErrorKind::TimedOut,
                    format!("zode pid {pid} did not become ready"),
                )))
            }
            Err(error) => {
                let _ = process.stop().await;
                Err(error)
            }
        }
    }

    fn url(&self, path: &str) -> TestResult<String> {
        Ok(format!(
            "{}{}",
            self.base_url
                .as_deref()
                .ok_or_else(|| Error::other("zode is not ready"))?,
            path
        ))
    }

    async fn stop(&mut self) -> TestResult<()> {
        if let Some(child) = self.child.take() {
            self.exit_status = Some(kill_and_reap(child).await?);
        }
        Ok(())
    }

    fn is_alive(&mut self) -> std::io::Result<bool> {
        Ok(self
            .child
            .as_mut()
            .map(|child| child.try_wait().map(|status| status.is_none()))
            .transpose()?
            .unwrap_or(false))
    }

    fn was_reaped(&self) -> bool {
        self.child.is_none() && self.exit_status.is_some()
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        reap_child_on_drop(self.child.take());
    }
}

struct SseFrames {
    stream: futures_util::stream::BoxStream<'static, Result<bytes::Bytes, reqwest::Error>>,
    buffer: Vec<u8>,
}

impl SseFrames {
    fn new(response: Response) -> Self {
        Self {
            stream: response.bytes_stream().boxed(),
            buffer: Vec::new(),
        }
    }

    async fn next(&mut self) -> TestResult<SseRecord> {
        loop {
            while let Some(end) = self.buffer.windows(2).position(|window| window == b"\n\n") {
                let frame = self.buffer.drain(..end + 2).collect::<Vec<_>>();
                if let Some(record) = parse_sse_frame(&frame)? {
                    return Ok(record);
                }
            }
            let chunk = timeout(Duration::from_secs(10), self.stream.next())
                .await?
                .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "SSE ended early"))??;
            self.buffer.extend_from_slice(&chunk);
        }
    }
}

#[derive(Debug)]
struct SseRecord {
    id: u64,
    event: String,
    data: Value,
}

fn parse_sse_frame(frame: &[u8]) -> TestResult<Option<SseRecord>> {
    let text = std::str::from_utf8(frame)?;
    let mut id = None;
    let mut event = None;
    let mut data = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("id: ") {
            id = Some(value.parse::<u64>()?);
        } else if let Some(value) = line.strip_prefix("event: ") {
            event = Some(value.to_owned());
        } else if let Some(value) = line.strip_prefix("data: ") {
            data = Some(serde_json::from_str::<Value>(value)?);
        }
    }
    match (id, event, data) {
        (Some(id), Some(event), Some(data)) => Ok(Some(SseRecord { id, event, data })),
        _ => Ok(None),
    }
}

fn database_path(label: &str) -> TestResult<TempDatabase> {
    TempDatabase::new(label)
}

async fn create_session(client: &Client, process: &Process, key: &str) -> TestResult<String> {
    let body = create_session_body(client, process, key).await?;
    require_ulid(&body)
}

async fn create_session_body(client: &Client, process: &Process, key: &str) -> TestResult<Value> {
    let response = authenticated(client.post(process.url("/v1/sessions")?))
        .header("Idempotency-Key", key)
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_json(response).await?;
    if status != StatusCode::CREATED {
        return Err(Box::new(Error::other(format!(
            "create {key} returned {status}: {body}",
        ))));
    }
    Ok(body)
}

async fn create_session_opaque(
    client: &Client,
    process: &Process,
    key: &str,
) -> TestResult<String> {
    let body = create_session_body(client, process, key).await?;
    body["session_id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            Error::new(ErrorKind::InvalidData, "create response has no session_id").into()
        })
}

async fn append_message(
    client: &Client,
    process: &Process,
    session_id: &str,
    key: &str,
    content: &str,
) -> TestResult<Value> {
    let response =
        authenticated(client.post(process.url(&format!("/v1/sessions/{session_id}/messages"))?))
            .header("Idempotency-Key", key)
            .json(&json!({ "content": content }))
            .send_with_timeout()
            .await?;
    let status = response.status();
    let body = response_text(response).await?;
    if status != StatusCode::ACCEPTED {
        return Err(Box::new(Error::other(format!(
            "message {key} returned {status}: {body}"
        ))));
    }
    Ok(serde_json::from_str(&body)?)
}

async fn history(
    database_path: &Path,
    message_count: usize,
    content: &str,
    snapshot_every: Option<&str>,
) -> TestResult<(Process, Client, String, u64)> {
    let process = Process::start(database_path, snapshot_every).await?;
    let client = http_client()?;
    let session_id = create_session(&client, &process, "create-history").await?;
    let mut version = 1;
    for index in 0..message_count {
        let body = append_message(
            &client,
            &process,
            &session_id,
            &format!("history-message-{index}"),
            content,
        )
        .await?;
        version = body["version"]
            .as_u64()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "message response has no version"))?;
    }
    let response = authenticated(client.get(process.url(&format!("/v1/sessions/{session_id}"))?))
        .send_with_timeout()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response_bytes(response).await?;
    Ok((process, client, session_id, version))
}

async fn history_opaque(
    database_path: &Path,
    message_count: usize,
    content: &str,
    snapshot_every: Option<&str>,
) -> TestResult<(Process, Client, String, u64)> {
    let process = Process::start(database_path, snapshot_every).await?;
    let client = http_client()?;
    let session_id = create_session_opaque(&client, &process, "create-history-opaque").await?;
    let mut version = 1;
    for index in 0..message_count {
        let body = append_message(
            &client,
            &process,
            &session_id,
            &format!("history-opaque-message-{index}"),
            content,
        )
        .await?;
        version = body["version"]
            .as_u64()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "message response has no version"))?;
    }
    let response = authenticated(client.get(process.url(&format!("/v1/sessions/{session_id}"))?))
        .send_with_timeout()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response_bytes(response).await?;
    Ok((process, client, session_id, version))
}

#[derive(Debug)]
struct SnapshotCandidate {
    stream_version: u64,
}

async fn latest_compatible_snapshot(
    path: &Path,
    session_id: &str,
    head_version: u64,
) -> TestResult<Option<SnapshotCandidate>> {
    let path = path.to_owned();
    let session_id = session_id.to_owned();
    db_blocking(move || {
        let connection = Connection::open(path)?;
        let mut statement = connection.prepare(
            "SELECT snapshot_id, stream_id, stream_version,
                    state_schema_version, reducer_schema_version,
                    encoding, checksum, payload
             FROM snapshots
             WHERE stream_id = ?1
             ORDER BY stream_version DESC, snapshot_id DESC",
        )?;
        let rows = statement.query_map(params![&session_id], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Vec<u8>>(7)?,
            ))
        })?;
        for row in rows {
            let (
                stream_id,
                stream_version,
                state_schema_version,
                reducer_schema_version,
                encoding,
                checksum,
                payload,
            ) = row?;
            let Ok(stream_version_u64) = u64::try_from(stream_version) else {
                continue;
            };
            if stream_id != session_id
                || stream_version_u64 == 0
                || stream_version_u64 > head_version
                || state_schema_version != SNAPSHOT_STATE_SCHEMA_VERSION
                || reducer_schema_version != SNAPSHOT_REDUCER_SCHEMA_VERSION
                || encoding != "json"
            {
                continue;
            }
            let expected_checksum = format!("sha256:{:x}", Sha256::digest(&payload));
            if checksum != expected_checksum {
                continue;
            }
            let Ok(state) = serde_json::from_slice::<Value>(&payload) else {
                continue;
            };
            if state["session_id"] != session_id || state["stream_version"] != stream_version_u64 {
                continue;
            }
            return Ok(Some(SnapshotCandidate {
                stream_version: stream_version_u64,
            }));
        }
        Ok(None)
    })
    .await
}

async fn require_compatible_snapshot(
    path: &Path,
    session_id: &str,
    head_version: u64,
) -> TestResult<SnapshotCandidate> {
    latest_compatible_snapshot(path, session_id, head_version)
        .await?
        .ok_or_else(|| {
            Error::other(format!(
                "E setup failure: no compatible persisted snapshot for {session_id} at or before version {head_version}"
            ))
            .into()
        })
}

async fn assert_final_sse(
    client: &Client,
    process: &Process,
    session_id: &str,
    version: u64,
) -> TestResult<()> {
    let response = authenticated(client.get(process.url("/v1/events")?))
        .header("Last-Event-ID", version.saturating_sub(1).to_string())
        .send_with_timeout()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut events = SseFrames::new(response);
    let final_event = events.next().await?;
    assert_eq!(final_event.id, version);
    assert_eq!(final_event.event, "message_appended");
    assert_eq!(final_event.data["session_id"], session_id);
    assert_eq!(final_event.data["version"], version);
    Ok(())
}

async fn mutate_event(
    path: &Path,
    stream_id: &str,
    stream_version: i64,
    event_type: String,
    payload: Vec<u8>,
) -> TestResult<()> {
    let path = path.to_owned();
    let stream_id = stream_id.to_owned();
    db_blocking(move || {
        let connection = Connection::open(path)?;
        connection.execute(
            "UPDATE events SET event_type = ?1, payload = ?2
             WHERE stream_id = ?3 AND stream_version = ?4",
            params![event_type, payload, stream_id, stream_version],
        )?;
        Ok(())
    })
    .await
}

async fn corrupt_tail_messages_for_redaction(
    path: &Path,
    stream_id: &str,
    head_version: u64,
    marker: &str,
) -> TestResult<()> {
    let path = path.to_owned();
    let stream_id = stream_id.to_owned();
    let marker = marker.to_owned();
    db_blocking(move || {
        let head_version = i64::try_from(head_version)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        let mut connection = Connection::open(path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata_clean: bool = transaction.query_row(
            "SELECT storage_schema_version = 1
                    AND projection_schema_version = 1
                    AND projections_dirty = 0
             FROM storage_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if !metadata_clean || head_version < 3 {
            return Err(rusqlite::Error::InvalidQuery);
        }

        let anchor = transaction.query_row(
            "SELECT event_prefix_digest_version, event_prefix_digest,
                    state_schema_version, reducer_schema_version,
                    state_digest_version, state_digest
             FROM integrity_anchors
             WHERE stream_id = ?1 AND stream_version = ?2",
            params![&stream_id, head_version],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )?;

        for version in [head_version - 1, head_version] {
            let (event_id, command_id, schema_version, payload) = transaction.query_row(
                "SELECT event_id, command_id, event_schema_version, payload
                 FROM events WHERE stream_id = ?1 AND stream_version = ?2",
                params![&stream_id, version],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )?;
            let mut value = serde_json::from_slice::<Value>(&payload)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            let message = value
                .get_mut("message")
                .and_then(Value::as_object_mut)
                .ok_or(rusqlite::Error::InvalidQuery)?;
            message.insert("message_id".to_owned(), Value::String(marker.clone()));
            message.insert("content".to_owned(), Value::String(marker.clone()));
            let replacement = serde_json::to_vec(&value)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            let event_schema_version = u32::try_from(schema_version)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            let fingerprint = e2e_event_fingerprint(
                &stream_id,
                u64::try_from(version)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?,
                &event_id,
                &command_id,
                event_schema_version,
                "message_appended",
                &replacement,
            );
            let changed = transaction.execute(
                "UPDATE events SET event_type = 'message_appended', payload = ?1,
                        event_fingerprint = ?2
                 WHERE stream_id = ?3 AND stream_version = ?4",
                params![&replacement, &fingerprint, &stream_id, version],
            )?;
            if changed != 1 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
        }

        transaction.execute(
            "INSERT INTO integrity_anchors
                (stream_id, stream_version, event_prefix_digest_version,
                 event_prefix_digest, state_schema_version, reducer_schema_version,
                 state_digest_version, state_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                &stream_id,
                head_version,
                anchor.0,
                &anchor.1,
                anchor.2,
                anchor.3,
                anchor.4,
                &anchor.5,
            ],
        )?;
        transaction.execute(
            "UPDATE storage_metadata SET projections_dirty = 0 WHERE singleton = 1",
            [],
        )?;

        let clean_after: bool = transaction.query_row(
            "SELECT storage_schema_version = 1
                    AND projection_schema_version = 1
                    AND projections_dirty = 0
             FROM storage_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let marker_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM events
             WHERE stream_id = ?1 AND stream_version > 1
               AND instr(CAST(payload AS TEXT), ?2) > 0",
            params![&stream_id, &marker],
            |row| row.get(0),
        )?;
        let creation_contains_marker: bool = transaction.query_row(
            "SELECT instr(CAST(payload AS TEXT), ?2) > 0
             FROM events WHERE stream_id = ?1 AND stream_version = 1",
            params![&stream_id, &marker],
            |row| row.get(0),
        )?;
        let anchor_restored = transaction
            .query_row(
                "SELECT 1 FROM integrity_anchors
                 WHERE stream_id = ?1 AND stream_version = ?2",
                params![&stream_id, head_version],
                |_row| Ok(()),
            )
            .is_ok();
        if !clean_after || marker_count != 2 || creation_contains_marker || !anchor_restored {
            return Err(rusqlite::Error::InvalidQuery);
        }
        transaction.commit()?;
        Ok(())
    })
    .await
}

#[derive(Debug)]
struct PayloadRewriteEvidence {
    original: Vec<u8>,
    replacement: Vec<u8>,
}

async fn rewrite_event_payload_preserving_semantics(
    path: &Path,
    stream_id: &str,
    stream_version: u64,
) -> TestResult<PayloadRewriteEvidence> {
    let path = path.to_owned();
    let stream_id = stream_id.to_owned();
    db_blocking(move || {
        let stream_version = i64::try_from(stream_version)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        let connection = Connection::open(path)?;
        let original = connection.query_row(
            "SELECT payload FROM events
             WHERE stream_id = ?1 AND stream_version = ?2",
            params![&stream_id, stream_version],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let value = serde_json::from_slice::<Value>(&original)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        let compact = serde_json::to_vec(&value)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        let mut replacement = serde_json::to_vec_pretty(&value)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        if replacement == original {
            replacement = compact;
            replacement.push(b' ');
        }
        while replacement == original {
            replacement.push(b'\n');
        }
        let round_trip = serde_json::from_slice::<Value>(&replacement)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        if round_trip != value {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let changed = connection.execute(
            "UPDATE events SET payload = ?1
             WHERE stream_id = ?2 AND stream_version = ?3",
            params![replacement, &stream_id, stream_version],
        )?;
        if changed != 1 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        Ok(PayloadRewriteEvidence {
            original,
            replacement,
        })
    })
    .await
}

#[derive(Debug)]
struct TailPayloadIntegrityEvidence {
    event_count_before: i64,
    event_count_after: i64,
    projected_head_before: i64,
    projected_head_after: i64,
    max_event_version_after: i64,
    metadata_clean_after: bool,
    payload_changed: bool,
    event_fingerprint_preserved: bool,
    head_anchor_restored: bool,
}

async fn rewrite_tail_payload_restore_head_anchor(
    path: &Path,
    stream_id: &str,
) -> TestResult<TailPayloadIntegrityEvidence> {
    let path = path.to_owned();
    let stream_id = stream_id.to_owned();
    db_blocking(move || {
        let connection = Connection::open(path)?;
        let metadata_clean_before = connection.query_row(
            "SELECT storage_schema_version = 1
                    AND projection_schema_version = 1
                    AND projections_dirty = 0
             FROM storage_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if !metadata_clean_before {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let projected_head_before = connection.query_row(
            "SELECT current_version FROM event_streams WHERE stream_id = ?1",
            params![&stream_id],
            |row| row.get::<_, i64>(0),
        )?;
        let max_event_version_before = connection.query_row(
            "SELECT MAX(stream_version) FROM events WHERE stream_id = ?1",
            params![&stream_id],
            |row| row.get::<_, i64>(0),
        )?;
        if projected_head_before <= 0 || projected_head_before != max_event_version_before {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let event_count_before = connection.query_row(
            "SELECT COUNT(*) FROM events WHERE stream_id = ?1",
            params![&stream_id],
            |row| row.get::<_, i64>(0),
        )?;
        let anchor = connection.query_row(
            "SELECT event_prefix_digest_version, event_prefix_digest,
                    state_schema_version, reducer_schema_version,
                    state_digest_version, state_digest
             FROM integrity_anchors
             WHERE stream_id = ?1 AND stream_version = ?2",
            params![&stream_id, projected_head_before],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )?;
        let (original_payload, original_fingerprint) = connection.query_row(
            "SELECT payload, event_fingerprint FROM events
             WHERE stream_id = ?1 AND stream_version = ?2",
            params![&stream_id, projected_head_before],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?;
        let value = serde_json::from_slice::<Value>(&original_payload)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        let mut replacement = serde_json::to_vec_pretty(&value)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        if replacement == original_payload {
            replacement = serde_json::to_vec(&value)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            replacement.push(b' ');
        }
        let round_trip = serde_json::from_slice::<Value>(&replacement)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        if round_trip != value || replacement == original_payload {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let changed = connection.execute(
            "UPDATE events SET payload = ?1
             WHERE stream_id = ?2 AND stream_version = ?3",
            params![&replacement, &stream_id, projected_head_before],
        )?;
        if changed != 1 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        connection.execute(
            "DELETE FROM integrity_anchors
             WHERE stream_id = ?1 AND stream_version = ?2",
            params![&stream_id, projected_head_before],
        )?;
        connection.execute(
            "INSERT INTO integrity_anchors
                (stream_id, stream_version, event_prefix_digest_version,
                 event_prefix_digest, state_schema_version, reducer_schema_version,
                 state_digest_version, state_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                &stream_id,
                projected_head_before,
                anchor.0,
                &anchor.1,
                anchor.2,
                anchor.3,
                anchor.4,
                &anchor.5,
            ],
        )?;
        connection.execute(
            "UPDATE storage_metadata SET projections_dirty = 0 WHERE singleton = 1",
            [],
        )?;
        let projected_head_after = connection.query_row(
            "SELECT current_version FROM event_streams WHERE stream_id = ?1",
            params![&stream_id],
            |row| row.get::<_, i64>(0),
        )?;
        let max_event_version_after = connection.query_row(
            "SELECT MAX(stream_version) FROM events WHERE stream_id = ?1",
            params![&stream_id],
            |row| row.get::<_, i64>(0),
        )?;
        let event_count_after = connection.query_row(
            "SELECT COUNT(*) FROM events WHERE stream_id = ?1",
            params![&stream_id],
            |row| row.get::<_, i64>(0),
        )?;
        let replacement_fingerprint = connection.query_row(
            "SELECT event_fingerprint FROM events
             WHERE stream_id = ?1 AND stream_version = ?2",
            params![&stream_id, projected_head_before],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let restored_anchor = connection.query_row(
            "SELECT event_prefix_digest_version, event_prefix_digest,
                    state_schema_version, reducer_schema_version,
                    state_digest_version, state_digest
             FROM integrity_anchors
             WHERE stream_id = ?1 AND stream_version = ?2",
            params![&stream_id, projected_head_before],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )?;
        let metadata_clean_after = connection.query_row(
            "SELECT storage_schema_version = 1
                    AND projection_schema_version = 1
                    AND projections_dirty = 0
             FROM storage_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        Ok(TailPayloadIntegrityEvidence {
            event_count_before,
            event_count_after,
            projected_head_before,
            projected_head_after,
            max_event_version_after,
            metadata_clean_after,
            payload_changed: original_payload != replacement,
            event_fingerprint_preserved: original_fingerprint == replacement_fingerprint,
            head_anchor_restored: restored_anchor == anchor,
        })
    })
    .await
}

async fn replace_event_update_trigger_with_noop(path: &Path) -> TestResult<String> {
    let path = path.to_owned();
    db_blocking(move || {
        let connection = Connection::open(path)?;
        connection.execute_batch(&format!(
            "DROP TRIGGER IF EXISTS {EVENTS_UPDATE_TRIGGER};
             CREATE TRIGGER {EVENTS_UPDATE_TRIGGER}
             AFTER UPDATE ON events BEGIN
                 SELECT 1;
             END;"
        ))?;
        connection.query_row(
            "SELECT sql FROM sqlite_master
             WHERE type = 'trigger' AND name = ?1",
            params![EVENTS_UPDATE_TRIGGER],
            |row| row.get::<_, String>(0),
        )
    })
    .await
}

async fn integrity_anchor_exists(
    path: &Path,
    stream_id: &str,
    stream_version: u64,
) -> TestResult<bool> {
    let path = path.to_owned();
    let stream_id = stream_id.to_owned();
    db_blocking(move || {
        let stream_version = i64::try_from(stream_version)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        let connection = Connection::open(path)?;
        connection
            .query_row(
                "SELECT 1 FROM integrity_anchors
                 WHERE stream_id = ?1 AND stream_version = ?2",
                params![stream_id, stream_version],
                |_row| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
    })
    .await
}

async fn delete_stream_head_integrity_anchor(path: &Path, stream_id: &str) -> TestResult<u64> {
    let path = path.to_owned();
    let stream_id = stream_id.to_owned();
    db_blocking(move || {
        let connection = Connection::open(path)?;
        let head = connection.query_row(
            "SELECT current_version FROM event_streams WHERE stream_id = ?1",
            params![&stream_id],
            |row| row.get::<_, i64>(0),
        )?;
        let deleted = connection.execute(
            "DELETE FROM integrity_anchors
             WHERE stream_id = ?1 AND stream_version = ?2",
            params![&stream_id, head],
        )?;
        if deleted != 1 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        u64::try_from(head)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
    })
    .await
}

#[derive(Debug)]
struct MissingAnchorTableEvidence {
    storage_schema_before: i64,
    projection_schema_before: i64,
    storage_schema_after: i64,
    projection_schema_after: i64,
    dirty_before: bool,
    dirty_after: bool,
    anchor_table_after_exists: bool,
}

async fn drop_integrity_anchors_preserving_metadata(
    path: &Path,
) -> TestResult<MissingAnchorTableEvidence> {
    let path = path.to_owned();
    db_blocking(move || {
        let connection = Connection::open(path)?;
        let metadata_before = connection.query_row(
            "SELECT storage_schema_version, projection_schema_version, projections_dirty
             FROM storage_metadata WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            },
        )?;
        let anchor_count =
            connection.query_row("SELECT COUNT(*) FROM integrity_anchors", [], |row| {
                row.get::<_, i64>(0)
            })?;
        if metadata_before.2 || anchor_count == 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }

        connection.execute_batch("DROP TABLE integrity_anchors")?;
        let metadata_after = connection.query_row(
            "SELECT storage_schema_version, projection_schema_version, projections_dirty
             FROM storage_metadata WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            },
        )?;
        let anchor_table_after_exists = connection
            .query_row(
                "SELECT 1 FROM sqlite_master
                 WHERE type = 'table' AND name = 'integrity_anchors'",
                [],
                |_row| Ok(()),
            )
            .optional()?
            .is_some();
        Ok(MissingAnchorTableEvidence {
            storage_schema_before: metadata_before.0,
            projection_schema_before: metadata_before.1,
            storage_schema_after: metadata_after.0,
            projection_schema_after: metadata_after.1,
            dirty_before: metadata_before.2,
            dirty_after: metadata_after.2,
            anchor_table_after_exists,
        })
    })
    .await
}

#[derive(Debug)]
struct MissingMetadataTableEvidence {
    event_count: i64,
    anchor_count: i64,
    metadata_table_before: bool,
    metadata_table_after: bool,
}

async fn drop_storage_metadata_table(path: &Path) -> TestResult<MissingMetadataTableEvidence> {
    let path = path.to_owned();
    db_blocking(move || {
        let mut connection = Connection::open(path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata_table_before = transaction
            .query_row(
                "SELECT 1 FROM sqlite_master
                 WHERE type = 'table' AND name = 'storage_metadata'",
                [],
                |_row| Ok(()),
            )
            .optional()?
            .is_some();
        let event_count = transaction.query_row("SELECT COUNT(*) FROM events", [], |row| {
            row.get::<_, i64>(0)
        })?;
        let anchor_count =
            transaction.query_row("SELECT COUNT(*) FROM integrity_anchors", [], |row| {
                row.get::<_, i64>(0)
            })?;
        if !metadata_table_before || event_count == 0 || anchor_count == 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }

        transaction.execute_batch("DROP TABLE storage_metadata")?;
        let metadata_table_after = transaction
            .query_row(
                "SELECT 1 FROM sqlite_master
                 WHERE type = 'table' AND name = 'storage_metadata'",
                [],
                |_row| Ok(()),
            )
            .optional()?
            .is_some();
        let event_count_after =
            transaction.query_row("SELECT COUNT(*) FROM events", [], |row| {
                row.get::<_, i64>(0)
            })?;
        if metadata_table_after || event_count_after != event_count {
            return Err(rusqlite::Error::InvalidQuery);
        }
        transaction.commit()?;
        Ok(MissingMetadataTableEvidence {
            event_count,
            anchor_count,
            metadata_table_before,
            metadata_table_after,
        })
    })
    .await
}

#[derive(Debug)]
struct MissingMetadataRowEvidence {
    event_count: i64,
    metadata_table_exists: bool,
    metadata_rows_before: i64,
    metadata_rows_after: i64,
}

async fn delete_storage_metadata_row(path: &Path) -> TestResult<MissingMetadataRowEvidence> {
    let path = path.to_owned();
    db_blocking(move || {
        let mut connection = Connection::open(path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata_table_exists = transaction
            .query_row(
                "SELECT 1 FROM sqlite_master
                 WHERE type = 'table' AND name = 'storage_metadata'",
                [],
                |_row| Ok(()),
            )
            .optional()?
            .is_some();
        let metadata_rows_before = if metadata_table_exists {
            transaction.query_row(
                "SELECT COUNT(*) FROM storage_metadata WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )?
        } else {
            0
        };
        let event_count = transaction.query_row("SELECT COUNT(*) FROM events", [], |row| {
            row.get::<_, i64>(0)
        })?;
        if !metadata_table_exists || metadata_rows_before != 1 || event_count == 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }

        transaction.execute("DELETE FROM storage_metadata WHERE singleton = 1", [])?;
        let metadata_rows_after = transaction.query_row(
            "SELECT COUNT(*) FROM storage_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if metadata_rows_after != 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        transaction.commit()?;
        Ok(MissingMetadataRowEvidence {
            event_count,
            metadata_table_exists,
            metadata_rows_before,
            metadata_rows_after,
        })
    })
    .await
}

#[derive(Debug)]
struct NonPrimaryEventEvidence {
    event_count_before: i64,
    payload_bytes_before: i64,
    event_count_after: i64,
    payload_bytes_after: i64,
    global_position_primary_key: i64,
    canonical_trigger_count: usize,
    metadata_clean: bool,
}

async fn rebuild_events_without_primary_key(path: &Path) -> TestResult<NonPrimaryEventEvidence> {
    let path = path.to_owned();
    db_blocking(move || {
        let mut connection = Connection::open(path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (event_count_before, payload_bytes_before) = transaction.query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(payload)), 0) FROM events",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        let metadata_clean_before = transaction.query_row(
            "SELECT storage_schema_version = 1
                    AND projection_schema_version = 1
                    AND projections_dirty = 0
             FROM storage_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if event_count_before == 0 || !metadata_clean_before {
            return Err(rusqlite::Error::InvalidQuery);
        }

        let mut trigger_sql = Vec::with_capacity(CANONICAL_TRIGGER_NAMES.len());
        for name in CANONICAL_TRIGGER_NAMES {
            trigger_sql.push(transaction.query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                params![name],
                |row| row.get::<_, String>(0),
            )?);
        }
        let mut index_sql = Vec::with_capacity(REQUIRED_INDEX_NAMES.len());
        for name in REQUIRED_INDEX_NAMES {
            index_sql.push(transaction.query_row(
                "SELECT sql FROM sqlite_master
                 WHERE type = 'index' AND name = ?1 AND sql IS NOT NULL",
                params![name],
                |row| row.get::<_, String>(0),
            )?);
        }

        for name in CANONICAL_TRIGGER_NAMES {
            transaction.execute_batch(&format!("DROP TRIGGER IF EXISTS {name};"))?;
        }
        for name in REQUIRED_INDEX_NAMES {
            transaction.execute_batch(&format!("DROP INDEX IF EXISTS {name};"))?;
        }
        transaction.execute_batch(
            "ALTER TABLE events RENAME TO e2e_events_source;
             CREATE TABLE events (
                 global_position INTEGER NOT NULL,
                 stream_id TEXT NOT NULL,
                 stream_version INTEGER NOT NULL CHECK (stream_version > 0),
                 event_id TEXT NOT NULL,
                 command_id TEXT NOT NULL,
                 command_fingerprint_version INTEGER NOT NULL,
                 command_fingerprint BLOB NOT NULL,
                 event_schema_version INTEGER NOT NULL,
                 event_type TEXT NOT NULL,
                 payload BLOB NOT NULL,
                 event_fingerprint_version INTEGER NOT NULL,
                 event_fingerprint BLOB NOT NULL,
                 UNIQUE (stream_id, stream_version),
                 UNIQUE (stream_id, event_id)
             );
             INSERT INTO events (
                 global_position, stream_id, stream_version, event_id, command_id,
                 command_fingerprint_version, command_fingerprint, event_schema_version,
                 event_type, payload, event_fingerprint_version, event_fingerprint
             ) SELECT global_position, stream_id, stream_version, event_id, command_id,
                 command_fingerprint_version, command_fingerprint, event_schema_version,
                 event_type, payload, event_fingerprint_version, event_fingerprint
             FROM e2e_events_source ORDER BY global_position;
             DROP TABLE e2e_events_source;",
        )?;
        for sql in index_sql {
            transaction.execute_batch(&sql)?;
        }
        for sql in trigger_sql {
            transaction.execute_batch(&sql)?;
        }

        let global_position_primary_key = {
            let mut statement = transaction.prepare("PRAGMA table_info(events)")?;
            let mut rows = statement.query([])?;
            let mut primary_key = None;
            while let Some(row) = rows.next()? {
                if row.get::<_, String>(1)? == "global_position" {
                    primary_key = Some(row.get::<_, i64>(5)?);
                    break;
                }
            }
            primary_key.ok_or(rusqlite::Error::InvalidQuery)?
        };
        let (event_count_after, payload_bytes_after) = transaction.query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(payload)), 0) FROM events",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        let mut canonical_trigger_count = 0;
        for name in CANONICAL_TRIGGER_NAMES {
            if transaction
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                    params![name],
                    |_row| Ok(()),
                )
                .optional()?
                .is_some()
            {
                canonical_trigger_count += 1;
            }
        }
        let metadata_clean = transaction.query_row(
            "SELECT storage_schema_version = 1
                    AND projection_schema_version = 1
                    AND projections_dirty = 0
             FROM storage_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if event_count_after != event_count_before
            || payload_bytes_after != payload_bytes_before
            || global_position_primary_key != 0
            || canonical_trigger_count != CANONICAL_TRIGGER_NAMES.len()
            || !metadata_clean
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        transaction.commit()?;
        Ok(NonPrimaryEventEvidence {
            event_count_before,
            payload_bytes_before,
            event_count_after,
            payload_bytes_after,
            global_position_primary_key,
            canonical_trigger_count,
            metadata_clean,
        })
    })
    .await
}

const EXTRA_TRIGGER_NAME: &str = "e2e_extra_event_streams_delete_on_event_insert";

#[derive(Debug)]
struct ExtraTriggerEvidence {
    extra_trigger_exists: bool,
    canonical_trigger_count: usize,
    metadata_clean: bool,
}

async fn add_unknown_storage_trigger(path: &Path) -> TestResult<ExtraTriggerEvidence> {
    let path = path.to_owned();
    db_blocking(move || {
        let mut connection = Connection::open(path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(&format!(
            "CREATE TRIGGER {EXTRA_TRIGGER_NAME}
             AFTER INSERT ON events BEGIN
                 DELETE FROM event_streams WHERE stream_id = NEW.stream_id;
             END;"
        ))?;
        let extra_trigger_exists = transaction
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                params![EXTRA_TRIGGER_NAME],
                |_row| Ok(()),
            )
            .optional()?
            .is_some();
        let mut canonical_trigger_count = 0;
        for name in CANONICAL_TRIGGER_NAMES {
            if transaction
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                    params![name],
                    |_row| Ok(()),
                )
                .optional()?
                .is_some()
            {
                canonical_trigger_count += 1;
            }
        }
        let metadata_clean = transaction.query_row(
            "SELECT storage_schema_version = 1
                    AND projection_schema_version = 1
                    AND projections_dirty = 0
             FROM storage_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if !extra_trigger_exists
            || canonical_trigger_count != CANONICAL_TRIGGER_NAMES.len()
            || !metadata_clean
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        transaction.commit()?;
        Ok(ExtraTriggerEvidence {
            extra_trigger_exists,
            canonical_trigger_count,
            metadata_clean,
        })
    })
    .await
}

#[derive(Clone, Copy, Debug)]
enum AuthorityConstraintMutation {
    EventsStreamVersionUnique,
    EventsEventIdUnique,
    EventsStreamVersionNotNull,
    EventsStreamVersionCheck,
    IntegrityAnchorsCompositePrimaryKey,
    SnapshotsSnapshotIdPrimaryKey,
    SnapshotsStreamVersionNotNull,
    SnapshotsStreamVersionCheck,
}

#[derive(Debug, PartialEq, Eq)]
struct AuthorityFacts {
    event_count: i64,
    anchor_count: i64,
    snapshot_count: i64,
    fact_digest: Vec<u8>,
}

#[derive(Debug)]
struct AuthorityConstraintEvidence {
    facts_before: AuthorityFacts,
    facts_after: AuthorityFacts,
    metadata_clean_before: bool,
    metadata_clean_after: bool,
    canonical_trigger_count: usize,
    required_index_count: usize,
    mutated_constraint_present: bool,
}

fn authority_facts(connection: &Connection) -> rusqlite::Result<AuthorityFacts> {
    let event_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
    let anchor_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM integrity_anchors", [], |row| {
            row.get(0)
        })?;
    let snapshot_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))?;
    let mut digest = Sha256::new();
    for (tag, query) in [
        (
            "events",
            "SELECT COALESCE(group_concat(row, char(10)), '') FROM
             (SELECT printf('%lld|%s|%lld|%s|%s|%lld|%s|%lld|%s|%s|%lld|%s',
                 global_position, hex(stream_id), stream_version, hex(event_id), hex(command_id),
                 command_fingerprint_version, hex(command_fingerprint), event_schema_version,
                 hex(event_type), hex(payload), event_fingerprint_version, hex(event_fingerprint)) AS row
              FROM events ORDER BY global_position)",
        ),
        (
            "integrity_anchors",
            "SELECT COALESCE(group_concat(row, char(10)), '') FROM
             (SELECT printf('%s|%lld|%lld|%s|%lld|%lld|%lld|%s',
                 hex(stream_id), stream_version, event_prefix_digest_version,
                 hex(event_prefix_digest), state_schema_version, reducer_schema_version,
                 state_digest_version, hex(state_digest)) AS row
              FROM integrity_anchors ORDER BY stream_id, stream_version)",
        ),
        (
            "snapshots",
            "SELECT COALESCE(group_concat(row, char(10)), '') FROM
             (SELECT printf('%lld|%s|%lld|%lld|%lld|%s|%s|%s|%lld|%s|%lld|%s',
                 snapshot_id, hex(stream_id), stream_version, state_schema_version,
                 reducer_schema_version, hex(encoding), hex(checksum), hex(payload),
                 event_prefix_digest_version, hex(event_prefix_digest),
                 state_digest_version, hex(state_digest)) AS row
              FROM snapshots ORDER BY snapshot_id)",
        ),
    ] {
        e2e_hash_field(&mut digest, tag.as_bytes());
        let rows: String = connection.query_row(query, [], |row| row.get(0))?;
        e2e_hash_field(&mut digest, rows.as_bytes());
    }

    Ok(AuthorityFacts {
        event_count,
        anchor_count,
        snapshot_count,
        fact_digest: digest.finalize().to_vec(),
    })
}

fn metadata_is_clean(connection: &Connection) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT storage_schema_version = 1
                AND projection_schema_version = 1
                AND projections_dirty = 0
         FROM storage_metadata WHERE singleton = 1",
        [],
        |row| row.get(0),
    )
}

fn catalog_sqls(
    connection: &Connection,
    object_type: &str,
    names: &[&str],
) -> rusqlite::Result<Vec<String>> {
    names
        .iter()
        .map(|name| {
            connection.query_row(
                "SELECT sql FROM sqlite_master
                 WHERE type = ?1 AND name = ?2 AND sql IS NOT NULL",
                params![object_type, name],
                |row| row.get(0),
            )
        })
        .collect()
}

fn table_sql(connection: &Connection, table: &str) -> rusqlite::Result<String> {
    connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
        params![table],
        |row| row.get(0),
    )
}

fn column_shape(
    connection: &Connection,
    table: &str,
    column: &str,
) -> rusqlite::Result<(i64, i64)> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        if row.get::<_, String>(1)? == column {
            return Ok((row.get(3)?, row.get(5)?));
        }
    }
    Err(rusqlite::Error::QueryReturnedNoRows)
}

fn composite_primary_key_present(connection: &Connection, table: &str) -> rusqlite::Result<bool> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    let mut primary_keys = Vec::new();
    while let Some(row) = rows.next()? {
        let primary_key = row.get::<_, i64>(5)?;
        if primary_key > 0 {
            primary_keys.push((primary_key, row.get::<_, String>(1)?));
        }
    }
    primary_keys.sort_by_key(|(sequence, _)| *sequence);
    Ok(primary_keys
        == vec![
            (1, "stream_id".to_owned()),
            (2, "stream_version".to_owned()),
        ])
}

fn normalized_sql(sql: &str) -> String {
    sql.to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn table_contains(connection: &Connection, table: &str, fragment: &str) -> rusqlite::Result<bool> {
    Ok(normalized_sql(&table_sql(connection, table)?).contains(fragment))
}

fn authority_constraint_present(
    connection: &Connection,
    mutation: AuthorityConstraintMutation,
) -> rusqlite::Result<bool> {
    Ok(match mutation {
        AuthorityConstraintMutation::EventsStreamVersionUnique => {
            table_contains(connection, "events", "unique (stream_id, stream_version)")?
        }
        AuthorityConstraintMutation::EventsEventIdUnique => {
            table_contains(connection, "events", "unique (stream_id, event_id)")?
        }
        AuthorityConstraintMutation::EventsStreamVersionNotNull => {
            column_shape(connection, "events", "stream_version")?.0 == 1
        }
        AuthorityConstraintMutation::EventsStreamVersionCheck => table_contains(
            connection,
            "events",
            "stream_version integer not null check",
        )?,
        AuthorityConstraintMutation::IntegrityAnchorsCompositePrimaryKey => {
            composite_primary_key_present(connection, "integrity_anchors")?
        }
        AuthorityConstraintMutation::SnapshotsSnapshotIdPrimaryKey => table_contains(
            connection,
            "snapshots",
            "snapshot_id integer primary key autoincrement",
        )?,
        AuthorityConstraintMutation::SnapshotsStreamVersionNotNull => {
            column_shape(connection, "snapshots", "stream_version")?.0 == 1
        }
        AuthorityConstraintMutation::SnapshotsStreamVersionCheck => table_contains(
            connection,
            "snapshots",
            "stream_version integer not null check",
        )?,
    })
}

fn events_constraint_table_sql(mutation: AuthorityConstraintMutation) -> String {
    let stream_version = match mutation {
        AuthorityConstraintMutation::EventsStreamVersionNotNull => {
            "stream_version INTEGER CHECK (stream_version > 0)"
        }
        AuthorityConstraintMutation::EventsStreamVersionCheck => "stream_version INTEGER NOT NULL",
        _ => "stream_version INTEGER NOT NULL CHECK (stream_version > 0)",
    };
    let unique_constraints = match mutation {
        AuthorityConstraintMutation::EventsStreamVersionUnique => "UNIQUE (stream_id, event_id)",
        AuthorityConstraintMutation::EventsEventIdUnique => "UNIQUE (stream_id, stream_version)",
        _ => "UNIQUE (stream_id, stream_version), UNIQUE (stream_id, event_id)",
    };
    format!(
        "CREATE TABLE events (
             global_position INTEGER PRIMARY KEY AUTOINCREMENT,
             stream_id TEXT NOT NULL,
             {stream_version},
             event_id TEXT NOT NULL,
             command_id TEXT NOT NULL,
             command_fingerprint_version INTEGER NOT NULL,
             command_fingerprint BLOB NOT NULL,
             event_schema_version INTEGER NOT NULL,
             event_type TEXT NOT NULL,
             payload BLOB NOT NULL,
             event_fingerprint_version INTEGER NOT NULL,
             event_fingerprint BLOB NOT NULL,
             {unique_constraints}
         );"
    )
}

fn anchors_constraint_table_sql() -> &'static str {
    "CREATE TABLE integrity_anchors (
         stream_id TEXT NOT NULL,
         stream_version INTEGER NOT NULL CHECK (stream_version > 0),
         event_prefix_digest_version INTEGER NOT NULL,
         event_prefix_digest BLOB NOT NULL,
         state_schema_version INTEGER NOT NULL,
         reducer_schema_version INTEGER NOT NULL,
         state_digest_version INTEGER NOT NULL,
         state_digest BLOB NOT NULL
     );"
}

fn snapshots_constraint_table_sql(mutation: AuthorityConstraintMutation) -> String {
    let snapshot_id = match mutation {
        AuthorityConstraintMutation::SnapshotsSnapshotIdPrimaryKey => {
            "snapshot_id INTEGER NOT NULL"
        }
        _ => "snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT",
    };
    let stream_version = match mutation {
        AuthorityConstraintMutation::SnapshotsStreamVersionNotNull => {
            "stream_version INTEGER CHECK (stream_version >= 0)"
        }
        AuthorityConstraintMutation::SnapshotsStreamVersionCheck => {
            "stream_version INTEGER NOT NULL"
        }
        _ => "stream_version INTEGER NOT NULL CHECK (stream_version >= 0)",
    };
    format!(
        "CREATE TABLE snapshots (
             {snapshot_id},
             stream_id TEXT NOT NULL,
             {stream_version},
             state_schema_version INTEGER NOT NULL CHECK (state_schema_version >= 0),
             reducer_schema_version INTEGER NOT NULL CHECK (reducer_schema_version >= 0),
             encoding TEXT NOT NULL,
             checksum TEXT NOT NULL,
             payload BLOB NOT NULL,
             event_prefix_digest_version INTEGER NOT NULL,
             event_prefix_digest BLOB NOT NULL,
             state_digest_version INTEGER NOT NULL,
             state_digest BLOB NOT NULL
         );"
    )
}

async fn mutate_authority_constraint(
    path: &Path,
    mutation: AuthorityConstraintMutation,
) -> TestResult<AuthorityConstraintEvidence> {
    let path = path.to_owned();
    db_blocking(move || {
        let mut connection = Connection::open(path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let facts_before = authority_facts(&transaction)?;
        let metadata_clean_before = metadata_is_clean(&transaction)?;
        let trigger_sql = catalog_sqls(&transaction, "trigger", &CANONICAL_TRIGGER_NAMES)?;
        let index_sql = catalog_sqls(&transaction, "index", &REQUIRED_INDEX_NAMES)?;
        if facts_before.event_count == 0
            || !metadata_clean_before
            || trigger_sql.len() != CANONICAL_TRIGGER_NAMES.len()
            || index_sql.len() != REQUIRED_INDEX_NAMES.len()
            || !authority_constraint_present(&transaction, mutation)?
        {
            return Err(rusqlite::Error::InvalidQuery);
        }

        for name in CANONICAL_TRIGGER_NAMES {
            transaction.execute_batch(&format!("DROP TRIGGER IF EXISTS {name};"))?;
        }
        for name in REQUIRED_INDEX_NAMES {
            transaction.execute_batch(&format!("DROP INDEX IF EXISTS {name};"))?;
        }

        let (table, source, create_sql) = match mutation {
            AuthorityConstraintMutation::EventsStreamVersionUnique
            | AuthorityConstraintMutation::EventsEventIdUnique
            | AuthorityConstraintMutation::EventsStreamVersionNotNull
            | AuthorityConstraintMutation::EventsStreamVersionCheck => (
                "events",
                "e2e_authority_events_source",
                events_constraint_table_sql(mutation),
            ),
            AuthorityConstraintMutation::IntegrityAnchorsCompositePrimaryKey => (
                "integrity_anchors",
                "e2e_authority_anchors_source",
                anchors_constraint_table_sql().to_owned(),
            ),
            AuthorityConstraintMutation::SnapshotsSnapshotIdPrimaryKey
            | AuthorityConstraintMutation::SnapshotsStreamVersionNotNull
            | AuthorityConstraintMutation::SnapshotsStreamVersionCheck => (
                "snapshots",
                "e2e_authority_snapshots_source",
                snapshots_constraint_table_sql(mutation),
            ),
        };
        transaction.execute_batch(&format!(
            "ALTER TABLE {table} RENAME TO {source};
             {create_sql}
             INSERT INTO {table} SELECT * FROM {source};
             DROP TABLE {source};"
        ))?;

        for sql in index_sql {
            transaction.execute_batch(&sql)?;
        }
        for sql in trigger_sql {
            transaction.execute_batch(&sql)?;
        }

        let facts_after = authority_facts(&transaction)?;
        let metadata_clean_after = metadata_is_clean(&transaction)?;
        let canonical_trigger_count =
            catalog_sqls(&transaction, "trigger", &CANONICAL_TRIGGER_NAMES)?.len();
        let required_index_count =
            catalog_sqls(&transaction, "index", &REQUIRED_INDEX_NAMES)?.len();
        let mutated_constraint_present = authority_constraint_present(&transaction, mutation)?;
        if facts_after != facts_before
            || !metadata_clean_after
            || canonical_trigger_count != CANONICAL_TRIGGER_NAMES.len()
            || required_index_count != REQUIRED_INDEX_NAMES.len()
            || mutated_constraint_present
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        transaction.commit()?;
        Ok(AuthorityConstraintEvidence {
            facts_before,
            facts_after,
            metadata_clean_before,
            metadata_clean_after,
            canonical_trigger_count,
            required_index_count,
            mutated_constraint_present,
        })
    })
    .await
}

#[derive(Clone, Copy, Debug)]
enum ProjectionConstraintMutation {
    EventStreamsConstraints,
    CommandsConstraints,
}

#[derive(Debug)]
struct ProjectionMutationEvidence {
    authority_facts_before: AuthorityFacts,
    authority_facts_after: AuthorityFacts,
    projection_rows_before: i64,
    projection_rows_after: i64,
    metadata_clean: bool,
    canonical_trigger_count: usize,
    malformed_shape: bool,
}

fn projection_shape_valid(
    connection: &Connection,
    mutation: ProjectionConstraintMutation,
) -> rusqlite::Result<bool> {
    match mutation {
        ProjectionConstraintMutation::EventStreamsConstraints => {
            let (stream_not_null, stream_pk) =
                column_shape(connection, "event_streams", "stream_id")?;
            let (version_not_null, _) =
                column_shape(connection, "event_streams", "current_version")?;
            Ok(stream_not_null == 1
                && stream_pk == 1
                && version_not_null == 1
                && table_contains(connection, "event_streams", "check (current_version >= 0)")?)
        }
        ProjectionConstraintMutation::CommandsConstraints => {
            let (stream_not_null, stream_pk) = column_shape(connection, "commands", "stream_id")?;
            let (command_not_null, command_pk) =
                column_shape(connection, "commands", "command_id")?;
            let (first_not_null, _) = column_shape(connection, "commands", "first_version")?;
            let (last_not_null, _) = column_shape(connection, "commands", "last_version")?;
            let (count_not_null, _) = column_shape(connection, "commands", "event_count")?;
            Ok(stream_not_null == 1
                && command_not_null == 1
                && stream_pk == 1
                && command_pk == 2
                && first_not_null == 1
                && last_not_null == 1
                && count_not_null == 1
                && table_contains(connection, "commands", "check (first_version >= 0)")?
                && table_contains(connection, "commands", "check (last_version >= 0)")?
                && table_contains(connection, "commands", "check (event_count >= 0)")?)
        }
    }
}

fn projection_table_sql(mutation: ProjectionConstraintMutation) -> &'static str {
    match mutation {
        ProjectionConstraintMutation::EventStreamsConstraints => {
            "CREATE TABLE event_streams (
                 stream_id TEXT NOT NULL,
                 current_version INTEGER
             );"
        }
        ProjectionConstraintMutation::CommandsConstraints => {
            "CREATE TABLE commands (
                 stream_id TEXT NOT NULL,
                 command_id TEXT NOT NULL,
                 fingerprint_version INTEGER NOT NULL,
                 request_hash BLOB NOT NULL,
                 first_version INTEGER,
                 last_version INTEGER,
                 event_count INTEGER
             );"
        }
    }
}

async fn mutate_projection_constraints(
    path: &Path,
    mutation: ProjectionConstraintMutation,
) -> TestResult<ProjectionMutationEvidence> {
    let path = path.to_owned();
    db_blocking(move || {
        let mut connection = Connection::open(path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authority_facts_before = authority_facts(&transaction)?;
        let metadata_clean = metadata_is_clean(&transaction)?;
        let trigger_sql = catalog_sqls(&transaction, "trigger", &CANONICAL_TRIGGER_NAMES)?;
        if authority_facts_before.event_count == 0
            || !metadata_clean
            || trigger_sql.len() != CANONICAL_TRIGGER_NAMES.len()
            || !projection_shape_valid(&transaction, mutation)?
        {
            return Err(rusqlite::Error::InvalidQuery);
        }

        for name in CANONICAL_TRIGGER_NAMES {
            transaction.execute_batch(&format!("DROP TRIGGER IF EXISTS {name};"))?;
        }
        let (table, source) = match mutation {
            ProjectionConstraintMutation::EventStreamsConstraints => {
                ("event_streams", "e2e_projection_event_streams_source")
            }
            ProjectionConstraintMutation::CommandsConstraints => {
                ("commands", "e2e_projection_commands_source")
            }
        };
        let projection_rows_before: i64 =
            transaction.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
        transaction.execute_batch(&format!(
            "ALTER TABLE {table} RENAME TO {source};
             {}
             INSERT INTO {table} SELECT * FROM {source};
             DROP TABLE {source};",
            projection_table_sql(mutation)
        ))?;
        let projection_rows_after: i64 =
            transaction.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
        for sql in trigger_sql {
            transaction.execute_batch(&sql)?;
        }

        let authority_facts_after = authority_facts(&transaction)?;
        let canonical_trigger_count =
            catalog_sqls(&transaction, "trigger", &CANONICAL_TRIGGER_NAMES)?.len();
        let malformed_shape = !projection_shape_valid(&transaction, mutation)?;
        if authority_facts_after != authority_facts_before
            || projection_rows_after != projection_rows_before
            || !metadata_is_clean(&transaction)?
            || canonical_trigger_count != CANONICAL_TRIGGER_NAMES.len()
            || !malformed_shape
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        transaction.commit()?;
        Ok(ProjectionMutationEvidence {
            authority_facts_before,
            authority_facts_after,
            projection_rows_before,
            projection_rows_after,
            metadata_clean,
            canonical_trigger_count,
            malformed_shape,
        })
    })
    .await
}

async fn projection_constraints_are_valid(
    path: &Path,
    mutation: ProjectionConstraintMutation,
) -> TestResult<bool> {
    let path = path.to_owned();
    db_blocking(move || {
        let connection = Connection::open(path)?;
        projection_shape_valid(&connection, mutation)
    })
    .await
}

fn e2e_hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn e2e_event_fingerprint(
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
    e2e_hash_field(&mut hasher, stream_id.as_bytes());
    hasher.update(stream_version.to_be_bytes());
    e2e_hash_field(&mut hasher, event_id.as_bytes());
    e2e_hash_field(&mut hasher, command_id.as_bytes());
    hasher.update(event_schema_version.to_be_bytes());
    e2e_hash_field(&mut hasher, event_type.as_bytes());
    e2e_hash_field(&mut hasher, payload);
    hasher.finalize().to_vec()
}

#[derive(Debug)]
struct UnprojectedEventEvidence {
    dirty_before: bool,
    dirty_after: bool,
    projection_head_after: i64,
    max_event_version_after: i64,
    inserted_event_version: i64,
    event_fingerprint_correct: bool,
    new_anchor_exists: bool,
}

async fn insert_unprojected_event(
    path: &Path,
    stream_id: &str,
    head_version: u64,
) -> TestResult<UnprojectedEventEvidence> {
    let path = path.to_owned();
    let stream_id = stream_id.to_owned();
    db_blocking(move || {
        let head_version = i64::try_from(head_version)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        let inserted_version = head_version
            .checked_add(1)
            .ok_or(rusqlite::Error::InvalidQuery)?;
        let event_id = "e2e-unprojected-event";
        let command_id = "e2e-unprojected-command";
        let event_schema_version = 1_i64;
        let event_type = "status_changed";
        let payload = br#"{"type":"status_changed","status":"idle"}"#.to_vec();
        let fingerprint = e2e_event_fingerprint(
            &stream_id,
            u64::try_from(inserted_version)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?,
            event_id,
            command_id,
            event_schema_version as u32,
            event_type,
            &payload,
        );
        let command_fingerprint = Sha256::digest(&payload).to_vec();
        let connection = Connection::open(path)?;
        let dirty_before = connection.query_row(
            "SELECT projections_dirty FROM storage_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if dirty_before {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let projection_head_before = connection.query_row(
            "SELECT current_version FROM event_streams WHERE stream_id = ?1",
            params![&stream_id],
            |row| row.get::<_, i64>(0),
        )?;
        let max_event_version_before = connection.query_row(
            "SELECT MAX(stream_version) FROM events WHERE stream_id = ?1",
            params![&stream_id],
            |row| row.get::<_, i64>(0),
        )?;
        if projection_head_before != head_version || max_event_version_before != head_version {
            return Err(rusqlite::Error::InvalidQuery);
        }

        connection.execute(
            "INSERT INTO events
                (stream_id, stream_version, event_id, command_id,
                 command_fingerprint_version, command_fingerprint,
                 event_schema_version, event_type, payload,
                 event_fingerprint_version, event_fingerprint)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                &stream_id,
                inserted_version,
                event_id,
                command_id,
                1_i64,
                command_fingerprint,
                event_schema_version,
                event_type,
                &payload,
                1_i64,
                &fingerprint,
            ],
        )?;
        let dirty_after = connection.query_row(
            "SELECT projections_dirty FROM storage_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        let projection_head_after = connection.query_row(
            "SELECT current_version FROM event_streams WHERE stream_id = ?1",
            params![&stream_id],
            |row| row.get::<_, i64>(0),
        )?;
        let max_event_version_after = connection.query_row(
            "SELECT MAX(stream_version) FROM events WHERE stream_id = ?1",
            params![&stream_id],
            |row| row.get::<_, i64>(0),
        )?;
        let stored_fingerprint = connection.query_row(
            "SELECT event_fingerprint FROM events
             WHERE stream_id = ?1 AND stream_version = ?2",
            params![&stream_id, inserted_version],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let new_anchor_exists = connection
            .query_row(
                "SELECT 1 FROM integrity_anchors
                 WHERE stream_id = ?1 AND stream_version = ?2",
                params![&stream_id, inserted_version],
                |_row| Ok(()),
            )
            .optional()?
            .is_some();
        Ok(UnprojectedEventEvidence {
            dirty_before,
            dirty_after,
            projection_head_after,
            max_event_version_after,
            inserted_event_version: inserted_version,
            event_fingerprint_correct: stored_fingerprint == fingerprint,
            new_anchor_exists,
        })
    })
    .await
}

fn assert_neutral_internal_error(label: &str, body: &str, session_id: &str) {
    assert!(
        !body.contains(session_id),
        "{label} disclosed session id: {body}"
    );
    let lower = body.to_ascii_lowercase();
    assert!(
        !lower.contains("sqlite"),
        "{label} disclosed sqlite detail: {body}"
    );
    assert!(
        !lower.contains("integrity"),
        "{label} disclosed integrity detail: {body}"
    );
    assert!(
        !lower.contains("anchor"),
        "{label} disclosed anchor detail: {body}"
    );
}

async fn assert_corrupt_public_views(
    client: &Client,
    process: &Process,
    session_id: &str,
) -> TestResult<()> {
    let get_response =
        authenticated(client.get(process.url(&format!("/v1/sessions/{session_id}"))?))
            .send_with_timeout()
            .await?;
    let get_status = get_response.status();
    let get_body = response_text(get_response).await?;

    let sse_response = authenticated(client.get(process.url("/v1/events")?))
        .send_with_timeout()
        .await?;
    let sse_status = sse_response.status();
    let sse_body = if sse_status == StatusCode::INTERNAL_SERVER_ERROR {
        response_text(sse_response).await?
    } else {
        drop(sse_response);
        String::new()
    };
    if get_status != StatusCode::INTERNAL_SERVER_ERROR
        || sse_status != StatusCode::INTERNAL_SERVER_ERROR
    {
        return Err(Error::other(format!(
            "corrupt public views were not neutral 500: GET={get_status} body={get_body}; SSE={sse_status} body={sse_body}"
        ))
        .into());
    }
    assert_neutral_internal_error("corrupt GET", &get_body, session_id);
    assert_neutral_internal_error("corrupt SSE", &sse_body, session_id);
    Ok(())
}

async fn begin_immediate_writer(path: &Path) -> TestResult<WriterBarrier> {
    let path = path.to_owned();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let task = spawn_db_blocking(move || -> TestResult<()> {
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ready_tx
            .send(())
            .map_err(|_| Error::other("writer barrier receiver dropped"))?;
        release_rx
            .recv()
            .map_err(|_| Error::other("writer barrier release dropped"))?;
        drop(transaction);
        Ok(())
    });
    tokio::task::spawn_blocking(move || ready_rx.recv()).await??;
    Ok(WriterBarrier {
        release: Some(release_tx),
        task: Some(task),
    })
}

struct WriterBarrier {
    release: Option<std::sync::mpsc::Sender<()>>,
    task: Option<tokio::task::JoinHandle<TestResult<()>>>,
}

impl WriterBarrier {
    async fn release(mut self) -> TestResult<()> {
        self.release
            .take()
            .ok_or_else(|| Error::other("writer barrier already released"))?
            .send(())
            .map_err(|_| Error::other("writer barrier worker exited"))?;
        self.task
            .take()
            .ok_or_else(|| Error::other("writer barrier task already consumed"))?
            .await??;
        Ok(())
    }
}

impl Drop for WriterBarrier {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_snapshot_cannot_mask_covered_prefix_payload_mutation() -> TestResult<()> {
    let path = database_path("snapshot-covered-prefix-corruption")?;
    let (mut process, client, session_id, head_version) =
        history_opaque(&path, 3, "snapshot-covered-prefix", Some("1")).await?;
    assert_final_sse(&client, &process, &session_id, head_version).await?;
    process.stop().await?;

    let snapshot = require_compatible_snapshot(&path, &session_id, head_version).await?;
    rewrite_event_payload_preserving_semantics(&path, &session_id, snapshot.stream_version).await?;

    let mut restarted = Process::start(&path, Some("1")).await?;
    let result = assert_corrupt_public_views(&client, &restarted, &session_id).await;
    restarted.stop().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_tail_payload_mutation_with_restored_head_anchor_is_not_blessed() -> TestResult<()> {
    let path = database_path("tail-payload-integrity")?;
    let (mut process, client, session_id, head_version) =
        history_opaque(&path, 2, "tail-payload-integrity", None).await?;
    assert_final_sse(&client, &process, &session_id, head_version).await?;
    process.stop().await?;

    let evidence = rewrite_tail_payload_restore_head_anchor(&path, &session_id).await?;
    assert_eq!(evidence.event_count_before, evidence.event_count_after);
    assert_eq!(
        evidence.projected_head_before,
        evidence.projected_head_after
    );
    assert_eq!(
        evidence.max_event_version_after,
        evidence.projected_head_before
    );
    assert!(evidence.metadata_clean_after);
    assert!(evidence.payload_changed);
    assert!(evidence.event_fingerprint_preserved);
    assert!(evidence.head_anchor_restored);

    let config = write_endpoint_config(&path, Vec::new(), 1)?;
    match ConfiguredServer::start_with_readiness_timeout(&path, &config, Duration::from_secs(2))
        .await
    {
        Err(error) => {
            let message = error.to_string();
            assert!(
                !message.contains("did not become ready"),
                "tail corruption was reported only as readiness timeout: {message}"
            );
            assert!(
                message.contains("non-zero"),
                "tail corruption did not produce active non-zero failure: {message}"
            );
            Ok(())
        }
        Ok(mut restarted) => {
            let client = http_client()?;
            let get_response =
                authenticated(client.get(restarted.url(&format!("/v1/sessions/{session_id}"))))
                    .send_with_timeout()
                    .await?;
            let get_status = get_response.status();
            let get_body = response_text(get_response).await?;
            let sse_response = authenticated(client.get(restarted.url("/v1/events")))
                .send_with_timeout()
                .await?;
            let sse_status = sse_response.status();
            let sse_body = if sse_status == StatusCode::INTERNAL_SERVER_ERROR {
                response_text(sse_response).await?
            } else {
                String::new()
            };
            restarted.stop().await?;
            assert_eq!(
                get_status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "tail payload corruption was silently accepted by GET: {get_body}"
            );
            assert_eq!(
                sse_status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "tail payload corruption was silently accepted by SSE: {sse_body}"
            );
            assert_neutral_internal_error("tail corruption GET", &get_body, &session_id);
            assert_neutral_internal_error("tail corruption SSE", &sse_body, &session_id);
            Ok(())
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_existing_events_without_storage_metadata_table_rejected_before_ready() -> TestResult<()>
{
    let path = database_path("events-without-storage-metadata-table")?;
    let (mut process, client, session_id, head_version) =
        history_opaque(&path, 2, "metadata table missing", None).await?;
    assert_final_sse(&client, &process, &session_id, head_version).await?;
    process.stop().await?;

    let evidence = drop_storage_metadata_table(&path).await?;
    assert!(evidence.event_count > 0);
    assert!(evidence.anchor_count > 0);
    assert!(evidence.metadata_table_before);
    assert!(!evidence.metadata_table_after);

    let config = write_endpoint_config(&path, Vec::new(), 1)?;
    require_active_nonzero_start_failure(
        &path,
        &config,
        "existing events without storage_metadata table",
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_missing_storage_metadata_row_cannot_bless_payload_mutation() -> TestResult<()> {
    let path = database_path("missing-storage-metadata-row")?;
    let (mut process, client, session_id, head_version) =
        history_opaque(&path, 3, "metadata row missing", Some("1")).await?;
    assert_final_sse(&client, &process, &session_id, head_version).await?;
    process.stop().await?;

    let snapshot = require_compatible_snapshot(&path, &session_id, head_version).await?;
    assert!(snapshot.stream_version > 0);
    assert!(snapshot.stream_version <= head_version);
    let rewrite =
        rewrite_event_payload_preserving_semantics(&path, &session_id, snapshot.stream_version)
            .await?;
    assert_ne!(rewrite.original, rewrite.replacement);
    assert_eq!(
        serde_json::from_slice::<Value>(&rewrite.original)?,
        serde_json::from_slice::<Value>(&rewrite.replacement)?
    );

    let evidence = delete_storage_metadata_row(&path).await?;
    assert!(evidence.event_count > 0);
    assert!(evidence.metadata_table_exists);
    assert_eq!(evidence.metadata_rows_before, 1);
    assert_eq!(evidence.metadata_rows_after, 0);

    let config = write_endpoint_config(&path, Vec::new(), 1)?;
    require_active_nonzero_start_failure(
        &path,
        &config,
        "missing storage_metadata row after payload mutation",
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_authority_schema_without_event_primary_key_rejected_before_ready() -> TestResult<()> {
    let path = database_path("events-without-primary-key")?;
    let (mut process, client, session_id, head_version) =
        history_opaque(&path, 2, "event primary key missing", None).await?;
    assert_final_sse(&client, &process, &session_id, head_version).await?;
    process.stop().await?;

    let evidence = rebuild_events_without_primary_key(&path).await?;
    assert_eq!(evidence.event_count_before, evidence.event_count_after);
    assert_eq!(evidence.payload_bytes_before, evidence.payload_bytes_after);
    assert_eq!(evidence.global_position_primary_key, 0);
    assert_eq!(
        evidence.canonical_trigger_count,
        CANONICAL_TRIGGER_NAMES.len()
    );
    assert!(evidence.metadata_clean);

    let config = write_endpoint_config(&path, Vec::new(), 1)?;
    require_active_nonzero_start_failure(
        &path,
        &config,
        "events global_position without primary key",
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_unknown_storage_trigger_rejected_before_ready() -> TestResult<()> {
    let path = database_path("unknown-storage-trigger")?;
    let (mut process, client, session_id, head_version) =
        history_opaque(&path, 2, "unknown storage trigger", None).await?;
    assert_final_sse(&client, &process, &session_id, head_version).await?;
    process.stop().await?;

    let evidence = add_unknown_storage_trigger(&path).await?;
    assert!(evidence.extra_trigger_exists);
    assert_eq!(
        evidence.canonical_trigger_count,
        CANONICAL_TRIGGER_NAMES.len()
    );
    assert!(evidence.metadata_clean);

    let config = write_endpoint_config(&path, Vec::new(), 1)?;
    require_active_nonzero_start_failure(&path, &config, "unknown storage trigger").await
}

fn assert_authority_constraint_evidence(evidence: &AuthorityConstraintEvidence, label: &str) {
    assert_eq!(
        evidence.facts_before, evidence.facts_after,
        "{label} changed persisted authority facts"
    );
    assert!(
        evidence.metadata_clean_before && evidence.metadata_clean_after,
        "{label} did not preserve clean metadata"
    );
    assert_eq!(
        evidence.canonical_trigger_count,
        CANONICAL_TRIGGER_NAMES.len(),
        "{label} did not preserve canonical triggers"
    );
    assert_eq!(
        evidence.required_index_count,
        REQUIRED_INDEX_NAMES.len(),
        "{label} did not preserve required indexes"
    );
    assert!(
        !evidence.mutated_constraint_present,
        "{label} mutation did not remove only the targeted constraint"
    );
}

async fn exercise_authority_rejection(
    database_label: &str,
    label: &str,
    mutation: AuthorityConstraintMutation,
    snapshot_every: Option<&str>,
) -> TestResult<()> {
    let path = database_path(database_label)?;
    let (mut process, client, session_id, head_version) =
        history_opaque(&path, 2, label, snapshot_every).await?;
    assert_final_sse(&client, &process, &session_id, head_version).await?;
    process.stop().await?;
    if snapshot_every.is_some() {
        let snapshot = require_compatible_snapshot(&path, &session_id, head_version).await?;
        assert!(snapshot.stream_version <= head_version);
    }

    let evidence = mutate_authority_constraint(&path, mutation).await?;
    assert_authority_constraint_evidence(&evidence, label);
    if matches!(
        mutation,
        AuthorityConstraintMutation::IntegrityAnchorsCompositePrimaryKey
    ) {
        assert!(evidence.facts_before.anchor_count > 0);
    }
    if matches!(
        mutation,
        AuthorityConstraintMutation::SnapshotsSnapshotIdPrimaryKey
            | AuthorityConstraintMutation::SnapshotsStreamVersionNotNull
            | AuthorityConstraintMutation::SnapshotsStreamVersionCheck
    ) {
        assert!(evidence.facts_before.snapshot_count > 0);
    }

    let config = write_endpoint_config(&path, Vec::new(), 1)?;
    require_active_nonzero_start_failure(&path, &config, label).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_authority_events_stream_version_unique_rejected_before_ready() -> TestResult<()> {
    exercise_authority_rejection(
        "authority-events-stream-version-unique",
        "events stream_version UNIQUE",
        AuthorityConstraintMutation::EventsStreamVersionUnique,
        None,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_authority_events_event_id_unique_rejected_before_ready() -> TestResult<()> {
    exercise_authority_rejection(
        "authority-events-event-id-unique",
        "events event_id UNIQUE",
        AuthorityConstraintMutation::EventsEventIdUnique,
        None,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_authority_events_stream_version_not_null_rejected_before_ready() -> TestResult<()> {
    exercise_authority_rejection(
        "authority-events-stream-version-not-null",
        "events stream_version NOT NULL",
        AuthorityConstraintMutation::EventsStreamVersionNotNull,
        None,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_authority_events_stream_version_check_rejected_before_ready() -> TestResult<()> {
    exercise_authority_rejection(
        "authority-events-stream-version-check",
        "events stream_version CHECK",
        AuthorityConstraintMutation::EventsStreamVersionCheck,
        None,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_authority_integrity_anchors_composite_primary_key_rejected_before_ready(
) -> TestResult<()> {
    exercise_authority_rejection(
        "authority-integrity-anchors-primary-key",
        "integrity_anchors composite primary key",
        AuthorityConstraintMutation::IntegrityAnchorsCompositePrimaryKey,
        None,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_authority_snapshots_snapshot_id_primary_key_rejected_before_ready() -> TestResult<()> {
    exercise_authority_rejection(
        "authority-snapshots-primary-key",
        "snapshots snapshot_id primary key",
        AuthorityConstraintMutation::SnapshotsSnapshotIdPrimaryKey,
        Some("1"),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_authority_snapshots_stream_version_not_null_rejected_before_ready() -> TestResult<()> {
    exercise_authority_rejection(
        "authority-snapshots-stream-version-not-null",
        "snapshots stream_version NOT NULL",
        AuthorityConstraintMutation::SnapshotsStreamVersionNotNull,
        Some("1"),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_authority_snapshots_stream_version_check_rejected_before_ready() -> TestResult<()> {
    exercise_authority_rejection(
        "authority-snapshots-stream-version-check",
        "snapshots stream_version CHECK",
        AuthorityConstraintMutation::SnapshotsStreamVersionCheck,
        Some("1"),
    )
    .await
}

fn assert_projection_mutation_evidence(evidence: &ProjectionMutationEvidence, label: &str) {
    assert_eq!(
        evidence.authority_facts_before, evidence.authority_facts_after,
        "{label} changed authority facts"
    );
    assert_eq!(
        evidence.projection_rows_before, evidence.projection_rows_after,
        "{label} changed projection rows during setup"
    );
    assert!(
        evidence.metadata_clean,
        "{label} did not preserve clean metadata"
    );
    assert_eq!(
        evidence.canonical_trigger_count,
        CANONICAL_TRIGGER_NAMES.len(),
        "{label} did not preserve canonical triggers"
    );
    assert!(evidence.malformed_shape, "{label} setup was not malformed");
}

async fn require_active_nonzero_start_failure(
    database_path: &Path,
    config_path: &Path,
    label: &str,
) -> TestResult<()> {
    let result = ConfiguredServer::start_with_readiness_timeout(
        database_path,
        config_path,
        Duration::from_secs(2),
    )
    .await;
    match result {
        Err(error) => {
            let message = error.to_string();
            assert!(
                !message.contains("did not become ready"),
                "{label} failure was only a readiness timeout: {message}"
            );
            assert!(
                message.contains("non-zero"),
                "{label} did not report an active non-zero child exit: {message}"
            );
            Ok(())
        }
        Ok(mut server) => {
            server.stop().await?;
            Err(Error::other(format!("{label} unexpectedly became ready")).into())
        }
    }
}

async fn exercise_projection_recovery(
    database_label: &str,
    mutation: ProjectionConstraintMutation,
    label: &str,
) -> TestResult<()> {
    let path = database_path(database_label)?;
    let (mut process, client, session_id, head_version) =
        history_opaque(&path, 2, "projection repair history", None).await?;
    let replay_key = "history-opaque-message-1";
    let replay_content = "projection repair history";
    let expected_replay =
        append_message(&client, &process, &session_id, replay_key, replay_content).await?;
    assert_final_sse(&client, &process, &session_id, head_version).await?;
    process.stop().await?;

    let evidence = mutate_projection_constraints(&path, mutation).await?;
    assert_projection_mutation_evidence(&evidence, label);

    let mut restarted = Process::start(&path, None).await?;
    let get_response =
        authenticated(client.get(restarted.url(&format!("/v1/sessions/{session_id}"))?))
            .send_with_timeout()
            .await?;
    let get_status = get_response.status();
    let get_body = response_json(get_response).await?;
    assert_eq!(get_status, StatusCode::OK, "{label} GET: {get_body}");
    assert_eq!(get_body["session_id"], session_id);
    assert_eq!(get_body["version"], head_version);
    assert_eq!(
        get_body["transcript"].as_array().map(Vec::len),
        Some(2),
        "{label} GET lost transcript"
    );
    assert_final_sse(&client, &restarted, &session_id, head_version).await?;

    let replay =
        append_message(&client, &restarted, &session_id, replay_key, replay_content).await?;
    assert_eq!(replay, expected_replay, "{label} idempotent replay changed");
    restarted.stop().await?;

    let schema_valid = projection_constraints_are_valid(&path, mutation).await?;
    assert!(
        schema_valid,
        "SQLite projection schema was not rebuilt for {label}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_sqlite_malformed_event_streams_schema_rebuilds_on_restart() -> TestResult<()> {
    exercise_projection_recovery(
        "malformed-event-streams-schema",
        ProjectionConstraintMutation::EventStreamsConstraints,
        "event_streams PK/UNIQUE/CHECK",
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_sqlite_malformed_commands_schema_rebuilds_on_restart() -> TestResult<()> {
    exercise_projection_recovery(
        "malformed-commands-schema",
        ProjectionConstraintMutation::CommandsConstraints,
        "commands PK/UNIQUE/CHECK",
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_same_name_noop_trigger_rejected_before_ready() -> TestResult<()> {
    let path = database_path("same-name-noop-trigger")?;
    let (mut process, client, session_id, head_version) =
        history_opaque(&path, 3, "same-name-noop-trigger", Some("1")).await?;
    assert_final_sse(&client, &process, &session_id, head_version).await?;
    process.stop().await?;

    let snapshot = require_compatible_snapshot(&path, &session_id, head_version).await?;
    assert!(snapshot.stream_version > 0 && snapshot.stream_version <= head_version);
    let trigger_sql = replace_event_update_trigger_with_noop(&path).await?;
    let trigger_sql_lower = trigger_sql.to_ascii_lowercase();
    assert!(trigger_sql_lower.contains(EVENTS_UPDATE_TRIGGER));
    assert!(trigger_sql_lower.contains("select 1"));
    assert!(!trigger_sql_lower.contains("delete from integrity_anchors"));
    rewrite_event_payload_preserving_semantics(&path, &session_id, snapshot.stream_version).await?;
    assert!(integrity_anchor_exists(&path, &session_id, snapshot.stream_version).await?);
    eprintln!(
        "same-name trigger preserved snapshot_version={} and anchor",
        snapshot.stream_version
    );

    let config = write_endpoint_config(&path, Vec::new(), 1)?;
    require_active_nonzero_start_failure(&path, &config, "same-name no-op trigger").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_missing_integrity_anchor_table_rejected_before_ready() -> TestResult<()> {
    let path = database_path("missing-integrity-anchor-table")?;
    let (mut process, client, session_id, head_version) =
        history_opaque(&path, 3, "missing-integrity-anchor-table", Some("1")).await?;
    assert_final_sse(&client, &process, &session_id, head_version).await?;
    process.stop().await?;
    let _snapshot = require_compatible_snapshot(&path, &session_id, head_version).await?;

    let evidence = drop_integrity_anchors_preserving_metadata(&path).await?;
    assert!(evidence.storage_schema_before > 0);
    assert!(evidence.projection_schema_before > 0);
    assert_eq!(
        evidence.storage_schema_before,
        evidence.storage_schema_after
    );
    assert_eq!(
        evidence.projection_schema_before,
        evidence.projection_schema_after
    );
    assert!(!evidence.dirty_before);
    assert!(!evidence.dirty_after);
    assert!(!evidence.anchor_table_after_exists);
    eprintln!("missing-anchor-table evidence: {evidence:?}");

    let config = write_endpoint_config(&path, Vec::new(), 1)?;
    require_active_nonzero_start_failure(&path, &config, "missing integrity anchor table").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_unprojected_insert_rejected_before_ready() -> TestResult<()> {
    let path = database_path("unprojected-event-insert")?;
    let (mut process, client, session_id, head_version) =
        history_opaque(&path, 2, "unprojected event insert", Some("1")).await?;
    assert_final_sse(&client, &process, &session_id, head_version).await?;
    process.stop().await?;

    let evidence = insert_unprojected_event(&path, &session_id, head_version).await?;
    assert!(!evidence.dirty_before);
    assert!(evidence.dirty_after);
    assert_eq!(evidence.projection_head_after, i64::try_from(head_version)?);
    assert_eq!(
        evidence.max_event_version_after,
        evidence.inserted_event_version
    );
    assert_eq!(
        evidence.inserted_event_version,
        i64::try_from(
            head_version
                .checked_add(1)
                .ok_or_else(|| Error::other("head version overflow in test setup"))?
        )?
    );
    assert!(evidence.event_fingerprint_correct);
    assert!(!evidence.new_anchor_exists);
    eprintln!("unprojected insert evidence: {evidence:?}");

    let config = write_endpoint_config(&path, Vec::new(), 1)?;
    require_active_nonzero_start_failure(&path, &config, "unprojected event insert").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_healthy_indexes_open_without_writer_rebuild() -> TestResult<()> {
    let path = database_path("healthy-open")?;
    let (mut initial, client, session_id, _version) = history(&path, 1, "healthy", None).await?;
    initial.stop().await?;

    let writer = begin_immediate_writer(&path).await?;
    let mut blocked = Process::spawn(&path, None).await?;
    let ready = blocked
        .wait_ready_or_reap(Duration::from_millis(500))
        .await?;

    let Some(base_url) = ready else {
        let pid = blocked.pid;
        let release_result = writer.release().await;
        let stop_result = blocked.stop().await;
        release_result?;
        stop_result?;
        return Err(Error::other(format!(
            "healthy database did not become ready while writer was held; pid={pid}"
        ))
        .into());
    };
    let release_result = writer.release().await;
    let observation = if release_result.is_ok() {
        async {
            let response =
                authenticated(client.get(format!("{base_url}/v1/sessions/{session_id}")))
                    .send_with_timeout()
                    .await?;
            let get_status = response.status();
            let get_body = response_text(response).await?;
            let sse_response = authenticated(client.get(format!("{base_url}/v1/events")))
                .send_with_timeout()
                .await?;
            let sse_status = sse_response.status();
            let mut connected = SseFrames::new(sse_response);
            let first_record = connected.next().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                get_status,
                get_body,
                sse_status,
                first_record,
            ))
        }
        .await
    } else {
        Err(Error::other("writer barrier release failed").into())
    };
    let stop_result = blocked.stop().await;
    release_result?;
    stop_result?;
    let (get_status, get_body, sse_status, first_record) = observation?;
    assert_eq!(get_status, StatusCode::OK, "{get_body}");
    assert_eq!(sse_status, StatusCode::OK);
    assert_eq!(first_record.event, "session_created");
    assert_eq!(first_record.data["session_id"], session_id);
    assert_eq!(first_record.data["version"], 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_public_500_redaction() -> TestResult<()> {
    let path = database_path("error-redaction")?;
    let (mut process, client, session_id, version) =
        history_opaque(&path, 2, "redact", None).await?;
    process.stop().await?;
    let marker = "SECRET_MARKER_I_7f3a";
    // Leave the creation fact untouched so startup's creation scan succeeds.
    // Duplicate a marker-bearing tail message instead; the payload remains a
    // valid MessageAppended event, but the reducer must reject its projection.
    corrupt_tail_messages_for_redaction(&path, &session_id, version, marker).await?;
    let mut restarted = Process::start(&path, None).await?;
    let response = authenticated(client.get(restarted.url(&format!("/v1/sessions/{session_id}"))?))
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_text(response).await?;
    restarted.stop().await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(!body.contains(marker), "corruption marker leaked: {body}");
    assert!(
        !body.to_lowercase().contains("sqlite"),
        "sqlite detail leaked: {body}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_rehydrate_corruption_maps_500() -> TestResult<()> {
    let path = database_path("projection-corruption")?;
    let (mut process, client, session_id, _version) = history(&path, 1, "corrupt", None).await?;
    process.stop().await?;
    // This decodes and validates as an event during index rebuild, but the
    // reducer must reject the unknown delivery during public rehydration.
    let payload = serde_json::to_vec(&json!({
        "type": "delivery_materialized",
        "queue_id": 1,
        "message": {
            "message_id": "corrupt-projection-message",
            "role": "user",
            "content": "valid event, invalid projection",
            "tool_call_id": null,
            "tool_calls": [],
            "dedupe_key": null,
            "source_queue_id": 1
        }
    }))?;
    mutate_event(
        &path,
        &session_id,
        2,
        "delivery_materialized".to_owned(),
        payload,
    )
    .await?;
    let mut restarted = Process::start(&path, None).await?;
    let response = authenticated(client.get(restarted.url(&format!("/v1/sessions/{session_id}"))?))
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_text(response).await?;
    restarted.stop().await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(!body.contains("invalid_request"), "{body}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_event_payload_byte_mutation_is_neutral_500() -> TestResult<()> {
    let path = database_path("event-payload-integrity")?;
    let (mut process, client, session_id, version) =
        history_opaque(&path, 1, "payload integrity", None).await?;
    process.stop().await?;
    rewrite_event_payload_preserving_semantics(&path, &session_id, version).await?;

    let mut restarted = Process::start(&path, None).await?;
    let result = assert_corrupt_public_views(&client, &restarted, &session_id).await;
    restarted.stop().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_missing_head_integrity_anchor_is_neutral_500() -> TestResult<()> {
    let path = database_path("missing-head-integrity-anchor")?;
    let (mut process, client, session_id, _version) =
        history_opaque(&path, 1, "missing head anchor", None).await?;
    process.stop().await?;
    delete_stream_head_integrity_anchor(&path, &session_id).await?;

    let mut restarted = Process::start(&path, None).await?;
    let result = assert_corrupt_public_views(&client, &restarted, &session_id).await;
    restarted.stop().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_readiness_failure_does_not_leave_child_running() -> TestResult<()> {
    let path = database_path("readiness-cleanup")?;
    let (mut initial, _, _session_id, _version) = history(&path, 1, "ready", None).await?;
    initial.stop().await?;
    let dirty = db_blocking({
        let path = path.to_owned();
        move || {
            let connection = Connection::open(path)?;
            let clean_before: bool = connection.query_row(
                "SELECT storage_schema_version = 1
                        AND projection_schema_version = 1
                        AND projections_dirty = 0
                 FROM storage_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )?;
            if !clean_before {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let changed = connection.execute(
                "UPDATE storage_metadata SET projections_dirty = 1
                 WHERE singleton = 1",
                [],
            )?;
            let dirty_after: bool = connection.query_row(
                "SELECT projections_dirty = 1 FROM storage_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )?;
            if changed != 1 || !dirty_after {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(dirty_after)
        }
    })
    .await?;
    assert!(
        dirty,
        "readiness cleanup setup did not mark projections dirty"
    );
    let writer = begin_immediate_writer(&path).await?;
    let mut blocked = Process::spawn(&path, None).await?;
    let pid = blocked.pid;
    let readiness = blocked.wait_ready_or_reap(Duration::from_millis(250)).await;
    let alive_after_timeout = blocked.is_alive()?;
    let reaped_after_timeout = blocked.was_reaped();
    let release_result = writer.release().await;
    let stop_result = blocked.stop().await;
    let readiness = readiness?;
    release_result?;
    stop_result?;
    assert!(
        readiness.is_none() && !alive_after_timeout && reaped_after_timeout,
        "readiness timeout did not reap pid={pid}: readiness={readiness:?}, alive={alive_after_timeout}, reaped={reaped_after_timeout}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_temp_database_path_drop_removes_directory() -> TestResult<()> {
    let database = database_path("temp-raii")?;
    let directory = database.parent().unwrap().to_owned();
    let mut process = Process::start(&database, None).await?;
    let client = http_client()?;
    let _session_id = create_session(&client, &process, "temp-create").await?;
    process.stop().await?;
    drop(database);
    assert!(
        !directory.exists(),
        "temporary database directory still exists after path drop: {}",
        directory.display()
    );
    Ok(())
}

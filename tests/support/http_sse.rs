#![allow(dead_code)]

use std::{
    env, fs,
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use crate::support::{
    authenticated, authenticated_as, http_client, kill_and_reap, reap_child_on_drop, require_ulid,
    response_bytes, response_json, response_text, write_endpoint_config, HttpRequestExt,
    TempDatabase,
};
use futures_util::StreamExt;
use reqwest::{Client, Response, StatusCode};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    time::timeout,
};

pub(crate) const READY_PREFIX: &str = "ZODE_READY ";

pub(crate) struct TestServer {
    pub(crate) child: Option<Child>,
    pub(crate) base_url: String,
}

pub(crate) fn conformance_endpoint_binary(
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let path = env::var_os("ZODE_CONFORMANCE_ENDPOINT_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_zode")));
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file() {
        return Err(Error::other(format!(
            "conformance endpoint binary is not a regular file: {}",
            path.display()
        ))
        .into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(Error::other(format!(
                "conformance endpoint binary is not executable: {}",
                path.display()
            ))
            .into());
        }
    }
    Ok(path)
}

impl TestServer {
    pub(crate) async fn start(
        database_path: &Path,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config_path = write_endpoint_config(database_path, Vec::new(), 1)?;
        let backend = env::var("ZODE_CONFORMANCE_BACKEND").unwrap_or_else(|_| "sqlite".to_owned());
        if backend != "sqlite" {
            let mut config: Value = serde_json::from_slice(&fs::read(&config_path)?)?;
            config["runtime_store"]["kind"] = Value::String(backend.clone());
            fs::write(&config_path, serde_json::to_vec(&config)?)?;
            fs::File::open(&config_path)?.sync_all()?;
        }
        let mut child = Command::new(conformance_endpoint_binary()?)
            .arg("--config")
            .arg(config_path)
            .arg("--database")
            .arg(database_path)
            .arg("--listen")
            .arg("127.0.0.1:0")
            .env("ZODE_CONFORMANCE_BACKEND", &backend)
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
                    "{error}; {backend} conformance endpoint exited with {status_kind} process status {status}"
                ))
                .into())
            }
        }
    }

    pub(crate) async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(child) = self.child.take() {
            let _ = kill_and_reap(child).await?;
        }
        Ok(())
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        reap_child_on_drop(self.child.take());
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SseRecord {
    pub(crate) id: String,
    pub(crate) event: String,
    pub(crate) data: Value,
}

pub(crate) fn test_database(
    label: &str,
) -> Result<TempDatabase, Box<dyn std::error::Error + Send + Sync>> {
    TempDatabase::new(label)
}

pub(crate) async fn json_response(
    response: Response,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    response_json(response).await
}

pub(crate) async fn read_sse_events(
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

pub(crate) async fn create_subject_session(
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

pub(crate) async fn list_subject_sessions(
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

pub(crate) fn assert_two_ordered_session_events(
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

pub(crate) fn assert_list_contains_only(
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

pub(crate) fn assert_same_safe_not_found(
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

pub(crate) async fn assert_session_replay_has_only_initial_event(
    client: &Client,
    server: &TestServer,
    subject: &str,
    session_id: &str,
    initial: &SseRecord,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert_eq!(initial.data["session_id"], session_id);
    let replay_response = authenticated_as(client.get(server.url("/v1/events")), subject)
        .header("Last-Event-ID", "0")
        .send_with_timeout()
        .await?;
    assert_eq!(replay_response.status(), StatusCode::OK);
    let replay = read_sse_events(replay_response, 1).await?;
    assert_eq!(replay, vec![initial.clone()]);

    let tail_response = authenticated_as(client.get(server.url("/v1/events")), subject)
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
pub(crate) enum OwnershipResource {
    Read,
    Message,
}

pub(crate) async fn assert_subject_safe_not_found(
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
    };
    let cross = request(cross_id).send_with_timeout().await?;
    let missing = request(missing_id).send_with_timeout().await?;
    let cross = (cross.status(), response_text(cross).await?);
    let missing = (missing.status(), response_text(missing).await?);
    assert_same_safe_not_found(
        match resource {
            OwnershipResource::Read => "GET",
            OwnershipResource::Message => "message",
        },
        cross,
        missing,
        markers,
    )
}

pub(crate) fn find_frame_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|position| position + 2)
}

pub(crate) fn parse_sse_frame(
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

pub(crate) async fn create_history(
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

pub(crate) async fn create_history_opaque(
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

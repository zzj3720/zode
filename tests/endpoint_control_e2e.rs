#![allow(dead_code)]

mod support;

use std::{
    env, fs,
    io::{Error, ErrorKind, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};

use hmac::{Hmac, Mac};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Client, RequestBuilder, Response, StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::{
    assert_response_headers_secret_free, authenticated, authenticated_as, db_blocking,
    is_crockford_ulid, kill_and_reap, reap_child_on_drop, response_bytes, response_json,
    response_text, sqlite_contains_secret, write_endpoint_config, ConfiguredServer, HttpRequestExt,
    ModelFixture, ModelScript, TempDatabase, TestResult, TestZode, TEST_CONTROLLER_SECRET,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader},
    process::{Child, Command},
    task::JoinHandle,
    time::timeout,
};

const SUBJECT_A: &str = "control-subject-a";
const SUBJECT_B: &str = "control-subject-b";
const PROFILE_ID: &str = "control-profile";
const SECRET_A: &str = "replica-secret-a-control-e2e";
const SECRET_B: &str = "replica-secret-b-control-e2e";
const SECRET_C: &str = "replica-secret-c-control-e2e";
const SECRET_D: &str = "replica-secret-d-control-e2e";
const AUTHORITY_A: &str = "authority-a-control-e2e";
const AUTHORITY_B: &str = "authority-b-control-e2e";
const AUTHORITY_A_SECRET: &str = "authority-a-secret-control-e2e";
const AUTHORITY_B_SECRET: &str = "authority-b-secret-control-e2e";
const AUTHORITY_A_NEW_SECRET: &str = "authority-a-new-secret-control-e2e";
const AUTHORITY_B_NEW_SECRET: &str = "authority-b-new-secret-control-e2e";
const ROTATION_BARRIER_TIMEOUT: Duration = Duration::from_secs(3);
const EXPIRY_REVISION_ONE: i64 = 4_102_444_800_000;
const EXPIRY_REVISION_TWO: i64 = 4_102_448_400_000;
const REPLICA_RECOVERY_CASSETTE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/replica_recovery_split.incident.json"
);
const REPLICA_RECOVERY_OWNER: &str =
    "e2e_auth_replica_recovery_does_not_split_active_and_receipt_metadata";
const REPLICA_RECOVERY_RECORDING_ID: &str = "replica-recovery-split-first-200";
const REPLICA_RECOVERY_PATH: &str = "/v1/auth-replicas/control-profile";
const REPLICA_RECOVERY_WHOLE_DIGEST: &str =
    "sha256:99c856fa040e320cf97850e5a45d5af9670ed8c0c6a5be91f35b6aebecd63a13";

async fn first_sse_session_id(mut response: Response) -> TestResult<String> {
    let mut buffer = Vec::new();
    loop {
        let chunk = timeout(Duration::from_secs(5), response.chunk())
            .await??
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "Endpoint SSE ended early"))?;
        buffer.extend_from_slice(&chunk);
        while let Some(frame_end) = buffer.windows(2).position(|window| window == b"\n\n") {
            let frame = buffer.drain(..frame_end + 2).collect::<Vec<_>>();
            let text = std::str::from_utf8(&frame)?;
            let Some(data) = text.lines().find_map(|line| line.strip_prefix("data: ")) else {
                continue;
            };
            let value: Value = serde_json::from_str(data)?;
            return value["session_id"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error::other("Endpoint SSE event omitted session_id").into());
        }
    }
}

fn config_for(database: &TempDatabase) -> TestResult<PathBuf> {
    write_endpoint_config(database.path(), Vec::new(), 1)
}

fn set_provider_execution_policy(
    config: &Path,
    adapter_kinds: &[&str],
    allowed_origins: &[&str],
) -> TestResult<()> {
    let mut value: Value = serde_json::from_slice(&fs::read(config)?)?;
    value["provider_execution"]["adapter_kinds"] = json!(adapter_kinds);
    value["provider_execution"]["allowed_base_url_origins"] = json!(allowed_origins);
    fs::write(config, serde_json::to_vec_pretty(&value)?)?;
    Ok(())
}

fn config_without_replica_store(database: &TempDatabase) -> TestResult<PathBuf> {
    // Keep the shared store configuration identical for both children while
    // removing an unrelated credential-directory lock from this ownership
    // probe. The only process-local ownership input under test is TMPDIR.
    let config = config_for(database)?;
    let mut value: Value = serde_json::from_slice(&fs::read(&config)?)?;
    value
        .as_object_mut()
        .ok_or_else(|| Error::other("endpoint config was not an object"))?
        .remove("credential_replica_store");
    fs::write(&config, serde_json::to_vec_pretty(&value)?)?;
    Ok(config)
}

fn config_for_authorities(
    database: &TempDatabase,
    authorities: &[(&str, &str)],
) -> TestResult<PathBuf> {
    let config = config_for(database)?;
    let root = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("temporary database has no parent directory"))?;
    let mut specs = Vec::with_capacity(authorities.len());
    for (index, (authority_id, secret)) in authorities.iter().enumerate() {
        let file_name = format!("controller-{index}.secret");
        let path = root.join(&file_name);
        fs::write(&path, secret)?;
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(&path)?.permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&path, permissions)?;
        }
        specs.push(json!({
            "authority_id": authority_id,
            "revision": 1,
            "kind": "bearer_secret_file",
            "secret_file": file_name,
        }));
    }
    let mut value: Value = serde_json::from_slice(&fs::read(&config)?)?;
    value["controller_auth"] = Value::Array(specs);
    fs::write(&config, serde_json::to_vec_pretty(&value)?)?;
    Ok(config)
}

async fn fs_blocking<T, F>(operation: F) -> TestResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> std::io::Result<T> + Send + 'static,
{
    Ok(tokio::task::spawn_blocking(operation).await??)
}

fn sidecar_path(database: &Path, suffix: &str) -> PathBuf {
    let mut value = database.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn controller_auth_dir(database: &Path) -> PathBuf {
    sidecar_path(database, ".controller-auth")
}

async fn identity_with_secret(
    client: &Client,
    server: &ConfiguredServer,
    secret: &str,
) -> TestResult<(StatusCode, Value)> {
    let response =
        authenticated_with_secret(client.get(server.url("/v1/identity")), secret, SUBJECT_A)
            .send_with_timeout()
            .await?;
    let status = response.status();
    let body = response_text(response).await?;
    assert_rotation_secret_free(&body, &[secret]);
    let value = serde_json::from_str(&body).unwrap_or(Value::String(body));
    Ok((status, value))
}

fn rotation_body(authority_id: &str, revision: u64, secret: &str) -> Value {
    json!({
        "schema": "zode.controller-auth.rotate.v1",
        "authority_id": authority_id,
        "revision": revision,
        "secret": {
            "encoding": "application/zode-secret-envelope",
            "payload": secret
        }
    })
}

type TestHmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
struct TestRotationSecret<'a> {
    encoding: &'static str,
    payload: &'a str,
}

#[derive(Serialize)]
struct TestRotationRequest<'a> {
    schema: &'static str,
    authority_id: &'a str,
    revision: u64,
    secret: TestRotationSecret<'a>,
}

fn control_digest(key: &[u8], purpose: &[u8], bytes: &[u8]) -> String {
    let mut mac = TestHmacSha256::new_from_slice(key).expect("test HMAC key is valid");
    mac.update(purpose);
    mac.update(&[0]);
    mac.update(bytes);
    let digest = mac.finalize().into_bytes();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(encoded, "{byte:02x}");
    }
    format!("hmac-sha256:v1:{encoded}")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

async fn append_stale_rotation_intent_without_secret(
    database: &Path,
    authority_id: &str,
    revision: u64,
    secret: &str,
    idempotency_key: &str,
) -> TestResult<()> {
    let control_directory = controller_auth_dir(database);
    let key = fs::read(control_directory.join("fingerprint.key"))?;
    let request_bytes = serde_json::to_vec(&TestRotationRequest {
        schema: "zode.controller-auth.rotate.v1",
        authority_id,
        revision,
        secret: TestRotationSecret {
            encoding: "application/zode-secret-envelope",
            payload: secret,
        },
    })?;
    let fingerprint = control_digest(&key, b"rotation-fingerprint:v1", &request_bytes);
    let mut operation_input = Vec::new();
    operation_input.extend_from_slice(b"zode.controller-auth.rotate.v1");
    operation_input.push(0);
    operation_input.extend_from_slice(authority_id.as_bytes());
    operation_input.push(0);
    operation_input.push(0);
    operation_input.extend_from_slice(idempotency_key.as_bytes());
    let operation_id = control_digest(&key, b"rotation-operation:v1", &operation_input);
    let secret_ref = format!(
        "secret-{}-{revision}-{}.secret",
        sha256_hex(authority_id.as_bytes()),
        sha256_hex(operation_id.as_bytes())
    );
    let intent = json!({
        "operation_id": operation_id,
        "authority_id": authority_id,
        "revision": revision,
        "fingerprint": fingerprint,
        "secret_ref": secret_ref,
        "phase": "intent",
        "status": 0,
        "response": null
    });
    let journal = control_directory.join("operations.jsonl");
    let mut options = fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(journal)?;
    serde_json::to_writer(&mut file, &intent)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

async fn rotate_once(
    client: &Client,
    server: &ConfiguredServer,
    current_secret: &str,
    authority_id: &str,
    next_secret: &str,
    revision: u64,
    key: &str,
) -> TestResult<(StatusCode, String)> {
    let response = authenticated_with_secret(
        client.put(server.url("/v1/controller-auth")),
        current_secret,
        SUBJECT_A,
    )
    .header("Idempotency-Key", key)
    .json(&rotation_body(authority_id, revision, next_secret))
    .send_with_timeout()
    .await?;
    let status = response.status();
    let body = response_text(response).await?;
    assert_rotation_secret_free(
        &body,
        &[
            current_secret,
            next_secret,
            AUTHORITY_A_SECRET,
            AUTHORITY_B_SECRET,
        ],
    );
    Ok((status, body))
}

async fn assert_rotation_succeeded(
    client: &Client,
    server: &ConfiguredServer,
    current_secret: &str,
    authority_id: &str,
    next_secret: &str,
    revision: u64,
    key: &str,
) -> TestResult<()> {
    let (status, body) = rotate_once(
        client,
        server,
        current_secret,
        authority_id,
        next_secret,
        revision,
        key,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "rotation setup failed: {body}");
    Ok(())
}

#[derive(Clone)]
struct RotationReceipt {
    next_secret: String,
    key: String,
    revision: u64,
    body: String,
}

async fn create_rotation_history(
    client: &Client,
    server: &ConfiguredServer,
    count: usize,
    secret_prefix: &str,
    key_prefix: &str,
) -> TestResult<(String, Vec<RotationReceipt>)> {
    let mut current_secret = TEST_CONTROLLER_SECRET.to_owned();
    let mut receipts = Vec::with_capacity(count);
    for index in 0..count {
        let next_secret = format!("{secret_prefix}-{index}-control-e2e");
        let revision = index as u64 + 2;
        let key = format!("{key_prefix}-{index}");
        let (status, body) = rotate_once(
            client,
            server,
            &current_secret,
            "controller-e2e",
            &next_secret,
            revision,
            &key,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "rotation {index} failed: {body}");
        let (identity_status, identity_body) =
            identity_with_secret(client, server, &next_secret).await?;
        assert_eq!(identity_status, StatusCode::OK);
        assert_eq!(identity_body["revision"], revision);
        receipts.push(RotationReceipt {
            next_secret: next_secret.clone(),
            key,
            revision,
            body,
        });
        current_secret = next_secret;
    }
    Ok((current_secret, receipts))
}

async fn replay_rotation(
    client: &Client,
    server: &ConfiguredServer,
    current_secret: &str,
    receipt: &RotationReceipt,
) -> TestResult<(StatusCode, String)> {
    rotate_once(
        client,
        server,
        current_secret,
        "controller-e2e",
        &receipt.next_secret,
        receipt.revision,
        &receipt.key,
    )
    .await
}

async fn assert_all_rotation_replays(
    client: &Client,
    server: &ConfiguredServer,
    current_secret: &str,
    receipts: &[RotationReceipt],
) -> TestResult<()> {
    for receipt in receipts {
        let (status, body) = replay_rotation(client, server, current_secret, receipt).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, receipt.body);
    }
    Ok(())
}

fn authenticated_with_secret(
    request: RequestBuilder,
    secret: &str,
    subject: &str,
) -> RequestBuilder {
    request
        .header("Authorization", format!("Bearer {secret}"))
        .header("Zode-Subject", subject)
}

fn assert_active_nonzero_error(label: &str, error: &dyn std::fmt::Display) {
    let message = error.to_string();
    assert!(
        !message.contains("did not become ready"),
        "{label} failure was only a readiness timeout"
    );
    assert!(
        message.contains("non-zero"),
        "{label} did not produce an active non-zero exit"
    );
}

async fn expect_active_nonzero_start_failure(
    database: &Path,
    config: &Path,
    label: &str,
    forbidden_output: Option<&str>,
) -> TestResult<()> {
    match ConfiguredServer::start_with_readiness_timeout(database, config, Duration::from_secs(2))
        .await
    {
        Err(error) => {
            let message = error.to_string();
            assert_active_nonzero_error(label, &message);
            if let Some(forbidden_output) = forbidden_output {
                assert!(!message.contains(forbidden_output));
            }
            Ok(())
        }
        Ok(mut server) => {
            server.stop().await?;
            Err(Error::other(format!("{label} unexpectedly became ready")).into())
        }
    }
}

async fn await_rotation_identity_barrier(
    client: Client,
    identity_url: String,
    new_secret: &str,
    subject: &str,
    markers: &[&str],
    mut first_rotation_task: tokio::task::JoinHandle<TestResult<Response>>,
) -> TestResult<()> {
    let mut first_task_consumed = false;
    let barrier_result = tokio::time::timeout(ROTATION_BARRIER_TIMEOUT, async {
        loop {
            tokio::select! {
                biased;
                first_result = &mut first_rotation_task, if !first_task_consumed => {
                    first_task_consumed = true;
                    let response = first_result
                        .map_err(|error| Error::other(format!("rotation request task failed: {error}")))??;
                    let status = response.status();
                    if !status.is_success() {
                        let body = response_text(response).await?;
                        assert_rotation_secret_free(&body, markers);
                        return Err(Error::other(format!(
                            "controller-auth rotation route unavailable: status {status}"
                        ))
                        .into());
                    }
                    drop(response);
                }
                identity_result = authenticated_with_secret(
                    client.get(&identity_url),
                    new_secret,
                    subject,
                )
                .send_with_timeout() => {
                    let response = identity_result?;
                    let status = response.status();
                    let body = response_text(response).await?;
                    assert_rotation_secret_free(&body, markers);
                    if status == StatusCode::OK {
                        let identity: Value = serde_json::from_str(&body).map_err(|error| {
                            Error::other(format!("rotation identity barrier returned invalid JSON: {error}"))
                        })?;
                        if identity["revision"] == 2 {
                            return Ok(());
                        }
                    }
                    tokio::task::yield_now().await;
                }
            }
        }
    })
    .await;

    if !first_task_consumed {
        first_rotation_task.abort();
        let _ = first_rotation_task.await;
    }

    match barrier_result {
        Ok(result) => result,
        Err(_) => Err(Error::new(
            ErrorKind::TimedOut,
            "controller-auth rotation identity barrier timed out",
        )
        .into()),
    }
}

async fn create_model_less(
    client: &Client,
    server: &ConfiguredServer,
    subject: &str,
    key: &str,
) -> TestResult<(String, Value)> {
    create_model_less_with_secret(client, server, TEST_CONTROLLER_SECRET, subject, key).await
}

async fn create_model_less_with_secret(
    client: &Client,
    server: &ConfiguredServer,
    secret: &str,
    subject: &str,
    key: &str,
) -> TestResult<(String, Value)> {
    let response =
        authenticated_with_secret(client.post(server.url("/v1/sessions")), secret, subject)
            .header("Idempotency-Key", key)
            .json(&json!({}))
            .send_with_timeout()
            .await?;
    let status = response.status();
    let body = response_json(response).await?;
    if status != StatusCode::CREATED {
        return Err(Error::other(format!(
            "model-less session create returned {status}: {body}"
        ))
        .into());
    }
    let session_id = body["session_id"].as_str().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            "model-less create response omitted session_id",
        )
    })?;
    Ok((session_id.to_owned(), body))
}

fn model_create_body(base_url: &str, kind: &str, minimum_auth_revision: u64) -> Value {
    json!({
        "model": {
            "provider": "fixture-provider",
            "provider_execution": {
                "schema": "zode.provider-execution.v1",
                "revision": 1,
                "kind": kind,
                "base_url": base_url
            },
            "model": "fixture-model",
            "auth_authority_id": "controller-e2e",
            "auth_profile_id": PROFILE_ID,
            "minimum_auth_revision": minimum_auth_revision
        }
    })
}

async fn create_model_body(
    client: &Client,
    server: &ConfiguredServer,
    subject: &str,
    key: &str,
    body: &Value,
) -> TestResult<Response> {
    let response = authenticated_as(client.post(server.url("/v1/sessions")), subject)
        .header("Idempotency-Key", key)
        .json(body)
        .send_with_timeout()
        .await?;
    assert_response_headers_secret_free(
        &response,
        &[
            SECRET_A,
            SECRET_B,
            SECRET_C,
            SECRET_D,
            TEST_CONTROLLER_SECRET,
            AUTHORITY_A_SECRET,
            AUTHORITY_B_SECRET,
            AUTHORITY_A_NEW_SECRET,
            AUTHORITY_B_NEW_SECRET,
            SUBJECT_A,
        ],
    );
    Ok(response)
}

async fn create_receipt_with_exact_replay(
    client: &Client,
    server: &ConfiguredServer,
    secret: &str,
    subject: &str,
    key: &str,
) -> TestResult<(String, String)> {
    let create =
        authenticated_with_secret(client.post(server.url("/v1/sessions")), secret, subject)
            .header("Idempotency-Key", key)
            .json(&json!({}))
            .send_with_timeout()
            .await?;
    let create_status = create.status();
    let create_body = response_text(create).await?;
    assert_eq!(create_status, StatusCode::CREATED, "{create_body}");
    let create_json: Value = serde_json::from_str(&create_body)?;
    let session_id = create_json["session_id"]
        .as_str()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "create response omitted session_id"))?;

    let replay =
        authenticated_with_secret(client.post(server.url("/v1/sessions")), secret, subject)
            .header("Idempotency-Key", key)
            .json(&json!({}))
            .send_with_timeout()
            .await?;
    let replay_status = replay.status();
    let replay_body = response_text(replay).await?;
    assert_eq!(replay_status, StatusCode::CREATED, "{replay_body}");
    assert_eq!(replay_body, create_body);
    Ok((session_id.to_owned(), create_body))
}

async fn assert_create_payload_conflict(
    client: &Client,
    server: &ConfiguredServer,
    secret: &str,
    subject: &str,
    key: &str,
) -> TestResult<()> {
    let response =
        authenticated_with_secret(client.post(server.url("/v1/sessions")), secret, subject)
            .header("Idempotency-Key", key)
            .json(&json!({"tools": ["different"]}))
            .send_with_timeout()
            .await?;
    let status = response.status();
    let body = response_text(response).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let error: Value = serde_json::from_str(&body)?;
    assert_eq!(error["error"]["code"], "conflict", "{body}");
    Ok(())
}

async fn get_session(
    client: &Client,
    server: &ConfiguredServer,
    subject: &str,
    session_id: &str,
) -> TestResult<(StatusCode, String)> {
    get_session_with_secret(client, server, TEST_CONTROLLER_SECRET, subject, session_id).await
}

async fn get_session_with_secret(
    client: &Client,
    server: &ConfiguredServer,
    secret: &str,
    subject: &str,
    session_id: &str,
) -> TestResult<(StatusCode, String)> {
    let response = authenticated_with_secret(
        client.get(server.url(&format!("/v1/sessions/{session_id}"))),
        secret,
        subject,
    )
    .send_with_timeout()
    .await?;
    let status = response.status();
    let body = response_text(response).await?;
    Ok((status, body))
}

async fn post_message(
    client: &Client,
    server: &ConfiguredServer,
    subject: &str,
    session_id: &str,
    key: &str,
) -> TestResult<(StatusCode, String)> {
    post_message_with_secret(
        client,
        server,
        TEST_CONTROLLER_SECRET,
        subject,
        session_id,
        key,
    )
    .await
}

async fn post_message_with_secret(
    client: &Client,
    server: &ConfiguredServer,
    secret: &str,
    subject: &str,
    session_id: &str,
    key: &str,
) -> TestResult<(StatusCode, String)> {
    let response = authenticated_with_secret(
        client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))),
        secret,
        subject,
    )
    .header("Idempotency-Key", key)
    .json(&json!({"content": "control message"}))
    .send_with_timeout()
    .await?;
    let status = response.status();
    let body = response_text(response).await?;
    Ok((status, body))
}

async fn list_sessions(
    client: &Client,
    server: &ConfiguredServer,
    subject: &str,
) -> TestResult<(StatusCode, String)> {
    list_sessions_with_secret(client, server, TEST_CONTROLLER_SECRET, subject).await
}

async fn list_sessions_with_secret(
    client: &Client,
    server: &ConfiguredServer,
    secret: &str,
    subject: &str,
) -> TestResult<(StatusCode, String)> {
    let response = authenticated_with_secret(
        client.get(server.url("/v1/sessions?limit=100")),
        secret,
        subject,
    )
    .send_with_timeout()
    .await?;
    let status = response.status();
    let body = response_text(response).await?;
    Ok((status, body))
}

fn assert_one_owned_session_list(
    status: StatusCode,
    body: &str,
    subject: &str,
    owner_session_id: &str,
    other_session_id: &str,
    missing_session_id: &str,
) -> TestResult<()> {
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
        only_session_id, owner_session_id,
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

fn assert_empty_session_list(status: StatusCode, body: &str, label: &str) -> TestResult<()> {
    assert_eq!(status, StatusCode::OK, "{label}: {body}");
    let list: Value = serde_json::from_str(body)?;
    assert_eq!(list["schema"], "zode.session-list.v1", "{label}: {body}");
    let items = list["items"]
        .as_array()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "session list omitted items"))?;
    assert!(
        items.is_empty(),
        "{label} exposed a create side effect: {body}"
    );
    Ok(())
}

async fn assert_model_admission_error(
    response: Response,
    expected_status: StatusCode,
    expected_code: &str,
    label: &str,
) -> TestResult<()> {
    assert_response_headers_secret_free(
        &response,
        &[
            SECRET_A,
            SECRET_B,
            SECRET_C,
            SECRET_D,
            TEST_CONTROLLER_SECRET,
        ],
    );
    let status = response.status();
    let body = response_text(response).await?;
    assert_secret_free(&body);
    assert_eq!(status, expected_status, "{label} was admitted: {body}");
    let error: Value = serde_json::from_str(&body)?;
    assert_eq!(error["error"]["code"], expected_code, "{label}: {body}");
    Ok(())
}

async fn identity(client: &Client, server: &ConfiguredServer) -> TestResult<(StatusCode, Value)> {
    let response = authenticated(client.get(server.url("/v1/identity")))
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body_text = response_text(response).await?;
    let body = serde_json::from_str(&body_text).unwrap_or(Value::String(body_text));
    Ok((status, body))
}

fn duplicate_headers(name: &str, values: &[&str]) -> TestResult<HeaderMap> {
    let name = HeaderName::from_bytes(name.as_bytes())?;
    let mut headers = HeaderMap::new();
    for value in values {
        headers.append(name.clone(), HeaderValue::from_str(value)?);
    }
    Ok(headers)
}

async fn assert_safe_auth_rejection(
    label: &str,
    request: RequestBuilder,
    session_id: &str,
    expected_status: StatusCode,
    expected_code: &str,
) -> TestResult<()> {
    let response = request.send_with_timeout().await?;
    let status = response.status();
    let body = response_text(response).await?;
    assert!(
        !body.contains(session_id),
        "{label} disclosed session existence"
    );
    assert_eq!(status, expected_status, "{label} returned the wrong status");
    let response_json: Value = serde_json::from_str(&body)
        .map_err(|_| Error::other(format!("{label} did not return a JSON error envelope")))?;
    assert_eq!(
        response_json["error"]["code"], expected_code,
        "{label} returned the wrong error category"
    );
    assert!(!body.to_lowercase().contains("sqlite"));
    assert!(!body.to_lowercase().contains("database"));
    Ok(())
}

fn assert_secret_free(body: &str) {
    for marker in [
        SECRET_A,
        SECRET_B,
        SECRET_C,
        SECRET_D,
        TEST_CONTROLLER_SECRET,
        support::TEST_SUBJECT,
    ] {
        assert!(
            !body.contains(marker),
            "public output contained a secret marker"
        );
    }
}

fn assert_rotation_secret_free(body: &str, markers: &[&str]) {
    for marker in markers {
        assert!(
            !body.contains(marker),
            "public output contained a secret marker"
        );
    }
}

async fn assert_control_secret_absent_from_runtime_artifacts(
    root: &Path,
    database: &Path,
    markers: &[&str],
) -> TestResult<()> {
    for marker in markers {
        assert!(
            !sqlite_contains_secret(database, marker).await?,
            "runtime SQLite or its journal files retained a controller secret"
        );
    }

    let root = root.to_owned();
    let control_directory = controller_auth_dir(database);
    let markers = markers
        .iter()
        .map(|marker| marker.as_bytes().to_vec())
        .collect::<Vec<_>>();
    fs_blocking(move || {
        fn scan(
            path: &Path,
            root: &Path,
            control_directory: &Path,
            markers: &[Vec<u8>],
        ) -> std::io::Result<()> {
            if path == control_directory || path == root.join("controller.secret") {
                return Ok(());
            }
            let metadata = fs::symlink_metadata(path)?;
            if metadata.is_dir() {
                for entry in fs::read_dir(path)? {
                    scan(&entry?.path(), root, control_directory, markers)?;
                }
                return Ok(());
            }
            if !metadata.is_file() {
                return Ok(());
            }
            let bytes = fs::read(path)?;
            if markers.iter().any(|marker| {
                !marker.is_empty()
                    && bytes
                        .windows(marker.len())
                        .any(|window| window == marker.as_slice())
            }) {
                return Err(Error::other(format!(
                    "runtime artifact retained a controller secret: {}",
                    path.display()
                )));
            }
            Ok(())
        }

        scan(&root, &root, &control_directory, &markers)
    })
    .await
}

fn assert_tombstoned_metadata(label: &str, body: &Value, expected_revision: u64) -> TestResult<()> {
    if body.get("revision").is_none() {
        return Err(Error::other(format!("{label} was not a replica metadata object")).into());
    }
    let metadata = body;
    assert_eq!(
        metadata["revision"], expected_revision,
        "{label} did not report revision {expected_revision}"
    );
    assert_eq!(
        metadata["schema"], "zode.auth-replica.v1",
        "{label} returned the wrong metadata schema"
    );
    assert_eq!(
        metadata["authority_id"], "controller-e2e",
        "{label} returned the wrong authority"
    );
    assert_eq!(
        metadata["auth_profile_id"], PROFILE_ID,
        "{label} returned the wrong profile"
    );
    assert_eq!(
        metadata["provider"], "fixture-provider",
        "{label} returned the wrong provider"
    );
    assert_eq!(
        metadata["status"], "tombstoned",
        "{label} did not report the required tombstoned status"
    );
    assert!(
        metadata["expires_at_ms"].is_null(),
        "{label} retained an active expiry: {metadata}"
    );
    Ok(())
}

fn assert_tombstoned_list(label: &str, body: &Value, expected_revision: u64) -> TestResult<()> {
    let mut containers = Vec::new();
    if let Some(items) = body.get("items").and_then(Value::as_array) {
        containers.push(items);
    }
    if let Some(replicas) = body.get("replicas").and_then(Value::as_array) {
        containers.push(replicas);
    }
    if let Some(items) = body.as_array() {
        containers.push(items);
    }
    if containers.len() != 1 {
        return Err(Error::other(format!(
            "{label} did not expose exactly one replica collection"
        ))
        .into());
    }
    let items = containers[0];
    assert_eq!(
        items.len(),
        1,
        "{label} exposed more than one logical current profile"
    );
    let metadata = items
        .first()
        .ok_or_else(|| Error::other(format!("{label} exposed no current profile")))?;
    assert_tombstoned_metadata(label, metadata, expected_revision)
}

fn assert_ready_replica_metadata(
    label: &str,
    body: &Value,
    expected_revision: u64,
) -> TestResult<()> {
    let object = body
        .as_object()
        .ok_or_else(|| Error::other(format!("{label} was not a replica metadata object")))?;
    let expected_fields = [
        "schema",
        "authority_id",
        "auth_profile_id",
        "provider",
        "revision",
        "status",
        "expires_at_ms",
    ];
    if object.len() != expected_fields.len()
        || expected_fields
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        return Err(Error::other(format!(
            "{label} did not expose the exact public ready metadata fields"
        ))
        .into());
    }
    assert_eq!(body["schema"], "zode.auth-replica.v1", "{label}");
    assert_eq!(body["authority_id"], "controller-e2e", "{label}");
    assert_eq!(body["auth_profile_id"], PROFILE_ID, "{label}");
    assert_eq!(body["provider"], "fixture-provider", "{label}");
    assert_eq!(body["revision"], expected_revision, "{label}");
    assert_eq!(body["status"], "ready", "{label}");
    assert!(
        body["expires_at_ms"].is_null(),
        "{label} exposed an unexpected expiry"
    );
    Ok(())
}

fn assert_single_ready_replica_list(
    label: &str,
    body: &Value,
    expected_revision: u64,
) -> TestResult<()> {
    let object = body
        .as_object()
        .ok_or_else(|| Error::other(format!("{label} was not a replica list object")))?;
    if object.len() != 2 || !object.contains_key("schema") || !object.contains_key("items") {
        return Err(Error::other(format!(
            "{label} did not expose the exact public replica-list fields"
        ))
        .into());
    }
    assert_eq!(body["schema"], "zode.auth-replica-list.v1", "{label}");
    let items = body["items"]
        .as_array()
        .ok_or_else(|| Error::other(format!("{label} omitted items")))?;
    assert_eq!(
        items.len(),
        1,
        "{label} exposed more than one current replica"
    );
    let item = items
        .first()
        .ok_or_else(|| Error::other(format!("{label} exposed no current replica")))?;
    let item_object = item
        .as_object()
        .ok_or_else(|| Error::other(format!("{label} item was not replica metadata")))?;
    let expected_item_fields = [
        "schema",
        "authority_id",
        "auth_profile_id",
        "provider",
        "revision",
        "status",
        "expires_at_ms",
    ];
    if item_object.len() != expected_item_fields.len()
        || expected_item_fields
            .iter()
            .any(|field| !item_object.contains_key(*field))
    {
        return Err(Error::other(format!(
            "{label} item did not expose the exact public ready metadata fields"
        ))
        .into());
    }
    assert_eq!(item["schema"], "zode.auth-replica.v1", "{label}");
    assert_eq!(item["auth_profile_id"], PROFILE_ID, "{label}");
    assert_eq!(item["authority_id"], "controller-e2e", "{label}");
    assert_eq!(item["provider"], "fixture-provider", "{label}");
    assert_eq!(item["revision"], expected_revision, "{label}");
    assert_eq!(item["status"], "ready", "{label}");
    assert!(
        item["expires_at_ms"].is_null(),
        "{label} item exposed an unexpected expiry"
    );
    Ok(())
}

fn assert_replica_list_omits_profile(label: &str, body: &Value) -> TestResult<()> {
    assert_eq!(body["schema"], "zode.auth-replica-list.v1", "{label}");
    let items = body["items"]
        .as_array()
        .ok_or_else(|| Error::other(format!("{label} omitted items")))?;
    assert!(
        items
            .iter()
            .all(|item| item["auth_profile_id"] != PROFILE_ID),
        "{label} exposed the missing profile: {body}"
    );
    Ok(())
}

async fn put_replica(
    client: &Client,
    server: &ConfiguredServer,
    key: &str,
    revision: u64,
    secret: Option<&str>,
) -> TestResult<(StatusCode, String)> {
    let body = match secret {
        Some(secret) => json!({
            "schema": "zode.auth-replica.install.v1",
            "authority_id": "controller-e2e",
            "provider": "fixture-provider",
            "kind": "api_key",
            "revision": revision,
            "credential_schema": "openai-compatible.api-key.v1",
            "expires_at_ms": null,
            "secret": {
                "encoding": "application/zode-secret-envelope",
                "payload": secret
            }
        }),
        None => json!({
            "schema": "zode.auth-replica.tombstone.v1",
            "authority_id": "controller-e2e",
            "provider": "fixture-provider",
            "revision": revision
        }),
    };
    put_replica_payload(client, server, key, body).await
}

struct ReplicaRecoveryPaths {
    active_record: PathBuf,
    revision_one_receipt: PathBuf,
    revision_two_receipt: PathBuf,
}

fn discover_replica_recovery_paths(
    root: &Path,
    authority_id: &str,
    profile_id: &str,
) -> std::io::Result<ReplicaRecoveryPaths> {
    let mut active_record = None;
    let mut receipts = Vec::<(u64, PathBuf)>::new();
    let mut pending = vec![root.to_owned()];
    let mut inspected = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            inspected = inspected.saturating_add(1);
            if inspected > 1_024 {
                return Err(Error::other(
                    "replica metadata checkpoint exceeded the bounded file scan",
                ));
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
                continue;
            };
            if value["schema"] == "zode.auth-replica.record.v1"
                && value["authority_id"] == authority_id
                && value["profile_id"] == profile_id
                && value["revision"] == 2
            {
                if active_record.replace(path).is_some() {
                    return Err(Error::other(
                        "multiple active replica records matched semantic checkpoint",
                    ));
                }
            } else if value["schema"] == "zode.auth-replica.receipt.v1"
                && value["authority_id"] == authority_id
                && value["profile_id"] == profile_id
                && matches!(value["revision"].as_u64(), Some(1 | 2))
            {
                receipts.push((value["revision"].as_u64().unwrap_or_default(), path));
            }
        }
    }
    let active_record = active_record.ok_or_else(|| {
        Error::other("semantic replica checkpoint did not find active revision 2 record")
    })?;
    let receipt_for = |revision: u64| -> std::io::Result<PathBuf> {
        let matches = receipts
            .iter()
            .filter(|(candidate, _)| *candidate == revision)
            .map(|(_, path)| path.clone())
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(Error::other(
                "semantic replica checkpoint had an ambiguous receipt",
            ));
        }
        Ok(matches.into_iter().next().expect("checked one receipt"))
    };
    Ok(ReplicaRecoveryPaths {
        active_record,
        revision_one_receipt: receipt_for(1)?,
        revision_two_receipt: receipt_for(2)?,
    })
}

async fn put_replica_payload(
    client: &Client,
    server: &ConfiguredServer,
    key: &str,
    body: Value,
) -> TestResult<(StatusCode, String)> {
    let response =
        authenticated(client.put(server.url(&format!("/v1/auth-replicas/{PROFILE_ID}"))))
            .header("Idempotency-Key", key)
            .json(&body)
            .send_with_timeout()
            .await?;
    let status = response.status();
    assert_response_headers_secret_free(&response, &[SECRET_A, SECRET_B, SECRET_C, SECRET_D]);
    let body = response_text(response).await?;
    assert_secret_free(&body);
    Ok((status, body))
}

async fn put_replica_with_expiry(
    client: &Client,
    server: &ConfiguredServer,
    key: &str,
    revision: u64,
    expires_at_ms: i64,
    secret: &str,
) -> TestResult<(StatusCode, String)> {
    put_replica_payload(
        client,
        server,
        key,
        json!({
            "schema": "zode.auth-replica.install.v1",
            "authority_id": "controller-e2e",
            "provider": "fixture-provider",
            "kind": "api_key",
            "revision": revision,
            "credential_schema": "openai-compatible.api-key.v1",
            "expires_at_ms": expires_at_ms,
            "secret": {
                "encoding": "application/zode-secret-envelope",
                "payload": secret
            }
        }),
    )
    .await
}

async fn read_replica(
    client: &Client,
    server: &ConfiguredServer,
) -> TestResult<(StatusCode, String)> {
    read_replica_at_path(client, server, &format!("/v1/auth-replicas/{PROFILE_ID}")).await
}

async fn read_replica_at_path(
    client: &Client,
    server: &ConfiguredServer,
    path: &str,
) -> TestResult<(StatusCode, String)> {
    let response = authenticated(client.get(server.url(path)))
        .send_with_timeout()
        .await?;
    let status = response.status();
    assert_response_headers_secret_free(
        &response,
        &[
            SECRET_A,
            SECRET_B,
            SECRET_C,
            SECRET_D,
            TEST_CONTROLLER_SECRET,
        ],
    );
    let body = response_text(response).await?;
    assert_secret_free(&body);
    Ok((status, body))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReplicaRecoveryIncident {
    schema: String,
    version: u64,
    recording_id: String,
    owner: String,
    boundary: String,
    first_failure: ReplicaRecoveryFailure,
    slots: Vec<String>,
    request: ReplicaRecoveryRequest,
    response: ReplicaRecoveryResponse,
    canonical_fingerprint: ReplicaRecoveryFingerprints,
    whole_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReplicaRecoveryFailure {
    status: u16,
    error_code: String,
    response_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReplicaRecoveryRequest {
    method: String,
    path: String,
    headers: Vec<ReplicaRecoveryHeader>,
    body: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReplicaRecoveryResponse {
    status: u16,
    headers: Vec<ReplicaRecoveryHeader>,
    body: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReplicaRecoveryHeader {
    name: String,
    value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReplicaRecoveryFingerprints {
    algorithm: String,
    request: String,
    response: String,
}

fn replica_recovery_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn replica_recovery_fingerprint<T: Serialize>(value: &T) -> TestResult<String> {
    Ok(replica_recovery_sha256(&serde_json::to_vec(value)?))
}

fn replica_recovery_whole_digest(cassette: &ReplicaRecoveryIncident) -> TestResult<String> {
    let mut unsigned = cassette.clone();
    unsigned.whole_digest.clear();
    Ok(format!(
        "sha256:{}",
        replica_recovery_sha256(&serde_json::to_vec(&unsigned)?)
    ))
}

fn make_replica_recovery_incident(
    request: ReplicaRecoveryRequest,
    response: ReplicaRecoveryResponse,
) -> TestResult<ReplicaRecoveryIncident> {
    let request_fingerprint = replica_recovery_fingerprint(&request)?;
    let response_fingerprint = replica_recovery_fingerprint(&response)?;
    let mut cassette = ReplicaRecoveryIncident {
        schema: "zode.http-incident-recording.v1".to_owned(),
        version: 1,
        recording_id: REPLICA_RECOVERY_RECORDING_ID.to_owned(),
        owner: REPLICA_RECOVERY_OWNER.to_owned(),
        boundary: "endpoint_http".to_owned(),
        first_failure: ReplicaRecoveryFailure {
            status: response.status,
            error_code: "stale_active_replica_after_receipt_loss".to_owned(),
            response_fingerprint: response_fingerprint.clone(),
        },
        slots: vec![
            "SLOT_CONTROLLER_AUTHORIZATION".to_owned(),
            "SLOT_CONTROLLER_SUBJECT".to_owned(),
        ],
        request,
        response,
        canonical_fingerprint: ReplicaRecoveryFingerprints {
            algorithm: "sha256".to_owned(),
            request: request_fingerprint,
            response: response_fingerprint,
        },
        whole_digest: String::new(),
    };
    cassette.whole_digest = replica_recovery_whole_digest(&cassette)?;
    Ok(cassette)
}

fn replica_recovery_secret_markers() -> [&'static str; 9] {
    [
        SECRET_A,
        SECRET_B,
        SECRET_C,
        SECRET_D,
        TEST_CONTROLLER_SECRET,
        AUTHORITY_A_SECRET,
        AUTHORITY_B_SECRET,
        AUTHORITY_A_NEW_SECRET,
        AUTHORITY_B_NEW_SECRET,
    ]
}

fn assert_replica_recovery_bytes_secret_free(bytes: &[u8]) -> TestResult<()> {
    for marker in replica_recovery_secret_markers() {
        if bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
        {
            return Err(Error::other("replica recovery recording retained a secret marker").into());
        }
    }
    Ok(())
}

fn load_replica_recovery_cassette() -> TestResult<ReplicaRecoveryIncident> {
    let bytes = fs::read(REPLICA_RECOVERY_CASSETTE)?;
    assert_replica_recovery_bytes_secret_free(&bytes)?;
    let cassette: ReplicaRecoveryIncident = serde_json::from_slice(&bytes)?;
    if cassette.schema != "zode.http-incident-recording.v1"
        || cassette.version != 1
        || cassette.recording_id != REPLICA_RECOVERY_RECORDING_ID
        || cassette.owner != REPLICA_RECOVERY_OWNER
        || cassette.boundary != "endpoint_http"
        || cassette.slots
            != [
                "SLOT_CONTROLLER_AUTHORIZATION".to_owned(),
                "SLOT_CONTROLLER_SUBJECT".to_owned(),
            ]
        || cassette.request.method != "GET"
        || cassette.request.path != REPLICA_RECOVERY_PATH
        || !cassette.request.body.is_empty()
        || cassette.request.headers
            != [
                ReplicaRecoveryHeader {
                    name: "authorization".to_owned(),
                    value: "SLOT_CONTROLLER_AUTHORIZATION".to_owned(),
                },
                ReplicaRecoveryHeader {
                    name: "zode-subject".to_owned(),
                    value: "SLOT_CONTROLLER_SUBJECT".to_owned(),
                },
            ]
        || cassette.response.status != 200
        || cassette.response.headers
            != [ReplicaRecoveryHeader {
                name: "content-type".to_owned(),
                value: "application/json".to_owned(),
            }]
        || cassette.first_failure.status != cassette.response.status
        || cassette.first_failure.error_code != "stale_active_replica_after_receipt_loss"
        || cassette.canonical_fingerprint.algorithm != "sha256"
        || cassette.canonical_fingerprint.request
            != replica_recovery_fingerprint(&cassette.request)?
        || cassette.canonical_fingerprint.response
            != replica_recovery_fingerprint(&cassette.response)?
        || cassette.first_failure.response_fingerprint != cassette.canonical_fingerprint.response
        || cassette.whole_digest != replica_recovery_whole_digest(&cassette)?
        || cassette.whole_digest != REPLICA_RECOVERY_WHOLE_DIGEST
    {
        return Err(Error::other("replica recovery cassette integrity was invalid").into());
    }
    let metadata: Value = serde_json::from_str(&cassette.response.body)?;
    if metadata["schema"] != "zode.auth-replica.v1"
        || metadata["authority_id"] != "controller-e2e"
        || metadata["auth_profile_id"] != PROFILE_ID
        || metadata["provider"] != "fixture-provider"
        || metadata["revision"] != 1
        || !metadata["expires_at_ms"].is_null()
        || metadata["status"] != "ready"
    {
        return Err(
            Error::other("replica recovery cassette did not retain the split metadata").into(),
        );
    }
    Ok(cassette)
}

fn capture_replica_recovery_first_exchange(
    request: &ReplicaRecoveryRequest,
    response: &ReplicaRecoveryResponse,
) -> TestResult<()> {
    if env::var_os("ZODE_CAPTURE_FIRST_OCCURRENCE").is_none() {
        return Ok(());
    }
    let cassette = make_replica_recovery_incident(request.clone(), response.clone())?;
    let bytes = serde_json::to_vec_pretty(&cassette)?;
    assert_replica_recovery_bytes_secret_free(&bytes)?;
    let quarantine = env::temp_dir().join("zode-e2e-quarantine");
    fs::create_dir_all(&quarantine)?;
    #[cfg(unix)]
    fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700))?;
    let path = quarantine.join(
        "e2e_auth_replica_recovery_does_not_split_active_and_receipt_metadata.first.secret-safe.json",
    );
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn replica_recovery_request_from_http(
    request: &reqwest::Request,
) -> TestResult<ReplicaRecoveryRequest> {
    let authorization = request
        .headers()
        .get_all("authorization")
        .iter()
        .collect::<Vec<_>>();
    let subjects = request
        .headers()
        .get_all("zode-subject")
        .iter()
        .collect::<Vec<_>>();
    if authorization.len() != 1
        || authorization[0].to_str()? != format!("Bearer {TEST_CONTROLLER_SECRET}")
        || subjects.len() != 1
        || subjects[0].to_str()? != support::TEST_SUBJECT
        || request.url().query().is_some()
        || request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .is_some_and(|body| !body.is_empty())
    {
        return Err(Error::other("replica recovery public request envelope was invalid").into());
    }
    Ok(ReplicaRecoveryRequest {
        method: request.method().as_str().to_owned(),
        path: request.url().path().to_owned(),
        headers: vec![
            ReplicaRecoveryHeader {
                name: "authorization".to_owned(),
                value: "SLOT_CONTROLLER_AUTHORIZATION".to_owned(),
            },
            ReplicaRecoveryHeader {
                name: "zode-subject".to_owned(),
                value: "SLOT_CONTROLLER_SUBJECT".to_owned(),
            },
        ],
        body: String::new(),
    })
}

async fn replay_replica_recovery_get(
    client: &Client,
    server: &ConfiguredServer,
    path: &str,
) -> TestResult<(ReplicaRecoveryRequest, ReplicaRecoveryResponse)> {
    let request = authenticated(client.get(server.url(path))).build()?;
    let safe_request = replica_recovery_request_from_http(&request)?;
    let response = timeout(Duration::from_secs(5), client.execute(request)).await??;
    assert_response_headers_secret_free(&response, &replica_recovery_secret_markers());
    let content_types = response
        .headers()
        .get_all(reqwest::header::CONTENT_TYPE)
        .iter()
        .collect::<Vec<_>>();
    if content_types.len() != 1 {
        return Err(Error::other("replica recovery response had ambiguous content type").into());
    }
    let status = response.status().as_u16();
    let content_type = content_types[0].to_str()?.to_owned();
    let body = response_text(response).await?;
    assert_secret_free(&body);
    Ok((
        safe_request,
        ReplicaRecoveryResponse {
            status,
            headers: vec![ReplicaRecoveryHeader {
                name: "content-type".to_owned(),
                value: content_type,
            }],
            body,
        },
    ))
}

fn replica_recovery_replayed_first_failure(
    cassette: &ReplicaRecoveryIncident,
    request: &ReplicaRecoveryRequest,
    response: &ReplicaRecoveryResponse,
) -> TestResult<bool> {
    if request != &cassette.request
        || replica_recovery_fingerprint(request)? != cassette.canonical_fingerprint.request
    {
        return Err(
            Error::other("replica recovery public request did not match its cassette").into(),
        );
    }
    let response_fingerprint = replica_recovery_fingerprint(response)?;
    Ok(response == &cassette.response
        && response_fingerprint == cassette.canonical_fingerprint.response
        && cassette.first_failure.status == response.status
        && cassette.first_failure.response_fingerprint == response_fingerprint)
}

async fn list_replicas(
    client: &Client,
    server: &ConfiguredServer,
) -> TestResult<(StatusCode, String)> {
    let response = authenticated(client.get(server.url("/v1/auth-replicas")))
        .send_with_timeout()
        .await?;
    let status = response.status();
    assert_response_headers_secret_free(
        &response,
        &[
            SECRET_A,
            SECRET_B,
            SECRET_C,
            SECRET_D,
            TEST_CONTROLLER_SECRET,
        ],
    );
    let body = response_text(response).await?;
    assert_secret_free(&body);
    Ok((status, body))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_missing_auth_replica_get_is_safe_not_found() -> TestResult<()> {
    let database = TempDatabase::new("control-missing-replica-get")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;

    let (list_status, list_body) = list_replicas(&client, &server).await?;
    assert_eq!(list_status, StatusCode::OK, "{list_body}");
    assert_replica_list_omits_profile("missing replica list", &serde_json::from_str(&list_body)?)?;

    let (status, body) = read_replica(&client, &server).await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "missing replica GET: {body}");
    let error: Value = serde_json::from_str(&body)?;
    assert_eq!(error["error"]["code"], "auth_replica_not_found", "{body}");
    assert_eq!(error["error"]["retryable"], false, "{body}");
    assert!(
        error["error"]["message"].as_str().is_some(),
        "missing replica GET omitted a safe error message: {body}"
    );
    assert!(
        !body.contains(PROFILE_ID),
        "missing replica GET disclosed the profile"
    );
    assert!(!body.to_lowercase().contains("sqlite"));
    assert!(!body.to_lowercase().contains("database"));
    server.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_identity_is_endpoint_owned_and_restart_stable() -> TestResult<()> {
    let database = TempDatabase::new("control-identity")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;

    let (status, first) = identity(&client, &server).await?;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["schema"], "zode.identity.v1");
    assert_eq!(first["protocol_version"], "zode.endpoint.v1");
    let endpoint_id = first["endpoint_id"]
        .as_str()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "identity omitted endpoint_id"))?
        .to_owned();
    assert!(!endpoint_id.is_empty());
    assert_ne!(endpoint_id, "controller-selected-id");

    let attempted_override =
        authenticated(client.get(server.url("/v1/identity?endpoint_id=controller-selected-id")))
            .header("X-Zode-Endpoint-ID", "controller-selected-id")
            .send_with_timeout()
            .await?;
    assert_eq!(attempted_override.status(), StatusCode::OK);
    let attempted_body = response_json(attempted_override).await?;
    assert_eq!(attempted_body["endpoint_id"], endpoint_id);

    server.stop().await?;
    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let (status, after) = identity(&client, &restarted).await?;
    assert_eq!(status, StatusCode::OK, "{after}");
    assert_eq!(after["endpoint_id"], endpoint_id);
    restarted.stop().await?;
    Ok(())
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_bootstrap_seed_is_consumed_after_active_manifest_and_stale_seed_cannot_reclaim(
) -> TestResult<()> {
    let database = TempDatabase::new("control-bootstrap-seed")?;
    let config = config_for(&database)?;
    let root = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("temporary database has no parent directory"))?;
    let seed = root.join("controller.secret");
    assert!(seed.is_file(), "test bootstrap seed was not created");

    let client = support::http_client()?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let identity_path = sidecar_path(database.path(), ".endpoint-id");
    let initialization_path = controller_auth_dir(database.path()).join("initialization.json");
    assert!(
        initialization_path.is_file(),
        "active controller initialization manifest was not durable before readiness"
    );
    assert!(
        !seed.exists(),
        "bootstrap seed remained after active manifest became durable"
    );
    assert!(
        identity_path.is_file(),
        "endpoint identity was not persisted"
    );
    server.stop().await?;

    fs::write(&seed, "stale-bootstrap-controller-secret")?;
    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(&seed)?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&seed, permissions)?;
    }

    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let (status, _) = identity_with_secret(&client, &restarted, TEST_CONTROLLER_SECRET).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "durable controller secret no longer works"
    );
    let (stale_status, stale_body) =
        identity_with_secret(&client, &restarted, "stale-bootstrap-controller-secret").await?;
    assert_eq!(
        stale_status,
        StatusCode::UNAUTHORIZED,
        "stale seed reclaimed authority: {stale_body}"
    );
    restarted.stop().await?;
    Ok(())
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_invalid_controller_auth_and_subject_fail_before_lookup() -> TestResult<()> {
    let database = TempDatabase::new("control-auth-validation")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let (session_id, _) = create_model_less(&client, &server, SUBJECT_A, "auth-seed").await?;
    let url = server.url(&format!("/v1/sessions/{session_id}"));

    let duplicate_authorization = client.get(&url).headers(duplicate_headers(
        "authorization",
        &[
            format!("Bearer {TEST_CONTROLLER_SECRET}").as_str(),
            "Bearer wrong-controller-secret",
        ],
    )?);
    let mut duplicate_subject_headers = HeaderMap::new();
    duplicate_subject_headers.append(
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {TEST_CONTROLLER_SECRET}"))?,
    );
    duplicate_subject_headers.append(
        HeaderName::from_static("zode-subject"),
        HeaderValue::from_static(SUBJECT_A),
    );
    duplicate_subject_headers.append(
        HeaderName::from_static("zode-subject"),
        HeaderValue::from_static(SUBJECT_B),
    );
    let auth_cases = vec![
        (
            "missing authorization",
            client.get(&url).header("Zode-Subject", SUBJECT_A),
        ),
        (
            "wrong authorization",
            client
                .get(&url)
                .header("Authorization", "Bearer wrong-controller-secret")
                .header("Zode-Subject", SUBJECT_A),
        ),
        ("duplicate authorization", duplicate_authorization),
        (
            "wrong authorization before empty subject",
            client
                .get(&url)
                .header("Authorization", "Bearer wrong-controller-secret")
                .header("Zode-Subject", ""),
        ),
        (
            "wrong authorization before oversized subject",
            client
                .get(&url)
                .header("Authorization", "Bearer wrong-controller-secret")
                .header("Zode-Subject", "s".repeat(1024)),
        ),
    ];
    for (label, request) in auth_cases {
        assert_safe_auth_rejection(
            label,
            request,
            &session_id,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        )
        .await?;
    }

    let subject_cases = vec![
        (
            "missing subject",
            client
                .get(&url)
                .header("Authorization", format!("Bearer {TEST_CONTROLLER_SECRET}")),
        ),
        (
            "empty subject",
            client
                .get(&url)
                .header("Authorization", format!("Bearer {TEST_CONTROLLER_SECRET}"))
                .header("Zode-Subject", ""),
        ),
        (
            "duplicate subject",
            client.get(&url).headers(duplicate_subject_headers),
        ),
    ];
    for (label, request) in subject_cases {
        assert_safe_auth_rejection(
            label,
            request,
            &session_id,
            StatusCode::BAD_REQUEST,
            "malformed_request",
        )
        .await?;
    }
    server.stop().await?;
    Ok(())
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_oversized_subject_is_rejected_as_payload_too_large() -> TestResult<()> {
    let database = TempDatabase::new("control-oversized-subject")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let (session_id, _) = create_model_less(&client, &server, SUBJECT_A, "oversized-seed").await?;
    let oversized_subject = "s".repeat(1024);
    let request = client
        .get(server.url(&format!("/v1/sessions/{session_id}")))
        .header("Authorization", format!("Bearer {TEST_CONTROLLER_SECRET}"))
        .header("Zode-Subject", oversized_subject);
    let result = assert_safe_auth_rejection(
        "oversized subject",
        request,
        &session_id,
        StatusCode::PAYLOAD_TOO_LARGE,
        "payload_too_large",
    )
    .await;
    server.stop().await?;
    result
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_authority_subject_create_receipts_are_scoped() -> TestResult<()> {
    let database = TempDatabase::new("control-create-receipts")?;
    let config = config_for_authorities(
        &database,
        &[
            (AUTHORITY_A, AUTHORITY_A_SECRET),
            (AUTHORITY_B, AUTHORITY_B_SECRET),
        ],
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;

    let (first_id, first_body) = create_receipt_with_exact_replay(
        &client,
        &server,
        AUTHORITY_A_SECRET,
        SUBJECT_A,
        "authority-shared-create-key",
    )
    .await?;
    let (second_id, second_body) = create_receipt_with_exact_replay(
        &client,
        &server,
        AUTHORITY_B_SECRET,
        SUBJECT_A,
        "authority-shared-create-key",
    )
    .await?;
    assert_ne!(first_id, second_id);
    assert!(is_crockford_ulid(&first_id), "first create was not a ULID");
    assert!(
        is_crockford_ulid(&second_id),
        "second create was not a ULID"
    );
    assert_ne!(first_body, second_body);

    assert_create_payload_conflict(
        &client,
        &server,
        AUTHORITY_A_SECRET,
        SUBJECT_A,
        "authority-shared-create-key",
    )
    .await?;
    assert_create_payload_conflict(
        &client,
        &server,
        AUTHORITY_B_SECRET,
        SUBJECT_A,
        "authority-shared-create-key",
    )
    .await?;

    let (subject_a_id, subject_a_body) = create_receipt_with_exact_replay(
        &client,
        &server,
        AUTHORITY_A_SECRET,
        SUBJECT_A,
        "subject-shared-create-key",
    )
    .await?;
    let (subject_b_id, subject_b_body) = create_receipt_with_exact_replay(
        &client,
        &server,
        AUTHORITY_A_SECRET,
        SUBJECT_B,
        "subject-shared-create-key",
    )
    .await?;
    assert_ne!(subject_a_id, subject_b_id);
    assert!(is_crockford_ulid(&subject_a_id));
    assert!(is_crockford_ulid(&subject_b_id));
    assert_ne!(subject_a_body, subject_b_body);
    assert_create_payload_conflict(
        &client,
        &server,
        AUTHORITY_A_SECRET,
        SUBJECT_A,
        "subject-shared-create-key",
    )
    .await?;
    assert_create_payload_conflict(
        &client,
        &server,
        AUTHORITY_A_SECRET,
        SUBJECT_B,
        "subject-shared-create-key",
    )
    .await?;
    server.stop().await?;
    Ok(())
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_subject_ownership_isolates_list_read_sse_and_messages() -> TestResult<()> {
    let database = TempDatabase::new("control-subject-isolation")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let (first_id, first_body) = create_receipt_with_exact_replay(
        &client,
        &server,
        TEST_CONTROLLER_SECRET,
        SUBJECT_A,
        "isolation-key",
    )
    .await?;
    let (second_id, second_body) = create_receipt_with_exact_replay(
        &client,
        &server,
        TEST_CONTROLLER_SECRET,
        SUBJECT_B,
        "isolation-key",
    )
    .await?;
    assert_ne!(first_id, second_id);
    assert_ne!(first_body, second_body);
    assert_create_payload_conflict(
        &client,
        &server,
        TEST_CONTROLLER_SECRET,
        SUBJECT_A,
        "isolation-key",
    )
    .await?;
    assert_create_payload_conflict(
        &client,
        &server,
        TEST_CONTROLLER_SECRET,
        SUBJECT_B,
        "isolation-key",
    )
    .await?;

    let (status, body) = get_session(&client, &server, SUBJECT_A, &first_id).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = get_session(&client, &server, SUBJECT_B, &second_id).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = get_session(&client, &server, SUBJECT_A, &second_id).await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross-subject read leaked: {body}"
    );
    let (status, body) = get_session(&client, &server, SUBJECT_B, &first_id).await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross-subject read leaked: {body}"
    );
    assert!(!body.contains(&first_id));

    for (subject, own_id, foreign_id) in [
        (SUBJECT_A, first_id.as_str(), second_id.as_str()),
        (SUBJECT_B, second_id.as_str(), first_id.as_str()),
    ] {
        let stream = authenticated_as(client.get(server.url("/v1/events")), subject)
            .send_with_timeout()
            .await?;
        assert_eq!(stream.status(), StatusCode::OK);
        let visible_id = first_sse_session_id(stream).await?;
        assert_eq!(visible_id, own_id);
        assert_ne!(visible_id, foreign_id);
    }

    let (status, body) = post_message(
        &client,
        &server,
        SUBJECT_A,
        &second_id,
        "cross-subject-message",
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross-subject message leaked: {body}"
    );
    let (status, body) = post_message(
        &client,
        &server,
        SUBJECT_B,
        &second_id,
        "own-subject-message",
    )
    .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    let (status, body) = list_sessions(&client, &server, SUBJECT_A).await?;
    assert_one_owned_session_list(
        status,
        &body,
        SUBJECT_A,
        &first_id,
        &second_id,
        "00000000000000000000000000",
    )?;
    let (status, body) = list_sessions(&client, &server, SUBJECT_B).await?;
    assert_one_owned_session_list(
        status,
        &body,
        SUBJECT_B,
        &second_id,
        &first_id,
        "00000000000000000000000000",
    )?;

    server.stop().await?;
    Ok(())
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_session_authority_ownership_isolates_list_read_message_and_sse() -> TestResult<()> {
    let database = TempDatabase::new("control-authority-session-isolation")?;
    let config = config_for_authorities(
        &database,
        &[
            (AUTHORITY_A, AUTHORITY_A_SECRET),
            (AUTHORITY_B, AUTHORITY_B_SECRET),
        ],
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;

    let (authority_a_session, _) = create_model_less_with_secret(
        &client,
        &server,
        AUTHORITY_A_SECRET,
        SUBJECT_A,
        "authority-session-a",
    )
    .await?;
    let (authority_b_session, _) = create_model_less_with_secret(
        &client,
        &server,
        AUTHORITY_B_SECRET,
        SUBJECT_A,
        "authority-session-b",
    )
    .await?;
    assert_ne!(authority_a_session, authority_b_session);

    let (status, body) =
        list_sessions_with_secret(&client, &server, AUTHORITY_A_SECRET, SUBJECT_A).await?;
    assert_one_owned_session_list(
        status,
        &body,
        "authority A",
        &authority_a_session,
        &authority_b_session,
        "00000000000000000000000000",
    )?;
    let (status, body) =
        list_sessions_with_secret(&client, &server, AUTHORITY_B_SECRET, SUBJECT_A).await?;
    assert_one_owned_session_list(
        status,
        &body,
        "authority B",
        &authority_b_session,
        &authority_a_session,
        "00000000000000000000000000",
    )?;

    let (status, body) = get_session_with_secret(
        &client,
        &server,
        AUTHORITY_A_SECRET,
        SUBJECT_A,
        &authority_a_session,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "authority A own read: {body}");
    let (status, body) = get_session_with_secret(
        &client,
        &server,
        AUTHORITY_B_SECRET,
        SUBJECT_A,
        &authority_b_session,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "authority B own read: {body}");

    for (label, secret, session_id) in [
        (
            "authority A cross read",
            AUTHORITY_A_SECRET,
            &authority_b_session,
        ),
        (
            "authority B cross read",
            AUTHORITY_B_SECRET,
            &authority_a_session,
        ),
    ] {
        let (status, body) =
            get_session_with_secret(&client, &server, secret, SUBJECT_A, session_id).await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "{label}: {body}");
        assert!(
            !body.contains(session_id),
            "{label} disclosed the foreign session"
        );
    }

    for (label, secret, session_id, key) in [
        (
            "authority A cross message",
            AUTHORITY_A_SECRET,
            &authority_b_session,
            "authority-cross-message-a",
        ),
        (
            "authority B cross message",
            AUTHORITY_B_SECRET,
            &authority_a_session,
            "authority-cross-message-b",
        ),
    ] {
        let (status, body) =
            post_message_with_secret(&client, &server, secret, SUBJECT_A, session_id, key).await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "{label}: {body}");
    }

    for (label, secret, own_session, foreign_session) in [
        (
            "authority A Endpoint SSE",
            AUTHORITY_A_SECRET,
            &authority_a_session,
            &authority_b_session,
        ),
        (
            "authority B Endpoint SSE",
            AUTHORITY_B_SECRET,
            &authority_b_session,
            &authority_a_session,
        ),
    ] {
        let response =
            authenticated_with_secret(client.get(server.url("/v1/events")), secret, SUBJECT_A)
                .send_with_timeout()
                .await?;
        assert_eq!(response.status(), StatusCode::OK, "{label}");
        let visible_id = first_sse_session_id(response).await?;
        assert_eq!(visible_id, own_session.as_str(), "{label}");
        assert_ne!(
            visible_id,
            foreign_session.as_str(),
            "{label} disclosed foreign session"
        );
    }

    let (status, body) = post_message_with_secret(
        &client,
        &server,
        AUTHORITY_A_SECRET,
        SUBJECT_A,
        &authority_a_session,
        "authority-own-message-a",
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "authority A own message: {body}"
    );
    let (status, body) = post_message_with_secret(
        &client,
        &server,
        AUTHORITY_B_SECRET,
        SUBJECT_A,
        &authority_b_session,
        "authority-own-message-b",
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "authority B own message: {body}"
    );

    server.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_auth_replica_revision_tombstone_and_restart_are_secret_free() -> TestResult<()> {
    let database = TempDatabase::new("control-replica-lifecycle")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;

    let (status, first_body) =
        put_replica(&client, &server, "replica-install-1", 1, Some(SECRET_A)).await?;
    assert!(
        status.is_success(),
        "replica install failed: {status} {first_body}"
    );
    let (replay_status, replay_body) =
        put_replica(&client, &server, "replica-install-1", 1, Some(SECRET_A)).await?;
    assert_eq!(replay_status, status);
    assert_eq!(replay_body, first_body);

    let (status, body) = put_replica(
        &client,
        &server,
        "replica-install-conflict",
        1,
        Some(SECRET_B),
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "same revision changed secret: {body}"
    );
    let (status, body) =
        put_replica(&client, &server, "replica-install-2", 2, Some(SECRET_B)).await?;
    assert!(
        status.is_success(),
        "newer replica did not win: {status} {body}"
    );
    let (status, body) =
        put_replica(&client, &server, "replica-install-stale", 1, Some(SECRET_C)).await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "stale replica replaced newer revision: {body}"
    );
    let (tombstone_status, tombstone_body) =
        put_replica(&client, &server, "replica-tombstone", 3, None).await?;
    assert!(
        tombstone_status.is_success(),
        "tombstone failed: {tombstone_status} {tombstone_body}"
    );
    let tombstone_metadata: Value = serde_json::from_str(&tombstone_body)?;
    assert_tombstoned_metadata("tombstone PUT", &tombstone_metadata, 3)?;
    let (tombstone_replay_status, tombstone_replay_body) =
        put_replica(&client, &server, "replica-tombstone", 3, None).await?;
    assert_eq!(tombstone_replay_status, tombstone_status);
    assert_eq!(tombstone_replay_body, tombstone_body);
    let (status, body) =
        put_replica(&client, &server, "replica-tombstone", 3, Some(SECRET_D)).await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "changed tombstone body reused the original operation: {body}"
    );
    let (status, body) =
        put_replica(&client, &server, "replica-resurrection", 2, Some(SECRET_D)).await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "stale install resurrected tombstone: {body}"
    );

    let (status, body) = read_replica(&client, &server).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let read_metadata: Value = serde_json::from_str(&body)?;
    assert_tombstoned_metadata("tombstoned GET", &read_metadata, 3)?;
    let (status, body) = list_replicas(&client, &server).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let list_metadata: Value = serde_json::from_str(&body)?;
    assert_tombstoned_list("tombstoned list", &list_metadata, 3)?;
    server.stop().await?;
    for marker in [SECRET_A, SECRET_B, SECRET_C, SECRET_D] {
        assert!(!sqlite_contains_secret(database.path(), marker).await?);
    }

    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let (status, body) = read_replica(&client, &restarted).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let read_metadata: Value = serde_json::from_str(&body)?;
    assert_tombstoned_metadata("restarted tombstoned GET", &read_metadata, 3)?;
    let (status, body) = list_replicas(&client, &restarted).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let list_metadata: Value = serde_json::from_str(&body)?;
    assert_tombstoned_list("restarted tombstoned list", &list_metadata, 3)?;
    restarted.stop().await?;
    for marker in [SECRET_A, SECRET_B, SECRET_C, SECRET_D] {
        assert!(!sqlite_contains_secret(database.path(), marker).await?);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_auth_replica_expiry_and_historical_receipt_survive_restart() -> TestResult<()> {
    let database = TempDatabase::new("control-replica-expiry-receipt")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let first_key = "replica-expiry-history-first";

    let (first_status, first_body) = put_replica_with_expiry(
        &client,
        &server,
        first_key,
        1,
        EXPIRY_REVISION_ONE,
        SECRET_A,
    )
    .await?;
    let first_metadata: Value = serde_json::from_str(&first_body)?;

    let (upgrade_status, upgrade_body) = put_replica_with_expiry(
        &client,
        &server,
        "replica-expiry-history-upgrade",
        2,
        EXPIRY_REVISION_TWO,
        SECRET_B,
    )
    .await?;
    assert!(
        upgrade_status.is_success(),
        "expiry revision upgrade failed: {upgrade_status} {upgrade_body}"
    );
    let upgrade_metadata: Value = serde_json::from_str(&upgrade_body)?;

    let (current_status, current_body) = read_replica(&client, &server).await?;
    let current_metadata: Value = serde_json::from_str(&current_body)?;
    server.stop().await?;
    assert!(!sqlite_contains_secret(database.path(), SECRET_A).await?);
    assert!(!sqlite_contains_secret(database.path(), SECRET_B).await?);

    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let (restart_status, restart_body) = read_replica(&client, &restarted).await?;
    let restart_metadata: Value = serde_json::from_str(&restart_body)?;
    let (replay_status, replay_body) = put_replica_with_expiry(
        &client,
        &restarted,
        first_key,
        1,
        EXPIRY_REVISION_ONE,
        SECRET_A,
    )
    .await?;
    let (after_replay_status, after_replay_body) = read_replica(&client, &restarted).await?;
    let after_replay_metadata: Value = serde_json::from_str(&after_replay_body)?;
    restarted.stop().await?;
    assert!(!sqlite_contains_secret(database.path(), SECRET_A).await?);
    assert!(!sqlite_contains_secret(database.path(), SECRET_B).await?);

    assert!(
        first_status.is_success(),
        "initial expiry install failed: {first_status} {first_body}"
    );
    assert!(upgrade_status.is_success(), "{upgrade_body}");
    assert_eq!(upgrade_metadata["revision"], 2, "{upgrade_body}");
    assert_eq!(upgrade_metadata["status"], "ready", "{upgrade_body}");
    assert_eq!(
        upgrade_metadata["expires_at_ms"], EXPIRY_REVISION_TWO,
        "upgrade PUT omitted the requested expiry: {upgrade_body}"
    );
    assert_eq!(
        first_metadata["expires_at_ms"], EXPIRY_REVISION_ONE,
        "initial PUT omitted the requested expiry: {first_body}"
    );
    assert_eq!(current_status, StatusCode::OK, "{current_body}");
    assert_eq!(current_metadata["revision"], 2, "{current_body}");
    assert_eq!(
        current_metadata["expires_at_ms"], EXPIRY_REVISION_TWO,
        "current replica GET omitted the latest expiry: {current_body}"
    );
    assert_eq!(restart_status, StatusCode::OK, "{restart_body}");
    assert_eq!(restart_metadata["revision"], 2, "{restart_body}");
    assert_eq!(
        restart_metadata["expires_at_ms"], EXPIRY_REVISION_TWO,
        "restart replica GET omitted the latest expiry: {restart_body}"
    );
    assert_eq!(after_replay_status, StatusCode::OK, "{after_replay_body}");
    assert_eq!(after_replay_metadata["revision"], 2, "{after_replay_body}");
    assert_eq!(
        after_replay_metadata["expires_at_ms"], EXPIRY_REVISION_TWO,
        "historical replay changed the current replica expiry: {after_replay_body}"
    );
    assert_eq!(
        replay_status, first_status,
        "historical expiry operation changed status after restart"
    );
    assert_eq!(
        replay_body, first_body,
        "historical expiry operation did not replay the original body"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_auth_replica_history_receipt_binds_original_revision() -> TestResult<()> {
    let database = TempDatabase::new("control-replica-history-receipt")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let key = "replica-history-receipt";

    let (first_status, first_body) = put_replica(&client, &server, key, 1, Some(SECRET_A)).await?;
    assert!(
        first_status.is_success(),
        "initial replica install failed: {first_status}"
    );
    let (replay_status, replay_body) =
        put_replica(&client, &server, key, 1, Some(SECRET_A)).await?;
    assert_eq!(replay_status, first_status);
    assert_eq!(replay_body, first_body);

    let changed_provider_body = json!({
        "schema": "zode.auth-replica.install.v1",
        "authority_id": "controller-e2e",
        "provider": "fixture-provider-alt",
        "kind": "api_key",
        "revision": 1,
        "credential_schema": "openai-compatible.api-key.v1",
        "expires_at_ms": null,
        "secret": {
            "encoding": "application/zode-secret-envelope",
            "payload": SECRET_A
        }
    });
    let (same_key_provider_status, same_key_provider_body) =
        put_replica_payload(&client, &server, key, changed_provider_body).await?;
    let changed_provider_new_key_body = json!({
        "schema": "zode.auth-replica.install.v1",
        "authority_id": "controller-e2e",
        "provider": "fixture-provider-alt-2",
        "kind": "api_key",
        "revision": 1,
        "credential_schema": "openai-compatible.api-key.v1",
        "expires_at_ms": null,
        "secret": {
            "encoding": "application/zode-secret-envelope",
            "payload": SECRET_A
        }
    });
    let (new_key_provider_status, new_key_provider_body) = put_replica_payload(
        &client,
        &server,
        "replica-history-provider-rebind",
        changed_provider_new_key_body,
    )
    .await?;
    assert_eq!(
        same_key_provider_status,
        StatusCode::CONFLICT,
        "same operation key admitted a different provider: same-key={same_key_provider_status}, new-key={new_key_provider_status}"
    );
    assert_secret_free(&same_key_provider_body);
    assert_eq!(
        new_key_provider_status,
        StatusCode::CONFLICT,
        "new operation key rebound the auth-replica resource to another provider: {new_key_provider_status}"
    );
    assert_secret_free(&new_key_provider_body);

    let (read_status, read_body) = read_replica(&client, &server).await?;
    assert_eq!(read_status, StatusCode::OK, "{read_body}");
    let before_restart: Value = serde_json::from_str(&read_body)?;
    assert_eq!(before_restart["provider"], "fixture-provider");
    assert_eq!(before_restart["revision"], 1);
    let (list_status, list_body) = list_replicas(&client, &server).await?;
    assert_eq!(list_status, StatusCode::OK, "{list_body}");
    assert_single_ready_replica_list(
        "changed-provider conflict created an extra current replica",
        &serde_json::from_str(&list_body)?,
        1,
    )?;

    server.stop().await?;
    assert!(!sqlite_contains_secret(database.path(), SECRET_A).await?);

    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let (restart_status, restart_body) = read_replica(&client, &restarted).await?;
    assert_eq!(restart_status, read_status);
    assert_eq!(restart_body, read_body);
    let after_restart: Value = serde_json::from_str(&restart_body)?;
    assert_eq!(after_restart["provider"], "fixture-provider");
    assert_eq!(after_restart["revision"], 1);
    let (restart_list_status, restart_list_body) = list_replicas(&client, &restarted).await?;
    assert_eq!(restart_list_status, StatusCode::OK, "{restart_list_body}");
    assert_single_ready_replica_list(
        "restart changed-provider conflict state",
        &serde_json::from_str(&restart_list_body)?,
        1,
    )?;

    let (upgrade_status, upgrade_body) = put_replica(
        &client,
        &restarted,
        "replica-history-upgrade",
        2,
        Some(SECRET_B),
    )
    .await?;
    assert!(
        upgrade_status.is_success(),
        "new operation key could not install revision 2: {upgrade_status}"
    );
    assert_rotation_secret_free(&upgrade_body, &[SECRET_A, SECRET_B]);

    let (upgrade_read_status, upgrade_read_body) = read_replica(&client, &restarted).await?;
    assert_eq!(upgrade_read_status, StatusCode::OK, "{upgrade_read_body}");
    let metadata: Value = serde_json::from_str(&upgrade_read_body)?;
    assert_eq!(metadata["revision"], 2);
    restarted.stop().await?;
    assert!(!sqlite_contains_secret(database.path(), SECRET_A).await?);
    assert!(!sqlite_contains_secret(database.path(), SECRET_B).await?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_auth_replica_recovery_does_not_split_active_and_receipt_metadata() -> TestResult<()> {
    let database = TempDatabase::new("control-replica-recovery-split")?;
    let config = config_for(&database)?;
    let mut model =
        ModelFixture::start(vec![ModelScript::final_text("replica recovery assistant")]).await?;
    // The provider policy now treats a host-only origin as that host's
    // default port, so this dynamic fixture must be explicitly allowlisted.
    set_provider_execution_policy(&config, &["openai_compatible"], &[&model.origin()])?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let capture_first_occurrence = env::var_os("ZODE_CAPTURE_FIRST_OCCURRENCE").is_some();
    let recovery_cassette = if capture_first_occurrence {
        None
    } else {
        Some(load_replica_recovery_cassette()?)
    };
    let recovery_path = recovery_cassette
        .as_ref()
        .map(|cassette| cassette.request.path.as_str())
        .unwrap_or(REPLICA_RECOVERY_PATH)
        .to_owned();
    let rev1_key = "replica-recovery-split-rev1";
    let rev2_key = "replica-recovery-split-rev2";

    let (status, body) = put_replica(&client, &server, rev1_key, 1, Some(SECRET_A)).await?;
    assert!(
        status.is_success(),
        "revision 1 setup failed: {status} {body}"
    );
    let (rev2_status, rev2_body) =
        put_replica(&client, &server, rev2_key, 2, Some(SECRET_B)).await?;
    assert!(
        rev2_status.is_success(),
        "revision 2 setup failed: {rev2_status} {rev2_body}"
    );
    assert_ready_replica_metadata(
        "revision 2 install response before crash checkpoint",
        &serde_json::from_str(&rev2_body)?,
        2,
    )?;

    let (status, body) = read_replica(&client, &server).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "revision 2 GET setup failed: {body}"
    );
    assert_ready_replica_metadata(
        "active revision 2 GET before crash checkpoint",
        &serde_json::from_str(&body)?,
        2,
    )?;
    let (status, body) = list_replicas(&client, &server).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "revision 2 list setup failed: {body}"
    );
    assert_single_ready_replica_list(
        "active revision 2 list before crash checkpoint",
        &serde_json::from_str(&body)?,
        2,
    )?;

    let (rev2_replay_status, rev2_replay_body) =
        put_replica(&client, &server, rev2_key, 2, Some(SECRET_B)).await?;
    assert_eq!(
        rev2_replay_status, rev2_status,
        "revision 2 operation replay changed the original status"
    );
    assert_eq!(
        rev2_replay_body, rev2_body,
        "revision 2 operation replay changed the original public body"
    );

    server.stop().await?;
    assert!(!sqlite_contains_secret(database.path(), SECRET_A).await?);
    assert!(!sqlite_contains_secret(database.path(), SECRET_B).await?);

    let credential_root = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("temporary database has no parent directory"))?
        .join("credentials");
    let checkpoint_paths = fs_blocking({
        let credential_root = credential_root.clone();
        move || discover_replica_recovery_paths(&credential_root, "controller-e2e", PROFILE_ID)
    })
    .await?;
    fs_blocking(move || {
        if !checkpoint_paths.active_record.is_file() {
            return Err(Error::other(
                "active revision 2 replica metadata was absent at crash checkpoint",
            ));
        }
        if !checkpoint_paths.revision_one_receipt.is_file()
            || !checkpoint_paths.revision_two_receipt.is_file()
        {
            return Err(Error::other(
                "revision receipt checkpoint was not fully persisted",
            ));
        }
        fs::remove_file(&checkpoint_paths.revision_two_receipt)?;
        if checkpoint_paths.revision_two_receipt.exists() {
            return Err(Error::other(
                "revision 2 receipt remained after crash checkpoint mutation",
            ));
        }
        Ok(())
    })
    .await?;

    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let (observed_request, observed_response) =
        replay_replica_recovery_get(&client, &restarted, &recovery_path).await?;
    capture_replica_recovery_first_exchange(&observed_request, &observed_response)?;
    let metadata_status = StatusCode::from_u16(observed_response.status)?;
    let metadata_body = &observed_response.body;
    let metadata_revision = if metadata_status == StatusCode::OK {
        serde_json::from_str::<Value>(metadata_body)?["revision"].as_u64()
    } else {
        None
    };
    let observed_matches_cassette = recovery_cassette
        .as_ref()
        .map(|cassette| {
            replica_recovery_replayed_first_failure(cassette, &observed_request, &observed_response)
        })
        .transpose()?
        .unwrap_or(false);
    if metadata_revision == Some(1) && recovery_cassette.is_some() && !observed_matches_cassette {
        return Err(Error::other(
            "replica recovery observed response did not match the immutable cassette",
        )
        .into());
    }
    let (list_status, list_body) = list_replicas(&client, &restarted).await?;
    let list_revision = if list_status == StatusCode::OK {
        let list: Value = serde_json::from_str(&list_body)?;
        list["items"]
            .as_array()
            .and_then(|items| (items.len() == 1).then(|| items[0]["revision"].as_u64()))
            .flatten()
    } else {
        None
    };

    let create_body = model_create_body(&model.provider_url(), "openai_compatible", 2);
    let response = create_model_body(
        &client,
        &restarted,
        SUBJECT_A,
        "replica-recovery-split-create",
        &create_body,
    )
    .await?;
    let resolver_create_status = response.status();
    let resolver_create_body = response_text(response).await?;
    assert_secret_free(&resolver_create_body);
    let mut resolver_revision = None;
    if resolver_create_status == StatusCode::CREATED {
        let create: Value = serde_json::from_str(&resolver_create_body)?;
        let session_id = create["session_id"]
            .as_str()
            .ok_or_else(|| Error::other("model selection response omitted session_id"))?;
        if !is_crockford_ulid(session_id) {
            return Err(Error::other("model selection response omitted an Endpoint ULID").into());
        }
        let (message_status, message_body) = post_message(
            &client,
            &restarted,
            SUBJECT_A,
            session_id,
            "replica-recovery-split-message",
        )
        .await?;
        if message_status == StatusCode::ACCEPTED {
            model.wait_for_requests(1).await?;
            let provider_headers = model
                .request_headers(0)
                .ok_or_else(|| Error::other("provider request headers were not captured"))?;
            let actual_authorization = provider_headers["authorization"]
                .as_str()
                .ok_or_else(|| Error::other("provider request omitted authorization"))?;
            if actual_authorization == format!("Bearer {SECRET_B}") {
                resolver_revision = Some(2);
            }
        } else {
            assert_secret_free(&message_body);
        }
    }

    if metadata_revision == Some(1) && list_revision == Some(1) && resolver_revision == Some(2) {
        return Err(Error::other(
            "replica recovery split evidence: GET/list metadata regressed to revision 1 while provider resolver used revision 2",
        )
        .into());
    }
    if metadata_status != StatusCode::OK
        || list_status != StatusCode::OK
        || metadata_revision != Some(2)
        || list_revision != Some(2)
        || resolver_revision != Some(2)
    {
        return Err(Error::other(format!(
            "replica recovery evidence was inconsistent: GET status {metadata_status} revision {metadata_revision:?}, list status {list_status} revision {list_revision:?}, resolver revision {resolver_revision:?}"
        ))
        .into());
    }

    restarted.stop().await?;
    assert!(!sqlite_contains_secret(database.path(), SECRET_A).await?);
    assert!(!sqlite_contains_secret(database.path(), SECRET_B).await?);
    model.stop().await?;
    Ok(())
}

async fn run_provider_policy_admission_case(
    name: &str,
    initial_adapter_kinds: &[&str],
    initial_allowed_origins: &[&str],
    final_adapter_kinds: &[&str],
    final_allowed_origins: &[&str],
    body: Value,
    key: &str,
) -> TestResult<()> {
    let database = TempDatabase::new(name)?;
    let config = config_for(&database)?;
    set_provider_execution_policy(&config, initial_adapter_kinds, initial_allowed_origins)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let (replica_status, replica_body) = put_replica(
        &client,
        &server,
        &format!("{name}-replica"),
        1,
        Some(SECRET_A),
    )
    .await?;
    assert!(
        replica_status.is_success(),
        "{name} replica setup failed: {replica_status} {replica_body}"
    );
    let (status, replica_read_body) = read_replica(&client, &server).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "{name} replica GET: {replica_read_body}"
    );
    assert_ready_replica_metadata(
        &format!("{name} replica GET"),
        &serde_json::from_str(&replica_read_body)?,
        1,
    )?;
    let (status, replica_list_body) = list_replicas(&client, &server).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "{name} replica list: {replica_list_body}"
    );
    assert_single_ready_replica_list(
        &format!("{name} replica list"),
        &serde_json::from_str(&replica_list_body)?,
        1,
    )?;

    let response = create_model_body(&client, &server, SUBJECT_A, key, &body).await?;
    assert_model_admission_error(
        response,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_request",
        name,
    )
    .await?;
    let (list_status, list_body) = list_sessions(&client, &server, SUBJECT_A).await?;
    assert_empty_session_list(list_status, &list_body, name)?;

    server.stop().await?;
    set_provider_execution_policy(&config, final_adapter_kinds, final_allowed_origins)?;
    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let retry_response = create_model_body(&client, &restarted, SUBJECT_A, key, &body).await?;
    let retry_status = retry_response.status();
    let retry_body = response_text(retry_response).await?;
    assert_secret_free(&retry_body);
    assert_eq!(
        retry_status,
        StatusCode::CREATED,
        "{name} retry was not a new admitted receipt: {retry_body}"
    );
    let retry_json: Value = serde_json::from_str(&retry_body)?;
    let retry_session_id = retry_json["session_id"]
        .as_str()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "retry omitted session_id"))?;
    assert!(
        is_crockford_ulid(retry_session_id),
        "{name} retry did not allocate an endpoint ULID: {retry_body}"
    );
    let (list_status, list_body) = list_sessions(&client, &restarted, SUBJECT_A).await?;
    assert_one_owned_session_list(
        list_status,
        &list_body,
        SUBJECT_A,
        retry_session_id,
        "00000000000000000000000000",
        "00000000000000000000000000",
    )?;
    restarted.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_model_create_rejects_disabled_adapter_before_receipt() -> TestResult<()> {
    run_provider_policy_admission_case(
        "control-create-disabled-adapter",
        &[],
        &["http://127.0.0.1:41000"],
        &["openai_compatible"],
        &["http://127.0.0.1:41000"],
        model_create_body("http://127.0.0.1:41000/v1", "openai_compatible", 1),
        "control-create-disabled-adapter",
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_model_create_rejects_disallowed_origin_before_receipt() -> TestResult<()> {
    run_provider_policy_admission_case(
        "control-create-disallowed-origin",
        &["openai_compatible"],
        &["http://127.0.0.1:41000"],
        &["openai_compatible"],
        &["http://localhost:41000"],
        model_create_body("http://localhost:41000/v1", "openai_compatible", 1),
        "control-create-disallowed-origin",
    )
    .await
}

const CREATE_INCIDENT_CAPTURE_ENV: &str = "ZODE_CAPTURE_HTTP_INCIDENT";
const CREATE_INCIDENT_SCHEMA: &str = "zode.http-incident-recording.v1";
const CREATE_INCIDENT_BOUNDARY: &str = "endpoint_http";
const CREATE_INCIDENT_READY_PREFIX: &str = "ZODE_READY ";
const CREATE_INCIDENT_OUTPUT_TIMEOUT: Duration = Duration::from_secs(5);
const CREATE_INCIDENT_READINESS_TIMEOUT: Duration = Duration::from_secs(10);
const SLOT_CONTROLLER_AUTHORIZATION: &str = "{{SLOT_CONTROLLER_AUTHORIZATION}}";
const SLOT_OWNER_SUBJECT: &str = "{{SLOT_OWNER_SUBJECT}}";
const SLOT_REPLICA_SECRET_A: &str = "{{SLOT_REPLICA_SECRET_A}}";
const SLOT_FIRST_FAILURE_SESSION_ID: &str = "{{SLOT_FIRST_FAILURE_SESSION_ID}}";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateIncidentRecording {
    schema: String,
    recording_id: String,
    purpose: String,
    owning_e2e: String,
    boundary: String,
    secret_slots: Vec<String>,
    first_seen_failure: CreateIncidentFailure,
    contract_response: CreateIncidentContract,
    exchanges: Vec<CreateIncidentExchange>,
    whole_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateIncidentFailure {
    boundary: String,
    safe_error: String,
    status: u16,
    response_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateIncidentContract {
    status: u16,
    error_code: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateIncidentExchange {
    sequence: u64,
    phase: String,
    request: CreateIncidentRequest,
    response: CreateIncidentResponse,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateIncidentRequest {
    method: String,
    path: String,
    headers: Vec<CreateIncidentHeader>,
    body_hex: String,
    canonical_json: Option<Value>,
    body_sha256: String,
    fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CreateIncidentHeader {
    name: String,
    value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateIncidentResponse {
    status: u16,
    headers: Vec<CreateIncidentHeader>,
    chunks: Vec<CreateIncidentChunk>,
    outcome: String,
    body_sha256: String,
    fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateIncidentChunk {
    at_us: u64,
    bytes_hex: String,
}

#[derive(Clone, Copy)]
enum ReplicaAdmissionSetup {
    Missing,
    Tombstoned,
    BelowMinimum,
}

type CreateIncidentOutputTask = JoinHandle<std::io::Result<Vec<u8>>>;

struct CreateIncidentEndpoint {
    child: Option<Child>,
    base_url: String,
    stdout_drain: Option<CreateIncidentOutputTask>,
    stderr_drain: Option<CreateIncidentOutputTask>,
}

impl CreateIncidentEndpoint {
    async fn start(database: &Path, config: &Path) -> TestResult<Self> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_zode"))
            .arg("--config")
            .arg(config)
            .arg("--database")
            .arg(database)
            .arg("--listen")
            .arg("127.0.0.1:0")
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::other("incident Endpoint stdout was unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| Error::other("incident Endpoint stderr was unavailable"))?;
        let stderr_drain = tokio::spawn(drain_create_incident_output(stderr));
        let mut stdout_reader = BufReader::new(stdout);
        let mut readiness_line = String::new();
        let readiness = timeout(
            CREATE_INCIDENT_READINESS_TIMEOUT,
            stdout_reader.read_line(&mut readiness_line),
        )
        .await;
        let line = match readiness {
            Ok(Ok(read)) if read > 0 => readiness_line.trim_end(),
            _ => {
                let _ = kill_and_reap(child).await;
                stderr_drain.abort();
                return Err(Error::other("incident Endpoint did not become ready").into());
            }
        };
        let base_url = line
            .strip_prefix(CREATE_INCIDENT_READY_PREFIX)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| Error::other("incident Endpoint readiness line was invalid"))?
            .trim()
            .to_owned();
        let stdout_drain = tokio::spawn(drain_create_incident_output(stdout_reader));
        Ok(Self {
            child: Some(child),
            base_url,
            stdout_drain: Some(stdout_drain),
            stderr_drain: Some(stderr_drain),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn stop(&mut self) -> TestResult<Vec<u8>> {
        if let Some(child) = self.child.take() {
            kill_and_reap(child).await?;
        }
        let mut output = Vec::new();
        if let Some(task) = self.stdout_drain.take() {
            output.extend(collect_create_incident_output(task).await?);
        }
        if let Some(task) = self.stderr_drain.take() {
            output.extend(collect_create_incident_output(task).await?);
        }
        Ok(output)
    }
}

impl Drop for CreateIncidentEndpoint {
    fn drop(&mut self) {
        if let Some(task) = self.stdout_drain.take() {
            task.abort();
        }
        if let Some(task) = self.stderr_drain.take() {
            task.abort();
        }
        reap_child_on_drop(self.child.take());
    }
}

async fn drain_create_incident_output<R>(mut reader: R) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::new();
    reader.read_to_end(&mut output).await?;
    Ok(output)
}

async fn collect_create_incident_output(task: CreateIncidentOutputTask) -> TestResult<Vec<u8>> {
    Ok(timeout(CREATE_INCIDENT_OUTPUT_TIMEOUT, task)
        .await
        .map_err(|_| Error::other("incident Endpoint output drain timed out"))?
        .map_err(|_| Error::other("incident Endpoint output task failed"))??)
}

fn create_incident_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn create_incident_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn create_incident_unhex(value: &str) -> TestResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::other("incident hex payload had odd length").into());
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|_| Error::other("incident hex payload was invalid").into())
        })
        .collect()
}

fn create_incident_body(response: &CreateIncidentResponse) -> TestResult<Vec<u8>> {
    let mut body = Vec::new();
    for chunk in &response.chunks {
        body.extend(create_incident_unhex(&chunk.bytes_hex)?);
    }
    Ok(body)
}

fn create_incident_request_fingerprint(request: &CreateIncidentRequest) -> TestResult<String> {
    let mut canonical = request.clone();
    canonical.fingerprint.clear();
    Ok(create_incident_sha256(&serde_json::to_vec(&canonical)?))
}

fn create_incident_response_fingerprint(response: &CreateIncidentResponse) -> TestResult<String> {
    let mut canonical = response.clone();
    canonical.fingerprint.clear();
    for chunk in &mut canonical.chunks {
        chunk.at_us = 0;
    }
    Ok(create_incident_sha256(&serde_json::to_vec(&canonical)?))
}

fn create_incident_whole_digest(recording: &CreateIncidentRecording) -> TestResult<String> {
    let mut canonical = recording.clone();
    canonical.whole_sha256.clear();
    Ok(create_incident_sha256(&serde_json::to_vec(&canonical)?))
}

fn make_create_incident_request(
    method: &str,
    path: &str,
    mut headers: Vec<CreateIncidentHeader>,
    body: &[u8],
) -> TestResult<CreateIncidentRequest> {
    headers.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.value.cmp(&right.value))
    });
    let mut request = CreateIncidentRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        headers,
        body_hex: create_incident_hex(body),
        canonical_json: if body.is_empty() {
            None
        } else {
            Some(serde_json::from_slice(body)?)
        },
        body_sha256: create_incident_sha256(body),
        fingerprint: String::new(),
    };
    request.fingerprint = create_incident_request_fingerprint(&request)?;
    Ok(request)
}

fn make_create_incident_response(
    status: u16,
    mut headers: Vec<CreateIncidentHeader>,
    body: &[u8],
    at_us: u64,
) -> TestResult<CreateIncidentResponse> {
    headers.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.value.cmp(&right.value))
    });
    let mut response = CreateIncidentResponse {
        status,
        headers,
        chunks: if body.is_empty() {
            Vec::new()
        } else {
            vec![CreateIncidentChunk {
                at_us,
                bytes_hex: create_incident_hex(body),
            }]
        },
        outcome: "complete".to_owned(),
        body_sha256: create_incident_sha256(body),
        fingerprint: String::new(),
    };
    response.fingerprint = create_incident_response_fingerprint(&response)?;
    Ok(response)
}

fn create_incident_headers(
    idempotency_key: Option<&str>,
    content_type: bool,
) -> Vec<CreateIncidentHeader> {
    let mut headers = vec![
        CreateIncidentHeader {
            name: "authorization".to_owned(),
            value: format!("Bearer {TEST_CONTROLLER_SECRET}"),
        },
        CreateIncidentHeader {
            name: "zode-subject".to_owned(),
            value: SUBJECT_A.to_owned(),
        },
    ];
    if let Some(idempotency_key) = idempotency_key {
        headers.push(CreateIncidentHeader {
            name: "idempotency-key".to_owned(),
            value: idempotency_key.to_owned(),
        });
    }
    if content_type {
        headers.push(CreateIncidentHeader {
            name: "content-type".to_owned(),
            value: "application/json".to_owned(),
        });
    }
    headers
}

fn create_incident_public_request(
    method: &str,
    path: &str,
    idempotency_key: Option<&str>,
    body: Option<&Value>,
) -> TestResult<CreateIncidentRequest> {
    let body = body
        .map(serde_json::to_vec)
        .transpose()?
        .unwrap_or_default();
    make_create_incident_request(
        method,
        path,
        create_incident_headers(idempotency_key, !body.is_empty()),
        &body,
    )
}

fn create_incident_response_headers(headers: &HeaderMap) -> Vec<CreateIncidentHeader> {
    ["content-type", "retry-after"]
        .into_iter()
        .filter_map(|name| {
            headers.get(name).and_then(|value| {
                Some(CreateIncidentHeader {
                    name: name.to_owned(),
                    value: value.to_str().ok()?.to_owned(),
                })
            })
        })
        .collect()
}

async fn execute_create_incident_request(
    client: &Client,
    endpoint: &CreateIncidentEndpoint,
    request: &CreateIncidentRequest,
) -> TestResult<CreateIncidentResponse> {
    let method = reqwest::Method::from_bytes(request.method.as_bytes())?;
    let body = create_incident_unhex(&request.body_hex)?;
    let mut outbound = client.request(method, endpoint.url(&request.path));
    for header in &request.headers {
        outbound = outbound.header(
            HeaderName::from_bytes(header.name.as_bytes())?,
            HeaderValue::from_str(&header.value)?,
        );
    }
    let response = outbound.body(body).send_with_timeout().await?;
    assert_response_headers_secret_free(
        &response,
        &[
            SECRET_A,
            SECRET_B,
            SECRET_C,
            SECRET_D,
            TEST_CONTROLLER_SECRET,
        ],
    );
    let status = response.status().as_u16();
    let headers = create_incident_response_headers(response.headers());
    let response_started = Instant::now();
    let body = response_bytes(response).await?;
    assert_create_incident_secret_free(&body, "public response")?;
    make_create_incident_response(
        status,
        headers,
        &body,
        response_started
            .elapsed()
            .as_micros()
            .try_into()
            .unwrap_or(u64::MAX),
    )
}

fn materialize_create_incident_request(
    request: &CreateIncidentRequest,
) -> TestResult<CreateIncidentRequest> {
    let mut request = request.clone();
    for header in &mut request.headers {
        header.value = header
            .value
            .replace(
                SLOT_CONTROLLER_AUTHORIZATION,
                &format!("Bearer {TEST_CONTROLLER_SECRET}"),
            )
            .replace(SLOT_OWNER_SUBJECT, SUBJECT_A);
    }
    let body = String::from_utf8(create_incident_unhex(&request.body_hex)?)?
        .replace(SLOT_REPLICA_SECRET_A, SECRET_A);
    let method = request.method.clone();
    let path = request.path.clone();
    make_create_incident_request(&method, &path, request.headers, body.as_bytes())
}

fn slot_first_failure_response(
    response: &CreateIncidentResponse,
) -> TestResult<CreateIncidentResponse> {
    let body = create_incident_body(response)?;
    let value: Value = serde_json::from_slice(&body)?;
    let session_id = value["session_id"]
        .as_str()
        .ok_or_else(|| Error::other("first 201 response omitted session_id"))?;
    if !is_crockford_ulid(session_id) {
        return Err(Error::other("first 201 response session_id was not an Endpoint ULID").into());
    }
    let safe_body = String::from_utf8(body)?.replace(session_id, SLOT_FIRST_FAILURE_SESSION_ID);
    let at_us = response
        .chunks
        .first()
        .map(|chunk| chunk.at_us)
        .unwrap_or_default();
    make_create_incident_response(
        response.status,
        response.headers.clone(),
        safe_body.as_bytes(),
        at_us,
    )
}

fn redact_create_incident(
    mut recording: CreateIncidentRecording,
) -> TestResult<CreateIncidentRecording> {
    for exchange in &mut recording.exchanges {
        for header in &mut exchange.request.headers {
            if header.name == "authorization" {
                header.value = SLOT_CONTROLLER_AUTHORIZATION.to_owned();
            } else if header.name == "zode-subject" {
                header.value = SLOT_OWNER_SUBJECT.to_owned();
            }
        }
        let body = String::from_utf8(create_incident_unhex(&exchange.request.body_hex)?)?
            .replace(SECRET_A, SLOT_REPLICA_SECRET_A);
        exchange.request = make_create_incident_request(
            &exchange.request.method,
            &exchange.request.path,
            exchange.request.headers.clone(),
            body.as_bytes(),
        )?;
        if exchange.phase == "create" {
            exchange.response = slot_first_failure_response(&exchange.response)?;
        }
    }
    recording.secret_slots = vec![
        "SLOT_CONTROLLER_AUTHORIZATION".to_owned(),
        "SLOT_FIRST_FAILURE_SESSION_ID".to_owned(),
        "SLOT_OWNER_SUBJECT".to_owned(),
        "SLOT_REPLICA_SECRET_A".to_owned(),
    ];
    let failure = recording
        .exchanges
        .iter()
        .find(|exchange| exchange.phase == "create")
        .ok_or_else(|| Error::other("incident recording omitted create exchange"))?;
    recording.first_seen_failure.status = failure.response.status;
    recording.first_seen_failure.response_fingerprint = failure.response.fingerprint.clone();
    recording.whole_sha256 = create_incident_whole_digest(&recording)?;
    let bytes = serde_json::to_vec(&recording)?;
    assert_create_incident_secret_free(&bytes, "secret-safe incident")?;
    Ok(recording)
}

fn create_incident_recording_id(owning_e2e: &str) -> TestResult<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(format!("{owning_e2e}-{}-{now}", std::process::id()))
}

fn create_incident_fixture_path(owning_e2e: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/http_incidents")
        .join(format!("{owning_e2e}.json"))
}

fn write_create_incident_capture(
    raw: &CreateIncidentRecording,
    safe: &CreateIncidentRecording,
) -> TestResult<PathBuf> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-recordings/quarantine")
        .join(&raw.recording_id);
    fs::create_dir_all(&directory)?;
    #[cfg(unix)]
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    write_create_incident_new(&directory.join("first.raw.json"), raw)?;
    write_create_incident_new(&directory.join("first.secret-safe.json"), safe)?;
    Ok(directory)
}

fn write_create_incident_new(path: &Path, recording: &CreateIncidentRecording) -> TestResult<()> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&serde_json::to_vec_pretty(recording)?)?;
    file.sync_all()?;
    Ok(())
}

fn load_create_incident(owning_e2e: &str) -> TestResult<CreateIncidentRecording> {
    let path = create_incident_fixture_path(owning_e2e);
    let bytes = fs::read(&path).map_err(|error| {
        Error::new(
            error.kind(),
            format!(
                "incident cassette {} is required; capture only the first unfixed occurrence with {CREATE_INCIDENT_CAPTURE_ENV}={owning_e2e}: {error}",
                path.display()
            ),
        )
    })?;
    assert_create_incident_secret_free(&bytes, "tracked incident cassette")?;
    let recording: CreateIncidentRecording = serde_json::from_slice(&bytes)?;
    validate_create_incident(&recording, owning_e2e)?;
    Ok(recording)
}

fn validate_create_incident(
    recording: &CreateIncidentRecording,
    owning_e2e: &str,
) -> TestResult<()> {
    if recording.schema != CREATE_INCIDENT_SCHEMA
        || recording.owning_e2e != owning_e2e
        || recording.boundary != CREATE_INCIDENT_BOUNDARY
        || recording.purpose.is_empty()
        || recording.recording_id.is_empty()
        || recording.contract_response.status != StatusCode::SERVICE_UNAVAILABLE.as_u16()
        || recording.contract_response.error_code != "auth_replica_unavailable"
        || recording.first_seen_failure.boundary != "public.session_create"
        || recording.first_seen_failure.status != StatusCode::CREATED.as_u16()
        || recording.whole_sha256 != create_incident_whole_digest(recording)?
    {
        return Err(Error::other("create incident cassette metadata was invalid").into());
    }
    if recording.secret_slots
        != [
            "SLOT_CONTROLLER_AUTHORIZATION",
            "SLOT_FIRST_FAILURE_SESSION_ID",
            "SLOT_OWNER_SUBJECT",
            "SLOT_REPLICA_SECRET_A",
        ]
    {
        return Err(Error::other("create incident cassette secret slots were invalid").into());
    }
    for (index, exchange) in recording.exchanges.iter().enumerate() {
        if exchange.sequence != index as u64
            || exchange.request.fingerprint
                != create_incident_request_fingerprint(&exchange.request)?
            || exchange.request.body_sha256
                != create_incident_sha256(&create_incident_unhex(&exchange.request.body_hex)?)
            || exchange.response.fingerprint
                != create_incident_response_fingerprint(&exchange.response)?
            || exchange.response.body_sha256
                != create_incident_sha256(&create_incident_body(&exchange.response)?)
            || exchange.response.outcome != "complete"
        {
            return Err(Error::other("create incident cassette exchange was invalid").into());
        }
        let body = create_incident_unhex(&exchange.request.body_hex)?;
        match &exchange.request.canonical_json {
            Some(canonical) if serde_json::from_slice::<Value>(&body)? == *canonical => {}
            None if body.is_empty() => {}
            _ => {
                return Err(
                    Error::other("create incident cassette canonical request diverged").into(),
                )
            }
        }
    }
    let create = recording
        .exchanges
        .last()
        .filter(|exchange| exchange.phase == "create")
        .ok_or_else(|| Error::other("create incident cassette did not end at create"))?;
    if create.response.fingerprint != recording.first_seen_failure.response_fingerprint {
        return Err(Error::other("create incident first-failure fingerprint diverged").into());
    }
    Ok(())
}

fn assert_create_incident_secret_free(bytes: &[u8], context: &str) -> TestResult<()> {
    for marker in [
        SECRET_A,
        SECRET_B,
        SECRET_C,
        SECRET_D,
        TEST_CONTROLLER_SECRET,
        AUTHORITY_A_SECRET,
        AUTHORITY_B_SECRET,
        AUTHORITY_A_NEW_SECRET,
        AUTHORITY_B_NEW_SECRET,
        SUBJECT_A,
    ] {
        if bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
        {
            return Err(Error::other(format!("{context} retained a secret marker")).into());
        }
    }
    if bytes
        .windows(b"Bearer ".len())
        .any(|window| window == b"Bearer ")
    {
        return Err(Error::other(format!("{context} retained bearer material")).into());
    }
    Ok(())
}

async fn assert_create_incident_sqlite_secret_free(database: &Path) -> TestResult<()> {
    for marker in [
        SECRET_A,
        SECRET_B,
        SECRET_C,
        SECRET_D,
        TEST_CONTROLLER_SECRET,
        AUTHORITY_A_SECRET,
        AUTHORITY_B_SECRET,
        AUTHORITY_A_NEW_SECRET,
        AUTHORITY_B_NEW_SECRET,
    ] {
        if sqlite_contains_secret(database, marker).await? {
            return Err(Error::other("incident SQLite retained a secret marker").into());
        }
    }
    Ok(())
}

fn recorded_replica_body(revision: u64, secret: Option<&str>) -> Value {
    match secret {
        Some(secret) => json!({
            "schema": "zode.auth-replica.install.v1",
            "authority_id": "controller-e2e",
            "provider": "fixture-provider",
            "kind": "api_key",
            "revision": revision,
            "credential_schema": "openai-compatible.api-key.v1",
            "expires_at_ms": null,
            "secret": {
                "encoding": "application/zode-secret-envelope",
                "payload": secret
            }
        }),
        None => json!({
            "schema": "zode.auth-replica.tombstone.v1",
            "authority_id": "controller-e2e",
            "provider": "fixture-provider",
            "revision": revision
        }),
    }
}

fn capture_replica_admission_requests(
    name: &str,
    setup: ReplicaAdmissionSetup,
    minimum_auth_revision: u64,
) -> TestResult<Vec<(String, CreateIncidentRequest)>> {
    let replica_path = format!("/v1/auth-replicas/{PROFILE_ID}");
    let mut requests = Vec::new();
    match setup {
        ReplicaAdmissionSetup::Missing => {
            requests.push((
                "setup.replica_list".to_owned(),
                create_incident_public_request("GET", "/v1/auth-replicas", None, None)?,
            ));
            requests.push((
                "setup.replica_get_missing".to_owned(),
                create_incident_public_request("GET", &replica_path, None, None)?,
            ));
        }
        ReplicaAdmissionSetup::Tombstoned => {
            requests.push((
                "setup.replica_install".to_owned(),
                create_incident_public_request(
                    "PUT",
                    &replica_path,
                    Some(&format!("{name}-initial")),
                    Some(&recorded_replica_body(1, Some(SECRET_A))),
                )?,
            ));
            requests.push((
                "setup.replica_tombstone".to_owned(),
                create_incident_public_request(
                    "PUT",
                    &replica_path,
                    Some(&format!("{name}-tombstone")),
                    Some(&recorded_replica_body(2, None)),
                )?,
            ));
            requests.push((
                "setup.replica_get_tombstoned".to_owned(),
                create_incident_public_request("GET", &replica_path, None, None)?,
            ));
            requests.push((
                "setup.replica_list_tombstoned".to_owned(),
                create_incident_public_request("GET", "/v1/auth-replicas", None, None)?,
            ));
        }
        ReplicaAdmissionSetup::BelowMinimum => {
            requests.push((
                "setup.replica_install".to_owned(),
                create_incident_public_request(
                    "PUT",
                    &replica_path,
                    Some(&format!("{name}-initial")),
                    Some(&recorded_replica_body(1, Some(SECRET_A))),
                )?,
            ));
            requests.push((
                "setup.replica_get_ready".to_owned(),
                create_incident_public_request("GET", &replica_path, None, None)?,
            ));
            requests.push((
                "setup.replica_list_ready".to_owned(),
                create_incident_public_request("GET", "/v1/auth-replicas", None, None)?,
            ));
        }
    }
    requests.push((
        "create".to_owned(),
        create_incident_public_request(
            "POST",
            "/v1/sessions",
            Some(&format!("{name}-create")),
            Some(&model_create_body(
                "http://127.0.0.1:41000/v1",
                "openai_compatible",
                minimum_auth_revision,
            )),
        )?,
    ));
    Ok(requests)
}

fn assert_replica_admission_phase(
    name: &str,
    phase: &str,
    response: &CreateIncidentResponse,
) -> TestResult<()> {
    let status = StatusCode::from_u16(response.status)?;
    let body = String::from_utf8(create_incident_body(response)?)?;
    match phase {
        "setup.replica_install" | "setup.replica_tombstone" => {
            if !status.is_success() {
                return Err(
                    Error::other(format!("{name} {phase} setup failed: {status} {body}")).into(),
                );
            }
        }
        "setup.replica_list" => {
            assert_eq!(status, StatusCode::OK, "{name} missing list: {body}");
            assert_replica_list_omits_profile(
                &format!("{name} missing replica list"),
                &serde_json::from_str(&body)?,
            )?;
        }
        "setup.replica_get_missing" => {
            assert_eq!(status, StatusCode::NOT_FOUND, "{name} missing GET: {body}");
            let error: Value = serde_json::from_str(&body)?;
            assert_eq!(error["error"]["code"], "auth_replica_not_found", "{body}");
        }
        "setup.replica_get_tombstoned" => {
            assert_eq!(status, StatusCode::OK, "{name} tombstone GET: {body}");
            assert_tombstoned_metadata(
                &format!("{name} tombstone GET"),
                &serde_json::from_str(&body)?,
                2,
            )?;
        }
        "setup.replica_list_tombstoned" => {
            assert_eq!(status, StatusCode::OK, "{name} tombstone list: {body}");
            assert_tombstoned_list(
                &format!("{name} tombstone list"),
                &serde_json::from_str(&body)?,
                2,
            )?;
        }
        "setup.replica_get_ready" => {
            assert_eq!(status, StatusCode::OK, "{name} ready GET: {body}");
            assert_ready_replica_metadata(
                &format!("{name} ready GET"),
                &serde_json::from_str(&body)?,
                1,
            )?;
        }
        "setup.replica_list_ready" => {
            assert_eq!(status, StatusCode::OK, "{name} ready list: {body}");
            assert_single_ready_replica_list(
                &format!("{name} ready list"),
                &serde_json::from_str(&body)?,
                1,
            )?;
        }
        _ => return Err(Error::other(format!("unknown incident setup phase {phase}")).into()),
    }
    Ok(())
}

fn make_create_incident_recording(
    owning_e2e: &str,
    exchanges: Vec<CreateIncidentExchange>,
) -> TestResult<(CreateIncidentRecording, CreateIncidentRecording)> {
    let create = exchanges
        .last()
        .filter(|exchange| exchange.phase == "create")
        .ok_or_else(|| Error::other("captured incident did not end at session create"))?;
    if create.response.status != StatusCode::CREATED.as_u16() {
        return Err(Error::other(format!(
            "first create occurrence was {}, not the unresolved 201 behavior",
            create.response.status
        ))
        .into());
    }
    let mut raw = CreateIncidentRecording {
        schema: CREATE_INCIDENT_SCHEMA.to_owned(),
        recording_id: create_incident_recording_id(owning_e2e)?,
        purpose: "preserve the first normal-miss session-create admission before auth-replica availability repair".to_owned(),
        owning_e2e: owning_e2e.to_owned(),
        boundary: CREATE_INCIDENT_BOUNDARY.to_owned(),
        secret_slots: Vec::new(),
        first_seen_failure: CreateIncidentFailure {
            boundary: "public.session_create".to_owned(),
            safe_error: "session create returned 201 without a usable auth replica".to_owned(),
            status: create.response.status,
            response_fingerprint: create.response.fingerprint.clone(),
        },
        contract_response: CreateIncidentContract {
            status: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
            error_code: "auth_replica_unavailable".to_owned(),
        },
        exchanges,
        whole_sha256: String::new(),
    };
    raw.whole_sha256 = create_incident_whole_digest(&raw)?;
    let safe = redact_create_incident(raw.clone())?;
    Ok((raw, safe))
}

fn assert_recorded_setup_response(
    recorded: &CreateIncidentExchange,
    actual: &CreateIncidentResponse,
) -> TestResult<()> {
    if actual.status != recorded.response.status
        || actual.fingerprint != recorded.response.fingerprint
    {
        return Err(Error::other(format!(
            "incident setup replay diverged at {}: recorded {} {}, actual {} {}",
            recorded.phase,
            recorded.response.status,
            recorded.response.fingerprint,
            actual.status,
            actual.fingerprint
        ))
        .into());
    }
    Ok(())
}

fn assert_first_failure_replayed(
    recording: &CreateIncidentRecording,
    actual: &CreateIncidentResponse,
) -> TestResult<()> {
    let safe = slot_first_failure_response(actual)?;
    if safe.status != recording.first_seen_failure.status
        || safe.fingerprint != recording.first_seen_failure.response_fingerprint
    {
        return Err(Error::other(format!(
            "actual 201 diverged from the retained first failure: recorded {}, actual {}",
            recording.first_seen_failure.response_fingerprint, safe.fingerprint
        ))
        .into());
    }
    Ok(())
}

fn assert_replica_unavailable_contract(
    recording: &CreateIncidentRecording,
    response: &CreateIncidentResponse,
) -> TestResult<()> {
    let body = String::from_utf8(create_incident_body(response)?)?;
    let status = StatusCode::from_u16(response.status)?;
    assert_eq!(
        status,
        StatusCode::from_u16(recording.contract_response.status)?,
        "session create violated the replica-unavailable contract: {body}"
    );
    let error: Value = serde_json::from_str(&body)?;
    assert_eq!(
        error["error"]["code"], recording.contract_response.error_code,
        "session create returned the wrong replica-unavailable error: {body}"
    );
    Ok(())
}

async fn execute_create_incident_json(
    client: &Client,
    endpoint: &CreateIncidentEndpoint,
    method: &str,
    path: &str,
    idempotency_key: Option<&str>,
    body: Option<&Value>,
) -> TestResult<(StatusCode, String)> {
    let request = create_incident_public_request(method, path, idempotency_key, body)?;
    let response = execute_create_incident_request(client, endpoint, &request).await?;
    Ok((
        StatusCode::from_u16(response.status)?,
        String::from_utf8(create_incident_body(&response)?)?,
    ))
}

async fn finish_replica_admission_recovery(
    name: &str,
    recovery_revision: u64,
    client: &Client,
    endpoint: &CreateIncidentEndpoint,
    create_request: &CreateIncidentRequest,
) -> TestResult<()> {
    let (list_status, list_body) = execute_create_incident_json(
        client,
        endpoint,
        "GET",
        "/v1/sessions?limit=100",
        None,
        None,
    )
    .await?;
    assert_empty_session_list(list_status, &list_body, name)?;

    let replica_path = format!("/v1/auth-replicas/{PROFILE_ID}");
    let (status, install_body) = execute_create_incident_json(
        client,
        endpoint,
        "PUT",
        &replica_path,
        Some(&format!("{name}-recovery")),
        Some(&recorded_replica_body(recovery_revision, Some(SECRET_B))),
    )
    .await?;
    assert!(
        status.is_success(),
        "{name} recovery replica setup failed: {status} {install_body}"
    );
    let (status, body) =
        execute_create_incident_json(client, endpoint, "GET", &replica_path, None, None).await?;
    assert_eq!(status, StatusCode::OK, "{name} recovery GET: {body}");
    assert_ready_replica_metadata(
        &format!("{name} recovery GET"),
        &serde_json::from_str(&body)?,
        recovery_revision,
    )?;
    let (status, body) =
        execute_create_incident_json(client, endpoint, "GET", "/v1/auth-replicas", None, None)
            .await?;
    assert_eq!(status, StatusCode::OK, "{name} recovery list: {body}");
    assert_single_ready_replica_list(
        &format!("{name} recovery list"),
        &serde_json::from_str(&body)?,
        recovery_revision,
    )?;

    let retry = execute_create_incident_request(client, endpoint, create_request).await?;
    let retry_status = StatusCode::from_u16(retry.status)?;
    let retry_body = String::from_utf8(create_incident_body(&retry)?)?;
    assert_eq!(
        retry_status,
        StatusCode::CREATED,
        "{name} retry was not a new admitted receipt: {retry_body}"
    );
    let retry_json: Value = serde_json::from_str(&retry_body)?;
    let retry_session_id = retry_json["session_id"]
        .as_str()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "replica retry omitted session_id"))?;
    assert!(is_crockford_ulid(retry_session_id));
    let (list_status, list_body) = execute_create_incident_json(
        client,
        endpoint,
        "GET",
        "/v1/sessions?limit=100",
        None,
        None,
    )
    .await?;
    assert_one_owned_session_list(
        list_status,
        &list_body,
        SUBJECT_A,
        retry_session_id,
        "00000000000000000000000000",
        "00000000000000000000000000",
    )?;
    Ok(())
}

async fn run_replica_admission_case(
    owning_e2e: &'static str,
    name: &str,
    minimum_auth_revision: u64,
    setup: ReplicaAdmissionSetup,
    recovery_revision: u64,
) -> TestResult<()> {
    let database = TempDatabase::new(name)?;
    let config = config_for(&database)?;
    set_provider_execution_policy(&config, &["openai_compatible"], &["http://127.0.0.1:41000"])?;
    let capture = env::var(CREATE_INCIDENT_CAPTURE_ENV)
        .ok()
        .is_some_and(|value| value == owning_e2e);
    if capture && create_incident_fixture_path(owning_e2e).exists() {
        return Err(Error::other("refusing to recapture an immutable tracked incident").into());
    }
    let recording = if capture {
        None
    } else {
        Some(load_create_incident(owning_e2e)?)
    };
    let mut endpoint = CreateIncidentEndpoint::start(&database, &config).await?;
    let client = support::http_client()?;

    let scenario_result = async {
        let mut captured = Vec::new();
        let expected_requests =
            capture_replica_admission_requests(name, setup, minimum_auth_revision)?;
        let requests = if let Some(recording) = &recording {
            recording
                .exchanges
                .iter()
                .map(|exchange| (exchange.phase.clone(), exchange.request.clone()))
                .collect::<Vec<_>>()
        } else {
            expected_requests.clone()
        };
        let expected_phases = expected_requests
            .iter()
            .map(|(phase, _)| phase)
            .collect::<Vec<_>>();
        if requests.iter().map(|(phase, _)| phase).collect::<Vec<_>>()
            != expected_phases
        {
            return Err(Error::other("incident cassette setup/create order was invalid").into());
        }

        let mut create_request = None;
        let mut create_response = None;
        for (sequence, (phase, stored_request)) in requests.into_iter().enumerate() {
            let request = if recording.is_some() {
                materialize_create_incident_request(&stored_request)?
            } else {
                stored_request
            };
            if recording.is_some()
                && request.fingerprint != expected_requests[sequence].1.fingerprint
            {
                return Err(Error::other(format!(
                    "incident cassette request diverged at phase {phase}"
                ))
                .into());
            }
            let response = execute_create_incident_request(&client, &endpoint, &request).await?;
            if phase == "create" {
                create_request = Some(request.clone());
                create_response = Some(response.clone());
            } else {
                assert_replica_admission_phase(name, &phase, &response)?;
                if let Some(recording) = &recording {
                    assert_recorded_setup_response(&recording.exchanges[sequence], &response)?;
                }
            }
            if capture {
                captured.push(CreateIncidentExchange {
                    sequence: sequence as u64,
                    phase,
                    request,
                    response,
                });
            }
        }

        let create_request = create_request
            .ok_or_else(|| Error::other("incident scenario omitted create request"))?;
        let create_response = create_response
            .ok_or_else(|| Error::other("incident scenario omitted create response"))?;
        if capture {
            let (raw, safe) = make_create_incident_recording(owning_e2e, captured)?;
            let quarantine = write_create_incident_capture(&raw, &safe)?;
            return Err(Error::other(format!(
                "captured first unresolved 201 at {}; expected 503 auth_replica_unavailable",
                quarantine.display()
            ))
            .into());
        }

        let recording = recording
            .as_ref()
            .ok_or_else(|| Error::other("incident replay omitted recording"))?;
        if create_response.status == recording.first_seen_failure.status {
            assert_first_failure_replayed(recording, &create_response)?;
            return Err(Error::other(format!(
                "replayed retained first failure: actual 201 matched {}; expected 503 auth_replica_unavailable",
                recording.first_seen_failure.response_fingerprint
            ))
            .into());
        }
        assert_replica_unavailable_contract(recording, &create_response)?;
        finish_replica_admission_recovery(
            name,
            recovery_revision,
            &client,
            &endpoint,
            &create_request,
        )
        .await
    }
    .await;

    let output_result = endpoint.stop().await;
    let output_scan = match &output_result {
        Ok(output) => assert_create_incident_secret_free(output, "Endpoint output"),
        Err(error) => Err(Error::other(format!("incident Endpoint stop failed: {error}")).into()),
    };
    let sqlite_scan = assert_create_incident_sqlite_secret_free(database.path()).await;
    output_result?;
    output_scan?;
    sqlite_scan?;
    scenario_result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_model_create_rejects_missing_replica_before_receipt() -> TestResult<()> {
    run_replica_admission_case(
        "e2e_model_create_rejects_missing_replica_before_receipt",
        "control-create-missing-replica",
        1,
        ReplicaAdmissionSetup::Missing,
        1,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_model_create_rejects_tombstoned_replica_before_receipt() -> TestResult<()> {
    run_replica_admission_case(
        "e2e_model_create_rejects_tombstoned_replica_before_receipt",
        "control-create-tombstoned-replica",
        2,
        ReplicaAdmissionSetup::Tombstoned,
        3,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_model_create_rejects_below_minimum_replica_before_receipt() -> TestResult<()> {
    run_replica_admission_case(
        "e2e_model_create_rejects_below_minimum_replica_before_receipt",
        "control-create-low-revision-replica",
        2,
        ReplicaAdmissionSetup::BelowMinimum,
        2,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_model_less_session_is_admitted_without_replica_install() -> TestResult<()> {
    let database = TempDatabase::new("control-model-less")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let (_, body) = create_model_less(&client, &server, SUBJECT_A, "model-less-create").await?;
    assert!(!body.to_string().contains("auth_profile"));
    server.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_same_stores_allow_one_endpoint_until_exit_then_preserve_state() -> TestResult<()> {
    let database = TempDatabase::new("control-single-owner")?;
    let config = config_for(&database)?;
    let mut first = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let (session_id, _) =
        create_model_less(&client, &first, SUBJECT_A, "single-owner-create").await?;

    let second = ConfiguredServer::start_with_readiness_timeout(
        &database,
        &config,
        Duration::from_millis(750),
    )
    .await;
    match second {
        Err(error) => {
            let message = error.to_string();
            assert!(
                !message.contains("did not become ready"),
                "second Endpoint failure was only a readiness timeout: {message}"
            );
            assert!(
                message.contains("non-zero"),
                "second Endpoint did not actively exit non-zero: {message}"
            );
        }
        Ok(mut second) => {
            second.stop().await?;
            first.stop().await?;
            return Err(
                Error::other("second Endpoint process became ready on the same stores").into(),
            );
        }
    }

    first.stop().await?;
    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let (status, body) = get_session(&client, &restarted, SUBJECT_A, &session_id).await?;
    assert_eq!(status, StatusCode::OK, "session was not preserved: {body}");
    let (status, identity_body) = identity(&client, &restarted).await?;
    assert_eq!(status, StatusCode::OK, "{identity_body}");
    restarted.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_unusable_controller_secret_is_rejected_before_ready() -> TestResult<()> {
    let database = TempDatabase::new("control-unusable-secret")?;
    let config = config_for(&database)?;
    let secret_path = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("temporary database has no parent directory"))?
        .join("controller.secret");
    fs::write(&secret_path, format!("{TEST_CONTROLLER_SECRET}\n"))?;

    let result =
        ConfiguredServer::start_with_readiness_timeout(&database, &config, Duration::from_secs(2))
            .await;
    match result {
        Err(error) => {
            let message = error.to_string();
            assert!(
                !message.contains("did not become ready"),
                "unusable controller secret failure was only a readiness timeout"
            );
            assert!(
                message.contains("non-zero"),
                "unusable controller secret did not produce an active non-zero exit"
            );
            assert!(!message.contains(TEST_CONTROLLER_SECRET));
            Ok(())
        }
        Ok(mut server) => {
            server.stop().await?;
            Err(Error::other("Endpoint became ready with an unusable controller secret").into())
        }
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_runtime_store_path_alias_cannot_split_endpoint_ownership() -> TestResult<()> {
    let database = TempDatabase::new("control-runtime-alias")?;
    let first_config = config_for(&database)?;
    let mut first = ConfiguredServer::start(&database, &first_config).await?;
    let client = support::http_client()?;
    let (_, body) = create_model_less(&client, &first, SUBJECT_A, "runtime-alias-seed").await?;
    assert!(body["session_id"].is_string());

    let root = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("temporary database has no parent directory"))?;
    let alias_path = root.join("runtime-alias.sqlite");
    symlink(database.path(), &alias_path)?;
    assert_eq!(
        fs::canonicalize(database.path())?,
        fs::canonicalize(&alias_path)?
    );

    let second_root = root.join("alias-endpoint");
    let second_credentials = second_root.join("credentials");
    let second_blobs = second_root.join("blobs");
    fs::create_dir_all(&second_credentials)?;
    fs::create_dir_all(&second_blobs)?;
    fs::write(
        second_root.join("controller.secret"),
        TEST_CONTROLLER_SECRET,
    )?;
    let mut second_secret_permissions =
        fs::metadata(second_root.join("controller.secret"))?.permissions();
    second_secret_permissions.set_mode(0o600);
    fs::set_permissions(
        second_root.join("controller.secret"),
        second_secret_permissions,
    )?;
    let mut second_config: Value = serde_json::from_slice(&fs::read(&first_config)?)?;
    second_config["runtime_store"]["path"] = json!(alias_path);
    second_config["credential_replica_store"]["directory"] = json!("credentials");
    second_config["blob_store"]["directory"] = json!("blobs");
    second_config["controller_auth"][0]["secret_file"] = json!("controller.secret");
    let second_config_path = second_root.join("runtime-config.json");
    fs::write(
        &second_config_path,
        serde_json::to_vec_pretty(&second_config)?,
    )?;

    let second_result = ConfiguredServer::start_with_readiness_timeout(
        &alias_path,
        &second_config_path,
        Duration::from_secs(2),
    )
    .await;
    let second_outcome: TestResult<()> = match second_result {
        Err(error) => {
            let message = error.to_string();
            assert!(
                !message.contains("did not become ready"),
                "runtime alias ownership failure was only a readiness timeout"
            );
            assert!(
                message.contains("non-zero"),
                "runtime alias did not produce an active non-zero exit"
            );
            Ok(())
        }
        Ok(mut second) => {
            second.stop().await?;
            Err(Error::other("Endpoint became ready through a runtime-store symlink alias").into())
        }
    };
    let first_stop = first.stop().await;
    second_outcome?;
    first_stop?;
    Ok(())
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_empty_controller_auth_is_rejected_before_ready() -> TestResult<()> {
    let database = TempDatabase::new("control-empty-auth")?;
    let config = config_for(&database)?;
    let mut config_json: Value = serde_json::from_slice(&fs::read(&config)?)?;
    config_json["controller_auth"] = json!([]);
    fs::write(&config, serde_json::to_vec_pretty(&config_json)?)?;
    expect_active_nonzero_start_failure(database.path(), &config, "empty controller_auth", None)
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_empty_controller_secret_is_rejected_before_ready() -> TestResult<()> {
    let database = TempDatabase::new("control-empty-secret")?;
    let config = config_for(&database)?;
    let secret_path = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("temporary database has no parent directory"))?
        .join("controller.secret");
    fs::write(&secret_path, b"")?;
    expect_active_nonzero_start_failure(database.path(), &config, "empty controller secret", None)
        .await
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_world_readable_controller_secret_is_rejected_before_ready() -> TestResult<()> {
    let database = TempDatabase::new("control-world-readable-secret")?;
    let config = config_for(&database)?;
    let secret_path = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("temporary database has no parent directory"))?
        .join("controller.secret");
    let mut permissions = fs::metadata(&secret_path)?.permissions();
    permissions.set_mode(0o644);
    fs::set_permissions(&secret_path, permissions)?;
    expect_active_nonzero_start_failure(
        database.path(),
        &config,
        "world-readable controller secret",
        Some(TEST_CONTROLLER_SECRET),
    )
    .await
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_controller_auth_rotation_lost_response_fences_old_secret_and_survives_restart(
) -> TestResult<()> {
    let database = TempDatabase::new("control-auth-rotation")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let old_secret = TEST_CONTROLLER_SECRET;
    let new_secret = "rotation-new-secret-control-e2e";
    let subject = SUBJECT_A;
    let create_key = "rotation-create-key";

    let create_response =
        authenticated_with_secret(client.post(server.url("/v1/sessions")), old_secret, subject)
            .header("Idempotency-Key", create_key)
            .json(&json!({}))
            .send_with_timeout()
            .await
            .map_err(|error| Error::other(format!("controller-auth create request: {error}")))?;
    let create_status = create_response.status();
    let create_body = response_text(create_response)
        .await
        .map_err(|error| Error::other(format!("controller-auth create response body: {error}")))?;
    assert_eq!(create_status, StatusCode::CREATED);
    let create_json: Value = serde_json::from_str(&create_body)?;
    let session_id = create_json["session_id"]
        .as_str()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "rotation create omitted session_id"))?
        .to_owned();

    let changed_secret = "changed-rotation-secret-control-e2e";
    let rotation_markers = [old_secret, new_secret, changed_secret];
    let rotation_operation = json!({
        "schema": "zode.controller-auth.rotate.v1",
        "authority_id": "controller-e2e",
        "revision": 2,
        "secret": {
            "encoding": "application/zode-secret-envelope",
            "payload": new_secret
        }
    });
    let first_rotation_task = tokio::spawn({
        let client = client.clone();
        let rotation_url = server.url("/v1/controller-auth");
        let rotation_operation = rotation_operation.clone();
        async move {
            authenticated_with_secret(client.put(rotation_url), old_secret, subject)
                .header("Idempotency-Key", "controller-rotation-operation")
                .json(&rotation_operation)
                .send_with_timeout()
                .await
        }
    });
    let barrier_result = await_rotation_identity_barrier(
        client.clone(),
        server.url("/v1/identity"),
        new_secret,
        subject,
        &rotation_markers,
        first_rotation_task,
    )
    .await;
    if let Err(error) = barrier_result {
        server.stop().await?;
        for &marker in &rotation_markers {
            assert!(!sqlite_contains_secret(database.path(), marker).await?);
        }
        return Err(error);
    }

    let new_probe =
        authenticated_with_secret(client.get(server.url("/v1/identity")), new_secret, subject)
            .send_with_timeout()
            .await?;
    assert_eq!(new_probe.status(), StatusCode::OK);
    let new_identity = response_json(new_probe).await?;
    assert_rotation_secret_free(&new_identity.to_string(), &rotation_markers);
    assert_eq!(new_identity["authority_id"], "controller-e2e");
    assert_eq!(new_identity["revision"], 2);

    let old_probe =
        authenticated_with_secret(client.get(server.url("/v1/identity")), old_secret, subject)
            .send_with_timeout()
            .await?;
    let old_status = old_probe.status();
    let old_body = response_text(old_probe).await?;
    assert_eq!(old_status, StatusCode::UNAUTHORIZED);
    assert_rotation_secret_free(&old_body, &rotation_markers);

    let retry_response = authenticated_with_secret(
        client.put(server.url("/v1/controller-auth")),
        new_secret,
        subject,
    )
    .header("Idempotency-Key", "controller-rotation-operation")
    .json(&json!({
        "schema": "zode.controller-auth.rotate.v1",
        "authority_id": "controller-e2e",
        "revision": 2,
        "secret": {
            "encoding": "application/zode-secret-envelope",
            "payload": new_secret
        }
    }))
    .send_with_timeout()
    .await?;
    let retry_status = retry_response.status();
    let retry_body = response_text(retry_response).await?;
    assert_rotation_secret_free(&retry_body, &rotation_markers);
    assert!(
        retry_status.is_success(),
        "rotation replay failed: {retry_status}"
    );
    let replay_response = authenticated_with_secret(
        client.put(server.url("/v1/controller-auth")),
        new_secret,
        subject,
    )
    .header("Idempotency-Key", "controller-rotation-operation")
    .json(&rotation_operation)
    .send_with_timeout()
    .await?;
    assert_eq!(replay_response.status(), retry_status);
    let replay_body = response_text(replay_response).await?;
    assert_rotation_secret_free(&replay_body, &rotation_markers);
    assert_eq!(replay_body, retry_body);

    let changed_response = authenticated_with_secret(
        client.put(server.url("/v1/controller-auth")),
        new_secret,
        subject,
    )
    .header("Idempotency-Key", "controller-rotation-operation")
    .json(&json!({
        "schema": "zode.controller-auth.rotate.v1",
        "authority_id": "controller-e2e",
        "revision": 2,
        "secret": {
                "encoding": "application/zode-secret-envelope",
            "payload": changed_secret
        }
    }))
    .send_with_timeout()
    .await?;
    assert_eq!(changed_response.status(), StatusCode::CONFLICT);
    let changed_body = response_text(changed_response).await?;
    assert_rotation_secret_free(&changed_body, &rotation_markers);
    let read_response = authenticated_with_secret(
        client.get(server.url(&format!("/v1/sessions/{session_id}"))),
        new_secret,
        subject,
    )
    .send_with_timeout()
    .await?;
    assert_eq!(read_response.status(), StatusCode::OK);
    let read_body = response_text(read_response).await?;
    assert_rotation_secret_free(&read_body, &rotation_markers);
    let sse_response =
        authenticated_with_secret(client.get(server.url("/v1/events")), new_secret, subject)
            .header("Last-Event-ID", "0")
            .send_with_timeout()
            .await?;
    assert_eq!(sse_response.status(), StatusCode::OK);
    drop(sse_response);
    let message_response = authenticated_with_secret(
        client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))),
        new_secret,
        subject,
    )
    .header("Idempotency-Key", "rotation-message-key")
    .json(&json!({"content": "after controller rotation"}))
    .send_with_timeout()
    .await?;
    assert_eq!(message_response.status(), StatusCode::ACCEPTED);
    let message_body = response_text(message_response).await?;
    assert_rotation_secret_free(&message_body, &rotation_markers);

    let create_replay =
        authenticated_with_secret(client.post(server.url("/v1/sessions")), new_secret, subject)
            .header("Idempotency-Key", create_key)
            .json(&json!({}))
            .send_with_timeout()
            .await?;
    assert_eq!(create_replay.status(), create_status);
    let create_replay_body = response_text(create_replay).await?;
    assert_rotation_secret_free(&create_replay_body, &rotation_markers);
    assert_eq!(create_replay_body, create_body);

    server.stop().await?;
    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let restarted_new = authenticated_with_secret(
        client.get(restarted.url("/v1/identity")),
        new_secret,
        subject,
    )
    .send_with_timeout()
    .await?;
    assert_eq!(restarted_new.status(), StatusCode::OK);
    let restarted_identity = response_json(restarted_new).await?;
    assert_rotation_secret_free(&restarted_identity.to_string(), &rotation_markers);
    assert_eq!(restarted_identity["revision"], 2);
    let restarted_old = authenticated_with_secret(
        client.get(restarted.url("/v1/identity")),
        old_secret,
        subject,
    )
    .send_with_timeout()
    .await?;
    assert_eq!(restarted_old.status(), StatusCode::UNAUTHORIZED);
    let restarted_old_body = response_text(restarted_old).await?;
    assert_rotation_secret_free(&restarted_old_body, &rotation_markers);
    restarted.stop().await?;
    for marker in [old_secret, new_secret, changed_secret] {
        assert!(!sqlite_contains_secret(database.path(), marker).await?);
    }
    Ok(())
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_stale_controller_rotation_intent_without_secret_reconciles_after_restart(
) -> TestResult<()> {
    let database = TempDatabase::new("control-stale-rotation-recovery")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    assert_rotation_succeeded(
        &client,
        &server,
        TEST_CONTROLLER_SECRET,
        "controller-e2e",
        AUTHORITY_A_NEW_SECRET,
        2,
        "stale-recovery-seed",
    )
    .await?;
    server.stop().await?;

    // Model the crash window after a stale revision's intent was appended but
    // before the request could persist its 409 receipt. A stale request never
    // stages secret bytes, so this valid intent intentionally has no secret
    // file beside the journal.
    let stale_secret = "stale-recovery-candidate-control-e2e";
    append_stale_rotation_intent_without_secret(
        database.path(),
        "controller-e2e",
        1,
        stale_secret,
        "stale-recovery-key",
    )
    .await?;

    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let (status, identity_body) =
        identity_with_secret(&client, &restarted, AUTHORITY_A_NEW_SECRET).await?;
    assert_eq!(status, StatusCode::OK, "stale recovery identity failed");
    assert_eq!(identity_body["revision"], 2);

    let (status, body) = rotate_once(
        &client,
        &restarted,
        AUTHORITY_A_NEW_SECRET,
        "controller-e2e",
        stale_secret,
        1,
        "stale-recovery-key",
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    restarted.stop().await?;
    Ok(())
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_stale_controller_rotation_intent_before_first_manifest_reconciles_after_restart(
) -> TestResult<()> {
    let database = TempDatabase::new("control-stale-initial-rotation-recovery")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let (status, identity_body) = identity(&client, &server).await?;
    assert_eq!(status, StatusCode::OK, "initial identity failed");
    assert_eq!(identity_body["revision"], 1);
    server.stop().await?;

    // Bootstrap revision 1 is already the authority fence even though no
    // active promotion manifest exists yet. Model a crash after a stale
    // intent was appended but before its 409 receipt was persisted.
    let stale_secret = "stale-initial-recovery-candidate-control-e2e";
    append_stale_rotation_intent_without_secret(
        database.path(),
        "controller-e2e",
        1,
        stale_secret,
        "stale-initial-recovery-key",
    )
    .await?;

    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let (status, identity_body) = identity(&client, &restarted).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "stale initial recovery identity failed"
    );
    assert_eq!(identity_body["revision"], 1);
    let (status, body) = rotate_once(
        &client,
        &restarted,
        TEST_CONTROLLER_SECRET,
        "controller-e2e",
        stale_secret,
        1,
        "stale-initial-recovery-key",
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    restarted.stop().await?;
    Ok(())
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_controller_secret_is_absent_from_public_logs_sqlite_snapshots_and_blobs(
) -> TestResult<()> {
    let database = TempDatabase::new("control-secret-nondisclosure")?;
    let config = config_for(&database)?;
    let root = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("temporary database has no parent directory"))?
        .to_owned();
    let old_secret = TEST_CONTROLLER_SECRET;
    let new_secret = "secret-nondisclosure-next-control-e2e";
    let markers = [old_secret, new_secret];
    let mut endpoint = TestZode::start(database.path(), &config, &markers).await?;
    let client = support::http_client()?;

    let scenario = async {
        let create_response = authenticated_with_secret(
            client.post(endpoint.url("/v1/sessions")),
            old_secret,
            SUBJECT_A,
        )
        .header("Idempotency-Key", "secret-nondisclosure-create")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
        assert_response_headers_secret_free(&create_response, &markers);
        let create_status = create_response.status();
        let create_body = response_text(create_response).await?;
        assert_rotation_secret_free(&create_body, &markers);
        assert_eq!(create_status, StatusCode::CREATED, "{create_body}");
        let _session_id = serde_json::from_str::<Value>(&create_body)?["session_id"]
            .as_str()
            .ok_or_else(|| Error::other("secret nondisclosure create omitted session_id"))?
            .to_owned();

        let rotation_response = authenticated_with_secret(
            client.put(endpoint.url("/v1/controller-auth")),
            old_secret,
            SUBJECT_A,
        )
        .header("Idempotency-Key", "secret-nondisclosure-rotation")
        .json(&rotation_body("controller-e2e", 2, new_secret))
        .send_with_timeout()
        .await?;
        assert_response_headers_secret_free(&rotation_response, &markers);
        let rotation_status = rotation_response.status();
        let rotation_body_text = response_text(rotation_response).await?;
        assert_rotation_secret_free(&rotation_body_text, &markers);
        assert_eq!(rotation_status, StatusCode::OK, "{rotation_body_text}");

        let old_identity = authenticated_with_secret(
            client.get(endpoint.url("/v1/identity")),
            old_secret,
            SUBJECT_A,
        )
        .send_with_timeout()
        .await?;
        assert_response_headers_secret_free(&old_identity, &markers);
        assert_eq!(old_identity.status(), StatusCode::UNAUTHORIZED);
        let old_identity_body = response_text(old_identity).await?;
        assert_rotation_secret_free(&old_identity_body, &markers);

        let new_identity = authenticated_with_secret(
            client.get(endpoint.url("/v1/identity")),
            new_secret,
            SUBJECT_A,
        )
        .send_with_timeout()
        .await?;
        assert_response_headers_secret_free(&new_identity, &markers);
        assert_eq!(new_identity.status(), StatusCode::OK);
        let new_identity_body = response_text(new_identity).await?;
        assert_rotation_secret_free(&new_identity_body, &markers);

        let mut events = authenticated_with_secret(
            client.get(endpoint.url("/v1/events")),
            new_secret,
            SUBJECT_A,
        )
        .send_with_timeout()
        .await?;
        assert_response_headers_secret_free(&events, &markers);
        assert_eq!(events.status(), StatusCode::OK);
        let first_chunk = timeout(Duration::from_secs(5), events.chunk())
            .await??
            .ok_or_else(|| {
                Error::other("controller secret nondisclosure SSE ended before a frame")
            })?;
        assert_rotation_secret_free(&String::from_utf8_lossy(&first_chunk), &markers);
        drop(events);
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    let stop_result = endpoint.stop(&markers).await;
    scenario?;
    stop_result?;
    assert_control_secret_absent_from_runtime_artifacts(&root, database.path(), &markers).await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_tmpdir_cannot_bypass_endpoint_ownership() -> TestResult<()> {
    let database = TempDatabase::new("control-tmpdir-ownership")?;
    let config = config_without_replica_store(&database)?;
    let root = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("temporary database has no parent directory"))?;
    let tmp_a = root.join("tmp-a");
    let tmp_b = root.join("tmp-b");
    fs::create_dir(&tmp_a)?;
    fs::create_dir(&tmp_b)?;

    let mut first = ConfiguredServer::start_with_readiness_timeout_and_env(
        &database,
        &config,
        Duration::from_secs(2),
        &[("TMPDIR", tmp_a.as_path())],
    )
    .await?;
    let client = support::http_client()?;
    let (status, first_identity) = identity(&client, &first).await?;
    assert_eq!(status, StatusCode::OK, "first Endpoint identity failed");
    assert!(first_identity["endpoint_id"].is_string());

    let second_result = ConfiguredServer::start_with_readiness_timeout_and_env(
        &database,
        &config,
        Duration::from_secs(2),
        &[("TMPDIR", tmp_b.as_path())],
    )
    .await;
    let second_outcome: TestResult<()> = match second_result {
        Err(error) => {
            let message = error.to_string();
            assert!(
                !message.contains("did not become ready"),
                "TMPDIR ownership rejection was only a readiness timeout: {message}"
            );
            assert!(
                message.contains("non-zero"),
                "TMPDIR ownership rejection was not an active non-zero exit: {message}"
            );
            Ok(())
        }
        Ok(mut second) => {
            second.stop().await?;
            Err(Error::other("second Endpoint became ready with a different TMPDIR").into())
        }
    };
    let first_stop = first.stop().await;
    second_outcome?;
    first_stop?;
    Ok(())
}

#[cfg(unix)]
#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_hardlink_runtime_store_fails_closed_without_state_split() -> TestResult<()> {
    let database = TempDatabase::new("control-hardlink-ownership")?;
    let config = config_for(&database)?;
    let mut first = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let (status, before) = identity(&client, &first).await?;
    assert_eq!(status, StatusCode::OK, "original Endpoint identity failed");
    let endpoint_id = before["endpoint_id"]
        .as_str()
        .ok_or_else(|| Error::other("identity setup omitted endpoint_id"))?
        .to_owned();
    let (_, session_body) =
        create_model_less(&client, &first, SUBJECT_A, "hardlink-session").await?;
    assert!(session_body["session_id"].is_string());
    assert_rotation_succeeded(
        &client,
        &first,
        TEST_CONTROLLER_SECRET,
        "controller-e2e",
        AUTHORITY_A_NEW_SECRET,
        2,
        "hardlink-rotation",
    )
    .await?;
    let (status, rotated) = identity_with_secret(&client, &first, AUTHORITY_A_NEW_SECRET).await?;
    assert_eq!(status, StatusCode::OK, "rotation setup did not activate");
    assert_eq!(rotated["endpoint_id"], endpoint_id);
    assert_eq!(rotated["revision"], 2);
    first.stop().await?;

    let root = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("temporary database has no parent directory"))?;
    let hardlink = root.join("runtime-hardlink.sqlite");
    let source = database.path().to_owned();
    let hardlink_for_create = hardlink.clone();
    fs_blocking(move || {
        fs::hard_link(source, &hardlink_for_create)?;
        Ok(())
    })
    .await?;
    assert!(fs::metadata(database.path())?.nlink() >= 2);

    let hardlink_result =
        ConfiguredServer::start_with_readiness_timeout(&hardlink, &config, Duration::from_secs(2))
            .await;
    let hardlink_outcome: TestResult<()> = match hardlink_result {
        Err(error) => {
            let message = error.to_string();
            assert!(
                !message.contains("did not become ready"),
                "hardlink rejection was only a readiness timeout: {message}"
            );
            assert!(
                message.contains("non-zero"),
                "hardlink rejection was not an active non-zero exit: {message}"
            );
            Ok(())
        }
        Ok(mut alias) => {
            alias.stop().await?;
            Err(Error::other("hardlink path became ready and could split Endpoint state").into())
        }
    };
    let hardlink_for_remove = hardlink.clone();
    fs_blocking(move || fs::remove_file(hardlink_for_remove)).await?;
    hardlink_outcome?;

    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let (status, after) = identity_with_secret(&client, &restarted, AUTHORITY_A_NEW_SECRET).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "original path failed after hardlink rejection"
    );
    assert_eq!(after["endpoint_id"], endpoint_id);
    assert_eq!(after["revision"], 2);
    restarted.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_missing_endpoint_identity_sidecar_is_rejected_before_ready() -> TestResult<()> {
    let database = TempDatabase::new("control-missing-endpoint-id")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let (status, identity_body) = identity(&client, &server).await?;
    assert_eq!(status, StatusCode::OK, "identity setup failed");
    let endpoint_id = identity_body["endpoint_id"]
        .as_str()
        .ok_or_else(|| Error::other("identity setup omitted endpoint_id"))?
        .to_owned();
    let (_, session_body) =
        create_model_less(&client, &server, SUBJECT_A, "missing-id-session").await?;
    assert!(session_body["session_id"].is_string());
    server.stop().await?;

    let database_for_facts = database.path().to_owned();
    let event_count = db_blocking(move || {
        let connection = rusqlite::Connection::open(database_for_facts)?;
        connection.query_row("SELECT COUNT(*) FROM events", [], |row| {
            row.get::<_, i64>(0)
        })
    })
    .await?;
    assert!(
        event_count > 0,
        "missing-id setup did not leave runtime facts"
    );
    let endpoint_path = sidecar_path(database.path(), ".endpoint-id");
    assert!(
        endpoint_path.is_file(),
        "endpoint identity sidecar was not created"
    );
    assert_eq!(
        fs::read_to_string(&endpoint_path)?,
        endpoint_id,
        "identity evidence did not match the public identity"
    );
    let endpoint_path_for_delete = endpoint_path.clone();
    fs_blocking(move || fs::remove_file(endpoint_path_for_delete)).await?;
    assert!(
        !endpoint_path.exists(),
        "endpoint identity sidecar was not removed"
    );

    expect_active_nonzero_start_failure(
        database.path(),
        &config,
        "missing endpoint identity sidecar",
        Some(&endpoint_id),
    )
    .await
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_missing_controller_auth_state_is_rejected_before_ready() -> TestResult<()> {
    let database = TempDatabase::new("control-missing-auth-state")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let (status, identity_body) = identity(&client, &server).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "controller state setup identity failed"
    );
    let endpoint_id = identity_body["endpoint_id"]
        .as_str()
        .ok_or_else(|| Error::other("controller state setup omitted endpoint_id"))?
        .to_owned();
    let (_, session_body) =
        create_model_less(&client, &server, SUBJECT_A, "missing-auth-session").await?;
    assert!(session_body["session_id"].is_string());
    assert_rotation_succeeded(
        &client,
        &server,
        TEST_CONTROLLER_SECRET,
        "controller-e2e",
        AUTHORITY_A_NEW_SECRET,
        2,
        "missing-auth-rotation",
    )
    .await?;
    let (status, rotated) = identity_with_secret(&client, &server, AUTHORITY_A_NEW_SECRET).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rotated["revision"], 2);
    server.stop().await?;

    let database_for_facts = database.path().to_owned();
    let event_count = db_blocking(move || {
        let connection = rusqlite::Connection::open(database_for_facts)?;
        connection.query_row("SELECT COUNT(*) FROM events", [], |row| {
            row.get::<_, i64>(0)
        })
    })
    .await?;
    assert!(
        event_count > 0,
        "missing-auth setup did not leave runtime facts"
    );
    let endpoint_path = sidecar_path(database.path(), ".endpoint-id");
    let auth_dir = controller_auth_dir(database.path());
    let bootstrap = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("temporary database has no parent directory"))?
        .join("controller.secret");
    assert!(
        endpoint_path.is_file(),
        "identity sidecar disappeared before damage"
    );
    assert!(
        !bootstrap.exists(),
        "bootstrap controller secret was not consumed before damage"
    );
    let state_entries = fs::read_dir(&auth_dir)?.count();
    assert!(
        state_entries > 0,
        "rotation did not create controller-auth state"
    );
    let auth_dir_for_delete = auth_dir.clone();
    fs_blocking(move || fs::remove_dir_all(auth_dir_for_delete)).await?;
    assert!(
        !auth_dir.exists(),
        "controller-auth state directory was not removed"
    );

    expect_active_nonzero_start_failure(
        database.path(),
        &config,
        "missing controller-auth state",
        Some(&endpoint_id),
    )
    .await
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_controller_authority_secret_collision_is_rejected_without_mutation() -> TestResult<()>
{
    let database = TempDatabase::new("control-authority-collision")?;
    let config = config_for_authorities(
        &database,
        &[
            (AUTHORITY_A, AUTHORITY_A_SECRET),
            (AUTHORITY_B, AUTHORITY_B_SECRET),
        ],
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let (status, a_before) = identity_with_secret(&client, &server, AUTHORITY_A_SECRET).await?;
    assert_eq!(status, StatusCode::OK, "authority A setup failed");
    assert_eq!(a_before["authority_id"], AUTHORITY_A);
    assert_eq!(a_before["revision"], 1);
    let (status, b_before) = identity_with_secret(&client, &server, AUTHORITY_B_SECRET).await?;
    assert_eq!(status, StatusCode::OK, "authority B setup failed");
    assert_eq!(b_before["authority_id"], AUTHORITY_B);
    assert_eq!(b_before["revision"], 1);

    let (status, body) = rotate_once(
        &client,
        &server,
        AUTHORITY_A_SECRET,
        AUTHORITY_A,
        AUTHORITY_B_SECRET,
        2,
        "authority-secret-collision",
    )
    .await?;
    assert!(
        matches!(
            status,
            StatusCode::CONFLICT | StatusCode::UNPROCESSABLE_ENTITY
        ),
        "authority secret collision was accepted: {status} {body}"
    );
    assert_rotation_secret_free(
        &body,
        &[
            AUTHORITY_A_SECRET,
            AUTHORITY_B_SECRET,
            AUTHORITY_A_NEW_SECRET,
            AUTHORITY_B_NEW_SECRET,
        ],
    );
    let (status, a_after) = identity_with_secret(&client, &server, AUTHORITY_A_SECRET).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "authority A changed after rejected collision"
    );
    assert_eq!(a_after["revision"], 1);
    let (status, b_after) = identity_with_secret(&client, &server, AUTHORITY_B_SECRET).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "authority B changed after rejected collision"
    );
    assert_eq!(b_after["revision"], 1);
    server.stop().await?;
    assert!(!sqlite_contains_secret(database.path(), AUTHORITY_A_SECRET).await?);
    assert!(!sqlite_contains_secret(database.path(), AUTHORITY_B_SECRET).await?);

    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let (status, a_restarted) =
        identity_with_secret(&client, &restarted, AUTHORITY_A_SECRET).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(a_restarted["revision"], 1);
    let (status, b_restarted) =
        identity_with_secret(&client, &restarted, AUTHORITY_B_SECRET).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(b_restarted["revision"], 1);
    restarted.stop().await?;
    Ok(())
}

async fn append_unknown_journal_phase(database: &Path) -> TestResult<PathBuf> {
    let journal = controller_auth_dir(database).join("operations.jsonl");
    let journal_for_write = journal.clone();
    fs_blocking(move || {
        let original = fs::read(&journal_for_write)?;
        let line = original
            .split(|byte| *byte == b'\n')
            .rev()
            .find(|line| !line.is_empty())
            .ok_or_else(|| Error::other("rotation journal had no durable record"))?;
        let mut record: Value = serde_json::from_slice(line)
            .map_err(|_| Error::other("rotation journal record was not JSON"))?;
        if record["operation_id"].as_str().is_none()
            || record["authority_id"].as_str().is_none()
            || record["revision"].as_u64().is_none()
        {
            return Err(Error::other(
                "rotation journal record was not a complete record",
            ));
        }
        record["phase"] = Value::String("unknown-phase-control-e2e".to_owned());
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&journal_for_write)?;
        let bytes = serde_json::to_vec(&record).map_err(Error::other)?;
        use std::io::Write;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(journal_for_write)
    })
    .await
}

fn file_backend_manifest_path(database: &Path, authority_id: &str) -> PathBuf {
    use std::fmt::Write;

    let mut key = String::with_capacity(64);
    for byte in Sha256::digest(authority_id.as_bytes()) {
        let _ = write!(key, "{byte:02x}");
    }
    controller_auth_dir(database).join(format!("active-{key}.manifest"))
}

#[derive(Debug, Clone, Copy)]
struct JournalStats {
    non_empty_lines: usize,
    bytes: usize,
}

async fn read_journal_stats(database: &Path) -> TestResult<JournalStats> {
    let journal = controller_auth_dir(database).join("operations.jsonl");
    fs_blocking(move || {
        let bytes = match fs::read(&journal) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        let non_empty_lines = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count();
        Ok(JournalStats {
            non_empty_lines,
            bytes: bytes.len(),
        })
    })
    .await
}

async fn remove_partial_rotation_state(database: &Path) -> TestResult<()> {
    let directory = controller_auth_dir(database);
    fs_blocking(move || {
        if !directory.join("fingerprint.key").is_file() {
            return Err(Error::other("rotation fingerprint key was not preserved"));
        }
        let mut removed = 0usize;
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if name == "operations.jsonl"
                || (name.starts_with("active-") && name.ends_with(".manifest"))
                || name.starts_with("secret-")
            {
                fs::remove_file(path)?;
                removed += 1;
            }
        }
        if removed == 0 {
            return Err(Error::other(
                "partial rotation state had no removable files",
            ));
        }
        Ok(())
    })
    .await
}

fn config_for_toctou_authorities(database: &TempDatabase) -> TestResult<(PathBuf, String)> {
    const AUTHORITY_COUNT: usize = 128;
    const SECRET_BYTES: usize = 64 * 1024;
    let mut authorities = Vec::with_capacity(AUTHORITY_COUNT);
    for index in 0..AUTHORITY_COUNT {
        let authority_id = format!("toctou-authority-{index:03}");
        let mut secret = vec![b'a'; SECRET_BYTES];
        let tail = format!("{index:03}");
        secret[SECRET_BYTES - tail.len()..].copy_from_slice(tail.as_bytes());
        let secret = String::from_utf8(secret).map_err(Error::other)?;
        authorities.push((authority_id, secret));
    }
    let authority_refs = authorities
        .iter()
        .map(|(authority, secret)| (authority.as_str(), secret.as_str()))
        .collect::<Vec<_>>();
    let config = config_for_authorities(database, &authority_refs)?;
    let mut value: Value = serde_json::from_slice(&fs::read(&config)?)?;
    value
        .as_object_mut()
        .ok_or_else(|| Error::other("endpoint config was not an object"))?
        .remove("credential_replica_store");
    fs::write(&config, serde_json::to_vec_pretty(&value)?)?;
    let first_secret = authorities
        .first()
        .map(|(_, secret)| secret.clone())
        .ok_or_else(|| Error::other("large authority setup was empty"))?;
    Ok((config, first_secret))
}

async fn await_manifest_revision(
    manifest: &Path,
    revision: u64,
    timeout_duration: Duration,
) -> TestResult<()> {
    let manifest = manifest.to_owned();
    tokio::time::timeout(timeout_duration, async move {
        loop {
            let path = manifest.clone();
            let found = fs_blocking(move || {
                let bytes = match fs::read(path) {
                    Ok(bytes) => bytes,
                    Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
                    Err(error) => return Err(error),
                };
                let pointer: Value = serde_json::from_slice(&bytes).map_err(Error::other)?;
                Ok(pointer["revision"].as_u64() == Some(revision))
            })
            .await?;
            if found {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "manifest revision barrier timed out"))?
}

async fn probe_identity_batch(
    client: &Client,
    base_url: &str,
    secret: &str,
    subject: &str,
    count: usize,
) -> TestResult<Vec<StatusCode>> {
    let start = Arc::new(tokio::sync::Barrier::new(count + 1));
    let mut tasks = Vec::with_capacity(count);
    for _ in 0..count {
        let client = client.clone();
        let base_url = base_url.to_owned();
        let secret = secret.to_owned();
        let subject = subject.to_owned();
        let start = start.clone();
        tasks.push(tokio::spawn(async move {
            start.wait().await;
            let response = authenticated_with_secret(
                client.get(format!("{base_url}/v1/identity")),
                &secret,
                &subject,
            )
            .send_with_timeout()
            .await?;
            let status = response.status();
            let body = response_text(response).await?;
            assert_rotation_secret_free(&body, &[&secret]);
            Ok::<StatusCode, Box<dyn std::error::Error + Send + Sync>>(status)
        }));
    }
    start.wait().await;
    let mut statuses = Vec::with_capacity(count);
    for task in tasks {
        statuses.push(task.await??);
    }
    Ok(statuses)
}

async fn journal_contains_authority(database: &Path, authority_id: &str) -> TestResult<bool> {
    let journal = controller_auth_dir(database).join("operations.jsonl");
    let authority_id = authority_id.to_owned();
    fs_blocking(move || {
        let bytes = fs::read(journal)?;
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let record: Value = serde_json::from_slice(line)
                .map_err(|_| Error::other("rotation journal was not JSON"))?;
            if record["authority_id"].as_str() == Some(authority_id.as_str()) {
                return Ok(true);
            }
        }
        Ok(false)
    })
    .await
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_unknown_controller_operation_phase_is_rejected_before_ready() -> TestResult<()> {
    let database = TempDatabase::new("control-unknown-journal-phase")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let (status, _) = identity(&client, &server).await?;
    assert_eq!(status, StatusCode::OK, "journal setup identity failed");
    assert_rotation_succeeded(
        &client,
        &server,
        TEST_CONTROLLER_SECRET,
        "controller-e2e",
        AUTHORITY_A_NEW_SECRET,
        2,
        "unknown-journal-rotation",
    )
    .await?;
    server.stop().await?;

    let journal = append_unknown_journal_phase(database.path()).await?;
    assert_eq!(
        journal,
        controller_auth_dir(database.path()).join("operations.jsonl")
    );
    let journal_bytes = fs::read(&journal)?;
    assert!(journal_bytes
        .windows(b"unknown-phase-control-e2e".len())
        .any(|window| window == b"unknown-phase-control-e2e"));
    assert_rotation_secret_free(
        &String::from_utf8_lossy(&journal_bytes),
        &[TEST_CONTROLLER_SECRET, AUTHORITY_A_NEW_SECRET],
    );

    expect_active_nonzero_start_failure(
        database.path(),
        &config,
        "unknown controller operation phase",
        Some(AUTHORITY_A_NEW_SECRET),
    )
    .await
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_file_backend_manifest_authority_binding_corruption_is_rejected_before_ready(
) -> TestResult<()> {
    let database = TempDatabase::new("control-manifest-authority-mismatch")?;
    let config = config_for_authorities(
        &database,
        &[
            (AUTHORITY_A, AUTHORITY_A_SECRET),
            (AUTHORITY_B, AUTHORITY_B_SECRET),
        ],
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let (status, _) = identity_with_secret(&client, &server, AUTHORITY_A_SECRET).await?;
    assert_eq!(status, StatusCode::OK, "authority A setup failed");
    let (status, _) = identity_with_secret(&client, &server, AUTHORITY_B_SECRET).await?;
    assert_eq!(status, StatusCode::OK, "authority B setup failed");
    assert_rotation_succeeded(
        &client,
        &server,
        AUTHORITY_B_SECRET,
        AUTHORITY_B,
        AUTHORITY_B_NEW_SECRET,
        2,
        "manifest-b-rotation",
    )
    .await?;
    server.stop().await?;

    let manifest_a = file_backend_manifest_path(database.path(), AUTHORITY_A);
    let manifest_b = file_backend_manifest_path(database.path(), AUTHORITY_B);
    assert!(
        !manifest_a.exists(),
        "A manifest unexpectedly existed before corruption"
    );
    assert!(
        manifest_b.is_file(),
        "B rotation did not create its manifest"
    );
    assert!(!journal_contains_authority(database.path(), AUTHORITY_A).await?);
    let pointer_b_bytes = fs::read(&manifest_b)?;
    let pointer_b: Value = serde_json::from_slice(&pointer_b_bytes)?;
    assert_eq!(pointer_b["authority_id"], AUTHORITY_B);
    assert_eq!(pointer_b["revision"], 2);
    assert_rotation_secret_free(
        &String::from_utf8_lossy(&pointer_b_bytes),
        &[
            AUTHORITY_A_SECRET,
            AUTHORITY_B_SECRET,
            AUTHORITY_A_NEW_SECRET,
            AUTHORITY_B_NEW_SECRET,
        ],
    );
    let manifest_a_for_copy = manifest_a.clone();
    let manifest_b_for_copy = manifest_b.clone();
    fs_blocking(move || {
        fs::copy(manifest_b_for_copy, manifest_a_for_copy)?;
        Ok(())
    })
    .await?;
    assert!(manifest_a.is_file(), "A manifest path was not created");
    let copied_a: Value = serde_json::from_slice(&fs::read(&manifest_a)?)?;
    assert_eq!(copied_a["authority_id"], AUTHORITY_B);
    assert_eq!(copied_a["revision"], 2);
    assert!(manifest_b.is_file(), "B manifest path was not preserved");
    assert_ne!(manifest_a, manifest_b);
    let preserved_b: Value = serde_json::from_slice(&fs::read(&manifest_b)?)?;
    assert_eq!(preserved_b["authority_id"], AUTHORITY_B);
    let remaining_manifests = fs::read_dir(controller_auth_dir(database.path()))?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("active-") && name.ends_with(".manifest"))
        })
        .count();
    assert_eq!(
        remaining_manifests, 2,
        "the A/B manifest paths were not both present"
    );

    let restart_config = config_for_authorities(&database, &[(AUTHORITY_A, AUTHORITY_A_SECRET)])?;
    let restart_config_json: Value = serde_json::from_slice(&fs::read(&restart_config)?)?;
    assert_eq!(
        restart_config_json["controller_auth"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        restart_config_json["controller_auth"][0]["authority_id"],
        AUTHORITY_A
    );
    let root = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("temporary database has no parent directory"))?;
    assert!(
        fs::read(root.join("controller-0.secret"))? == AUTHORITY_A_SECRET.as_bytes(),
        "restart configuration did not retain A bootstrap secret"
    );
    assert!(
        !root.join("controller-1.secret").exists(),
        "B bootstrap seed was not consumed after initial durable state"
    );

    match ConfiguredServer::start_with_readiness_timeout(
        database.path(),
        &restart_config,
        Duration::from_secs(2),
    )
    .await
    {
        Err(error) => {
            let message = error.to_string();
            assert!(
                !message.contains("did not become ready"),
                "file-backend manifest binding rejection was only a readiness timeout: {message}"
            );
            assert!(
                message.contains("non-zero"),
                "file-backend manifest binding rejection was not an active non-zero exit: {message}"
            );
            Ok(())
        }
        Ok(mut restarted) => {
            let (status, body) =
                identity_with_secret(&client, &restarted, AUTHORITY_B_NEW_SECRET).await?;
            assert_eq!(
                status,
                StatusCode::OK,
                "cross-authority manifest was not accepted as A: {body}"
            );
            assert_eq!(body["authority_id"], AUTHORITY_A);
            assert_eq!(body["revision"], 2);
            restarted.stop().await?;
            Err(Error::other(
                "file-backend manifest authority binding corruption unexpectedly became ready",
            )
            .into())
        }
    }
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_partial_controller_rotation_state_is_rejected_before_ready() -> TestResult<()> {
    let database = TempDatabase::new("control-partial-rotation")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    assert_rotation_succeeded(
        &client,
        &server,
        TEST_CONTROLLER_SECRET,
        "controller-e2e",
        AUTHORITY_A_NEW_SECRET,
        2,
        "partial-rotation",
    )
    .await?;
    let (status, identity_body) =
        identity_with_secret(&client, &server, AUTHORITY_A_NEW_SECRET).await?;
    assert_eq!(status, StatusCode::OK, "rotation setup did not activate");
    assert_eq!(identity_body["revision"], 2);
    server.stop().await?;

    let endpoint_id_path = sidecar_path(database.path(), ".endpoint-id");
    assert!(
        endpoint_id_path.is_file(),
        "endpoint identity was not preserved"
    );
    remove_partial_rotation_state(database.path()).await?;
    assert!(endpoint_id_path.is_file(), "endpoint identity was removed");
    assert!(
        controller_auth_dir(database.path())
            .join("fingerprint.key")
            .is_file(),
        "rotation fingerprint key was removed"
    );

    match ConfiguredServer::start_with_readiness_timeout(
        database.path(),
        &config,
        Duration::from_secs(2),
    )
    .await
    {
        Err(error) => {
            assert_active_nonzero_error("partial rotation rejection", &error);
            Ok(())
        }
        Ok(mut restarted) => {
            let (status, body) =
                identity_with_secret(&client, &restarted, TEST_CONTROLLER_SECRET).await?;
            assert_eq!(
                status,
                StatusCode::OK,
                "partial state unexpectedly rejected old bootstrap auth: {body}"
            );
            assert_eq!(
                body["revision"], 1,
                "partial state did not visibly roll back to the bootstrap revision"
            );
            restarted.stop().await?;
            Err(Error::other(
                "partial controller rotation state became ready and rolled back to revision 1",
            )
            .into())
        }
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_controller_lock_sidecar_symlink_is_rejected_before_ready() -> TestResult<()> {
    let database = TempDatabase::new("control-lock-sidecar-symlink")?;
    let config = config_for(&database)?;
    let root = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("temporary database has no parent directory"))?;
    let sentinel = root.join("lock-sentinel");
    let lock_path = sidecar_path(database.path(), ".endpoint.lock");
    let sentinel_for_setup = sentinel.clone();
    let lock_for_setup = lock_path.clone();
    let database_for_setup = database.path().to_owned();
    fs_blocking(move || {
        fs::write(&database_for_setup, b"")?;
        fs::write(&sentinel_for_setup, b"sentinel")?;
        let mut permissions = fs::metadata(&sentinel_for_setup)?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&sentinel_for_setup, permissions)?;
        symlink(&sentinel_for_setup, &lock_for_setup)?;
        Ok(())
    })
    .await?;
    let lock_metadata = fs::symlink_metadata(&lock_path)?;
    assert!(lock_metadata.file_type().is_symlink());
    assert_eq!(fs::read_link(&lock_path)?, sentinel);

    match ConfiguredServer::start_with_readiness_timeout(
        database.path(),
        &config,
        Duration::from_secs(2),
    )
    .await
    {
        Err(error) => {
            assert_active_nonzero_error("lock sidecar symlink rejection", &error);
            Ok(())
        }
        Ok(mut server) => {
            let client = support::http_client()?;
            let (status, body) = identity(&client, &server).await?;
            assert_eq!(
                status,
                StatusCode::OK,
                "symlinked lock sidecar did not expose the old ready behavior: {body}"
            );
            server.stop().await?;
            Err(Error::other("Endpoint followed a symlinked lock sidecar and became ready").into())
        }
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_runtime_store_symlink_toctou_cannot_cross_ownership() -> TestResult<()> {
    let database = TempDatabase::new("control-runtime-toctou")?;
    let root = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("temporary database has no parent directory"))?;
    let database_b = root.join("runtime-b.sqlite");
    let (config, large_secret) = config_for_toctou_authorities(&database)?;
    let mut initialized_b = ConfiguredServer::start(&database_b, &config).await?;
    let client = support::http_client()?;
    let (status, _) = identity_with_secret(&client, &initialized_b, &large_secret).await?;
    assert_eq!(status, StatusCode::OK, "independent B setup failed");
    initialized_b.stop().await?;

    let runtime_link = root.join("runtime-link.sqlite");
    symlink(database.path(), &runtime_link)?;
    let lock_a = sidecar_path(database.path(), ".endpoint.lock");
    assert!(
        !lock_a.exists(),
        "A lock sidecar existed before process one"
    );
    let swap_link = runtime_link.clone();
    let swap_target = database_b.clone();
    let swap_temp = root.join("runtime-link.swap");
    let mut first = match ConfiguredServer::start_with_path_barrier(
        &runtime_link,
        &config,
        Duration::from_secs(20),
        &lock_a,
        move || {
            symlink(&swap_target, &swap_temp)?;
            fs::rename(&swap_temp, &swap_link)?;
            Ok(())
        },
    )
    .await
    {
        support::PathBarrierStart::Ready(server) => server,
        support::PathBarrierStart::ActiveNonzero(_) => {
            assert!(fs::canonicalize(&runtime_link)? == fs::canonicalize(&database_b)?);
            return Ok(());
        }
        support::PathBarrierStart::TimeoutOrHarness(message) => {
            return Err(Error::other(format!("TOCTOU barrier failed: {message}")).into());
        }
    };
    assert!(
        fs::canonicalize(&runtime_link)? == fs::canonicalize(&database_b)?,
        "runtime symlink swap did not complete before readiness"
    );
    assert!(lock_a.is_file(), "A lock sidecar was not observed");

    let (status, _) = identity_with_secret(&client, &first, &large_secret).await?;
    assert_eq!(status, StatusCode::OK, "process one did not become usable");
    let (session_id, _) =
        create_model_less_with_secret(&client, &first, &large_secret, SUBJECT_A, "toctou-session")
            .await?;
    first.stop().await?;

    let mut direct_a = ConfiguredServer::start(database.path(), &config).await?;
    let (status_a, body_a) =
        get_session_with_secret(&client, &direct_a, &large_secret, SUBJECT_A, &session_id).await?;
    direct_a.stop().await?;

    let mut direct_b = ConfiguredServer::start(&database_b, &config).await?;
    let (status_b, body_b) =
        get_session_with_secret(&client, &direct_b, &large_secret, SUBJECT_A, &session_id).await?;
    direct_b.stop().await?;
    assert_eq!(
        status_b,
        StatusCode::NOT_FOUND,
        "process two observed process-one's session through the swapped store: B={body_b}; A={status_a} {body_a}"
    );
    assert_eq!(
        status_a,
        StatusCode::OK,
        "direct A lost process-one's session: {body_a}; B={status_b} {body_b}"
    );
    Ok(())
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_manifest_promotion_fences_old_secret_before_public_completion() -> TestResult<()> {
    const PROBE_COUNT: usize = 128;
    const ROTATION_ROUNDS: usize = 6;
    let database = TempDatabase::new("control-manifest-fence")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    assert_rotation_succeeded(
        &client,
        &server,
        TEST_CONTROLLER_SECRET,
        "controller-e2e",
        AUTHORITY_A_NEW_SECRET,
        2,
        "manifest-fence-seed",
    )
    .await?;
    let mut current_secret = AUTHORITY_A_NEW_SECRET.to_owned();
    for round in 0..ROTATION_ROUNDS {
        let next_secret = format!("manifest-fence-secret-{round}-control-e2e");
        let revision = 3 + round as u64;
        let key = format!("manifest-fence-{round}");
        let manifest = file_backend_manifest_path(database.path(), "controller-e2e");
        let rotation_client = client.clone();
        let rotation_url = server.url("/v1/controller-auth");
        let rotation_secret = current_secret.clone();
        let rotation_next = next_secret.clone();
        let rotation_key = key.clone();
        let rotation_body = rotation_body("controller-e2e", revision, &rotation_next);
        let rotation_task = tokio::spawn(async move {
            let response = authenticated_with_secret(
                rotation_client.put(rotation_url),
                &rotation_secret,
                SUBJECT_A,
            )
            .header("Idempotency-Key", rotation_key)
            .json(&rotation_body)
            .send_with_timeout()
            .await?;
            let status = response.status();
            let body = response_text(response).await?;
            assert_rotation_secret_free(&body, &[&rotation_secret, &rotation_next]);
            Ok::<(StatusCode, String), Box<dyn std::error::Error + Send + Sync>>((status, body))
        });
        await_manifest_revision(&manifest, revision, ROTATION_BARRIER_TIMEOUT).await?;
        let post_barrier_statuses = probe_identity_batch(
            &client,
            &server.url(""),
            &current_secret,
            SUBJECT_A,
            PROBE_COUNT,
        )
        .await?;
        let (status, body) = rotation_task.await??;
        assert_eq!(
            status,
            StatusCode::OK,
            "rotation round {round} failed: {body}"
        );
        let (status, identity_body) = identity_with_secret(&client, &server, &next_secret).await?;
        assert_eq!(status, StatusCode::OK, "new secret was not usable");
        assert_eq!(identity_body["revision"], revision);
        let accepted = post_barrier_statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count();
        assert_eq!(
            accepted, 0,
            "old secret was accepted after the manifest barrier in round {round}: {accepted}/{PROBE_COUNT}"
        );
        assert!(post_barrier_statuses
            .iter()
            .all(|status| *status == StatusCode::UNAUTHORIZED));
        current_secret = next_secret;
    }
    server.stop().await?;
    Ok(())
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_historical_controller_rotation_receipts_survive_restart() -> TestResult<()> {
    let database = TempDatabase::new("control-historical-receipts")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let (current_secret, receipts) =
        create_rotation_history(&client, &server, 3, "historical-receipt", "historical-key")
            .await?;
    let first = receipts
        .first()
        .ok_or_else(|| Error::other("historical receipt setup was empty"))?;
    server.stop().await?;

    match ConfiguredServer::start(&database, &config).await {
        Err(error) => {
            assert_active_nonzero_error("historical receipt restart", &error);
            Err(Error::other(format!(
                "historical controller receipts could not survive restart: {error}"
            ))
            .into())
        }
        Ok(mut restarted) => {
            let (status, identity_body) =
                identity_with_secret(&client, &restarted, &current_secret).await?;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(identity_body["revision"], 4);
            assert_all_rotation_replays(&client, &restarted, &current_secret, &receipts).await?;
            let changed_secret = "historical-receipt-changed-control-e2e";
            let (status, body) = rotate_once(
                &client,
                &restarted,
                &current_secret,
                "controller-e2e",
                changed_secret,
                first.revision,
                &first.key,
            )
            .await?;
            assert_eq!(status, StatusCode::CONFLICT, "{body}");
            restarted.stop().await?;
            Ok(())
        }
    }
}

#[ignore = "retired: Endpoint listen-scope trust"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_completed_rotations_bound_journal_and_preserve_historical_receipts() -> TestResult<()>
{
    const ROTATION_COUNT: usize = 16;
    const MAX_JOURNAL_LINES: usize = 4;
    const MAX_JOURNAL_BYTES: usize = 64 * 1024;
    let database = TempDatabase::new("control-bounded-journal")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let (current_secret, receipts) = create_rotation_history(
        &client,
        &server,
        ROTATION_COUNT,
        "bounded-journal",
        "bounded-key",
    )
    .await?;
    server.stop().await?;

    let stats = read_journal_stats(database.path()).await?;
    assert!(
        stats.non_empty_lines <= MAX_JOURNAL_LINES && stats.bytes <= MAX_JOURNAL_BYTES,
        "completed receipts were not compacted: {} non-empty journal lines, {} bytes",
        stats.non_empty_lines,
        stats.bytes
    );
    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let (status, identity_body) =
        identity_with_secret(&client, &restarted, &current_secret).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(identity_body["revision"], ROTATION_COUNT as u64 + 1);
    assert_all_rotation_replays(&client, &restarted, &current_secret, &receipts).await?;
    restarted.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_controller_auth_directory_swap_cannot_acknowledge_split_state() -> TestResult<()> {
    let database = TempDatabase::new("control-directory-swap")?;
    let config = config_for(&database)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;

    let (status, identity_body) = identity(&client, &server).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "directory-swap setup failed: {identity_body}"
    );
    let control_directory = controller_auth_dir(database.path());
    let preserved_directory = sidecar_path(database.path(), ".controller-auth.preserved");
    let replacement_directory = sidecar_path(database.path(), ".controller-auth.replacement");
    assert!(
        control_directory.is_dir(),
        "controller sidecar directory was not created"
    );
    assert!(!preserved_directory.exists());
    assert!(!replacement_directory.exists());

    // Preserve the original test-owned sidecars and replace only the pathname
    // while the real Endpoint remains ready. No file is deleted or overwritten.
    fs::rename(&control_directory, &preserved_directory)?;
    fs::create_dir(&replacement_directory)?;
    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(&replacement_directory)?.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&replacement_directory, permissions)?;
    }
    fs::rename(&replacement_directory, &control_directory)?;

    let next_secret = "directory-swap-next-secret-control-e2e";
    let response = authenticated_with_secret(
        client.put(server.url("/v1/controller-auth")),
        TEST_CONTROLLER_SECRET,
        SUBJECT_A,
    )
    .header("Idempotency-Key", "directory-swap-rotation")
    .json(&rotation_body("controller-e2e", 2, next_secret))
    .send_with_timeout()
    .await?;
    let rotation_status = response.status();
    let rotation_body_text = response_text(response).await?;
    assert_rotation_secret_free(&rotation_body_text, &[TEST_CONTROLLER_SECRET, next_secret]);
    assert!(
        !rotation_status.is_success(),
        "controller-auth rotation acknowledged after its sidecar directory was swapped: {} {}",
        rotation_status,
        rotation_body_text
    );

    server.stop().await?;
    Ok(())
}

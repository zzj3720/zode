#![allow(dead_code)]

mod support;

use std::{
    fs,
    io::{Error, ErrorKind, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use futures_util::StreamExt;
use reqwest::{header::HeaderMap, Client, StatusCode};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::{
    authenticated_as, http_client, install_test_replica, require_ulid, response_text,
    sqlite_contains_secret, write_endpoint_config, HttpRequestExt, LlmHttpProxy, LlmHttpRecording,
    LlmHttpRecordingMetadata, ModelFixture, ModelHold, ModelScript, TempDatabase, TestResult,
    TestZode, ToolFixture, TEST_CONTROLLER_AUTHORITY, TEST_CONTROLLER_SECRET, TEST_PROVIDER_SECRET,
    TEST_SUBJECT,
};
use tokio::time::timeout;

const HEALTH_E2E: &str =
    "e2e_endpoint_health_is_controller_authenticated_and_independent_of_active_session_work";
const CAPABILITIES_E2E: &str =
    "e2e_endpoint_capabilities_are_restart_stable_bounded_and_non_secret";
const WRONG_CONTROLLER_SECRET: &str = "wrong-controller-secret-endpoint-metadata-e2e";
const HEALTH_MAX_BYTES: usize = 4 * 1024;
const CAPABILITIES_MAX_BYTES: usize = 1024 * 1024;
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const HISTORY_MARKER: &str = "endpoint-capability-history-marker";
const ASSISTANT_MARKER: &str = "endpoint-capability-assistant-marker";
const HELD_PROVIDER_ASSISTANT_MARKER: &str = "endpoint-health-provider-released-final-marker";

#[derive(Clone, Debug, Serialize)]
struct RecordedHeader {
    name: String,
    value: String,
}

#[derive(Clone, Debug)]
struct ProbeExchange {
    phase: String,
    path: String,
    authorization: Option<String>,
    response: ProbeResponse,
}

#[derive(Clone, Debug)]
struct ProbeResponse {
    status: Option<u16>,
    headers: Vec<RecordedHeader>,
    chunks: Vec<RecordedChunk>,
    body: Vec<u8>,
    outcome: &'static str,
}

#[derive(Clone, Debug)]
struct RecordedChunk {
    at_us: u64,
    bytes: Vec<u8>,
}

impl ProbeResponse {
    fn status(&self) -> Option<StatusCode> {
        self.status
            .and_then(|status| StatusCode::from_u16(status).ok())
    }

    fn content_type(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name == "content-type")
            .map(|header| header.value.as_str())
    }

    fn require_complete(&self) -> Result<(), String> {
        if self.outcome == "complete" {
            Ok(())
        } else {
            Err(format!("request ended with {}", self.outcome))
        }
    }
}

async fn metadata_probe(
    client: &Client,
    base_url: &str,
    phase: &str,
    path: &str,
    bearer: Option<&str>,
) -> ProbeExchange {
    let authorization = bearer.map(|secret| format!("Bearer {secret}"));
    let mut request = client.get(format!("{base_url}{path}"));
    if let Some(value) = authorization.as_deref() {
        request = request.header("Authorization", value);
    }

    let sent = timeout(PROBE_TIMEOUT, request.send()).await;
    let response = match sent {
        Err(_) => ProbeResponse {
            status: None,
            headers: Vec::new(),
            chunks: Vec::new(),
            body: Vec::new(),
            outcome: "response_headers_timeout",
        },
        Ok(Err(_)) => ProbeResponse {
            status: None,
            headers: Vec::new(),
            chunks: Vec::new(),
            body: Vec::new(),
            outcome: "transport_error",
        },
        Ok(Ok(response)) => {
            let status = Some(response.status().as_u16());
            let headers = captured_response_headers(response.headers());
            let response_started = Instant::now();
            let deadline = response_started + PROBE_TIMEOUT;
            let mut stream = response.bytes_stream();
            let mut chunks = Vec::new();
            let mut body = Vec::new();
            let outcome = loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break "response_body_timeout";
                }
                match timeout(remaining, stream.next()).await {
                    Err(_) => break "response_body_timeout",
                    Ok(None) => break "complete",
                    Ok(Some(Err(_))) => break "response_body_error",
                    Ok(Some(Ok(chunk))) => {
                        let Some(next_len) = body.len().checked_add(chunk.len()) else {
                            break "response_body_too_large";
                        };
                        if next_len > MAX_CAPTURE_BYTES {
                            break "response_body_too_large";
                        }
                        body.extend_from_slice(&chunk);
                        chunks.push(RecordedChunk {
                            at_us: elapsed_us(response_started),
                            bytes: chunk.to_vec(),
                        });
                    }
                }
            };
            ProbeResponse {
                status,
                headers,
                chunks,
                body,
                outcome,
            }
        }
    };

    ProbeExchange {
        phase: phase.to_owned(),
        path: path.to_owned(),
        authorization,
        response,
    }
}

fn elapsed_us(started: Instant) -> u64 {
    started.elapsed().as_micros().try_into().unwrap_or(u64::MAX)
}

fn captured_response_headers(headers: &HeaderMap) -> Vec<RecordedHeader> {
    let mut selected = headers
        .iter()
        .map(|(name, value)| RecordedHeader {
            name: name.as_str().to_owned(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.value.cmp(&right.value))
    });
    selected
}

fn validate_health(response: &ProbeResponse, expected_endpoint_id: &str) -> Result<(), String> {
    response.require_complete()?;
    if response.status() != Some(StatusCode::OK) {
        return Err(format!(
            "expected HTTP 200, got {}",
            response
                .status
                .map_or_else(|| "no status".to_owned(), |status| status.to_string())
        ));
    }
    validate_json_content_type(response)?;
    if response.body.len() > HEALTH_MAX_BYTES {
        return Err(format!("health body exceeded {HEALTH_MAX_BYTES} bytes"));
    }
    let body: Value = serde_json::from_slice(&response.body)
        .map_err(|_| "health response was not JSON".to_owned())?;
    require_exact_object_keys(
        &body,
        &["endpoint_id", "protocol_version", "schema", "status"],
        "health",
    )?;
    if body["schema"] != "zode.endpoint-health.v1"
        || body["protocol_version"] != "zode.endpoint.v1"
        || body["endpoint_id"] != expected_endpoint_id
        || body["status"] != "ready"
    {
        return Err("health response did not match the exact readiness projection".to_owned());
    }
    Ok(())
}

fn validate_capabilities(
    response: &ProbeResponse,
    expected_endpoint_id: &str,
) -> Result<(), String> {
    response.require_complete()?;
    if response.status() != Some(StatusCode::OK) {
        return Err(format!(
            "expected HTTP 200, got {}",
            response
                .status
                .map_or_else(|| "no status".to_owned(), |status| status.to_string())
        ));
    }
    validate_json_content_type(response)?;
    if response.body.len() > CAPABILITIES_MAX_BYTES {
        return Err(format!(
            "capabilities body exceeded {CAPABILITIES_MAX_BYTES} bytes"
        ));
    }
    let body: Value = serde_json::from_slice(&response.body)
        .map_err(|_| "capabilities response was not JSON".to_owned())?;
    require_exact_object_keys(
        &body,
        &[
            "auth_replica_credential_schemas",
            "built_in_tools",
            "endpoint_id",
            "limits",
            "outbound_capabilities",
            "protocol_version",
            "provider_adapter_kinds",
            "schema",
            "tools",
        ],
        "capabilities",
    )?;
    if body["schema"] != "zode.endpoint-capabilities.v1"
        || body["protocol_version"] != "zode.endpoint.v1"
        || body["endpoint_id"] != expected_endpoint_id
    {
        return Err("capabilities response omitted its exact Endpoint identity".to_owned());
    }

    require_exact_sorted_strings(&body, "provider_adapter_kinds", &["openai_compatible"])?;
    require_exact_sorted_strings(
        &body,
        "auth_replica_credential_schemas",
        &["openai-compatible.api-key.v1"],
    )?;
    require_exact_sorted_strings(
        &body,
        "outbound_capabilities",
        &["provider_http", "tool_http"],
    )?;
    require_exact_sorted_strings(&body, "built_in_tools", &["wait_for"])?;
    require_exact_tools(&body)?;
    require_exact_object_keys(
        &body["limits"],
        &[
            "max_auth_replica_request_bytes",
            "max_inline_tool_output_bytes",
            "max_session_request_bytes",
            "wait_for_default_seconds",
            "wait_for_max_seconds",
            "wait_for_min_seconds",
        ],
        "capabilities limits",
    )?;
    if body["limits"]["max_session_request_bytes"] != 262_144
        || body["limits"]["max_auth_replica_request_bytes"] != 131_072
        || body["limits"]["max_inline_tool_output_bytes"] != 65_536
        || body["limits"]["wait_for_min_seconds"] != 1
        || body["limits"]["wait_for_default_seconds"] != 60
        || body["limits"]["wait_for_max_seconds"] != 600
    {
        return Err("capabilities response did not match the exact flat limits".to_owned());
    }
    Ok(())
}

fn require_exact_object_keys(value: &Value, expected: &[&str], field: &str) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{field} was not an object"))?;
    let mut actual = object.keys().map(String::as_str).collect::<Vec<_>>();
    actual.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    if actual != expected {
        return Err(format!("{field} did not match its exact public keys"));
    }
    Ok(())
}

fn require_exact_tools(body: &Value) -> Result<(), String> {
    let tools = body["tools"]
        .as_array()
        .ok_or_else(|| "capabilities tools was not an array".to_owned())?;
    let expected = [
        ("fixture_tool", "response"),
        ("éclair_fixture_tool", "response"),
    ];
    if tools.len() != expected.len() {
        return Err("capabilities tools did not match effective config".to_owned());
    }
    for (tool, (name, completion_mode)) in tools.iter().zip(expected) {
        require_exact_object_keys(tool, &["completion_mode", "name"], "capability tool")?;
        if tool["name"] != name || tool["completion_mode"] != completion_mode {
            return Err("capabilities tools were not sorted configuration projections".to_owned());
        }
    }
    Ok(())
}

fn validate_json_content_type(response: &ProbeResponse) -> Result<(), String> {
    if response
        .content_type()
        .is_some_and(|value| value.starts_with("application/json"))
    {
        Ok(())
    } else {
        Err("response did not use application/json".to_owned())
    }
}

fn require_exact_sorted_strings(
    body: &Value,
    field: &str,
    expected: &[&str],
) -> Result<(), String> {
    let values = body[field]
        .as_array()
        .ok_or_else(|| format!("capabilities field {field} was not an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("capabilities field {field} contained a non-string"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(format!(
            "capabilities field {field} was not sorted and unique"
        ));
    }
    let expected = expected
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    if values != expected {
        return Err(format!(
            "capabilities field {field} did not match effective config"
        ));
    }
    Ok(())
}

fn validate_auth_rejection(response: &ProbeResponse) -> Result<(), String> {
    response.require_complete()?;
    if response.status() != Some(StatusCode::UNAUTHORIZED) {
        return Err(format!(
            "expected HTTP 401, got {}",
            response
                .status
                .map_or_else(|| "no status".to_owned(), |status| status.to_string())
        ));
    }
    validate_json_content_type(response)?;
    if response.body.len() > HEALTH_MAX_BYTES {
        return Err("authentication error exceeded its response bound".to_owned());
    }
    let body: Value = serde_json::from_slice(&response.body)
        .map_err(|_| "authentication error was not JSON".to_owned())?;
    require_exact_object_keys(&body, &["error"], "authentication error")?;
    require_exact_object_keys(
        &body["error"],
        &["code", "message", "retryable"],
        "authentication error body",
    )?;
    if body["error"]["code"] != "unauthenticated"
        || body["error"]["retryable"] != false
        || body["error"]["message"] != "authentication required"
    {
        return Err("authentication error was not the neutral public shape".to_owned());
    }
    Ok(())
}

fn assert_observation_omits(
    response: &ProbeResponse,
    forbidden: &[(&str, String)],
) -> Result<(), String> {
    for (label, marker) in forbidden.iter().filter(|(_, marker)| !marker.is_empty()) {
        let in_body = response
            .body
            .windows(marker.len())
            .any(|window| window == marker.as_bytes());
        let in_headers = response
            .headers
            .iter()
            .any(|header| header.value.contains(marker));
        if in_body || in_headers {
            return Err(format!("response leaked forbidden {label}"));
        }
    }
    Ok(())
}

async fn create_model_session(
    client: &Client,
    server: &TestZode,
    provider_url: &str,
    idempotency_key: &str,
    tools: &[&str],
) -> TestResult<String> {
    let response = authenticated_as(client.post(server.url("/v1/sessions")), TEST_SUBJECT)
        .header("Idempotency-Key", idempotency_key)
        .json(&json!({
            "model": {
                "provider": "fixture-provider",
                "provider_execution": {
                    "schema": "zode.provider-execution.v1",
                    "revision": 1,
                    "kind": "openai_compatible",
                    "base_url": provider_url
                },
                "model": "fixture-model",
                "auth_authority_id": TEST_CONTROLLER_AUTHORITY,
                "auth_profile_id": "profile-e2e",
                "minimum_auth_revision": 1
            },
            "tools": tools
        }))
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_text(response).await?;
    if status != StatusCode::CREATED {
        return Err(Error::other(format!(
            "metadata setup session create returned HTTP {status}"
        ))
        .into());
    }
    require_ulid(&serde_json::from_str(&body)?)
}

fn set_provider_origin(config: &Path, provider_url: &str) -> TestResult<()> {
    let mut value: Value = serde_json::from_slice(&fs::read(config)?)?;
    let origin = url::Url::parse(provider_url)?
        .origin()
        .ascii_serialization();
    value["provider_execution"]["allowed_base_url_origins"] = json!([origin]);
    fs::write(config, serde_json::to_vec_pretty(&value)?)?;
    Ok(())
}

async fn read_endpoint_id(client: &Client, server: &TestZode) -> TestResult<String> {
    let response = authenticated_as(client.get(server.url("/v1/identity")), TEST_SUBJECT)
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_text(response).await?;
    if status != StatusCode::OK {
        return Err(Error::other(format!("metadata identity setup returned HTTP {status}")).into());
    }
    let body: Value = serde_json::from_str(&body)?;
    body["endpoint_id"]
        .as_str()
        .filter(|endpoint_id| !endpoint_id.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| Error::other("metadata identity setup omitted endpoint_id").into())
}

async fn append_message(
    client: &Client,
    server: &TestZode,
    session_id: &str,
    idempotency_key: &str,
    content: &str,
) -> TestResult<()> {
    let response = authenticated_as(
        client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))),
        TEST_SUBJECT,
    )
    .header("Idempotency-Key", idempotency_key)
    .json(&json!({"content": content}))
    .send_with_timeout()
    .await?;
    let status = response.status();
    let _ = response_text(response).await?;
    if status != StatusCode::ACCEPTED {
        return Err(Error::other(format!("metadata setup message returned HTTP {status}")).into());
    }
    Ok(())
}

async fn wait_for_single_exact_assistant(
    client: &Client,
    server: &TestZode,
    session_id: &str,
    marker: &str,
) -> TestResult<()> {
    timeout(PROBE_TIMEOUT, async {
        loop {
            let assistants = session_assistant_contents(client, server, session_id).await?;
            match assistants.as_slice() {
                [] => {}
                [content] if content == marker => return Ok(()),
                _ => {
                    return Err(Error::other(
                        "metadata session transcript did not contain exactly one exact assistant",
                    )
                    .into())
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "metadata session barrier timed out"))?
}

async fn wait_for_session_marker(
    client: &Client,
    server: &TestZode,
    session_id: &str,
    marker: &str,
) -> TestResult<()> {
    timeout(PROBE_TIMEOUT, async {
        loop {
            if session_assistant_contents(client, server, session_id)
                .await?
                .iter()
                .any(|content| content.contains(marker))
            {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "metadata session barrier timed out"))?
}

async fn session_assistant_contents(
    client: &Client,
    server: &TestZode,
    session_id: &str,
) -> TestResult<Vec<String>> {
    let response = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}"))),
        TEST_SUBJECT,
    )
    .send_with_timeout()
    .await?;
    let status = response.status();
    let body = response_text(response).await?;
    if status != StatusCode::OK {
        return Err(
            Error::other(format!("metadata session barrier returned HTTP {status}")).into(),
        );
    }
    let session: Value = serde_json::from_str(&body)?;
    let messages = session["transcript"]
        .as_array()
        .ok_or_else(|| Error::other("metadata session transcript was not an array"))?;
    messages
        .iter()
        .filter(|message| message["role"] == "assistant")
        .map(|message| {
            message["content"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error::other("metadata assistant content was not a string").into())
        })
        .collect()
}

fn configured_tools(adapter_url: &str) -> Vec<Value> {
    vec![
        configured_response_tool("éclair_fixture_tool", adapter_url),
        configured_response_tool("fixture_tool", adapter_url),
    ]
}

fn configured_response_tool(name: &str, adapter_url: &str) -> Value {
    json!({
        "name": name,
        "description": "non-secret response-mode capability fixture",
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

fn configured_external_callback_tool(name: &str, adapter_url: &str) -> Value {
    json!({
        "name": name,
        "description": "external callback capability fixture",
        "input_schema": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "additionalProperties": false
        },
        "completion_mode": "external_callback",
        "auto_wait_timeout_seconds": 20,
        "recovery": {
            "on_running_restart": "await_callback",
            "retry_dispatch": "never"
        },
        "adapter": {"kind": "http", "url": adapter_url}
    })
}

fn shallow_route_error(owner: &str, path: &str) -> TestResult<()> {
    Err(Error::other(format!(
        "{owner} reached shallow HTTP 404 at {path}; register the authenticated GET route before the first behavioral recording run"
    ))
    .into())
}

fn contract_failure(
    owner: &str,
    purpose: &str,
    reason: String,
    exchanges: &[ProbeExchange],
    provider: Option<&LlmHttpRecording>,
) -> TestResult<()> {
    let quarantine =
        retain_first_post_bootstrap_failure(owner, purpose, &reason, exchanges, provider)?;
    Err(Error::other(format!(
        "{owner} retained its first post-bootstrap mismatch ({reason}) at {}",
        quarantine.display()
    ))
    .into())
}

fn retain_first_post_bootstrap_failure(
    owner: &str,
    purpose: &str,
    reason: &str,
    exchanges: &[ProbeExchange],
    provider: Option<&LlmHttpRecording>,
) -> TestResult<PathBuf> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-recordings/quarantine")
        .join(format!("{owner}-first-post-bootstrap"));
    let root = directory
        .parent()
        .ok_or_else(|| Error::other("metadata incident quarantine has no root"))?;
    fs::create_dir_all(root)?;
    #[cfg(unix)]
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    match fs::create_dir(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => return Ok(directory),
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;

    let raw = incident_document(owner, purpose, reason, exchanges)?;
    write_restricted_new(&directory.join("incident.raw.json"), &raw)?;
    if let Some(provider) = provider {
        write_restricted_new(
            &directory.join("provider.raw.json"),
            &serde_json::to_value(provider)?,
        )?;
    }
    Ok(directory)
}

fn incident_document(
    owner: &str,
    purpose: &str,
    reason: &str,
    exchanges: &[ProbeExchange],
) -> TestResult<Value> {
    let exchanges = exchanges
        .iter()
        .enumerate()
        .map(|(sequence, exchange)| {
            let request_body = Vec::<u8>::new();
            let request_headers = exchange
                .authorization
                .as_ref()
                .map(|value| {
                    vec![json!({
                        "name": "authorization",
                        "value": value})]
                })
                .unwrap_or_default();
            let mut request = json!({
                "method": "GET",
                "path": exchange.path,
                "semantic_headers": request_headers,
                "zode_subject_present": false,
                "raw_body_hex": hex_encode(&request_body),
                "canonical_json": null,
                "raw_body_sha256": sha256_hex(&request_body)});
            request["fingerprint"] = Value::String(value_fingerprint(&request));
            let mut response = json!({
                "status": exchange.response.status,
                "semantic_headers": exchange.response.headers.iter().filter(|header| {
                    matches!(header.name.as_str(), "cache-control" | "content-type" | "retry-after")
                }).collect::<Vec<_>>(),
                "chunks": exchange.response.chunks.iter().enumerate().map(|(sequence, chunk)| json!({
                    "sequence": sequence,
                    "at_us": chunk.at_us,
                    "bytes_hex": hex_encode(&chunk.bytes)})).collect::<Vec<_>>(),
                "outcome": exchange.response.outcome,
                "raw_body_sha256": sha256_hex(&exchange.response.body)});
            response["fingerprint"] = Value::String(value_fingerprint(&response));
            json!({
                "sequence": sequence,
                "phase": exchange.phase,
                "request": request,
                "response": response})
        })
        .collect::<Vec<_>>();
    let response_fingerprint = exchanges
        .last()
        .and_then(|exchange| exchange["response"]["fingerprint"].as_str())
        .ok_or_else(|| Error::other("metadata incident had no failing response fingerprint"))?;
    let mut recording = json!({
        "schema": "zode.http-incident-recording.v1",
        "recording_id": format!("http-incident:{owner}:v1"),
        "purpose": purpose,
        "owner": "tests/endpoint_metadata_e2e.rs",
        "boundary": "Endpoint public HTTP",
        "owning_e2e": owner,
        "secret_slots": [],
        "first_seen_failure": {
            "boundary": "endpoint.metadata_read",
            "safe_error": reason,
            "response_fingerprint": response_fingerprint},
        "exchanges": exchanges,
        "whole_sha256": ""});
    refresh_whole_digest(&mut recording)?;
    Ok(recording)
}

fn refresh_whole_digest(recording: &mut Value) -> TestResult<()> {
    recording["whole_sha256"] = Value::String(String::new());
    let digest = sha256_hex(&serde_json::to_vec(recording)?);
    recording["whole_sha256"] = Value::String(digest);
    Ok(())
}

fn write_restricted_new(path: &Path, value: &Value) -> TestResult<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn assert_artifacts_omit(root: &Path, marker: &str, label: &str) -> TestResult<()> {
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() {
                let bytes = fs::read(&path)?;
                if bytes
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes())
                {
                    return Err(Error::other(format!(
                        "{label} reached test artifact {}",
                        path.display()
                    ))
                    .into());
                }
            }
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn value_fingerprint(value: &Value) -> String {
    sha256_hex(value.to_string().as_bytes())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn merge_result(
    primary: TestResult<()>,
    cleanup_errors: Vec<String>,
    context: &str,
) -> TestResult<()> {
    match (primary, cleanup_errors.is_empty()) {
        (Ok(()), true) => Ok(()),
        (Ok(()), false) => Err(Error::other(format!(
            "{context} cleanup failed: {}",
            cleanup_errors.join("; ")
        ))
        .into()),
        (Err(error), true) => Err(error),
        (Err(error), false) => Err(Error::other(format!(
            "{context} failed: {error}; cleanup failed: {}",
            cleanup_errors.join("; ")
        ))
        .into()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_endpoint_health_is_controller_authenticated_and_independent_of_active_session_work(
) -> TestResult<()> {
    let database = TempDatabase::new("endpoint-health")?;
    let config = write_endpoint_config(database.path(), Vec::new(), 1)?;
    let hold = ModelHold::new();
    let mut model = ModelFixture::start(vec![ModelScript::hold_entered(
        hold.clone(),
        ModelScript::final_text(HELD_PROVIDER_ASSISTANT_MARKER),
    )])
    .await?;
    let model_origin = model.origin();
    let recording_directory = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("health database had no root"))?
        .join("transient-health-provider-recording");
    let mut provider_proxy = LlmHttpProxy::record(
        &model_origin,
        "fixture-provider",
        "fixture-model",
        recording_directory,
        LlmHttpRecordingMetadata {
            recording_id: "endpoint-health-held-provider-first-occurrence".to_owned(),
            purpose: "retain the provider exchange that makes health independence observable"
                .to_owned(),
            owner: HEALTH_E2E.to_owned(),
            boundary: "Endpoint aimux to provider fixture".to_owned(),
            secret_slots: vec!["SLOT_PROVIDER_AUTHORIZATION".to_owned()],
        },
    )
    .await?;
    let model_url = provider_proxy.base_url("/v1");
    set_provider_origin(&config, &model_url)?;
    let process_forbidden = [
        TEST_CONTROLLER_SECRET,
        TEST_PROVIDER_SECRET,
        WRONG_CONTROLLER_SECRET,
    ];
    let mut server = Some(TestZode::start(database.path(), &config, &process_forbidden).await?);
    let client = http_client()?;
    let mut deferred_mismatch: Option<(&'static str, String, Vec<ProbeExchange>)> = None;
    let mut held_session_id = None;

    let mut primary = async {
        let current = server.as_ref().expect("health Endpoint was started");
        let root = database
            .path()
            .parent()
            .ok_or_else(|| Error::other("health database had no root"))?;
        let endpoint_id = read_endpoint_id(&client, current).await?;
        install_test_replica(&client, &current.url(""), "health-install-replica").await?;
        let session_id = create_model_session(
            &client,
            current,
            &model_url,
            "health-create-session",
            &[],
        )
        .await?;
        append_message(
            &client,
            current,
            &session_id,
            "health-hold-message",
            "health-active-provider-marker",
        )
        .await?;
        hold.wait_entered().await?;
        held_session_id = Some(session_id.clone());
        if model.request_count() != 1 {
            return Err(Error::other("health fixture did not hold exactly one provider request").into());
        }

        let path = "/v1/health";
        let valid = metadata_probe(
            &client,
            &current.url(""),
            "health.valid_controller_while_provider_held",
            path,
            Some(TEST_CONTROLLER_SECRET),
        )
        .await;
        if valid.response.status() == Some(StatusCode::NOT_FOUND) {
            return shallow_route_error(HEALTH_E2E, path);
        }
        let forbidden = vec![
            ("controller credential", TEST_CONTROLLER_SECRET.to_owned()),
            (
                "invalid controller credential",
                WRONG_CONTROLLER_SECRET.to_owned(),
            ),
            ("provider credential", TEST_PROVIDER_SECRET.to_owned()),
            ("provider URL", model_url.clone()),
            ("provider fixture origin", model_origin.clone()),
            ("Endpoint URL", current.url("")),
            ("temporary root", root.display().to_string()),
            ("runtime database path", database.path().display().to_string()),
            ("config path", config.display().to_string()),
            ("session ID", session_id.clone()),
            ("session history", "health-active-provider-marker".to_owned()),
            ("provider instance", "fixture-provider".to_owned()),
            ("model instance", "fixture-model".to_owned()),
            ("profile instance", "profile-e2e".to_owned())];
        let validation = validate_health(&valid.response, &endpoint_id)
            .and_then(|()| assert_observation_omits(&valid.response, &forbidden));
        if let Err(reason) = validation {
            deferred_mismatch = Some((
                "retain the first authenticated health mismatch while a provider stream is held",
                reason,
                vec![valid],
            ));
            return Ok(());
        }

        for (phase, bearer) in [
            ("health.missing_controller", None),
            ("health.invalid_controller", Some(WRONG_CONTROLLER_SECRET))] {
            let open = metadata_probe(&client, &current.url(""), phase, path, bearer).await;
            let validation = validate_health(&open.response, &endpoint_id)
                .and_then(|()| assert_observation_omits(&open.response, &forbidden));
            if let Err(reason) = validation {
                deferred_mismatch = Some((
                    "retain the first unauthenticated health mismatch while a provider stream is held",
                    reason,
                    vec![open],
                ));
                return Ok(());
            }
        }
        if model.request_count() != 1 {
            return Err(Error::other("health probes altered the held provider work").into());
        }
        Ok(())
    }
    .await;

    let mut completion_errors = Vec::new();
    if let Some(session_id) = held_session_id.as_deref() {
        let current = server.as_ref().expect("health Endpoint was started");
        match session_assistant_contents(&client, current, session_id).await {
            Ok(assistants) if assistants.is_empty() => {}
            Ok(_) => completion_errors
                .push("Endpoint exposed an assistant before provider release".to_owned()),
            Err(error) => completion_errors.push(error.to_string()),
        }
    }
    hold.release();
    if let Some(session_id) = held_session_id.as_deref() {
        let completion = async {
            let current = server.as_ref().expect("health Endpoint was started");
            provider_proxy.wait_for_completed_exchanges(1).await?;
            wait_for_single_exact_assistant(
                &client,
                current,
                session_id,
                HELD_PROVIDER_ASSISTANT_MARKER,
            )
            .await
        }
        .await;
        if let Err(error) = completion {
            completion_errors.push(error.to_string());
        }
    }
    primary = merge_result(
        primary,
        completion_errors,
        "Endpoint health durable provider completion",
    );
    if primary.is_ok() {
        if let Some((purpose, reason, exchanges)) = deferred_mismatch.take() {
            primary = async {
                let provider = provider_proxy.recording()?;
                contract_failure(HEALTH_E2E, purpose, reason, &exchanges, Some(&provider))
            }
            .await;
        }
    }
    let mut cleanup_errors = Vec::new();
    if let Some(mut current) = server.take() {
        if let Err(error) = current.stop(&process_forbidden).await {
            cleanup_errors.push(error.to_string());
        }
    }
    if let Err(error) = model.stop().await {
        cleanup_errors.push(error.to_string());
    }
    if let Err(error) = provider_proxy.stop().await {
        cleanup_errors.push(error.to_string());
    }
    match sqlite_contains_secret(database.path(), TEST_PROVIDER_SECRET).await {
        Ok(false) => {}
        Ok(true) => cleanup_errors.push("provider credential reached runtime SQLite".to_owned()),
        Err(error) => cleanup_errors.push(error.to_string()),
    }
    if let Some(root) = database.path().parent() {
        if let Err(error) = assert_artifacts_omit(
            root,
            WRONG_CONTROLLER_SECRET,
            "invalid controller credential",
        ) {
            cleanup_errors.push(error.to_string());
        }
    } else {
        cleanup_errors.push("health database had no artifact root".to_owned());
    }
    merge_result(primary, cleanup_errors, "Endpoint health E2E")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_endpoint_capabilities_are_restart_stable_bounded_and_non_secret() -> TestResult<()> {
    let database = TempDatabase::new("endpoint-capabilities")?;
    let mut tool = ToolFixture::start(Vec::new()).await?;
    let tool_url = tool.adapter_url();
    let config = write_endpoint_config(database.path(), configured_tools(&tool_url), 1)?;
    let mut model = ModelFixture::start(vec![ModelScript::final_text(ASSISTANT_MARKER)]).await?;
    let model_url = model.provider_url();
    set_provider_origin(&config, &model_url)?;
    let process_forbidden = [
        TEST_CONTROLLER_SECRET,
        TEST_PROVIDER_SECRET,
        WRONG_CONTROLLER_SECRET,
    ];
    let mut server = Some(TestZode::start(database.path(), &config, &process_forbidden).await?);
    let client = http_client()?;

    let primary = async {
        let current = server.as_ref().expect("capabilities Endpoint was started");
        let endpoint_id = read_endpoint_id(&client, current).await?;
        install_test_replica(&client, &current.url(""), "capabilities-install-replica").await?;
        let session_id = create_model_session(
            &client,
            current,
            &model_url,
            "capabilities-create-session",
            &["fixture_tool"],
        )
        .await?;
        append_message(
            &client,
            current,
            &session_id,
            "capabilities-history-message",
            HISTORY_MARKER,
        )
        .await?;
        model.wait_for_requests(1).await?;
        wait_for_session_marker(&client, current, &session_id, ASSISTANT_MARKER).await?;

        let path = "/v1/capabilities";
        let first = metadata_probe(
            &client,
            &current.url(""),
            "capabilities.before_restart",
            path,
            Some(TEST_CONTROLLER_SECRET),
        )
        .await;
        if first.response.status() == Some(StatusCode::NOT_FOUND) {
            return shallow_route_error(CAPABILITIES_E2E, path);
        }
        let root = database
            .path()
            .parent()
            .ok_or_else(|| Error::other("capabilities database had no root"))?;
        let forbidden = vec![
            ("controller credential", TEST_CONTROLLER_SECRET.to_owned()),
            (
                "invalid controller credential",
                WRONG_CONTROLLER_SECRET.to_owned(),
            ),
            ("provider credential", TEST_PROVIDER_SECRET.to_owned()),
            ("controller authority", TEST_CONTROLLER_AUTHORITY.to_owned()),
            ("owner subject", TEST_SUBJECT.to_owned()),
            ("provider URL", model_url.clone()),
            ("tool URL", tool_url.clone()),
            ("Endpoint URL", current.url("")),
            ("temporary root", root.display().to_string()),
            ("configured origin", "http://127.0.0.1".to_owned()),
            (
                "runtime database path",
                database.path().display().to_string(),
            ),
            ("config path", config.display().to_string()),
            (
                "secret directory path",
                root.join("credentials").display().to_string(),
            ),
            (
                "blob directory path",
                root.join("blobs").display().to_string(),
            ),
            (
                "controller secret path",
                root.join("controller.secret").display().to_string(),
            ),
            ("provider instance", "fixture-provider".to_owned()),
            ("model instance", "fixture-model".to_owned()),
            ("profile instance", "profile-e2e".to_owned()),
            ("session ID", session_id.clone()),
            ("session history", HISTORY_MARKER.to_owned()),
            ("assistant history", ASSISTANT_MARKER.to_owned()),
            ("create receipt", "capabilities-create-session".to_owned()),
            ("message receipt", "capabilities-history-message".to_owned()),
        ];
        let validation = validate_capabilities(&first.response, &endpoint_id)
            .and_then(|()| assert_observation_omits(&first.response, &forbidden));
        if let Err(reason) = validation {
            return contract_failure(
                CAPABILITIES_E2E,
                "retain the first deterministic capability projection mismatch",
                reason,
                std::slice::from_ref(&first),
                None,
            );
        }

        for (phase, bearer) in [
            ("capabilities.missing_controller", None),
            (
                "capabilities.invalid_controller",
                Some(WRONG_CONTROLLER_SECRET),
            ),
        ] {
            let open = metadata_probe(&client, &current.url(""), phase, path, bearer).await;
            let validation = validate_capabilities(&open.response, &endpoint_id)
                .and_then(|()| assert_observation_omits(&open.response, &forbidden));
            if let Err(reason) = validation {
                return contract_failure(
                    CAPABILITIES_E2E,
                    "retain the first unauthenticated capability mismatch",
                    reason,
                    std::slice::from_ref(&open),
                    None,
                );
            }
        }
        if tool.invocation_count() != 0 {
            return Err(Error::other("capability read invoked a configured tool").into());
        }

        let first_body = first.response.body.clone();
        let mut first_server = server
            .take()
            .expect("capabilities Endpoint was available before restart");
        first_server.stop(&process_forbidden).await?;
        server = Some(TestZode::start(database.path(), &config, &process_forbidden).await?);
        let restarted = server
            .as_ref()
            .expect("capabilities Endpoint was restarted");
        let second = metadata_probe(
            &client,
            &restarted.url(""),
            "capabilities.after_restart",
            path,
            Some(TEST_CONTROLLER_SECRET),
        )
        .await;
        let validation = validate_capabilities(&second.response, &endpoint_id)
            .and_then(|()| assert_observation_omits(&second.response, &forbidden))
            .and_then(|()| {
                if second.response.body == first_body {
                    Ok(())
                } else {
                    Err("capability projection bytes changed across restart".to_owned())
                }
            });
        if let Err(reason) = validation {
            return contract_failure(
                CAPABILITIES_E2E,
                "retain the first restart-stability capability mismatch",
                reason,
                &[first, second],
                None,
            );
        }
        if tool.invocation_count() != 0 {
            return Err(Error::other("restart capability read invoked a configured tool").into());
        }
        Ok(())
    }
    .await;

    let mut cleanup_errors = Vec::new();
    if let Some(mut current) = server.take() {
        if let Err(error) = current.stop(&process_forbidden).await {
            cleanup_errors.push(error.to_string());
        }
    }
    if let Err(error) = model.stop().await {
        cleanup_errors.push(error.to_string());
    }
    if let Err(error) = tool.stop().await {
        cleanup_errors.push(error.to_string());
    }
    match sqlite_contains_secret(database.path(), TEST_PROVIDER_SECRET).await {
        Ok(false) => {}
        Ok(true) => cleanup_errors.push("provider credential reached runtime SQLite".to_owned()),
        Err(error) => cleanup_errors.push(error.to_string()),
    }
    if let Some(root) = database.path().parent() {
        if let Err(error) = assert_artifacts_omit(
            root,
            WRONG_CONTROLLER_SECRET,
            "invalid controller credential",
        ) {
            cleanup_errors.push(error.to_string());
        }
    } else {
        cleanup_errors.push("capabilities database had no artifact root".to_owned());
    }
    merge_result(primary, cleanup_errors, "Endpoint capabilities E2E")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_external_callback_capability_is_advertised_when_runtime_ready() -> TestResult<()> {
    let database = TempDatabase::new("endpoint-capabilities-callback-advertised")?;
    let mut tool = ToolFixture::start(Vec::new()).await?;
    let config = write_endpoint_config(
        database.path(),
        vec![configured_external_callback_tool(
            "callback_fixture_tool",
            &tool.adapter_url(),
        )],
        1,
    )?;
    let mut server = TestZode::start(database.path(), &config, &[TEST_CONTROLLER_SECRET]).await?;
    let client = http_client()?;
    let exchange = metadata_probe(
        &client,
        &server.url(""),
        "callback-capabilities.advertised",
        "/v1/capabilities",
        Some(TEST_CONTROLLER_SECRET),
    )
    .await;
    exchange.response.require_complete()?;
    assert_eq!(exchange.response.status(), Some(StatusCode::OK));
    let body: Value = serde_json::from_slice(&exchange.response.body)?;
    let tools = body["tools"]
        .as_array()
        .ok_or_else(|| Error::other("callback capability tools was not an array"))?;
    assert!(tools.iter().any(|tool| {
        tool["name"] == "callback_fixture_tool" && tool["completion_mode"] == "external_callback"
    }));
    let outbound = body["outbound_capabilities"]
        .as_array()
        .ok_or_else(|| Error::other("callback capability outbound list was not an array"))?;
    assert!(outbound
        .iter()
        .any(|capability| capability == "external_callback"));

    server.stop(&[TEST_CONTROLLER_SECRET]).await?;
    tool.stop().await?;
    Ok(())
}

#![allow(dead_code)]

mod support;

use std::{
    env, fs,
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, StatusCode as AxumStatusCode},
    response::Response as AxumResponse,
    routing::post,
    Router,
};

use bytes::Bytes;
use futures_util::StreamExt;
use reqwest::{Client, Response, StatusCode};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::{
    assert_response_headers_secret_free, authenticated, canonical_json, db_blocking,
    install_test_replica, require_ulid, response_json, response_text, sqlite_contains_secret,
    write_endpoint_config, ConfiguredServer, HttpFixture, HttpRequestExt, LlmHttpChunkKind,
    LlmHttpHeader, LlmHttpProxy, LlmHttpRecording, LlmHttpRecordingChunk, LlmHttpRecordingExchange,
    LlmHttpRecordingMetadata, LlmHttpRecordingRequest, LlmHttpRecordingResponse,
    LlmHttpResponseOutcome, ModelFixture, ModelHold, ModelScript, TempDatabase, TestResult,
    ToolFixture, ToolScript, HTTP_INCIDENT_RECORDING_SCHEMA, LLM_HTTP_RECORDING_SCHEMA,
    TEST_PROVIDER_SECRET,
};
use tokio::{sync::Notify, time::timeout};

const TOMBSTONE_PROVIDER_SECRET: &str = "tombstone-provider-secret-runtime-e2e";
const PARTIAL_TOOL_INPUT_INCIDENT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/incidents/model_stop_after_partial_tool_input.incident.json"
);
const TEXT_AND_TOOL_CALL_INCIDENT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/incidents/model_tool_call_preserves_assistant_text.incident.json"
);

#[derive(Clone)]
struct RawProviderResponse {
    chunks: Vec<Bytes>,
    release_before_last: Option<Arc<Notify>>,
}

struct RawProviderState {
    scripts: Mutex<Vec<RawProviderResponse>>,
    requests: Mutex<Vec<Value>>,
    request_seen: Notify,
}

struct RawProviderFixture {
    server: HttpFixture,
    state: Arc<RawProviderState>,
}

impl RawProviderFixture {
    async fn start(scripts: Vec<RawProviderResponse>) -> TestResult<Self> {
        let state = Arc::new(RawProviderState {
            scripts: Mutex::new(scripts),
            requests: Mutex::new(Vec::new()),
            request_seen: Notify::new(),
        });
        let router = Router::new()
            .route("/chat/completions", post(raw_provider_request))
            .route("/v1/chat/completions", post(raw_provider_request))
            .with_state(state.clone());
        let server = HttpFixture::start(router).await?;
        Ok(Self { server, state })
    }

    fn base_url(&self) -> String {
        self.server.url("")
    }

    async fn wait_for_requests(&self, expected: usize) -> TestResult<()> {
        timeout(Duration::from_secs(5), async {
            loop {
                if self
                    .state
                    .requests
                    .lock()
                    .expect("raw provider request mutex poisoned")
                    .len()
                    >= expected
                {
                    return;
                }
                self.state.request_seen.notified().await;
            }
        })
        .await
        .map_err(|_| {
            Error::new(
                ErrorKind::TimedOut,
                "raw provider request barrier timed out",
            )
        })?;
        Ok(())
    }

    async fn stop(&mut self) -> TestResult<()> {
        self.server.stop().await
    }
}

async fn raw_provider_request(
    State(state): State<Arc<RawProviderState>>,
    _headers: HeaderMap,
    body: Bytes,
) -> AxumResponse {
    let request = serde_json::from_slice(&body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()));
    state
        .requests
        .lock()
        .expect("raw provider request mutex poisoned")
        .push(request);
    state.request_seen.notify_waiters();
    let response = {
        let mut scripts = state
            .scripts
            .lock()
            .expect("raw provider script mutex poisoned");
        if scripts.is_empty() {
            RawProviderResponse {
                chunks: final_provider_response("unexpected extra provider request").chunks,
                release_before_last: None,
            }
        } else {
            scripts.remove(0)
        }
    };
    let chunks = response.chunks;
    let release_before_last = response.release_before_last;
    let body = async_stream::stream! {
        let split = chunks.len().saturating_sub(1);
        for chunk in chunks.iter().take(split) {
            yield Ok::<Bytes, std::io::Error>(chunk.clone());
        }
        if let Some(release) = release_before_last {
            release.notified().await;
        }
        for chunk in chunks.iter().skip(split) {
            yield Ok::<Bytes, std::io::Error>(chunk.clone());
        }
    };
    AxumResponse::builder()
        .status(AxumStatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(body))
        .expect("raw provider response builds")
}

fn provider_sse(value: Value) -> Bytes {
    Bytes::from(format!("data: {value}\n\n"))
}

fn provider_done() -> Bytes {
    Bytes::from_static(b"data: [DONE]\n\n")
}

fn final_provider_response(text: &str) -> RawProviderResponse {
    RawProviderResponse {
        chunks: vec![
            provider_sse(json!({
                "choices": [{"delta": {"content": text}, "finish_reason": null}]
            })),
            provider_sse(json!({
                "choices": [{"delta": {}, "finish_reason": "stop"}]
            })),
            provider_done(),
        ],
        release_before_last: None,
    }
}

fn partial_tool_input_stop_response(release: Arc<Notify>) -> RawProviderResponse {
    RawProviderResponse {
        chunks: vec![
            provider_sse(json!({
                "choices": [{"delta": {"tool_calls": [{
                    "index": 0,
                    "id": "partial-stop-call",
                    "type": "function",
                    "function": {"name": "fixture_tool", "arguments": ""}
                }]}, "finish_reason": null}]
            })),
            provider_sse(json!({
                "choices": [{"delta": {"tool_calls": [{
                    "index": 0,
                    "function": {"arguments": "{\"value\":\"par"}
                }]}, "finish_reason": null}]
            })),
            provider_sse(json!({
                "choices": [{"delta": {"tool_calls": [{
                    "index": 0,
                    "function": {"arguments": "tial\"}"}
                }]}, "finish_reason": null}]
            })),
            provider_sse(json!({
                "choices": [{"delta": {}, "finish_reason": "stop"}]
            })),
            provider_done(),
        ],
        release_before_last: Some(release),
    }
}

fn text_and_tool_call_response() -> RawProviderResponse {
    RawProviderResponse {
        chunks: vec![
            provider_sse(json!({
                "choices": [{"delta": {"content": "before tool"}, "finish_reason": null}]
            })),
            provider_sse(json!({
                "choices": [{"delta": {"tool_calls": [{
                    "index": 0,
                    "id": "text-tool-call",
                    "type": "function",
                    "function": {"name": "fixture_tool", "arguments": "{\"value\":\"tool\"}"}
                }]}, "finish_reason": null}]
            })),
            provider_sse(json!({
                "choices": [{"delta": {}, "finish_reason": "tool_calls"}]
            })),
            provider_done(),
        ],
        release_before_last: None,
    }
}

fn first_occurrence_quarantine_path(owner: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::other("system clock preceded the Unix epoch"))?
        .as_nanos();
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-recordings/quarantine")
        .join(format!("{owner}-{}-{nanos}", std::process::id())))
}

fn decode_incident_hex(value: &str) -> TestResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::other("provider incident chunk hex had odd length").into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}

fn encode_incident_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn incident_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn incident_recording(path: &Path, owner: &str) -> TestResult<LlmHttpRecording> {
    let bytes = fs::read(path)?;
    for marker in [TEST_PROVIDER_SECRET, TOMBSTONE_PROVIDER_SECRET] {
        if bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
        {
            return Err(Error::other("tracked provider incident contained a secret marker").into());
        }
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    let root = value
        .as_object()
        .ok_or_else(|| Error::other("provider incident cassette was not an object"))?;
    let mut root_keys = root.keys().map(String::as_str).collect::<Vec<_>>();
    root_keys.sort_unstable();
    let mut expected_root_keys = vec![
        "boundary",
        "canonical_fingerprint",
        "exchanges",
        "first_failure",
        "model",
        "owner",
        "provider",
        "recording_id",
        "schema",
        "slots",
        "version",
        "whole_digest",
    ];
    expected_root_keys.sort_unstable();
    if root_keys != expected_root_keys {
        return Err(
            Error::other("provider incident cassette had unknown or missing fields").into(),
        );
    }
    if value["schema"] != HTTP_INCIDENT_RECORDING_SCHEMA
        || value["owner"] != owner
        || value["boundary"] != "endpoint_model_provider"
        || value["version"] != 1
        || value["provider"] != "fixture-provider"
        || value["model"] != "fixture-model"
    {
        return Err(Error::other("provider incident cassette metadata was invalid").into());
    }
    if value["slots"] != json!(["SLOT_PROVIDER_MODEL_AUTHORIZATION"])
        || value["first_failure"]["status"] != 200
        || value["first_failure"]["boundary"].as_str().is_none()
        || value["first_failure"]["error_code"].as_str().is_none()
    {
        return Err(Error::other("provider incident cassette failure metadata was invalid").into());
    }
    let (recording_id, expected_fingerprints, expected_whole) = match owner {
        "e2e_model_stop_after_partial_tool_input_has_no_assistant_or_tool_effect" => (
            "model-stop-after-partial-tool-input-first-occurrence",
            [
                (
                    "091388c650fa830a673aaeadf5b67481760ce54c8fa42d6ce0d7f223ec2deab7",
                    "1d5ff146224c19e0d87db7ad5ee682f906b121cb494de75ea2f51925ad346951",
                ),
                (
                    "84fb9e627c0a0b16054d21dd06f401caf215bee942f744ba7ccd841652e16f76",
                    "3d2de698ee6894c6788960d59a06cfd566bfec2cd774aa400cf65abe4d50e331",
                ),
            ],
            "sha256:2af0f26b4d8c3cd554b784251bf303e666c6edb1f04512bceb22b733823b3152",
        ),
        "e2e_model_tool_call_preserves_assistant_text" => (
            "model-tool-call-preserves-assistant-text-first-occurrence",
            [
                (
                    "80e98278d0034b1beb69615ffa847bf9dda450e8eaad5c5fcf62900500424cd3",
                    "530e23d5cc5dd00d59e1f88898336b657a282d874f37c59f80831d0a04178003",
                ),
                (
                    "b541bc58309095306dd22e91d9b6355b7166f0f08dff4d6ab0fae4b47fb92c8d",
                    "c0ee1b9c04b7592dc0e13d48798842f2916606d5e2d3dc6098890e47c80c7b8b",
                ),
            ],
            "sha256:716fb40002615fad4c68305f8830ec3f1a205f321d34be96429473fce6969587",
        ),
        _ => return Err(Error::other("provider incident cassette owner was not approved").into()),
    };
    if value["recording_id"] != recording_id
        || value["whole_digest"] != expected_whole
        || value["canonical_fingerprint"]["algorithm"] != "sha256"
    {
        return Err(
            Error::other("provider incident cassette fingerprint envelope was invalid").into(),
        );
    }
    let fingerprint_exchanges = value["canonical_fingerprint"]["exchanges"]
        .as_array()
        .ok_or_else(|| Error::other("provider incident cassette omitted exchange fingerprints"))?;
    if fingerprint_exchanges.len() != expected_fingerprints.len() {
        return Err(
            Error::other("provider incident cassette fingerprint count was invalid").into(),
        );
    }
    for (index, (request, response)) in expected_fingerprints.iter().enumerate() {
        if fingerprint_exchanges[index]["request"] != *request
            || fingerprint_exchanges[index]["response"] != *response
        {
            return Err(
                Error::other("provider incident cassette fingerprints were changed").into(),
            );
        }
    }
    let provider = value["provider"]
        .as_str()
        .ok_or_else(|| Error::other("provider incident omitted provider"))?;
    let model = value["model"]
        .as_str()
        .ok_or_else(|| Error::other("provider incident omitted model"))?;
    let exchanges = value["exchanges"]
        .as_array()
        .ok_or_else(|| Error::other("provider incident omitted exchanges"))?;
    if exchanges.is_empty() {
        return Err(Error::other("provider incident had no exchanges").into());
    }
    if exchanges.len() != expected_fingerprints.len() {
        return Err(Error::other("provider incident cassette exchange count was changed").into());
    }
    let requests = exchanges
        .iter()
        .enumerate()
        .map(|(index, exchange)| {
            let exchange_object = exchange
                .as_object()
                .ok_or_else(|| Error::other("provider incident exchange was not an object"))?;
            let mut exchange_keys = exchange_object
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>();
            exchange_keys.sort_unstable();
            if exchange_keys != ["body", "method", "path", "response"] {
                return Err(Error::other("provider incident exchange had unknown fields").into());
            }
            let response = &exchange["response"];
            let response_object = response
                .as_object()
                .ok_or_else(|| Error::other("provider incident response was not an object"))?;
            let mut response_keys = response_object
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>();
            response_keys.sort_unstable();
            if response_keys
                != [
                    "chunks",
                    "complete",
                    "content_type",
                    "status",
                    "stream_error",
                ]
            {
                return Err(Error::other("provider incident response had unknown fields").into());
            }
            let chunks = response["chunks"]
                .as_array()
                .ok_or_else(|| Error::other("provider incident omitted response chunks"))?
                .iter()
                .map(|chunk| {
                    let chunk_object = chunk
                        .as_object()
                        .ok_or_else(|| Error::other("provider incident chunk was not an object"))?;
                    let mut chunk_keys =
                        chunk_object.keys().map(String::as_str).collect::<Vec<_>>();
                    chunk_keys.sort_unstable();
                    if chunk_keys != ["at_us", "bytes_hex"] {
                        return Err(
                            Error::other("provider incident chunk had unknown fields").into()
                        );
                    }
                    Ok(LlmHttpRecordingChunk {
                        kind: LlmHttpChunkKind::Sse,
                        sequence: 0,
                        at_us: chunk["at_us"]
                            .as_u64()
                            .ok_or_else(|| Error::other("provider incident omitted chunk time"))?,
                        bytes_hex: chunk["bytes_hex"]
                            .as_str()
                            .ok_or_else(|| Error::other("provider incident omitted chunk bytes"))?
                            .to_owned(),
                    })
                })
                .collect::<TestResult<Vec<_>>>()?;
            let method = exchange["method"]
                .as_str()
                .ok_or_else(|| Error::other("provider incident omitted request method"))?;
            let path = exchange["path"]
                .as_str()
                .ok_or_else(|| Error::other("provider incident omitted request path"))?;
            let body = exchange["body"]
                .as_str()
                .ok_or_else(|| Error::other("provider incident omitted request body"))?;
            let raw_body = body.as_bytes();
            let canonical_body = canonical_json(raw_body)?;
            let request_digest =
                incident_digest(format!("{method}\n{path}\n{canonical_body}").as_bytes());
            let mut response_bytes = Vec::new();
            for chunk in &chunks {
                response_bytes.extend(decode_incident_hex(&chunk.bytes_hex)?);
            }
            let response_digest = incident_digest(&response_bytes);
            if request_digest != expected_fingerprints[index].0
                || response_digest != expected_fingerprints[index].1
            {
                return Err(
                    Error::other("provider incident exchange fingerprint did not match").into(),
                );
            }
            let response_status = response["status"]
                .as_u64()
                .ok_or_else(|| Error::other("provider incident omitted response status"))?
                as u16;
            let response_content_type = response["content_type"]
                .as_str()
                .ok_or_else(|| Error::other("provider incident omitted content type"))?
                .to_owned();
            Ok(LlmHttpRecordingExchange {
                sequence: index as u64,
                logical_round: index as u64,
                wire_attempt: 0,
                request: LlmHttpRecordingRequest {
                    method: method.to_owned(),
                    path: path.to_owned(),
                    semantic_headers: vec![
                        LlmHttpHeader {
                            name: "accept".to_owned(),
                            value: "*/*".to_owned(),
                        },
                        LlmHttpHeader {
                            name: "content-type".to_owned(),
                            value: "application/json".to_owned(),
                        },
                    ],
                    raw_body_hex: encode_incident_hex(raw_body),
                    canonical_json: Some(canonical_body.clone()),
                    raw_body_sha256: incident_digest(raw_body),
                    canonical_json_sha256: Some(incident_digest(canonical_body.as_bytes())),
                },
                response: LlmHttpRecordingResponse {
                    status: Some(response_status),
                    content_type: Some(response_content_type.clone()),
                    semantic_headers: vec![LlmHttpHeader {
                        name: "content-type".to_owned(),
                        value: response_content_type,
                    }],
                    chunks: chunks
                        .into_iter()
                        .enumerate()
                        .map(|(sequence, mut chunk)| {
                            chunk.sequence = sequence as u64;
                            chunk
                        })
                        .collect(),
                    outcome: LlmHttpResponseOutcome::Complete { done_seen: true },
                },
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    let mut unsigned = value.clone();
    unsigned["whole_digest"] = Value::String(String::new());
    let whole_digest = format!(
        "sha256:{}",
        incident_digest(&serde_json::to_vec(&unsigned)?)
    );
    if whole_digest != expected_whole || value["whole_digest"] != whole_digest {
        return Err(Error::other("provider incident whole-envelope digest was invalid").into());
    }
    LlmHttpRecording {
        schema: LLM_HTTP_RECORDING_SCHEMA.to_owned(),
        recording_id: recording_id.to_owned(),
        purpose: "replay first observed provider incident".to_owned(),
        owner: owner.to_owned(),
        boundary: "endpoint_model_provider".to_owned(),
        secret_slots: vec!["SLOT_PROVIDER_MODEL_AUTHORIZATION".to_owned()],
        provider: provider.to_owned(),
        model: model.to_owned(),
        requests,
        envelope_sha256: String::new(),
    }
    .with_digest()
}

struct ModelNetworkFixture {
    proxy: LlmHttpProxy,
    upstream: Option<RawProviderFixture>,
    release: Option<Arc<Notify>>,
    capture: bool,
}

impl ModelNetworkFixture {
    async fn start(
        owner: &str,
        cassette: &Path,
        scripts: Vec<RawProviderResponse>,
        captured_timing: bool,
    ) -> TestResult<Self> {
        let capture = env::var_os("ZODE_CAPTURE_FIRST_OCCURRENCE").is_some();
        if capture {
            let release = scripts
                .first()
                .and_then(|script| script.release_before_last.clone());
            let upstream = RawProviderFixture::start(scripts).await?;
            let quarantine = first_occurrence_quarantine_path(owner)?;
            let metadata = LlmHttpRecordingMetadata {
                recording_id: format!("{owner}-first-occurrence"),
                purpose: "replay first observed provider incident".to_owned(),
                owner: owner.to_owned(),
                boundary: "endpoint_model_provider".to_owned(),
                secret_slots: vec!["SLOT_PROVIDER_MODEL_AUTHORIZATION".to_owned()],
            };
            let proxy = LlmHttpProxy::record(
                upstream.base_url(),
                "fixture-provider",
                "fixture-model",
                quarantine,
                metadata,
            )
            .await?;
            Ok(Self {
                proxy,
                upstream: Some(upstream),
                release,
                capture,
            })
        } else {
            let recording = incident_recording(cassette, owner)?;
            let proxy = LlmHttpProxy::replay_with_authorization(
                recording,
                captured_timing,
                Some(TEST_PROVIDER_SECRET.to_owned()),
            )
            .await?;
            Ok(Self {
                proxy,
                upstream: None,
                release: None,
                capture,
            })
        }
    }

    fn provider_url(&self) -> String {
        self.proxy.base_url("/v1")
    }

    async fn wait_for_requests(&self, expected: usize) -> TestResult<()> {
        timeout(Duration::from_secs(10), async {
            loop {
                if self.proxy.observed_requests().len() >= expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| {
            Error::new(
                ErrorKind::TimedOut,
                "recording proxy request barrier timed out",
            )
        })?;
        Ok(())
    }

    async fn wait_for_recordings(&self, expected: usize) -> TestResult<()> {
        if !self.capture {
            return Ok(());
        }
        timeout(Duration::from_secs(10), async {
            loop {
                if let Some(error) = self.proxy.flush_error() {
                    return Err(Error::other(format!(
                        "provider recorder flush failed: {error}"
                    )));
                }
                let recorded = self.proxy.recording().map_err(|error| {
                    Error::other(format!("provider recorder read failed: {error}"))
                })?;
                if recorded.requests.len() >= expected {
                    return Ok(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| {
            Error::new(
                ErrorKind::TimedOut,
                "provider recorder flush barrier timed out",
            )
        })??;
        Ok(())
    }

    fn release(&self) -> TestResult<()> {
        let release = self
            .release
            .as_ref()
            .ok_or_else(|| Error::other("provider response had no release barrier"))?;
        release.notify_one();
        Ok(())
    }

    fn assert_replay_exhausted(&self) -> TestResult<()> {
        if !self.capture && !self.proxy.replay_exhausted() {
            return Err(
                Error::other("provider cassette replay left an unconsumed exchange").into(),
            );
        }
        Ok(())
    }

    async fn stop(&mut self) -> TestResult<()> {
        self.proxy.stop().await?;
        if let Some(upstream) = &mut self.upstream {
            upstream.stop().await?;
        }
        Ok(())
    }
}

struct SseFrames {
    stream: futures_util::stream::BoxStream<'static, Result<Bytes, reqwest::Error>>,
    buffer: Vec<u8>,
}

#[derive(Debug)]
struct SseFrame {
    id: String,
    event: String,
    data: Value,
}

impl SseFrames {
    fn new(response: Response) -> Self {
        Self {
            stream: response.bytes_stream().boxed(),
            buffer: Vec::new(),
        }
    }

    async fn next(&mut self) -> TestResult<SseFrame> {
        self.next_with_secret_markers(&[]).await
    }

    async fn next_secret_free(&mut self, markers: &[&str]) -> TestResult<SseFrame> {
        self.next_with_secret_markers(markers).await
    }

    async fn next_with_secret_markers(&mut self, markers: &[&str]) -> TestResult<SseFrame> {
        loop {
            if let Some(end) = self.buffer.windows(2).position(|window| window == b"\n\n") {
                let frame = self.buffer.drain(..end + 2).collect::<Vec<_>>();
                assert_bytes_secret_free(&frame, markers);
                if let Some(parsed) = parse_sse_frame(&frame)? {
                    return Ok(parsed);
                }
            }
            let chunk = timeout(Duration::from_secs(10), self.stream.next())
                .await?
                .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "SSE ended early"))??;
            self.buffer.extend_from_slice(&chunk);
        }
    }
}

fn assert_bytes_secret_free(bytes: &[u8], markers: &[&str]) {
    for marker in markers {
        let marker = marker.as_bytes();
        assert!(
            !marker.is_empty() && !bytes.windows(marker.len()).any(|window| window == marker),
            "public SSE frame contained a secret marker"
        );
    }
}

fn parse_sse_frame(frame: &[u8]) -> TestResult<Option<SseFrame>> {
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
            data = Some(serde_json::from_str(value)?);
        }
    }
    Ok(match (id, event, data) {
        (Some(id), Some(event), Some(data)) => Some(SseFrame { id, event, data }),
        _ => None,
    })
}

async fn next_event_with_kind(frames: &mut SseFrames, wanted: &str) -> TestResult<SseFrame> {
    for _ in 0..128 {
        let frame = frames.next().await.map_err(|error| {
            Error::other(format!(
                "expected durable event {wanted:?} was not observed: {error}"
            ))
        })?;
        if frame.event == wanted || frame.data["kind"] == wanted {
            return Ok(frame);
        }
    }
    Err(Error::new(
        ErrorKind::NotFound,
        "expected durable event was not observed",
    )
    .into())
}

async fn next_assistant_with_content(
    frames: &mut SseFrames,
    expected_content: &str,
) -> TestResult<SseFrame> {
    for _ in 0..128 {
        let frame = next_event_with_kind(frames, "assistant_message_committed").await?;
        if frame.data["data"]["message"]["content"] == expected_content {
            return Ok(frame);
        }
    }
    Err(Error::other("expected durable assistant content was not observed").into())
}

async fn next_assistant_with_failure(
    frames: &mut SseFrames,
    expected_content: &str,
) -> TestResult<(SseFrame, bool)> {
    let mut failure_seen = false;
    for _ in 0..128 {
        let frame = frames
            .next_secret_free(&[TEST_PROVIDER_SECRET, TOMBSTONE_PROVIDER_SECRET])
            .await?;
        if frame.event == "model_attempt_failed" || frame.data["kind"] == "model_attempt_failed" {
            let error = &frame.data["data"]["error"];
            assert!(
                error["class"].as_str().is_some(),
                "provider failure event omitted its typed error class"
            );
            failure_seen = true;
        }
        if (frame.event == "assistant_message_committed"
            || frame.data["kind"] == "assistant_message_committed")
            && frame.data["data"]["message"]["content"] == expected_content
        {
            return Ok((frame, failure_seen));
        }
    }
    Err(Error::other("recovery assistant was not observed after provider failure").into())
}

async fn next_auth_replica_unavailable(
    frames: &mut SseFrames,
    session_id: &str,
) -> TestResult<SseFrame> {
    for _ in 0..128 {
        let frame = frames
            .next_secret_free(&[TOMBSTONE_PROVIDER_SECRET])
            .await?;
        if frame.event == "model_attempt_failed" || frame.data["kind"] == "model_attempt_failed" {
            assert_eq!(frame.data["session_id"], session_id);
            assert_eq!(
                frame.data["data"]["error"]["class"], "auth_replica_unavailable",
                "model attempt failure had the wrong public auth error"
            );
            return Ok(frame);
        }
    }
    Err(Error::new(
        ErrorKind::NotFound,
        "durable auth_replica_unavailable model terminal was not observed",
    )
    .into())
}

fn config_file(
    database: &std::path::Path,
    model_url: &str,
    tool_url: Option<&str>,
    max_attempts: u64,
) -> TestResult<std::path::PathBuf> {
    let mut tools = Vec::new();
    if let Some(tool_url) = tool_url {
        tools.push(json!({
            "name": "fixture_tool",
            "description": "controlled HTTP tool",
            "input_schema": {"type": "object"},
            "completion_mode": "response",
            "auto_wait_timeout_seconds": 20,
            "recovery": {
                "on_running_restart": "unknown_outcome",
                "retry_dispatch": "never"
            },
            "adapter": {"kind": "http", "url": tool_url}
        }));
    }
    let path = write_endpoint_config(database, tools, max_attempts)?;
    let provider_url = url::Url::parse(model_url)
        .map_err(|error| Error::other(format!("invalid model fixture URL: {error}")))?;
    let provider_origin = provider_url.origin().ascii_serialization();
    let mut config: Value = serde_json::from_slice(&fs::read(&path)?)?;
    config["provider_execution"]["allowed_base_url_origins"] = json!([provider_origin]);
    fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    Ok(path)
}

fn model_selection(provider_url: &str, schema: &str, revision: u64) -> Value {
    json!({
        "provider": "fixture-provider",
        "provider_execution": {
            "schema": schema,
            "revision": revision,
            "kind": "openai_compatible",
            "base_url": provider_url
        },
        "model": "fixture-model",
        "auth_authority_id": "controller-e2e",
        "auth_profile_id": "profile-e2e",
        "minimum_auth_revision": 1
    })
}

fn assert_text_secret_free(text: &str) {
    assert!(
        !text.contains(TOMBSTONE_PROVIDER_SECRET),
        "public response contained a secret marker"
    );
}

async fn response_text_secret_free(response: Response) -> TestResult<String> {
    assert_response_headers_secret_free(&response, &[TOMBSTONE_PROVIDER_SECRET]);
    let body = response_text(response).await?;
    assert_text_secret_free(&body);
    Ok(body)
}

async fn put_runtime_replica(
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
    let response = authenticated(client.put(server.url("/v1/auth-replicas/profile-e2e")))
        .header("Idempotency-Key", key)
        .json(&body)
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_text_secret_free(response).await?;
    Ok((status, body))
}

async fn create_session(
    client: &Client,
    server: &ConfiguredServer,
    provider_url: &str,
    idempotency_key: &str,
) -> TestResult<String> {
    install_test_replica(
        client,
        &server.url(""),
        &format!("install-{idempotency_key}"),
    )
    .await?;
    let response = authenticated(client.post(server.url("/v1/sessions")))
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
                "auth_authority_id": "controller-e2e",
                "auth_profile_id": "profile-e2e",
                "minimum_auth_revision": 1
            },
            "tools": ["fixture_tool"]
        }))
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_json(response).await?;
    if status != StatusCode::CREATED {
        return Err(Error::other(format!(
            "session creation did not return 201: {status} {body}"
        ))
        .into());
    }
    require_ulid(&body)
}

async fn post_message(
    client: &Client,
    server: &ConfiguredServer,
    session_id: &str,
    key: &str,
    content: &str,
) -> TestResult<Value> {
    let response =
        authenticated(client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))))
            .header("Idempotency-Key", key)
            .json(&json!({"content": content}))
            .send_with_timeout()
            .await?;
    let status = response.status();
    assert_response_headers_secret_free(&response, &[TOMBSTONE_PROVIDER_SECRET]);
    let body = response_json(response).await?;
    assert_text_secret_free(&body.to_string());
    if status != StatusCode::ACCEPTED {
        return Err(Error::other(format!(
            "message admission did not return 202: {status} {body}"
        ))
        .into());
    }
    Ok(body)
}

async fn get_session(client: &Client, server: &ConfiguredServer, id: &str) -> TestResult<Value> {
    let response = authenticated(client.get(server.url(&format!("/v1/sessions/{id}"))))
        .send_with_timeout()
        .await?;
    let status = response.status();
    assert_response_headers_secret_free(&response, &[TOMBSTONE_PROVIDER_SECRET]);
    let body = response_json(response).await?;
    assert_text_secret_free(&body.to_string());
    if status != StatusCode::OK {
        return Err(Error::other(format!("session read failed: {status} {body}")).into());
    }
    Ok(body)
}

async fn open_events(
    client: &Client,
    server: &ConfiguredServer,
    session_id: &str,
) -> TestResult<SseFrames> {
    open_events_with_cursor(client, server, session_id, None).await
}

async fn open_events_with_cursor(
    client: &Client,
    server: &ConfiguredServer,
    session_id: &str,
    last_event_id: Option<&str>,
) -> TestResult<SseFrames> {
    let request =
        authenticated(client.get(server.url(&format!("/v1/sessions/{session_id}/events"))));
    let request = if let Some(last_event_id) = last_event_id {
        request.header("Last-Event-ID", last_event_id)
    } else {
        request
    };
    let response = request.send_with_timeout().await?;
    assert_response_headers_secret_free(&response, &[TOMBSTONE_PROVIDER_SECRET]);
    if response.status() != StatusCode::OK {
        let status = response.status();
        let body = response_text_secret_free(response).await?;
        return Err(Error::other(format!("event stream did not open: {status} {body}")).into());
    }
    Ok(SseFrames::new(response))
}

async fn create_with_model_body(
    client: &Client,
    server: &ConfiguredServer,
    key: &str,
    model: Value,
) -> TestResult<(StatusCode, String)> {
    let response = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", key)
        .json(&json!({"model": model}))
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_text_secret_free(response).await?;
    Ok((status, body))
}

async fn list_sessions(
    client: &Client,
    server: &ConfiguredServer,
) -> TestResult<(StatusCode, String)> {
    let response = authenticated(client.get(server.url("/v1/sessions?limit=100")))
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_text(response).await?;
    Ok((status, body))
}

fn assert_no_model_effect(state: &Value, label: &str) -> TestResult<()> {
    let transcript = state["transcript"]
        .as_array()
        .ok_or_else(|| Error::other(format!("{label} omitted transcript")))?;
    assert!(
        transcript
            .iter()
            .all(|message| message["role"].as_str() != Some("assistant")),
        "{label} committed an assistant effect"
    );
    let tool_calls = state["tool_calls"]
        .as_array()
        .ok_or_else(|| Error::other(format!("{label} omitted tool_calls")))?;
    assert!(tool_calls.is_empty(), "{label} committed a tool effect");
    Ok(())
}

async fn latest_compatible_snapshot_state(
    path: &std::path::Path,
    session_id: &str,
    head_version: u64,
) -> TestResult<Option<(u64, Value)>> {
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
            let Ok(stream_version) = u64::try_from(stream_version) else {
                continue;
            };
            if stream_id != session_id
                || stream_version > head_version
                || state_schema_version != 1
                || reducer_schema_version != 1
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
            if state["session_id"] == session_id && state["stream_version"] == stream_version {
                let required_fields = [
                    "session_id",
                    "owner",
                    "created_at_ms",
                    "selection",
                    "status",
                    "transcript",
                    "delivery_queue",
                    "delivery_ack",
                    "active_wait",
                    "async_tool_calls",
                    "stream_version",
                    "dedupe_facts",
                ];
                if required_fields
                    .iter()
                    .any(|field| state.get(*field).is_none())
                {
                    continue;
                }
                return Ok(Some((stream_version, state)));
            }
        }
        Ok(None)
    })
    .await
}

fn wire_dialogue(request: &Value) -> TestResult<Vec<(String, String)>> {
    let messages = request["messages"]
        .as_array()
        .ok_or_else(|| Error::other("provider request omitted messages"))?;
    messages
        .iter()
        .filter(|message| matches!(message["role"].as_str(), Some("user" | "assistant")))
        .map(|message| {
            let role = message["role"]
                .as_str()
                .ok_or_else(|| Error::other("provider message omitted role"))?
                .to_owned();
            let content = match &message["content"] {
                Value::String(content) => content.clone(),
                content => content.to_string(),
            };
            Ok((role, content))
        })
        .collect()
}

fn normalize_public_transcript(state: &Value, label: &str) -> TestResult<Vec<Value>> {
    let transcript = state["transcript"]
        .as_array()
        .ok_or_else(|| Error::other(format!("{label} omitted transcript")))?;
    transcript
        .iter()
        .map(|message| {
            let message_id = message["message_id"]
                .as_str()
                .ok_or_else(|| Error::other(format!("{label} omitted message_id")))?;
            let role = message["role"]
                .as_str()
                .ok_or_else(|| Error::other(format!("{label} omitted role")))?;
            let content = message["content"]
                .as_str()
                .ok_or_else(|| Error::other(format!("{label} omitted content")))?;
            let tool_call_id = message.get("tool_call_id").cloned().unwrap_or(Value::Null);
            if !tool_call_id.is_null() && tool_call_id.as_str().is_none() {
                return Err(Error::other(format!("{label} had a non-string tool_call_id")).into());
            }
            let tool_calls = message["tool_calls"]
                .as_array()
                .ok_or_else(|| Error::other(format!("{label} omitted tool_calls")))?
                .iter()
                .map(|call| {
                    let tool_call_id = call["tool_call_id"]
                        .as_str()
                        .ok_or_else(|| Error::other(format!("{label} omitted tool call id")))?;
                    let tool_name = call["tool_name"]
                        .as_str()
                        .ok_or_else(|| Error::other(format!("{label} omitted tool name")))?;
                    Ok(json!({
                        "tool_call_id": tool_call_id,
                        "tool_name": tool_name,
                    }))
                })
                .collect::<TestResult<Vec<_>>>()?;
            Ok(json!({
                "message_id": message_id,
                "role": role,
                "content": content,
                "tool_call_id": tool_call_id,
                "tool_calls": tool_calls,
            }))
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_runtime_commits_honor_snapshot_cadence_and_restart() -> TestResult<()> {
    let database = TempDatabase::new("runtime-snapshot-cadence")?;
    let mut model =
        ModelFixture::start(vec![ModelScript::final_text("snapshot cadence assistant")]).await?;
    let config = config_file(&database, &model.provider_url(), None, 1)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    install_test_replica(&client, &server.url(""), "install-snapshot-cadence").await?;
    let (create_status, create_body) = create_with_model_body(
        &client,
        &server,
        "create-snapshot-cadence",
        model_selection(&model.provider_url(), "zode.provider-execution.v1", 1),
    )
    .await?;
    assert_eq!(create_status, StatusCode::CREATED, "{create_body}");
    let create_metadata: Value = serde_json::from_str(&create_body)?;
    let session_id = require_ulid(&create_metadata)?;
    let mut events = open_events(&client, &server, &session_id).await?;
    let accepted = post_message(
        &client,
        &server,
        &session_id,
        "snapshot-cadence-message",
        "snapshot cadence user",
    )
    .await?;
    assert_eq!(
        accepted["version"], 2,
        "the known create/queue commit shape changed"
    );
    model.wait_for_requests(1).await?;
    let assistant_event = next_event_with_kind(&mut events, "assistant_message_committed")
        .await
        .map_err(|error| {
            Error::other(format!(
                "snapshot cadence assistant was not durable: {error}"
            ))
        })?;
    assert!(
        assistant_event
            .data
            .to_string()
            .contains("snapshot cadence assistant"),
        "assistant event did not contain the fixture response"
    );
    let assistant_version = assistant_event.data["version"]
        .as_u64()
        .ok_or_else(|| Error::other("assistant event omitted its durable version"))?;
    let final_state = get_session(&client, &server, &session_id).await?;
    let final_version = final_state["version"]
        .as_u64()
        .ok_or_else(|| Error::other("snapshot cadence GET omitted version"))?;
    assert_eq!(
        assistant_version, final_version,
        "assistant publication did not reach the terminal public version: assistant={assistant_version}, final={final_version}, state={final_state}"
    );
    let transcript = final_state["transcript"]
        .as_array()
        .ok_or_else(|| Error::other("snapshot cadence GET omitted transcript"))?;
    let transcript_sequence = transcript
        .iter()
        .map(|message| Some((message["role"].as_str()?, message["content"].as_str()?)))
        .collect::<Option<Vec<_>>>();
    assert_eq!(
        transcript_sequence,
        Some(vec![
            ("user", "snapshot cadence user"),
            ("assistant", "snapshot cadence assistant"),
        ]),
        "snapshot cadence GET did not expose the complete transcript"
    );

    server.stop().await?;
    let (snapshot_version, snapshot_state) =
        latest_compatible_snapshot_state(database.path(), &session_id, final_version)
            .await?
            .ok_or_else(|| {
                Error::other("snapshot cadence produced no compatible persisted snapshot")
            })?;
    assert_eq!(
        snapshot_version, final_version,
        "runtime commits outran snapshot cadence: final version {final_version}, latest compatible snapshot {snapshot_version}"
    );
    assert_eq!(snapshot_state["session_id"], final_state["session_id"]);
    assert_eq!(snapshot_state["stream_version"], final_state["version"]);
    assert_eq!(
        normalize_public_transcript(&snapshot_state, "snapshot payload")?,
        normalize_public_transcript(&final_state, "public final state")?,
        "snapshot transcript differed after normalizing to public message semantics"
    );
    assert_eq!(snapshot_state["status"], final_state["status"]);
    assert_eq!(
        snapshot_state["selection"]["model"]["provider"],
        final_state["model"]["provider"]
    );
    assert_eq!(
        snapshot_state["selection"]["model"]["provider_execution"]["schema"],
        final_state["model"]["provider_execution_schema"]
    );
    assert_eq!(
        snapshot_state["selection"]["model"]["provider_execution"]["revision"],
        final_state["model"]["provider_execution_revision"]
    );
    assert_eq!(
        snapshot_state["selection"]["model"]["provider_execution"]["kind"],
        final_state["model"]["provider_execution_kind"]
    );
    assert_eq!(
        snapshot_state["selection"]["model"]["provider_execution"]["base_url"],
        final_state["model"]["provider_execution_base_url"]
    );
    assert_eq!(
        snapshot_state["selection"]["model"]["model"],
        final_state["model"]["model"]
    );
    assert_eq!(
        snapshot_state["selection"]["model"]["auth_authority_id"],
        final_state["model"]["auth_authority_id"]
    );
    assert_eq!(
        snapshot_state["selection"]["model"]["auth_profile_id"],
        final_state["model"]["auth_profile_id"]
    );
    assert_eq!(
        snapshot_state["selection"]["model"]["auth_revision"],
        final_state["model"]["auth_revision"]
    );
    assert_eq!(
        snapshot_state["delivery_ack"],
        final_state["delivery"]["acknowledged_through"]
    );
    assert!(
        snapshot_state["delivery_queue"]
            .as_array()
            .is_some_and(|items| items.is_empty()),
        "snapshot payload retained an unexpected pending delivery"
    );
    assert!(
        snapshot_state["async_tool_calls"]
            .as_object()
            .is_some_and(|calls| calls.is_empty()),
        "snapshot payload retained an unexpected async tool call"
    );
    assert!(
        final_state["tool_calls"]
            .as_array()
            .is_some_and(|calls| calls.is_empty()),
        "public final state retained an unexpected tool call"
    );

    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let restarted_state = get_session(&client, &restarted, &session_id).await?;
    assert_eq!(restarted_state["version"], final_state["version"]);
    assert_eq!(restarted_state["transcript"], final_state["transcript"]);
    let mut replay = open_events(&client, &restarted, &session_id).await?;
    let replayed_assistant =
        next_event_with_kind(&mut replay, "assistant_message_committed").await?;
    assert!(replayed_assistant
        .data
        .to_string()
        .contains("snapshot cadence assistant"));
    restarted.stop().await?;
    model.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_golden_assembled_model_tool_loop_survives_restart() -> TestResult<()> {
    let database = TempDatabase::new("runtime-golden")?;
    let mut model = ModelFixture::start(vec![
        ModelScript::tool_call("call-golden", "fixture_tool", r#"{"value":"one"}"#),
        ModelScript::final_text("assembled final"),
        ModelScript::final_text("follow-up final"),
    ])
    .await?;
    let mut tool = ToolFixture::start(vec![ToolScript::Response(json!({
        "status": "completed",
        "result": {"content": "tool side effect accepted"}
    }))])
    .await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        2,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id =
        create_session(&client, &server, &model.provider_url(), "create-golden").await?;
    let mut events = open_events(&client, &server, &session_id).await?;
    post_message(
        &client,
        &server,
        &session_id,
        "golden-message-1",
        "first user message",
    )
    .await?;
    tool.wait_for_invocations(1).await?;
    let first_headers = model
        .request_headers(0)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "first provider headers missing"))?;
    assert_eq!(
        first_headers["authorization"],
        format!("Bearer {TEST_PROVIDER_SECRET}")
    );
    let final_event = next_event_with_kind(&mut events, "assistant_message_committed").await?;
    assert!(!final_event.data.to_string().contains(TEST_PROVIDER_SECRET));
    assert_eq!(final_event.data["session_id"], session_id);
    let before_restart = get_session(&client, &server, &session_id).await?;
    assert!(before_restart.to_string().contains("assembled final"));
    assert!(!before_restart.to_string().contains(TEST_PROVIDER_SECRET));
    assert_eq!(tool.invocation_count(), 1);

    server.stop().await?;
    assert!(!sqlite_contains_secret(database.path(), TEST_PROVIDER_SECRET).await?);
    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let mut restarted_events = open_events(&client, &restarted, &session_id).await?;
    post_message(
        &client,
        &restarted,
        &session_id,
        "golden-message-2",
        "follow-up after restart",
    )
    .await?;
    model.wait_for_requests(3).await?;
    let follow_up_wire = model
        .request(2)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "follow-up model request missing"))?;
    assert!(follow_up_wire.to_string().contains("first user message"));
    let follow_up_event = next_assistant_with_content(&mut restarted_events, "follow-up final")
        .await
        .map_err(|error| Error::other(format!("follow-up assistant was not durable: {error}")))?;
    assert_eq!(follow_up_event.data["session_id"], session_id);
    assert_eq!(
        tool.invocation_count(),
        1,
        "restart duplicated the tool effect"
    );
    let after_restart = get_session(&client, &restarted, &session_id).await?;
    assert!(after_restart.to_string().contains("follow-up final"));
    assert!(!after_restart.to_string().contains(TEST_PROVIDER_SECRET));
    restarted.stop().await?;
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_round_boundary_steering_waits_for_the_next_model_round() -> TestResult<()> {
    let database = TempDatabase::new("runtime-steering")?;
    let release = Arc::new(Notify::new());
    let mut model = ModelFixture::start(vec![
        ModelScript::hold(
            release.clone(),
            ModelScript::tool_call("call-steering", "fixture_tool", r#"{"value":"x"}"#),
        ),
        ModelScript::final_text("steered final"),
    ])
    .await?;
    let mut tool = ToolFixture::start(vec![ToolScript::Response(json!({
        "status": "completed",
        "result": {"content": "done"}
    }))])
    .await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        2,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id =
        create_session(&client, &server, &model.provider_url(), "create-steering").await?;
    post_message(&client, &server, &session_id, "steering-a", "message A").await?;
    model.wait_for_requests(1).await?;
    let first_wire = model
        .request(0)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "first model request missing"))?;
    assert!(!first_wire.to_string().contains("message B"));
    post_message(&client, &server, &session_id, "steering-b", "message B").await?;
    assert_eq!(
        model.request_count(),
        1,
        "same-session activations overlapped"
    );
    release.notify_waiters();
    tool.wait_for_invocations(1).await?;
    model.wait_for_requests(2).await?;
    let second_wire = model
        .request(1)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "second model request missing"))?;
    assert!(second_wire.to_string().contains("message B"));
    server.stop().await?;
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_round_boundary_final_defers_steering_to_next_activation() -> TestResult<()> {
    let database = TempDatabase::new("runtime-final-boundary")?;
    let release = Arc::new(Notify::new());
    let mut model = ModelFixture::start(vec![
        ModelScript::hold(release.clone(), ModelScript::final_text("A finished")),
        ModelScript::final_text("B finished later"),
    ])
    .await?;
    let mut tool = ToolFixture::start(Vec::new()).await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        2,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        "create-final-boundary",
    )
    .await?;
    post_message(&client, &server, &session_id, "final-a", "message A").await?;
    model.wait_for_requests(1).await?;
    post_message(&client, &server, &session_id, "final-b", "message B").await?;
    assert_eq!(
        model.request_count(),
        1,
        "a second round started before A finished"
    );
    release.notify_waiters();
    model.wait_for_requests(2).await?;
    let second_wire = model
        .request(1)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "deferred model request missing"))?;
    assert!(second_wire.to_string().contains("message B"));
    server.stop().await?;
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_concurrent_inputs_preserve_both_assistant_rounds() -> TestResult<()> {
    let database = TempDatabase::new("runtime-concurrent-inputs")?;
    let release = Arc::new(Notify::new());
    let mut model = ModelFixture::start(vec![
        ModelScript::hold(release.clone(), ModelScript::final_text("assistant A")),
        ModelScript::final_text("assistant B"),
    ])
    .await?;
    let mut tool = ToolFixture::start(Vec::new()).await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        2,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        "create-concurrent-inputs",
    )
    .await?;
    let mut events = open_events(&client, &server, &session_id).await?;

    post_message(
        &client,
        &server,
        &session_id,
        "concurrent-input-a",
        "input A",
    )
    .await?;
    model.wait_for_requests(1).await?;
    post_message(
        &client,
        &server,
        &session_id,
        "concurrent-input-b",
        "input B",
    )
    .await?;
    assert_eq!(
        model.request_count(),
        1,
        "input B started an overlapping round"
    );

    release.notify_waiters();
    model.wait_for_requests(2).await?;
    let first_assistant = next_event_with_kind(&mut events, "assistant_message_committed")
        .await
        .map_err(|error| Error::other(format!("first assistant round was lost: {error}")))?;
    let second_assistant = next_event_with_kind(&mut events, "assistant_message_committed")
        .await
        .map_err(|error| Error::other(format!("second assistant round was missing: {error}")))?;
    assert!(
        first_assistant.data.to_string().contains("assistant A"),
        "first durable assistant did not contain assistant A"
    );
    assert!(
        second_assistant.data.to_string().contains("assistant B"),
        "second durable assistant did not contain assistant B"
    );
    assert!(
        first_assistant.id.parse::<u64>()? < second_assistant.id.parse::<u64>()?,
        "assistant events were not durably ordered"
    );

    let second_wire = model
        .request(1)
        .ok_or_else(|| Error::other("second provider wire request was missing"))?;
    let second_wire = second_wire.to_string();
    let input_a = second_wire
        .find("input A")
        .ok_or_else(|| Error::other("second provider wire omitted input A"))?;
    let assistant_a = second_wire
        .find("assistant A")
        .ok_or_else(|| Error::other("second provider wire omitted assistant A"))?;
    let input_b = second_wire
        .find("input B")
        .ok_or_else(|| Error::other("second provider wire omitted input B"))?;
    assert!(
        input_a < assistant_a && assistant_a < input_b,
        "second provider wire did not order input A, assistant A, input B"
    );

    let state = get_session(&client, &server, &session_id).await?;
    let transcript = state["transcript"]
        .as_array()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "transcript was missing"))?;
    let transcript_sequence = transcript
        .iter()
        .map(|message| Some((message["role"].as_str()?, message["content"].as_str()?)))
        .collect::<Option<Vec<_>>>();
    assert_eq!(
        transcript_sequence,
        Some(vec![
            ("user", "input A"),
            ("assistant", "assistant A"),
            ("user", "input B"),
            ("assistant", "assistant B"),
        ]),
        "transcript did not preserve the complete input/assistant order"
    );

    server.stop().await?;
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_get_rehydrates_while_model_request_is_held() -> TestResult<()> {
    let database = TempDatabase::new("runtime-get-nonblocking")?;
    let release = Arc::new(Notify::new());
    let mut model = ModelFixture::start(vec![ModelScript::hold(
        release.clone(),
        ModelScript::final_text("held final"),
    )])
    .await?;
    let mut tool = ToolFixture::start(Vec::new()).await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        1,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        "create-get-nonblocking",
    )
    .await?;
    let accepted = post_message(
        &client,
        &server,
        &session_id,
        "get-nonblocking-message",
        "durable before model completion",
    )
    .await?;
    let accepted_version = accepted["version"]
        .as_u64()
        .ok_or_else(|| Error::other("message acceptance omitted version"))?;
    model.wait_for_requests(1).await?;

    let observed = timeout(
        Duration::from_secs(1),
        get_session(&client, &server, &session_id),
    )
    .await;
    release.notify_waiters();
    let cleanup = async {
        server.stop().await?;
        model.stop().await?;
        tool.stop().await?;
        TestResult::Ok(())
    };
    cleanup.await?;

    match observed {
        Ok(Ok(state)) => {
            let version = state["version"]
                .as_u64()
                .ok_or_else(|| Error::other("GET projection omitted version"))?;
            assert!(
                version >= accepted_version,
                "GET version {version} was behind accepted message version {accepted_version}"
            );
            let content = "durable before model completion";
            let transcript_contains = state["transcript"]
                .as_array()
                .map(|messages| {
                    messages
                        .iter()
                        .any(|message| message["content"].as_str() == Some(content))
                })
                .unwrap_or(false);
            let pending_contains = state["delivery"]["pending"].to_string().contains(content);
            assert!(
                transcript_contains || pending_contains,
                "GET durable projection did not expose the accepted input: {state}"
            );
            Ok(())
        }
        Ok(Err(error)) => Err(error),
        Err(_) => {
            Err(Error::other("public GET timed out while the provider request was held").into())
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_credential_bearing_model_base_url_is_rejected_without_side_effects() -> TestResult<()>
{
    let database = TempDatabase::new("runtime-credential-bearing-base-url")?;
    let marker = "SECRET_MARKER_MODEL_BASE_URL_QUERY";
    let mut model = ModelFixture::start(Vec::new()).await?;
    let config = config_file(&database, &model.provider_url(), None, 1)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    install_test_replica(
        &client,
        &server.url(""),
        "install-credential-bearing-base-url",
    )
    .await?;
    let before_list = list_sessions(&client, &server).await?;
    let invalid_model = model_selection(
        &format!("{}?api_key={marker}", model.provider_url()),
        "zode.provider-execution.v1",
        1,
    );
    let (status, body) = create_with_model_body(
        &client,
        &server,
        "credential-bearing-base-url",
        invalid_model,
    )
    .await?;
    let response_marker = body.contains(marker);
    let mut session_id = None;
    let mut get_marker = false;
    let mut sse_marker = false;
    if status == StatusCode::CREATED {
        if let Ok(value) = serde_json::from_str::<Value>(&body) {
            session_id = value["session_id"].as_str().map(str::to_owned);
        }
    }
    if let Some(session_id) = &session_id {
        let get_response =
            authenticated(client.get(server.url(&format!("/v1/sessions/{session_id}"))))
                .send_with_timeout()
                .await?;
        let get_body = response_text(get_response).await?;
        get_marker = get_body.contains(marker);

        let sse_response = authenticated(
            client
                .get(server.url(&format!("/v1/sessions/{session_id}/events")))
                .header("Last-Event-ID", "0"),
        )
        .send_with_timeout()
        .await?;
        if sse_response.status() == StatusCode::OK {
            let mut frames = SseFrames::new(sse_response);
            if let Ok(Ok(frame)) = timeout(Duration::from_secs(2), frames.next()).await {
                sse_marker = frame.data.to_string().contains(marker);
            }
        } else {
            sse_marker = response_text(sse_response).await?.contains(marker);
        }
    }
    let after_list = list_sessions(&client, &server).await?;
    let provider_requests = model.request_count();
    server.stop().await?;
    model.stop().await?;
    let sqlite_marker = sqlite_contains_secret(database.path(), marker).await?;

    if response_marker || get_marker || sse_marker || sqlite_marker {
        return Err(Error::other(format!(
            "credential-bearing base_url marker leaked: response={response_marker}, GET={get_marker}, SSE={sse_marker}, SQLite={sqlite_marker}"
        ))
        .into());
    }
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let error: Value = serde_json::from_str(&body)?;
    assert_eq!(error["error"]["code"], "invalid_request");
    assert_eq!(before_list, after_list);
    assert_eq!(provider_requests, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_unknown_provider_execution_schema_is_rejected_and_revision_round_trips(
) -> TestResult<()> {
    let database = TempDatabase::new("runtime-unknown-provider-execution")?;
    let mut model = ModelFixture::start(Vec::new()).await?;
    let config = config_file(&database, &model.provider_url(), None, 1)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    install_test_replica(
        &client,
        &server.url(""),
        "install-unknown-provider-execution",
    )
    .await?;
    let before_list = list_sessions(&client, &server).await?;
    let (unknown_schema_status, unknown_schema_body) = create_with_model_body(
        &client,
        &server,
        "unknown-provider-execution-schema",
        model_selection(&model.provider_url(), "zode.provider-execution.v999", 1),
    )
    .await?;
    let after_unknown_schema_list = list_sessions(&client, &server).await?;

    let mut legal_revision_results = Vec::new();
    for revision in [2_u64, 4_u64] {
        let (status, body) = create_with_model_body(
            &client,
            &server,
            &format!("known-provider-execution-revision-{revision}"),
            model_selection(
                &model.provider_url(),
                "zode.provider-execution.v1",
                revision,
            ),
        )
        .await?;
        let get_body = if status == StatusCode::CREATED {
            let create_body: Value = serde_json::from_str(&body)?;
            let session_id = create_body["session_id"]
                .as_str()
                .ok_or_else(|| Error::other("known revision create omitted session_id"))?;
            Some(get_session(&client, &server, session_id).await?)
        } else {
            None
        };
        legal_revision_results.push((revision, status, body, get_body));
    }
    let provider_requests = model.request_count();
    server.stop().await?;
    model.stop().await?;

    assert_eq!(
        unknown_schema_status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown provider execution schema was admitted: {unknown_schema_body}"
    );
    let unknown_schema_error: Value = serde_json::from_str(&unknown_schema_body)?;
    assert_eq!(unknown_schema_error["error"]["code"], "invalid_request");
    assert_eq!(before_list, after_unknown_schema_list);
    assert_eq!(provider_requests, 0);

    for (revision, status, body, get_body) in legal_revision_results {
        assert_eq!(
            status,
            StatusCode::CREATED,
            "legal provider execution revision {revision} was rejected: {body}"
        );
        let get_body = get_body.ok_or_else(|| {
            Error::other(format!(
                "legal provider execution revision {revision} had no GET projection"
            ))
        })?;
        assert_eq!(get_body["model"]["provider"], "fixture-provider");
        assert_eq!(get_body["model"]["provider_execution_revision"], revision);
        assert_eq!(get_body["model"]["model"], "fixture-model");
        assert_eq!(get_body["model"]["auth_authority_id"], "controller-e2e");
        assert_eq!(get_body["model"]["auth_profile_id"], "profile-e2e");
        assert_eq!(get_body["model"]["auth_revision"], 1);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_model_pre_stream_rate_limit_is_one_logical_request() -> TestResult<()> {
    let database = TempDatabase::new("runtime-pre-stream-retry")?;
    let mut model = ModelFixture::start(vec![
        ModelScript::status(503),
        ModelScript::final_text("retry succeeded"),
    ])
    .await?;
    let mut tool = ToolFixture::start(Vec::new()).await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        1,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id =
        create_session(&client, &server, &model.provider_url(), "create-pre-stream").await?;
    let mut events = open_events(&client, &server, &session_id).await?;
    post_message(
        &client,
        &server,
        &session_id,
        "pre-stream-message",
        "retryable transport response",
    )
    .await?;
    model.wait_for_requests(2).await?;
    assert_eq!(
        model.request_count(),
        2,
        "pre-stream retry did not stay one logical request"
    );
    let assistant = next_event_with_kind(&mut events, "assistant_message_committed")
        .await
        .map_err(|error| {
            Error::other(format!(
                "pre-stream retry did not commit the final assistant: {error}"
            ))
        })?;
    assert!(
        assistant.data.to_string().contains("retry succeeded"),
        "pre-stream retry assistant did not contain the successful final text"
    );
    let state = get_session(&client, &server, &session_id).await?;
    let transcript = state["transcript"]
        .as_array()
        .ok_or_else(|| Error::other("GET projection omitted transcript"))?;
    let assistants = transcript
        .iter()
        .filter(|message| message["role"].as_str() == Some("assistant"))
        .collect::<Vec<_>>();
    assert_eq!(
        assistants.len(),
        1,
        "pre-stream retry committed an unexpected number of assistant messages"
    );
    assert_eq!(
        assistants[0]["content"].as_str(),
        Some("retry succeeded"),
        "pre-stream retry assistant content was not the successful final text"
    );
    server.stop().await?;
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_tombstoned_replica_never_reaches_provider_before_or_after_restart() -> TestResult<()> {
    let database = TempDatabase::new("runtime-tombstoned-replica")?;
    let mut model = ModelFixture::start(Vec::new()).await?;
    let config = config_file(&database, &model.provider_url(), None, 1)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;

    let (install_status, install_body) = put_runtime_replica(
        &client,
        &server,
        "runtime-tombstone-install",
        2,
        Some(TOMBSTONE_PROVIDER_SECRET),
    )
    .await?;
    assert_eq!(install_status, StatusCode::CREATED, "{install_body}");
    let install_metadata: Value = serde_json::from_str(&install_body)?;
    assert_eq!(install_metadata["revision"], 2);
    assert_eq!(install_metadata["status"], "ready");

    let mut selection = model_selection(&model.provider_url(), "zode.provider-execution.v1", 2);
    selection["minimum_auth_revision"] = json!(2);
    let (create_status, create_body) =
        create_with_model_body(&client, &server, "runtime-tombstone-session", selection).await?;
    assert_eq!(create_status, StatusCode::CREATED, "{create_body}");
    let create_metadata: Value = serde_json::from_str(&create_body)?;
    let session_id = create_metadata["session_id"]
        .as_str()
        .ok_or_else(|| Error::other("tombstone runtime session omitted session_id"))?
        .to_owned();

    let (tombstone_status, tombstone_body) =
        put_runtime_replica(&client, &server, "runtime-tombstone-revoke", 3, None).await?;
    assert!(
        tombstone_status.is_success(),
        "tombstone admission did not succeed: {tombstone_status} {tombstone_body}"
    );
    let tombstone_metadata: Value = serde_json::from_str(&tombstone_body)?;
    assert_eq!(tombstone_metadata["revision"], 3);
    assert_eq!(tombstone_metadata["status"], "tombstoned");

    let mut events = open_events(&client, &server, &session_id).await?;
    post_message(
        &client,
        &server,
        &session_id,
        "runtime-tombstone-message-before-restart",
        "message after replica tombstone",
    )
    .await?;
    let first_failure = next_auth_replica_unavailable(&mut events, &session_id).await?;
    assert_eq!(model.request_count(), 0);
    let first_state = get_session(&client, &server, &session_id).await?;
    assert_no_model_effect(&first_state, "pre-restart tombstone session")?;

    let first_failure_id = first_failure.id.clone();
    server.stop().await?;
    assert!(!sqlite_contains_secret(database.path(), TOMBSTONE_PROVIDER_SECRET).await?);

    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let mut restarted_events =
        open_events_with_cursor(&client, &restarted, &session_id, Some(&first_failure_id)).await?;
    post_message(
        &client,
        &restarted,
        &session_id,
        "runtime-tombstone-message-after-restart",
        "message after replica tombstone restart",
    )
    .await?;
    let second_failure = next_auth_replica_unavailable(&mut restarted_events, &session_id).await?;
    let first_failure_position = first_failure.id.parse::<u64>().map_err(|error| {
        Error::other(format!(
            "first auth failure had a non-numeric SSE id: {error}"
        ))
    })?;
    let second_failure_position = second_failure.id.parse::<u64>().map_err(|error| {
        Error::other(format!(
            "second auth failure had a non-numeric SSE id: {error}"
        ))
    })?;
    assert!(
        first_failure_position < second_failure_position,
        "restart auth failure SSE ids were not strictly increasing: {} then {}",
        first_failure.id,
        second_failure.id
    );
    assert_eq!(model.request_count(), 0);
    let second_state = get_session(&client, &restarted, &session_id).await?;
    assert_no_model_effect(&second_state, "post-restart tombstone session")?;

    drop(restarted_events);
    let mut replay =
        open_events_with_cursor(&client, &restarted, &session_id, Some(&first_failure_id)).await?;
    let replayed_failure = next_auth_replica_unavailable(&mut replay, &session_id).await?;
    assert_eq!(
        replayed_failure.id, second_failure.id,
        "Last-Event-ID replay did not return the second durable auth failure"
    );

    restarted.stop().await?;
    model.stop().await?;
    assert!(!sqlite_contains_secret(database.path(), TOMBSTONE_PROVIDER_SECRET).await?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_restart_recovers_queued_input_without_another_command() -> TestResult<()> {
    let database = TempDatabase::new("runtime-queued-input-recovery")?;
    let hold = ModelHold::new();
    let mut model = ModelFixture::start(vec![
        ModelScript::hold_entered(hold.clone(), ModelScript::final_text("unused A attempt")),
        ModelScript::final_text("assistant A"),
        ModelScript::final_text("assistant B"),
    ])
    .await?;
    let config = config_file(&database, &model.provider_url(), None, 2)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    install_test_replica(&client, &server.url(""), "install-queued-input-recovery").await?;
    let (create_status, create_body) = create_with_model_body(
        &client,
        &server,
        "create-queued-input-recovery",
        model_selection(&model.provider_url(), "zode.provider-execution.v1", 1),
    )
    .await?;
    assert_eq!(create_status, StatusCode::CREATED, "{create_body}");
    let create_metadata: Value = serde_json::from_str(&create_body)?;
    let session_id = require_ulid(&create_metadata)?;
    post_message(
        &client,
        &server,
        &session_id,
        "queued-recovery-a",
        "input A",
    )
    .await?;
    model.wait_for_requests(1).await?;
    hold.wait_entered().await?;
    post_message(
        &client,
        &server,
        &session_id,
        "queued-recovery-b",
        "input B",
    )
    .await?;

    // ConfiguredServer::stop force-kills and reaps the real Endpoint child;
    // this is the crash boundary, not a graceful runtime shutdown.
    let pre_crash_request_count = model.seal_request_phase();
    assert_eq!(
        pre_crash_request_count, 1,
        "a second provider request started before the crash boundary"
    );
    server.stop().await?;
    assert_eq!(
        model.request_count(),
        1,
        "provider received a second request before kill/reap"
    );
    assert_eq!(
        model.request_phase_violations(),
        0,
        "provider request phase observed a request before kill/reap"
    );
    model.open_request_phase();
    hold.release();

    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let mut events = open_events(&client, &restarted, &session_id).await?;
    if let Err(error) = model.wait_for_requests(3).await {
        let _ = restarted.stop().await;
        let _ = model.stop().await;
        return Err(Error::other(format!(
            "restart did not issue recovery provider requests for A and B: {error}"
        ))
        .into());
    }
    let recovery_request_count = model.seal_request_phase();
    assert_eq!(
        recovery_request_count, 3,
        "restart issued more than two recovery provider requests"
    );
    let first_assistant = next_event_with_kind(&mut events, "assistant_message_committed")
        .await
        .map_err(|error| Error::other(format!("recovery assistant A was not durable: {error}")))?;
    let second_assistant = next_event_with_kind(&mut events, "assistant_message_committed")
        .await
        .map_err(|error| Error::other(format!("recovery assistant B was not durable: {error}")))?;
    assert_eq!(
        first_assistant.data["data"]["message"]["content"],
        "assistant A"
    );
    assert_eq!(
        second_assistant.data["data"]["message"]["content"],
        "assistant B"
    );
    let first_version = first_assistant.data["version"]
        .as_u64()
        .ok_or_else(|| Error::other("recovery assistant A omitted event version"))?;
    let second_version = second_assistant.data["version"]
        .as_u64()
        .ok_or_else(|| Error::other("recovery assistant B omitted event version"))?;
    assert!(
        first_version < second_version,
        "recovery assistant events were not ordered: {first_version} then {second_version}"
    );
    let replay_a_wire = model
        .request(1)
        .ok_or_else(|| Error::other("recovery provider request for A was missing"))?;
    assert_eq!(
        wire_dialogue(&replay_a_wire)?,
        vec![("user".to_owned(), "input A".to_owned())],
        "first recovery provider request did not contain only input A"
    );
    let replay_b_wire = model
        .request(2)
        .ok_or_else(|| Error::other("recovery provider request for B was missing"))?;
    assert_eq!(
        wire_dialogue(&replay_b_wire)?,
        vec![
            ("user".to_owned(), "input A".to_owned()),
            ("assistant".to_owned(), "assistant A".to_owned()),
            ("user".to_owned(), "input B".to_owned()),
        ],
        "second recovery provider request did not preserve A, assistant A, B order"
    );
    let state = get_session(&client, &restarted, &session_id).await?;
    let transcript = state["transcript"]
        .as_array()
        .ok_or_else(|| Error::other("recovery GET omitted transcript"))?;
    let transcript_sequence = transcript
        .iter()
        .map(|message| Some((message["role"].as_str()?, message["content"].as_str()?)))
        .collect::<Option<Vec<_>>>();
    assert_eq!(
        transcript_sequence,
        Some(vec![
            ("user", "input A"),
            ("assistant", "assistant A"),
            ("user", "input B"),
            ("assistant", "assistant B"),
        ]),
        "recovery transcript did not materialize A and B exactly once in order"
    );
    restarted.stop().await?;
    assert_eq!(
        model.request_count(),
        3,
        "restart recovery provider request count was not exactly two"
    );
    assert_eq!(
        model.request_phase_violations(),
        0,
        "provider issued an extra recovery request after the exact-count barrier"
    );
    model.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_model_partial_stream_retry_has_no_partial_tool_effect() -> TestResult<()> {
    let database = TempDatabase::new("runtime-stream-retry")?;
    let mut model = ModelFixture::start(vec![
        ModelScript::partial_failure(
            "partial text must not persist",
            "call-partial",
            "fixture_tool",
            r#"{"value":"partial"}"#,
        ),
        ModelScript::tool_call("call-success", "fixture_tool", r#"{"value":"success"}"#),
        ModelScript::final_text("successful retry final"),
    ])
    .await?;
    let mut tool = ToolFixture::start(vec![ToolScript::Response(json!({
        "status": "completed",
        "result": {"content": "only successful attempt"}
    }))])
    .await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        2,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id =
        create_session(&client, &server, &model.provider_url(), "create-partial").await?;
    post_message(
        &client,
        &server,
        &session_id,
        "partial-message",
        "trigger partial stream",
    )
    .await?;
    model.wait_for_requests(2).await?;
    tool.wait_for_invocations(1).await?;
    assert_eq!(tool.invocation_count(), 1);
    let state = get_session(&client, &server, &session_id).await?;
    assert!(!state.to_string().contains("partial text must not persist"));
    server.stop().await?;
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_provider_stream_disconnect_finishes_activation_for_next_message() -> TestResult<()> {
    let database = TempDatabase::new("runtime-provider-disconnect-recovery")?;
    let hold = ModelHold::new();
    let mut model = ModelFixture::start(vec![
        ModelScript::stream_failure_hold(hold.clone()),
        ModelScript::final_text("message after provider disconnect"),
    ])
    .await?;
    let mut tool = ToolFixture::start(Vec::new()).await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        1,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        "create-provider-disconnect-recovery",
    )
    .await?;
    let mut events = open_events(&client, &server, &session_id).await?;
    post_message(
        &client,
        &server,
        &session_id,
        "provider-disconnect-first-message",
        "first message before provider disconnect",
    )
    .await?;
    hold.wait_entered().await?;
    post_message(
        &client,
        &server,
        &session_id,
        "provider-disconnect-second-message",
        "message after provider disconnect",
    )
    .await?;
    hold.release();

    let failure = next_event_with_kind(&mut events, "model_attempt_failed").await?;
    assert_eq!(failure.data["session_id"], session_id);

    let assistant =
        next_assistant_with_content(&mut events, "message after provider disconnect").await?;
    assert_eq!(assistant.data["session_id"], session_id);
    let finished = next_event_with_kind(&mut events, "activation_finished").await?;
    assert_eq!(finished.data["session_id"], session_id);
    let recovered_state = get_session(&client, &server, &session_id).await?;
    assert_eq!(recovered_state["active_activation"], Value::Null);
    assert_eq!(recovered_state["active_model_round"], Value::Null);
    assert_eq!(recovered_state["status"], "idle");
    assert_eq!(model.request_count(), 2);

    server.stop().await?;
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_provider_process_exit_finishes_activation_without_stuck_working() -> TestResult<()> {
    let database = TempDatabase::new("runtime-provider-process-exit")?;
    let hold = ModelHold::new();
    let model = ModelFixture::start(vec![ModelScript::stream_hold(hold.clone())]).await?;
    let mut tool = ToolFixture::start(Vec::new()).await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        1,
    )?;
    let mut config_value: Value = serde_json::from_slice(&fs::read(&config)?)?;
    config_value["runtime"]["model_stream_idle_timeout_ms"] = json!(100);
    fs::write(&config, serde_json::to_vec_pretty(&config_value)?)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        "create-provider-process-exit",
    )
    .await?;
    let mut events = open_events(&client, &server, &session_id).await?;
    post_message(
        &client,
        &server,
        &session_id,
        "provider-process-exit-message",
        "message before provider process exit",
    )
    .await?;
    hold.wait_entered().await?;
    drop(model);

    let failure = next_event_with_kind(&mut events, "model_attempt_failed").await?;
    assert_eq!(failure.data["session_id"], session_id);
    let finished = next_event_with_kind(&mut events, "activation_finished").await?;
    assert_eq!(finished.data["session_id"], session_id);
    let state = get_session(&client, &server, &session_id).await?;
    assert_eq!(state["active_activation"], Value::Null);
    assert_eq!(state["active_model_round"], Value::Null);
    assert_eq!(state["status"], "idle");

    server.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_restart_reconciles_failed_model_attempt_before_terminal_finish() -> TestResult<()> {
    let database = TempDatabase::new("runtime-failed-attempt-recovery")?;
    let hold = ModelHold::new();
    let mut model =
        ModelFixture::start(vec![ModelScript::stream_failure_hold(hold.clone())]).await?;
    let mut tool = ToolFixture::start(Vec::new()).await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        1,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        "create-failed-attempt-recovery",
    )
    .await?;
    let mut events = open_events(&client, &server, &session_id).await?;
    post_message(
        &client,
        &server,
        &session_id,
        "failed-attempt-recovery-message",
        "recover terminal failure after restart",
    )
    .await?;
    hold.wait_entered().await?;
    hold.release();

    let failure = next_event_with_kind(&mut events, "model_attempt_failed").await?;
    assert_eq!(failure.data["session_id"], session_id);
    server.stop().await?;
    model.stop().await?;

    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let mut recovery_events =
        open_events_with_cursor(&client, &restarted, &session_id, Some(&failure.id)).await?;
    next_event_with_kind(&mut recovery_events, "model_attempts_exhausted").await?;
    next_event_with_kind(&mut recovery_events, "model_attempt_failed").await?;
    next_event_with_kind(&mut recovery_events, "activation_finished").await?;
    let state = get_session(&client, &restarted, &session_id).await?;
    assert_eq!(state["active_activation"], Value::Null);
    assert_eq!(state["active_model_round"], Value::Null);
    assert_eq!(state["status"], "idle");

    restarted.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_restart_reconciles_failed_model_attempt_before_retry_schedule() -> TestResult<()> {
    let database = TempDatabase::new("runtime-failed-attempt-retry-recovery")?;
    let hold = ModelHold::new();
    let mut model = ModelFixture::start(vec![
        ModelScript::stream_failure_hold(hold.clone()),
        ModelScript::final_text("retry recovered after restart"),
    ])
    .await?;
    let mut tool = ToolFixture::start(Vec::new()).await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        2,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        "create-failed-attempt-retry-recovery",
    )
    .await?;
    let mut events = open_events(&client, &server, &session_id).await?;
    post_message(
        &client,
        &server,
        &session_id,
        "failed-attempt-retry-recovery-message",
        "recover scheduled retry after restart",
    )
    .await?;
    hold.wait_entered().await?;
    hold.release();

    let failure = next_event_with_kind(&mut events, "model_attempt_failed").await?;
    assert_eq!(failure.data["session_id"], session_id);
    // Stop immediately after the public failure fact.  The retry boundary is
    // intentionally absent from this crash window; restart must schedule the
    // same prepared request rather than leave the failed round active.
    server.stop().await?;

    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let mut recovery_events =
        open_events_with_cursor(&client, &restarted, &session_id, Some(&failure.id)).await?;
    next_event_with_kind(&mut recovery_events, "model_step_retrying").await?;
    model.wait_for_requests(2).await?;
    let assistant =
        next_assistant_with_content(&mut recovery_events, "retry recovered after restart").await?;
    assert_eq!(assistant.data["session_id"], session_id);
    let state = get_session(&client, &restarted, &session_id).await?;
    assert_eq!(state["active_activation"], Value::Null);
    assert_eq!(state["active_model_round"], Value::Null);
    assert_eq!(state["status"], "idle");

    restarted.stop().await?;
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_invalid_model_tool_arguments_are_rejected_before_side_effect() -> TestResult<()> {
    let database = TempDatabase::new("runtime-invalid-tool-arguments")?;
    let mut model = ModelFixture::start(vec![
        ModelScript::tool_call(
            "call-invalid-arguments-1",
            "fixture_tool",
            r#"{"value":42}"#,
        ),
        ModelScript::tool_call(
            "call-invalid-arguments-2",
            "fixture_tool",
            r#"{"value":42}"#,
        ),
    ])
    .await?;
    let mut tool = ToolFixture::start(vec![ToolScript::Response(json!({
        "status": "completed",
        "result": {"content": "side effect must not run"}
    }))])
    .await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        2,
    )?;
    let mut config_value: Value = serde_json::from_slice(&fs::read(&config)?)?;
    // This anchor covers only a configured ordinary adapter tool. The
    // runtime-owned wait_for contract has separate explicit-wait E2Es and is
    // intentionally not changed or asserted by this schema boundary.
    config_value["tools"][0]["input_schema"] = json!({
        "type": "object",
        "properties": {"value": {"type": "string"}},
        "required": ["value"],
        "additionalProperties": false
    });
    fs::write(&config, serde_json::to_vec_pretty(&config_value)?)?;

    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        "create-invalid-tool-arguments",
    )
    .await?;
    let mut events = open_events(&client, &server, &session_id).await?;
    post_message(
        &client,
        &server,
        &session_id,
        "invalid-tool-arguments-message",
        "invoke the fixture tool",
    )
    .await?;
    model.wait_for_requests(2).await?;

    tokio::select! {
        result = next_event_with_kind(&mut events, "model_attempt_failed") => {
            let frame = result?;
            assert_eq!(
                frame.data["data"]["error"]["class"],
                "invalid_tool_arguments"
            );
        }
        result = tool.wait_for_invocations(1) => {
            result?;
            return Err(Error::other(
                "invalid ordinary adapter arguments reached the tool adapter",
            ).into());
        }
    }
    assert_eq!(tool.invocation_count(), 0);
    let state = timeout(Duration::from_secs(5), async {
        loop {
            let state = get_session(&client, &server, &session_id).await?;
            if state["status"] == "idle" && state["active_activation"].is_null() {
                return Ok::<Value, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::TimedOut,
            "invalid tool terminal barrier timed out",
        )
    })??;
    assert_no_model_effect(&state, "invalid model tool arguments")?;
    assert_eq!(state["status"], "idle");
    assert!(state["active_activation"].is_null());
    assert!(state["active_model_round"].is_null());
    assert_eq!(model.request_count(), 2);
    server.stop().await?;
    assert!(!sqlite_contains_secret(database.path(), TEST_PROVIDER_SECRET).await?);
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_max_rounds_per_activation_stops_tool_feedback_loop() -> TestResult<()> {
    let database = TempDatabase::new("runtime-max-rounds")?;
    let mut model = ModelFixture::start(vec![
        ModelScript::tool_call("call-round-limit", "fixture_tool", r#"{"value":"one"}"#),
        ModelScript::final_text("unexpected second round"),
    ])
    .await?;
    let mut tool = ToolFixture::start(vec![ToolScript::Response(json!({
        "status": "completed",
        "result": {"content": "tool result"}
    }))])
    .await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        1,
    )?;
    let mut config_value: Value = serde_json::from_slice(&fs::read(&config)?)?;
    config_value["runtime"]["max_rounds_per_activation"] = json!(1);
    fs::write(&config, serde_json::to_vec_pretty(&config_value)?)?;

    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id =
        create_session(&client, &server, &model.provider_url(), "create-max-rounds").await?;
    let mut events = open_events(&client, &server, &session_id).await?;
    post_message(
        &client,
        &server,
        &session_id,
        "max-rounds-message",
        "run the bounded tool loop",
    )
    .await?;

    tokio::select! {
        result = model.wait_for_requests(2) => {
            result?;
            return Err(Error::other(
                "activation exceeded configured max_rounds_per_activation",
            ).into());
        }
        result = next_event_with_kind(&mut events, "activation_finished") => {
            result?;
        }
    }
    tool.wait_for_invocations(1).await?;
    assert_eq!(model.request_count(), 1);
    let state = get_session(&client, &server, &session_id).await?;
    assert_eq!(state["status"], "idle");
    assert!(state["active_activation"].is_null());
    assert!(state["active_model_round"].is_null());
    assert!(state["transcript"]
        .as_array()
        .is_some_and(|messages| messages
            .iter()
            .all(|message| { message["content"] != "unexpected second round" })));
    assert_eq!(tool.invocation_count(), 1);
    server.stop().await?;
    assert!(!sqlite_contains_secret(database.path(), TEST_PROVIDER_SECRET).await?);
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_hard_crash_recovery_exhausts_one_model_attempt_and_keeps_delivery_runnable(
) -> TestResult<()> {
    let database = TempDatabase::new("runtime-crash-exhausted")?;
    let release = Arc::new(Notify::new());
    let mut model = ModelFixture::start(vec![ModelScript::hold(
        release,
        ModelScript::final_text("must not be reached"),
    )])
    .await?;
    let mut tool = ToolFixture::start(Vec::new()).await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        1,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id =
        create_session(&client, &server, &model.provider_url(), "create-crash-one").await?;
    post_message(
        &client,
        &server,
        &session_id,
        "crash-one-message",
        "queued before crash",
    )
    .await?;
    model.wait_for_requests(1).await?;
    server.stop().await?;
    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let state = get_session(&client, &restarted, &session_id).await?;
    assert!(state.to_string().contains("model_attempts_exhausted"));
    assert!(state.to_string().contains("queued before crash"));
    restarted.stop().await?;
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_hard_crash_after_retry_fact_claims_one_scheduled_attempt() -> TestResult<()> {
    let database = TempDatabase::new("runtime-crash-retry")?;
    let mut model = ModelFixture::start(vec![
        // A non-retryable provider response keeps aimux from consuming the
        // second fixture script as a transport retry.  This leaves the
        // runtime model-attempt retry fact as the only retry boundary tested
        // below.
        ModelScript::status(400),
        ModelScript::final_text("retry recovery final"),
    ])
    .await?;
    let mut tool = ToolFixture::start(Vec::new()).await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        2,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id =
        create_session(&client, &server, &model.provider_url(), "create-crash-two").await?;
    let mut events = open_events(&client, &server, &session_id).await?;
    post_message(
        &client,
        &server,
        &session_id,
        "crash-two-message",
        "retry then crash",
    )
    .await?;
    model.wait_for_requests(1).await?;
    let retry = next_event_with_kind(&mut events, "model_step_retrying").await?;
    assert_eq!(retry.data["kind"], "model_step_retrying");
    assert_eq!(
        model.request_count(),
        1,
        "retry fact did not precede next attempt"
    );
    server.stop().await?;
    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    model.wait_for_requests(2).await?;
    // The fixture's request barrier fires on admission, before the streamed
    // response is reduced into the durable assistant message.
    let state = timeout(Duration::from_secs(5), async {
        loop {
            let state = get_session(&client, &restarted, &session_id).await?;
            if state.to_string().contains("retry recovery final") {
                return Ok::<Value, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::TimedOut,
            "retry recovery assistant projection timed out",
        )
    })??;
    assert!(state.to_string().contains("retry recovery final"));
    restarted.stop().await?;
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_model_stop_after_partial_tool_input_has_no_assistant_or_tool_effect() -> TestResult<()>
{
    const E2E: &str = "e2e_model_stop_after_partial_tool_input_has_no_assistant_or_tool_effect";
    let database = TempDatabase::new("runtime-partial-tool-input-stop")?;
    let release = Arc::new(Notify::new());
    let mut model = ModelNetworkFixture::start(
        E2E,
        Path::new(PARTIAL_TOOL_INPUT_INCIDENT),
        vec![
            partial_tool_input_stop_response(release.clone()),
            final_provider_response("queued input recovered"),
        ],
        true,
    )
    .await?;
    let mut tool = ToolFixture::start(Vec::new()).await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        1,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        "create-partial-tool-input-stop",
    )
    .await?;
    let mut events = open_events(&client, &server, &session_id).await?;
    post_message(
        &client,
        &server,
        &session_id,
        "partial-tool-input-message",
        "first input before partial stop",
    )
    .await?;
    model.wait_for_requests(1).await?;
    post_message(
        &client,
        &server,
        &session_id,
        "queued-after-partial-tool-input",
        "queued input after partial stop",
    )
    .await?;
    if model.capture {
        model.release()?;
    }
    model.wait_for_requests(2).await?;
    model.wait_for_recordings(2).await?;
    let (_recovered, failure_seen) =
        next_assistant_with_failure(&mut events, "queued input recovered").await?;
    assert!(
        failure_seen,
        "partial provider stream did not produce a public typed provider failure"
    );
    let state = get_session(&client, &server, &session_id).await?;
    let transcript = state["transcript"]
        .as_array()
        .ok_or_else(|| Error::other("partial-stop GET omitted transcript"))?;
    assert_eq!(
        transcript.len(),
        3,
        "partial provider candidate was persisted"
    );
    assert_eq!(transcript[0]["role"], "user");
    assert_eq!(transcript[0]["content"], "first input before partial stop");
    assert_eq!(transcript[1]["role"], "user");
    assert_eq!(transcript[1]["content"], "queued input after partial stop");
    assert_eq!(transcript[2]["role"], "assistant");
    assert_eq!(transcript[2]["content"], "queued input recovered");
    assert!(
        transcript.iter().all(|message| message["tool_calls"]
            .as_array()
            .is_some_and(|calls| calls.is_empty())),
        "partial provider stream created a durable tool call"
    );
    assert_eq!(tool.invocation_count(), 0);
    model.assert_replay_exhausted()?;
    server.stop().await?;
    assert!(!sqlite_contains_secret(database.path(), TEST_PROVIDER_SECRET).await?);
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_model_tool_call_preserves_assistant_text() -> TestResult<()> {
    const E2E: &str = "e2e_model_tool_call_preserves_assistant_text";
    let database = TempDatabase::new("runtime-tool-call-assistant-text")?;
    let mut model = ModelNetworkFixture::start(
        E2E,
        Path::new(TEXT_AND_TOOL_CALL_INCIDENT),
        vec![
            text_and_tool_call_response(),
            final_provider_response("after tool round"),
        ],
        false,
    )
    .await?;
    let mut tool = ToolFixture::start(vec![ToolScript::Response(json!({
        "status": "completed",
        "result": {"content": "tool result accepted"}
    }))])
    .await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        Some(&tool.adapter_url()),
        1,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        "create-text-and-tool-call",
    )
    .await?;
    let mut events = open_events(&client, &server, &session_id).await?;
    post_message(
        &client,
        &server,
        &session_id,
        "text-and-tool-call-message",
        "run tool with assistant preamble",
    )
    .await?;
    model.wait_for_requests(1).await?;
    tool.wait_for_invocations(1).await?;
    model.wait_for_requests(2).await?;
    model.wait_for_recordings(2).await?;
    next_assistant_with_content(&mut events, "after tool round").await?;
    assert_eq!(tool.invocation_count(), 1);
    let state = get_session(&client, &server, &session_id).await?;
    let transcript = state["transcript"]
        .as_array()
        .ok_or_else(|| Error::other("text/tool GET omitted transcript"))?;
    assert_eq!(
        transcript.len(),
        4,
        "tool round transcript had wrong length"
    );
    assert_eq!(transcript[0]["role"], "user");
    assert_eq!(transcript[0]["content"], "run tool with assistant preamble");
    assert_eq!(transcript[1]["role"], "assistant");
    assert_eq!(transcript[1]["content"], "before tool");
    assert_eq!(
        transcript[1]["tool_calls"],
        json!([{"tool_call_id": "text-tool-call", "tool_name": "fixture_tool"}])
    );
    assert_eq!(transcript[2]["role"], "tool");
    assert_eq!(transcript[2]["tool_call_id"], "text-tool-call");
    assert_eq!(transcript[2]["content"], "tool result accepted");
    assert_eq!(transcript[2]["tool_calls"], json!([]));
    assert_eq!(transcript[3]["role"], "assistant");
    assert_eq!(transcript[3]["content"], "after tool round");
    assert_eq!(transcript[3]["tool_calls"], json!([]));
    model.assert_replay_exhausted()?;
    server.stop().await?;
    assert!(!sqlite_contains_secret(database.path(), TEST_PROVIDER_SECRET).await?);
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

mod support;

use std::{
    fs,
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_stream::stream;
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, StatusCode},
    response::Response as AxumResponse,
    routing::get,
    Router,
};
use bytes::Bytes;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::process_capture::ProcessCaptureSet;
use support::{
    authenticated_as, canonical_json, http_client, new_llm_recording_run_dir,
    persist_public_http_gap_exchange, run_provider_attempt_until_cancel, run_provider_failure,
    run_provider_failure_with_process_capture, run_provider_roundtrip_and_restart,
    scan_llm_recording_tree, sqlite_contains_secret, write_endpoint_config, HttpFixture,
    LlmHttpAttemptPlan, LlmHttpObservedRequest, LlmHttpProxy, LlmHttpRecording,
    LlmHttpRecordingMetadata, LlmHttpResponseOutcome, ModelFixture, ModelHold, ModelScript,
    ProviderRoundtripSpec, PublicHttpGapExchange, TempDatabase, TestResult, TestZode,
    LLM_HTTP_RECORDING_SCHEMA, MAX_LLM_CHUNK_DELAY_US, MAX_LLM_RESPONSE_BYTES,
    MAX_LLM_RESPONSE_CHUNKS, TEST_CONTROLLER_AUTHORITY, TEST_CONTROLLER_SECRET,
};
use tokio::{sync::Notify, time::timeout};

const PROVIDER: &str = "opencode-go";
const MODEL: &str = "deepseek-v4-flash";
const PROFILE: &str = "opencode-live-provider-e2e";
const SUBJECT: &str = "recorded-provider-subject";
const FIRST_PROMPT: &str = "Reply with exactly ZODE_LIVE_OK.";
const RESTART_PROMPT: &str = "Reply with exactly ZODE_LIVE_RESTART_OK.";
const REPLAY_SECRET: &str = "offline-recording-provider-key";
const RECORDING_PATH: &str =
    "tests/fixtures/provider_recordings/opencode_go_deepseek_v4_flash.v2.json";
const FIRST_OCCURRENCE_PATH: &str =
    "tests/fixtures/provider_recordings/opencode_go_deepseek_v4_flash.v1.json";
const FIRST_OCCURRENCE_SIDECAR_PATH: &str =
    "tests/fixtures/provider_recordings/opencode_go_deepseek_v4_flash.v1.sidecar.json";
const FIRST_OCCURRENCE_BYTES: usize = 36_462;
const FIRST_OCCURRENCE_SHA256: &str =
    "3f0f7b69fac0620b0b24d774972840c0b9ee99897c2e16a63466309248b160ab";
const LEGACY_SIDECAR_SCHEMA: &str = "zode.llm-http-recording-legacy-sidecar.v1";
const SENTINEL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyRecording {
    schema: String,
    provider: String,
    model: String,
    requests: Vec<LegacyExchange>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyExchange {
    method: String,
    path: String,
    body: String,
    response: LegacyResponse,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyResponse {
    status: u16,
    content_type: String,
    complete: bool,
    stream_error: String,
    chunks: Vec<LegacyChunk>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyChunk {
    at_us: u64,
    bytes_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacySidecar {
    schema: String,
    source_file: String,
    source_bytes: usize,
    source_sha256: String,
    owner: String,
    boundary: String,
    request_match: String,
    exchanges: Vec<LegacySidecarExchange>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacySidecarExchange {
    sequence: usize,
    request_body_sha256: String,
    response_body_sha256: String,
    response_chunk_count: usize,
    legacy_outcome: String,
    replay_outcome: String,
}

struct LegacyReplayState {
    requests: Vec<LegacyExchange>,
    next: Mutex<usize>,
    mismatch: Mutex<Option<String>>,
}

struct LegacyReplayFixture {
    server: HttpFixture,
    state: Arc<LegacyReplayState>,
}

impl LegacyReplayFixture {
    async fn start(recording: LegacyRecording) -> TestResult<Self> {
        let state = Arc::new(LegacyReplayState {
            requests: recording.requests,
            next: Mutex::new(0),
            mismatch: Mutex::new(None),
        });
        let router = Router::new()
            .fallback(legacy_replay_request)
            .with_state(state.clone());
        let server = HttpFixture::start(router).await?;
        Ok(Self { server, state })
    }

    fn base_url(&self, path: &str) -> String {
        self.server.url(path)
    }

    fn assert_exhausted(&self) -> TestResult<()> {
        if let Some(error) = self
            .state
            .mismatch
            .lock()
            .expect("legacy replay mismatch mutex poisoned")
            .as_ref()
        {
            return Err(Error::other(error.clone()).into());
        }
        let consumed = *self
            .state
            .next
            .lock()
            .expect("legacy replay cursor mutex poisoned");
        if consumed != self.state.requests.len() {
            return Err(Error::other("legacy replay did not consume every exchange").into());
        }
        Ok(())
    }

    async fn stop(&mut self) -> TestResult<()> {
        self.server.stop().await
    }
}

async fn legacy_replay_request(
    State(state): State<Arc<LegacyReplayState>>,
    request: Request,
) -> AxumResponse {
    let method = request.method().as_str().to_owned();
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| request.uri().path())
        .to_owned();
    let body = match to_bytes(request.into_body(), 4 * 1024 * 1024).await {
        Ok(body) => body,
        Err(_) => return legacy_replay_error(&state, "legacy replay request body was invalid"),
    };
    let canonical_body = match canonical_json(&body) {
        Ok(body) => body,
        Err(_) => return legacy_replay_error(&state, "legacy replay request was not JSON"),
    };
    let expected = {
        let mut next = state
            .next
            .lock()
            .expect("legacy replay cursor mutex poisoned");
        let Some(expected) = state.requests.get(*next) else {
            return legacy_replay_error(
                &state,
                "legacy replay observed a request after cassette end",
            );
        };
        if expected.method != method || expected.path != path || expected.body != canonical_body {
            return legacy_replay_error(
                &state,
                "legacy replay request did not match the retained exchange",
            );
        }
        *next += 1;
        expected.clone()
    };
    let chunks = match expected
        .response
        .chunks
        .iter()
        .map(|chunk| decode_hex(&chunk.bytes_hex).map(Bytes::from))
        .collect::<TestResult<Vec<_>>>()
    {
        Ok(chunks) => chunks,
        Err(_) => return legacy_replay_error(&state, "legacy replay chunk was invalid"),
    };
    let body = stream! {
        for chunk in chunks {
            yield Ok::<Bytes, std::io::Error>(chunk);
        }
    };
    AxumResponse::builder()
        .status(expected.response.status)
        .header(header::CONTENT_TYPE, expected.response.content_type)
        .body(Body::from_stream(body))
        .expect("legacy replay response builds")
}

fn legacy_replay_error(state: &LegacyReplayState, message: &str) -> AxumResponse {
    let mut mismatch = state
        .mismatch
        .lock()
        .expect("legacy replay mismatch mutex poisoned");
    if mismatch.is_none() {
        *mismatch = Some(message.to_owned());
    }
    AxumResponse::builder()
        .status(StatusCode::CONFLICT)
        .body(Body::from("legacy provider replay mismatch"))
        .expect("legacy replay error response builds")
}

#[derive(Clone)]
struct NetworkSentinelState {
    unexpected_requests: Arc<AtomicUsize>,
}

struct NetworkSentinel {
    server: HttpFixture,
    unexpected_requests: Arc<AtomicUsize>,
}

impl NetworkSentinel {
    async fn start() -> TestResult<Self> {
        let unexpected_requests = Arc::new(AtomicUsize::new(0));
        let state = NetworkSentinelState {
            unexpected_requests: unexpected_requests.clone(),
        };
        let router = Router::new()
            .route("/sentinel-ready", get(|| async { StatusCode::NO_CONTENT }))
            .fallback(network_sentinel_request)
            .with_state(state);
        let server = HttpFixture::start(router).await?;
        let response = timeout(
            SENTINEL_TIMEOUT,
            http_client()?.get(server.url("/sentinel-ready")).send(),
        )
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "network sentinel barrier timed out"))??;
        if response.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(Error::other("network sentinel barrier returned the wrong status").into());
        }
        Ok(Self {
            server,
            unexpected_requests,
        })
    }

    fn child_environment(&self) -> Vec<(String, String)> {
        let proxy = self.server.url("");
        [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ]
        .into_iter()
        .map(|name| (name.to_owned(), proxy.clone()))
        .chain([
            ("NO_PROXY".to_owned(), "127.0.0.1,localhost".to_owned()),
            ("no_proxy".to_owned(), "127.0.0.1,localhost".to_owned()),
        ])
        .collect()
    }

    fn unexpected_requests(&self) -> usize {
        self.unexpected_requests.load(Ordering::SeqCst)
    }

    async fn stop(&mut self) -> TestResult<()> {
        self.server.stop().await
    }
}

async fn network_sentinel_request(State(state): State<NetworkSentinelState>) -> StatusCode {
    state.unexpected_requests.fetch_add(1, Ordering::SeqCst);
    StatusCode::BAD_GATEWAY
}

fn decode_hex(value: &str) -> TestResult<Vec<u8>> {
    if !value.is_ascii() || !value.len().is_multiple_of(2) {
        return Err(Error::other("legacy replay chunk encoding was invalid").into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = legacy_hex_nibble(pair[0])
                .ok_or_else(|| Error::other("legacy replay chunk encoding was invalid"))?;
            let low = legacy_hex_nibble(pair[1])
                .ok_or_else(|| Error::other("legacy replay chunk encoding was invalid"))?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn digest_without_validation(mut recording: LlmHttpRecording) -> TestResult<LlmHttpRecording> {
    recording.envelope_sha256.clear();
    let preimage = serde_json::to_vec(&recording)?;
    recording.envelope_sha256 = format!("{:x}", Sha256::digest(preimage));
    Ok(recording)
}

fn legacy_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn config_for_replay(database: &Path, provider_base_url: &str) -> TestResult<PathBuf> {
    // The public policy is an origin allowlist, while the model descriptor
    // carries the recorder's `/v1` base URL.  Normalize the test input here
    // so every recorder call exercises the same production exact-origin rule.
    let provider_origin = url::Url::parse(provider_base_url)?
        .origin()
        .ascii_serialization();
    let path = write_endpoint_config(database, Vec::new(), 1)?;
    let mut config: Value = serde_json::from_slice(&fs::read(&path)?)?;
    config["provider_execution"]["adapter_kinds"] = json!(["openai_compatible"]);
    config["provider_execution"]["allowed_base_url_origins"] = json!([provider_origin]);
    fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    Ok(path)
}

fn assert_recording_secret_free(recording: &LlmHttpRecording, markers: &[&str]) -> TestResult<()> {
    let bytes = serde_json::to_vec(recording)?;
    for marker in markers.iter().filter(|marker| !marker.is_empty()) {
        if bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
        {
            return Err(Error::other("provider recording exposed credential material").into());
        }
    }
    Ok(())
}

fn requests_match(
    recording: &LlmHttpRecording,
    observed: &[LlmHttpObservedRequest],
) -> TestResult<()> {
    if observed.len() != recording.requests.len() {
        return Err(Error::other("replay observed an unexpected provider request count").into());
    }
    for (actual, expected) in observed.iter().zip(&recording.requests) {
        if actual.method != expected.request.method
            || actual.path != expected.request.path
            || actual.semantic_headers != expected.request.semantic_headers
            || actual.raw_body_hex != expected.request.raw_body_hex
            || actual.canonical_json != expected.request.canonical_json
        {
            return Err(Error::other("replay provider request differed from cassette").into());
        }
    }
    Ok(())
}

fn recording_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(RECORDING_PATH)
}

fn replay_markers() -> Vec<String> {
    let mut markers = vec![REPLAY_SECRET.to_owned(), TEST_CONTROLLER_SECRET.to_owned()];
    if let Ok(key) = std::env::var("OPENCODE_API_KEY") {
        markers.push(key);
    }
    markers
}

fn first_occurrence_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIRST_OCCURRENCE_PATH)
}

fn first_occurrence_sidecar_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIRST_OCCURRENCE_SIDECAR_PATH)
}

fn assert_bytes_secret_free(bytes: &[u8], markers: &[String]) -> TestResult<()> {
    if markers
        .iter()
        .filter(|marker| !marker.is_empty())
        .any(|marker| {
            bytes
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        })
    {
        return Err(Error::other("provider fixture exposed credential material").into());
    }
    Ok(())
}

fn load_legacy_first_occurrence() -> TestResult<LegacyRecording> {
    let exact_bytes = fs::read(first_occurrence_path())?;
    if exact_bytes.len() != FIRST_OCCURRENCE_BYTES
        || format!("{:x}", Sha256::digest(&exact_bytes)) != FIRST_OCCURRENCE_SHA256
    {
        return Err(Error::other("retained v1 first-occurrence bytes changed").into());
    }
    let sidecar_bytes = fs::read(first_occurrence_sidecar_path())?;
    let markers = replay_markers();
    assert_bytes_secret_free(&exact_bytes, &markers)?;
    assert_bytes_secret_free(&sidecar_bytes, &markers)?;
    let recording: LegacyRecording = serde_json::from_slice(&exact_bytes)?;
    let sidecar: LegacySidecar = serde_json::from_slice(&sidecar_bytes)?;
    if recording.schema != LLM_HTTP_RECORDING_SCHEMA
        || recording.provider != PROVIDER
        || recording.model != MODEL
        || recording.requests.len() != 2
        || sidecar.schema != LEGACY_SIDECAR_SCHEMA
        || sidecar.source_file != "opencode_go_deepseek_v4_flash.v1.json"
        || sidecar.source_bytes != FIRST_OCCURRENCE_BYTES
        || sidecar.source_sha256 != FIRST_OCCURRENCE_SHA256
        || sidecar.owner != "e2e_opencode_v1_first_occurrence_remains_replayable"
        || sidecar.boundary != "endpoint_aimux_provider_http"
        || sidecar.request_match != "canonical_json"
        || sidecar.exchanges.len() != recording.requests.len()
    {
        return Err(Error::other("legacy recording sidecar metadata was invalid").into());
    }
    for (sequence, (exchange, evidence)) in recording
        .requests
        .iter()
        .zip(&sidecar.exchanges)
        .enumerate()
    {
        let response_bytes = exchange
            .response
            .chunks
            .iter()
            .map(|chunk| decode_hex(&chunk.bytes_hex))
            .collect::<TestResult<Vec<_>>>()?
            .concat();
        let chunk_times_are_ordered = exchange
            .response
            .chunks
            .windows(2)
            .all(|chunks| chunks[0].at_us <= chunks[1].at_us);
        if evidence.sequence != sequence
            || exchange.method != "POST"
            || !exchange.path.ends_with("/chat/completions")
            || canonical_json(exchange.body.as_bytes())? != exchange.body
            || format!("{:x}", Sha256::digest(exchange.body.as_bytes()))
                != evidence.request_body_sha256
            || format!("{:x}", Sha256::digest(&response_bytes)) != evidence.response_body_sha256
            || exchange.response.status != 200
            || exchange.response.content_type != "text/event-stream"
            || exchange.response.complete
            || exchange.response.stream_error != "client_disconnect"
            || evidence.response_chunk_count != exchange.response.chunks.len()
            || evidence.legacy_outcome != "client_disconnect_after_done"
            || evidence.replay_outcome != "complete_after_done"
            || !chunk_times_are_ordered
            || !response_bytes
                .windows(b"data: [DONE]".len())
                .any(|window| window == b"data: [DONE]")
            || !response_bytes
                .windows(b"\"finish_reason\":\"stop\"".len())
                .any(|window| window == b"\"finish_reason\":\"stop\"")
        {
            return Err(Error::other(format!(
                "legacy recording exchange {sequence} did not match its compatibility evidence"
            ))
            .into());
        }
    }
    Ok(recording)
}

async fn replay_recording_roundtrip(
    recording: &LlmHttpRecording,
    captured_timing: bool,
    label: &str,
) -> TestResult<()> {
    replay_recording_roundtrip_with_environment(recording, captured_timing, label, Vec::new()).await
}

async fn replay_recording_roundtrip_with_environment(
    recording: &LlmHttpRecording,
    captured_timing: bool,
    label: &str,
    child_environment: Vec<(String, String)>,
) -> TestResult<()> {
    let marker_values = replay_markers();
    let marker_refs = marker_values.iter().map(String::as_str).collect::<Vec<_>>();
    assert_recording_secret_free(recording, &marker_refs)?;
    let mut proxy = LlmHttpProxy::replay_with_authorization(
        recording.clone(),
        captured_timing,
        Some(REPLAY_SECRET.to_owned()),
    )
    .await?;
    let provider_path = recording
        .requests
        .first()
        .and_then(|exchange| exchange.request.path.strip_suffix("/chat/completions"))
        .ok_or_else(|| Error::other("provider recording path was not a chat-completions route"))?;
    let database = TempDatabase::new(label)?;
    let config = config_for_replay(database.path(), &proxy.base_url(""))?;
    let primary = run_provider_roundtrip_and_restart(ProviderRoundtripSpec {
        database: database.path().to_owned(),
        config,
        provider_base_url: proxy.base_url(provider_path),
        provider: PROVIDER.to_owned(),
        model: MODEL.to_owned(),
        profile: PROFILE.to_owned(),
        subject: SUBJECT.to_owned(),
        provider_secret: REPLAY_SECRET.to_owned(),
        first_prompt: FIRST_PROMPT.to_owned(),
        first_marker: "ZODE_LIVE_OK".to_owned(),
        restart_prompt: RESTART_PROMPT.to_owned(),
        restart_marker: "ZODE_LIVE_RESTART_OK".to_owned(),
        idempotency_prefix: label.to_owned(),
        forbidden: marker_values,
        child_environment,
    })
    .await;

    let mut cleanup_errors = Vec::new();
    if !proxy.replay_exhausted() {
        cleanup_errors.push("offline replay did not fully consume every exchange".to_owned());
    }
    if let Err(error) = requests_match(recording, &proxy.observed_requests()) {
        cleanup_errors.push(error.to_string());
    }
    if let Err(error) = proxy.stop().await {
        cleanup_errors.push(format!("replay proxy stop failed: {error}"));
    }
    match sqlite_contains_secret(database.path(), REPLAY_SECRET).await {
        Ok(true) => cleanup_errors.push("replay credential reached runtime SQLite".to_owned()),
        Ok(false) => {}
        Err(error) => cleanup_errors.push(error.to_string()),
    }
    match sqlite_contains_secret(database.path(), TEST_CONTROLLER_SECRET).await {
        Ok(true) => cleanup_errors.push("controller credential reached runtime SQLite".to_owned()),
        Ok(false) => {}
        Err(error) => cleanup_errors.push(error.to_string()),
    }
    if cleanup_errors.is_empty() {
        return primary;
    }
    let cleanup = cleanup_errors.join("; ");
    match primary {
        Ok(()) => Err(Error::other(format!("recorded provider cleanup failed: {cleanup}")).into()),
        Err(error) => Err(Error::other(format!(
            "recorded provider failed: {error}; cleanup failed: {cleanup}"
        ))
        .into()),
    }
}

async fn replay_legacy_first_occurrence(recording: LegacyRecording) -> TestResult<()> {
    let provider_path = recording
        .requests
        .first()
        .and_then(|exchange| exchange.path.strip_suffix("/chat/completions"))
        .ok_or_else(|| Error::other("legacy recording path was not a chat-completions route"))?
        .to_owned();
    let mut replay = LegacyReplayFixture::start(recording).await?;
    let marker_values = replay_markers();
    let database = TempDatabase::new("recorded-v1-first-occurrence")?;
    let config = config_for_replay(database.path(), &replay.base_url(""))?;
    let primary = run_provider_roundtrip_and_restart(ProviderRoundtripSpec {
        database: database.path().to_owned(),
        config,
        provider_base_url: replay.base_url(&provider_path),
        provider: PROVIDER.to_owned(),
        model: MODEL.to_owned(),
        profile: PROFILE.to_owned(),
        subject: SUBJECT.to_owned(),
        provider_secret: REPLAY_SECRET.to_owned(),
        first_prompt: FIRST_PROMPT.to_owned(),
        first_marker: "ZODE_LIVE_OK".to_owned(),
        restart_prompt: RESTART_PROMPT.to_owned(),
        restart_marker: "ZODE_LIVE_RESTART_OK".to_owned(),
        idempotency_prefix: "recorded-v1-first-occurrence".to_owned(),
        forbidden: marker_values,
        child_environment: Vec::new(),
    })
    .await;
    let exhausted = replay.assert_exhausted();
    let stopped = replay.stop().await;
    let sqlite_secret = sqlite_contains_secret(database.path(), REPLAY_SECRET).await;
    exhausted?;
    stopped?;
    if sqlite_secret? {
        return Err(Error::other("legacy replay credential reached runtime SQLite").into());
    }
    primary
}

fn assert_pre_stream_retry_recording(recording: &LlmHttpRecording) -> TestResult<()> {
    let attempts = recording
        .requests
        .iter()
        .map(|exchange| {
            (
                exchange.sequence,
                exchange.logical_round,
                exchange.wire_attempt,
                exchange.response.status,
            )
        })
        .collect::<Vec<_>>();
    if attempts
        != vec![
            (0, 0, 0, Some(503)),
            (1, 0, 1, Some(200)),
            (2, 1, 0, Some(200)),
        ]
    {
        return Err(Error::other(format!(
            "pre-stream retry recording had the wrong ordered attempts: {attempts:?}"
        ))
        .into());
    }
    let first = &recording.requests[0];
    let retry = &recording.requests[1];
    if first.request.raw_body_hex != retry.request.raw_body_hex
        || first.request.raw_body_sha256 != retry.request.raw_body_sha256
        || first.request.canonical_json != retry.request.canonical_json
        || first.request.canonical_json_sha256 != retry.request.canonical_json_sha256
    {
        return Err(Error::other("pre-stream retry changed its logical request bytes").into());
    }
    if !matches!(
        first.response.outcome,
        LlmHttpResponseOutcome::Complete { done_seen: false }
    ) || !matches!(
        retry.response.outcome,
        LlmHttpResponseOutcome::Complete { done_seen: true }
    ) {
        return Err(Error::other("pre-stream retry outcomes were not captured exactly").into());
    }
    Ok(())
}

async fn capture_pre_stream_retry() -> TestResult<(LlmHttpRecording, PathBuf)> {
    capture_pre_stream_retry_with_plan(None).await
}

async fn capture_pre_stream_retry_with_plan(
    attempt_plan: Option<Vec<LlmHttpAttemptPlan>>,
) -> TestResult<(LlmHttpRecording, PathBuf)> {
    let mut provider = ModelFixture::start(vec![
        ModelScript::status(503),
        ModelScript::final_text("ZODE_LIVE_OK"),
        ModelScript::final_text("ZODE_LIVE_RESTART_OK"),
    ])
    .await?;
    let run_directory = new_llm_recording_run_dir()?;
    let recording_id = run_directory
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::other("pre-stream recording run id was invalid"))?
        .to_owned();
    let mut recorder = LlmHttpProxy::record_with_attempt_plan(
        provider.origin(),
        PROVIDER,
        MODEL,
        &run_directory,
        LlmHttpRecordingMetadata {
            recording_id,
            purpose: "pre_stream_retry_503_then_200".to_owned(),
            owner: "e2e_llm_recorder_captures_pre_stream_retry_as_ordered_wire_attempts".to_owned(),
            boundary: "endpoint_aimux_provider_http".to_owned(),
            secret_slots: vec!["SLOT_PROVIDER_AUTHORIZATION_HEADER".to_owned()],
        },
        attempt_plan,
    )
    .await?;
    let database = TempDatabase::new("record-pre-stream-retry")?;
    let config = config_for_replay(database.path(), &recorder.base_url(""))?;
    let primary = run_provider_roundtrip_and_restart(ProviderRoundtripSpec {
        database: database.path().to_owned(),
        config,
        provider_base_url: recorder.base_url("/v1"),
        provider: PROVIDER.to_owned(),
        model: MODEL.to_owned(),
        profile: PROFILE.to_owned(),
        subject: SUBJECT.to_owned(),
        provider_secret: REPLAY_SECRET.to_owned(),
        first_prompt: FIRST_PROMPT.to_owned(),
        first_marker: "ZODE_LIVE_OK".to_owned(),
        restart_prompt: RESTART_PROMPT.to_owned(),
        restart_marker: "ZODE_LIVE_RESTART_OK".to_owned(),
        idempotency_prefix: "record-pre-stream-retry".to_owned(),
        forbidden: vec![REPLAY_SECRET.to_owned(), TEST_CONTROLLER_SECRET.to_owned()],
        child_environment: Vec::new(),
    })
    .await;
    let recorder_stop = recorder.stop().await;
    let provider_stop = provider.stop().await;
    primary?;
    recorder_stop?;
    provider_stop?;
    if let Some(error) = recorder.flush_error() {
        return Err(Error::other(format!("pre-stream recording flush failed: {error}")).into());
    }
    let recording = recorder.recording()?;
    recording.write_atomic(
        &run_directory.join("recording.json"),
        &[REPLAY_SECRET, TEST_CONTROLLER_SECRET],
    )?;
    scan_llm_recording_tree(&run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    Ok((recording, run_directory))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_llm_recorder_redacts_authorization_into_named_synthetic_slot() -> TestResult<()> {
    const SLOT: &str = "SLOT_PROVIDER_AUTHORIZATION_HEADER";
    let mut provider =
        ModelFixture::start(vec![ModelScript::final_text("auth slot final")]).await?;
    let (mut recorder, run_directory) = start_synthetic_recorder(
        provider.origin(),
        "synthetic_authorization_slot",
        "e2e_llm_recorder_redacts_authorization_into_named_synthetic_slot",
    )
    .await?;
    let database = TempDatabase::new("recording-authorization-slot")?;
    let config = config_for_replay(database.path(), &recorder.base_url("/v1"))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database,
            config,
            recorder.base_url("/v1"),
            "recording-authorization-slot",
        ),
        cancel.clone(),
    ));
    recorder.wait_for_completed_exchanges(1).await?;
    cancel.notify_one();
    attempt.await.map_err(|error| {
        Error::other(format!("authorization-slot exercise task failed: {error}"))
    })??;
    let upstream_headers = provider
        .request_headers(0)
        .ok_or_else(|| Error::other("provider fixture did not retain request headers"))?;
    let authorization = upstream_headers["authorization"]
        .as_str()
        .ok_or_else(|| Error::other("provider fixture request omitted authorization"))?;
    if !authorization.contains(REPLAY_SECRET) {
        return Err(
            Error::other("provider fixture did not receive the installed authorization").into(),
        );
    }
    recorder.stop().await?;
    provider.stop().await?;
    let recording = recorder.recording()?;
    if !recording.secret_slots.iter().any(|slot| slot == SLOT) {
        return Err(Error::other("recording omitted the authorization synthetic slot").into());
    }
    assert_recording_secret_free(&recording, &[REPLAY_SECRET])?;
    if recording.requests.iter().any(|exchange| {
        exchange
            .request
            .semantic_headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("authorization"))
    }) {
        return Err(Error::other("recording retained authorization material").into());
    }
    let first = recording
        .requests
        .first()
        .ok_or_else(|| Error::other("authorization recording omitted its first request"))?;
    let body = decode_hex(&first.request.raw_body_hex)?;
    for literal in [
        None,
        Some("Bearer SLOT_PROVIDER_AUTHORIZATION_HEADER"),
        Some("Bearer wrong-provider-key"),
    ] {
        let mut replay = LlmHttpProxy::replay_with_authorization(
            recording.clone(),
            false,
            Some(REPLAY_SECRET.to_owned()),
        )
        .await?;
        let mut request = http_client()?.post(replay.base_url(&first.request.path));
        for semantic in &first.request.semantic_headers {
            request = request.header(&semantic.name, &semantic.value);
        }
        if let Some(value) = literal {
            request = request.header("authorization", value);
        }
        let response = request.body(body.clone()).send().await?;
        if response.status().as_u16() != StatusCode::CONFLICT.as_u16() {
            return Err(Error::other(
                "replay accepted a missing or literal synthetic authorization",
            )
            .into());
        }
        replay.stop().await?;
    }
    let mut replay = LlmHttpProxy::replay_with_authorization(
        recording.clone(),
        false,
        Some(REPLAY_SECRET.to_owned()),
    )
    .await?;
    let mut request = http_client()?.post(replay.base_url(&first.request.path));
    for semantic in &first.request.semantic_headers {
        request = request.header(&semantic.name, &semantic.value);
    }
    let response = request
        .header("authorization", format!("Bearer {REPLAY_SECRET}"))
        .body(body)
        .send()
        .await?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(Error::other("replay rejected the bound authorization value").into());
    }
    let _ = response.bytes().await?;
    if !replay.replay_exhausted() {
        return Err(Error::other("bound authorization replay did not consume its exchange").into());
    }
    replay.stop().await?;
    replay_synthetic_failure(recording.clone(), "replay-authorization-slot").await?;
    recording.write_atomic(
        &run_directory.join("recording.json"),
        &[REPLAY_SECRET, TEST_CONTROLLER_SECRET],
    )?;
    scan_llm_recording_tree(&run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_llm_recorder_explicit_authorization_requirement_covers_custom_slot() -> TestResult<()>
{
    const CUSTOM_SLOT: &str = "SLOT_PROVIDER_AUTH";
    let mut provider =
        ModelFixture::start(vec![ModelScript::final_text("custom auth slot final")]).await?;
    let run_directory = new_llm_recording_run_dir()?;
    let recording_id = run_directory
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::other("custom auth recording run id was invalid"))?
        .to_owned();
    let mut recorder = LlmHttpProxy::record_with_attempt_plan_and_authorization(
        provider.origin(),
        PROVIDER,
        MODEL,
        &run_directory,
        LlmHttpRecordingMetadata {
            recording_id,
            purpose: "explicit_custom_authorization_slot".to_owned(),
            owner: "e2e_llm_recorder_explicit_authorization_requirement_covers_custom_slot"
                .to_owned(),
            boundary: "endpoint_aimux_provider_http".to_owned(),
            secret_slots: vec![CUSTOM_SLOT.to_owned()],
        },
        None,
        true,
    )
    .await?;
    let database = TempDatabase::new("recording-custom-auth-slot")?;
    let config = config_for_replay(database.path(), &recorder.base_url("/v1"))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database,
            config,
            recorder.base_url("/v1"),
            "recording-custom-auth-slot",
        ),
        cancel.clone(),
    ));
    recorder.wait_for_completed_exchanges(1).await?;
    cancel.notify_one();
    attempt
        .await
        .map_err(|error| Error::other(format!("custom auth-slot exercise failed: {error}")))??;
    recorder.stop().await?;
    provider.stop().await?;
    let recording = recorder.recording()?;
    if recording.secret_slots != vec![CUSTOM_SLOT.to_owned()] {
        return Err(Error::other("custom authorization slot was not retained").into());
    }
    let first = recording
        .requests
        .first()
        .ok_or_else(|| Error::other("custom authorization recording omitted its request"))?;
    let body = decode_hex(&first.request.raw_body_hex)?;
    let path = first.request.path.clone();
    let semantic_headers = first.request.semantic_headers.clone();
    let mut replay = LlmHttpProxy::replay_with_authorization(
        recording.clone(),
        false,
        Some(REPLAY_SECRET.into()),
    )
    .await?;
    let mut request = http_client()?.post(replay.base_url(&path));
    for semantic in &semantic_headers {
        request = request.header(&semantic.name, &semantic.value);
    }
    let response = request.body(body.clone()).send().await?;
    if response.status() != reqwest::StatusCode::CONFLICT {
        return Err(Error::other(
            "replay accepted a missing Authorization header for an explicit custom slot",
        )
        .into());
    }
    replay.stop().await?;
    let mut replay = LlmHttpProxy::replay_with_authorization(
        recording.clone(),
        false,
        Some(REPLAY_SECRET.into()),
    )
    .await?;
    let mut request = http_client()?.post(replay.base_url(&path));
    for semantic in &semantic_headers {
        request = request.header(&semantic.name, &semantic.value);
    }
    let response = request
        .header("authorization", format!("Bearer {REPLAY_SECRET}"))
        .body(body)
        .send()
        .await?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(Error::other(
            "replay rejected the bound Authorization header for a custom slot",
        )
        .into());
    }
    let _ = response.bytes().await?;
    replay.stop().await?;
    recording.write_atomic(
        &run_directory.join("recording.json"),
        &[REPLAY_SECRET, TEST_CONTROLLER_SECRET],
    )?;
    scan_llm_recording_tree(&run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_model_replay_rejects_wrong_provider_authorization() -> TestResult<()> {
    const WRONG_PROVIDER_REPLICA: &str = "wrong-provider-replica-key";

    // Capture through the real Endpoint + temporary SQLite process before
    // exercising the compatibility replay entry.  This keeps the cassette's
    // provider request and synthetic Authorization slot tied to the public
    // model path rather than a hand-built request.
    let (recording, _run_directory) =
        capture_complete_recording_for("e2e_model_replay_rejects_wrong_provider_authorization")
            .await?;
    let mut replay = LlmHttpProxy::replay(recording, false).await?;
    let database = TempDatabase::new("model-replay-wrong-provider-authorization")?;
    let config = config_for_replay(database.path(), &replay.base_url(""))?;
    let mut spec = synthetic_spec(
        &database,
        config,
        replay.base_url("/v1"),
        "model-replay-wrong-provider-authorization",
    );
    spec.provider_secret = WRONG_PROVIDER_REPLICA.to_owned();
    spec.forbidden.push(WRONG_PROVIDER_REPLICA.to_owned());

    // The replay proxy must reject the wrong replica with a typed HTTP
    // failure before consuming the cassette.  The Endpoint's public SSE
    // path consequently reports model_attempt_failed and cannot commit an
    // assistant message from the replayed response.
    run_provider_failure(spec).await?;
    if !replay.observed_requests().is_empty() {
        return Err(Error::other(
            "wrong provider authorization reached cassette matching and could produce an assistant",
        )
        .into());
    }
    if replay.replay_exhausted() {
        return Err(
            Error::other("wrong provider authorization consumed the replay exchange").into(),
        );
    }
    replay.stop().await?;
    Ok(())
}

fn synthetic_spec(
    database: &TempDatabase,
    config: PathBuf,
    provider_base_url: String,
    prefix: &str,
) -> ProviderRoundtripSpec {
    ProviderRoundtripSpec {
        database: database.path().to_owned(),
        config,
        provider_base_url,
        provider: PROVIDER.to_owned(),
        model: MODEL.to_owned(),
        profile: PROFILE.to_owned(),
        subject: SUBJECT.to_owned(),
        provider_secret: REPLAY_SECRET.to_owned(),
        first_prompt: "exercise recorder failure path".to_owned(),
        first_marker: "unused".to_owned(),
        restart_prompt: "unused".to_owned(),
        restart_marker: "unused".to_owned(),
        idempotency_prefix: prefix.to_owned(),
        forbidden: vec![REPLAY_SECRET.to_owned(), TEST_CONTROLLER_SECRET.to_owned()],
        child_environment: Vec::new(),
    }
}

async fn start_synthetic_recorder(
    upstream: String,
    purpose: &str,
    owner: &str,
) -> TestResult<(LlmHttpProxy, PathBuf)> {
    start_synthetic_recorder_with_plan(upstream, purpose, owner, None).await
}

async fn start_synthetic_recorder_with_plan(
    upstream: String,
    purpose: &str,
    owner: &str,
    attempt_plan: Option<Vec<LlmHttpAttemptPlan>>,
) -> TestResult<(LlmHttpProxy, PathBuf)> {
    let run_directory = new_llm_recording_run_dir()?;
    let recording_id = run_directory
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::other("synthetic recording run id was invalid"))?
        .to_owned();
    let recorder = LlmHttpProxy::record_with_attempt_plan(
        upstream,
        PROVIDER,
        MODEL,
        &run_directory,
        LlmHttpRecordingMetadata {
            recording_id,
            purpose: purpose.to_owned(),
            owner: owner.to_owned(),
            boundary: "endpoint_aimux_provider_http".to_owned(),
            secret_slots: vec!["SLOT_PROVIDER_AUTHORIZATION_HEADER".to_owned()],
        },
        attempt_plan,
    )
    .await?;
    Ok((recorder, run_directory))
}

async fn finish_synthetic_recorder(
    recorder: &mut LlmHttpProxy,
    run_directory: &Path,
) -> TestResult<LlmHttpRecording> {
    recorder.stop().await?;
    if let Some(error) = recorder.flush_error() {
        return Err(Error::other(format!("synthetic recording flush failed: {error}")).into());
    }
    let recording = recorder.recording()?;
    recording.write_atomic(
        &run_directory.join("recording.json"),
        &[REPLAY_SECRET, TEST_CONTROLLER_SECRET],
    )?;
    scan_llm_recording_tree(run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    Ok(recording)
}

/// Retain the first post-adoption reproduction of the exact-origin fixture
/// gap.  The intentionally mismatched allowlist makes the real Endpoint
/// reject session admission before any provider-boundary recorder exchange;
/// the public 422 request/response is durably captured in its own quarantine
/// run and is explicitly related to (rather than relabelled as) the retained
/// historical gap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_later_test_reproduction_of_exact_origin_gap() -> TestResult<()> {
    let mut provider =
        ModelFixture::start(vec![ModelScript::final_text("unreachable provider")]).await?;
    let (mut recorder, recorder_directory) = start_synthetic_recorder(
        provider.origin(),
        "later_exact_origin_gap_reproduction",
        "later_test_reproduction_of_gap",
    )
    .await?;
    let evidence_directory = new_llm_recording_run_dir()?;
    let database = TempDatabase::new("later-exact-origin-gap")?;
    // Deliberately preserve the pre-fix fixture mismatch: the policy allows
    // the upstream fixture origin while the model descriptor names the test
    // recorder origin.  Production compares complete URL origins exactly.
    let config = config_for_replay(database.path(), &provider.origin())?;
    let mut endpoint = TestZode::start(
        database.path(),
        &config,
        &[REPLAY_SECRET, TEST_CONTROLLER_SECRET],
    )
    .await?;
    let request_body = json!({
        "model": {
            "provider": PROVIDER,
            "provider_execution": {
                "schema": "zode.provider-execution.v1",
                "revision": 1,
                "kind": "openai_compatible",
                "base_url": recorder.base_url("/v1")
            },
            "model": MODEL,
            "auth_authority_id": TEST_CONTROLLER_AUTHORITY,
            "auth_profile_id": PROFILE,
            "minimum_auth_revision": 1
        }
    });
    let request_bytes = serde_json::to_vec(&request_body)?;
    let response = authenticated_as(http_client()?.post(endpoint.url("/v1/sessions")), SUBJECT)
        .header("Idempotency-Key", "later-test-reproduction-of-gap")
        .json(&request_body)
        .send()
        .await?;
    let status = response.status();
    let response_body = response.bytes().await?;
    let evidence_path = persist_public_http_gap_exchange(
        &evidence_directory,
        PublicHttpGapExchange {
            e2e_name: "later_test_reproduction_of_gap",
            relation: "later_test_reproduction_of_gap",
            boundary: "public.session_create",
            method: "POST",
            path: "/v1/sessions",
            request_body: &request_bytes,
            response_status: status.as_u16(),
            response_body: &response_body,
        },
    )?;
    let recorder_requests = recorder.observed_requests();
    let provider_requests = provider.request_count();
    let endpoint_stop = endpoint
        .stop(&[REPLAY_SECRET, TEST_CONTROLLER_SECRET])
        .await;
    let recorder_stop = recorder.stop().await;
    let provider_stop = provider.stop().await;
    endpoint_stop?;
    recorder_stop?;
    provider_stop?;
    if status != reqwest::StatusCode::UNPROCESSABLE_ENTITY {
        return Err(Error::other(format!(
            "later exact-origin reproduction returned HTTP {status}, expected 422"
        ))
        .into());
    }
    if !recorder_requests.is_empty() || provider_requests != 0 {
        return Err(Error::other(format!(
            "session-create 422 unexpectedly reached provider boundary (recorder={}, provider={provider_requests})",
            recorder_requests.len()
        ))
        .into());
    }
    scan_llm_recording_tree(
        &evidence_directory,
        &[REPLAY_SECRET, TEST_CONTROLLER_SECRET],
    )?;
    scan_llm_recording_tree(
        &recorder_directory,
        &[REPLAY_SECRET, TEST_CONTROLLER_SECRET],
    )?;
    eprintln!(
        "later_test_reproduction_of_gap retained public 422 evidence at {} (recorder barrier: 0 exchanges)",
        evidence_path.display()
    );
    Ok(())
}

async fn capture_stream_error_recording() -> TestResult<(LlmHttpRecording, PathBuf)> {
    let hold = ModelHold::new();
    let mut provider =
        ModelFixture::start(vec![ModelScript::stream_failure_hold(hold.clone())]).await?;
    let (mut recorder, run_directory) = start_synthetic_recorder(
        provider.origin(),
        "synthetic_aborted_terminal_stream",
        "e2e_recorded_provider_replay_does_not_count_aborted_terminal_stream",
    )
    .await?;
    let database = TempDatabase::new("recording-aborted-terminal-stream")?;
    let config = config_for_replay(database.path(), &recorder.base_url("/v1"))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database,
            config,
            recorder.base_url("/v1"),
            "recording-aborted-terminal-stream",
        ),
        cancel.clone(),
    ));
    hold.wait_entered().await?;
    recorder.wait_for_recorded_chunks(1).await?;
    hold.release();
    recorder.wait_for_completed_exchanges(1).await?;
    cancel.notify_one();
    attempt
        .await
        .map_err(|error| Error::other(format!("terminal-stream capture task failed: {error}")))??;
    recorder.stop().await?;
    provider.stop().await?;
    let recording = recorder.recording()?;
    if recording.requests.len() != 1
        || !matches!(
            recording.requests[0].response.outcome,
            LlmHttpResponseOutcome::StreamError
        )
    {
        return Err(Error::other("terminal-stream fixture did not retain StreamError").into());
    }
    recording.write_atomic(
        &run_directory.join("recording.json"),
        &[REPLAY_SECRET, TEST_CONTROLLER_SECRET],
    )?;
    scan_llm_recording_tree(&run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    Ok((recording, run_directory))
}

async fn capture_transport_error_recording() -> TestResult<(LlmHttpRecording, PathBuf)> {
    let (mut recorder, run_directory) = start_synthetic_recorder_with_plan(
        "http://127.0.0.1:1".to_owned(),
        "synthetic_transport_terminal_consumption",
        "e2e_recorded_provider_replay_requires_transport_error_terminal_consumption",
        Some(vec![
            LlmHttpAttemptPlan {
                logical_round: 0,
                wire_attempt: 0,
            },
            LlmHttpAttemptPlan {
                logical_round: 0,
                wire_attempt: 1,
            },
            LlmHttpAttemptPlan {
                logical_round: 0,
                wire_attempt: 2,
            },
        ]),
    )
    .await?;
    let database = TempDatabase::new("recording-transport-terminal-consumption")?;
    let config = config_for_replay(database.path(), &recorder.base_url(""))?;
    run_provider_failure(synthetic_spec(
        &database,
        config,
        recorder.base_url("/v1"),
        "recording-transport-terminal-consumption",
    ))
    .await?;
    recorder.stop().await?;
    let recording = recorder.recording()?;
    if recording.requests.len() != 3
        || recording
            .requests
            .iter()
            .enumerate()
            .any(|(index, exchange)| {
                exchange.logical_round != 0
                    || exchange.wire_attempt != index as u64
                    || !matches!(
                        exchange.response.outcome,
                        LlmHttpResponseOutcome::TransportError
                    )
            })
    {
        return Err(Error::other(
            "transport-error fixture did not retain its ordered wire attempts",
        )
        .into());
    }
    recording.write_atomic(
        &run_directory.join("recording.json"),
        &[REPLAY_SECRET, TEST_CONTROLLER_SECRET],
    )?;
    scan_llm_recording_tree(&run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    Ok((recording, run_directory))
}

async fn capture_complete_recording() -> TestResult<(LlmHttpRecording, PathBuf)> {
    capture_complete_recording_for(
        "e2e_recorded_provider_replay_does_not_count_aborted_complete_before_terminal",
    )
    .await
}

async fn capture_complete_recording_for(owner: &str) -> TestResult<(LlmHttpRecording, PathBuf)> {
    let mut provider =
        ModelFixture::start(vec![ModelScript::final_text("complete terminal hold")]).await?;
    let (mut recorder, run_directory) =
        start_synthetic_recorder(provider.origin(), "synthetic_complete_terminal_hold", owner)
            .await?;
    let database = TempDatabase::new("recording-complete-terminal-hold")?;
    let config = config_for_replay(database.path(), &recorder.base_url("/v1"))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database,
            config,
            recorder.base_url("/v1"),
            "recording-complete-terminal-hold",
        ),
        cancel.clone(),
    ));
    recorder.wait_for_completed_exchanges(1).await?;
    cancel.notify_one();
    attempt.await.map_err(|error| {
        Error::other(format!("complete-terminal capture task failed: {error}"))
    })??;
    recorder.stop().await?;
    provider.stop().await?;
    let recording = recorder.recording()?;
    if recording.requests.len() != 1
        || !matches!(
            recording.requests[0].response.outcome,
            LlmHttpResponseOutcome::Complete { .. }
        )
    {
        return Err(Error::other("complete-terminal fixture did not retain Complete").into());
    }
    recording.write_atomic(
        &run_directory.join("recording.json"),
        &[REPLAY_SECRET, TEST_CONTROLLER_SECRET],
    )?;
    scan_llm_recording_tree(&run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    Ok((recording, run_directory))
}

async fn replay_synthetic_failure(recording: LlmHttpRecording, prefix: &str) -> TestResult<()> {
    let expected = recording.requests.len();
    let mut replay =
        LlmHttpProxy::replay_with_authorization(recording, false, Some(REPLAY_SECRET.to_owned()))
            .await?;
    let database = TempDatabase::new(prefix)?;
    let config = config_for_replay(database.path(), &replay.base_url(""))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(&database, config, replay.base_url("/v1"), prefix),
        cancel.clone(),
    ));
    replay.wait_for_completed_exchanges(expected).await?;
    cancel.notify_one();
    let primary = attempt
        .await
        .map_err(|error| Error::other(format!("synthetic replay task failed: {error}")))?;
    let exhausted = replay.replay_exhausted();
    replay.stop().await?;
    primary?;
    if !exhausted {
        return Err(Error::other("synthetic replay did not consume exactly its cassette").into());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_recorded_opencode_provider_roundtrip_and_restart() -> TestResult<()> {
    let recording = LlmHttpRecording::load(&recording_path())?;
    if recording.requests.len() < 2 {
        return Err(Error::other("provider recording omitted one of the two model rounds").into());
    }

    let captured_timing = std::env::var("ZODE_REPLAY_CAPTURED_TIMING").as_deref() == Ok("1");
    let started = std::time::Instant::now();
    replay_recording_roundtrip(&recording, captured_timing, "recorded-provider").await?;
    eprintln!(
        "recorded provider replay mode={} total_ms={} exchanges={}",
        if captured_timing {
            "captured"
        } else {
            "immediate"
        },
        started.elapsed().as_millis(),
        recording.requests.len()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_llm_recorder_captures_pre_stream_retry_as_ordered_wire_attempts() -> TestResult<()> {
    let (recording, run_directory) = capture_pre_stream_retry().await?;
    assert_pre_stream_retry_recording(&recording)?;
    let persisted = LlmHttpRecording::load(&run_directory.join("recording.json"))?;
    assert_pre_stream_retry_recording(&persisted)?;
    replay_recording_roundtrip(&persisted, false, "replay-pre-stream-retry").await?;
    eprintln!(
        "pre-stream retry capture/replay retained at {}",
        run_directory.display()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_llm_recorder_uses_explicit_attempt_plan_for_identical_round_bodies() -> TestResult<()>
{
    let plan = vec![
        LlmHttpAttemptPlan {
            logical_round: 0,
            wire_attempt: 0,
        },
        LlmHttpAttemptPlan {
            logical_round: 1,
            wire_attempt: 0,
        },
        LlmHttpAttemptPlan {
            logical_round: 2,
            wire_attempt: 0,
        },
    ];
    let (recording, run_directory) = capture_pre_stream_retry_with_plan(Some(plan.clone())).await?;
    let attempts = recording
        .requests
        .iter()
        .map(|exchange| (exchange.logical_round, exchange.wire_attempt))
        .collect::<Vec<_>>();
    if attempts != vec![(0, 0), (1, 0), (2, 0)] {
        return Err(Error::other(format!(
            "explicit attempt plan was not retained: {attempts:?}"
        ))
        .into());
    }
    if recording.requests[0].request.canonical_json != recording.requests[1].request.canonical_json
    {
        return Err(Error::other(
            "explicit-plan fixture did not exercise identical request bodies",
        )
        .into());
    }
    let persisted = LlmHttpRecording::load(&run_directory.join("recording.json"))?;
    if persisted
        .requests
        .iter()
        .map(|exchange| (exchange.logical_round, exchange.wire_attempt))
        .collect::<Vec<_>>()
        != attempts
    {
        return Err(Error::other("persisted attempt plan differed from capture").into());
    }
    replay_recording_roundtrip(&persisted, false, "replay-explicit-attempt-plan").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_recorded_provider_replay_does_not_count_aborted_terminal_stream() -> TestResult<()> {
    let (recording, _run_directory) = capture_stream_error_recording().await?;
    let chunk_count = recording.requests[0].response.chunks.len() as u64;
    let terminal_hold = Arc::new(Notify::new());
    let mut replay = LlmHttpProxy::replay_with_terminal_hold(
        recording,
        false,
        Some(REPLAY_SECRET.to_owned()),
        terminal_hold.clone(),
    )
    .await?;
    let database = TempDatabase::new("replay-aborted-terminal-stream")?;
    let config = config_for_replay(database.path(), &replay.base_url(""))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database,
            config,
            replay.base_url("/v1"),
            "replay-aborted-terminal-stream",
        ),
        cancel.clone(),
    ));
    replay.wait_for_replayed_chunks(chunk_count).await?;
    cancel.notify_one();
    attempt.await.map_err(|error| {
        Error::other(format!(
            "aborted terminal-stream replay task failed: {error}"
        ))
    })??;
    if replay.replay_exhausted() {
        return Err(
            Error::other("aborted terminal stream was counted as an exhausted replay").into(),
        );
    }
    // Assert while the terminal outcome is still held.  Releasing the hold
    // first would let a graceful proxy shutdown race the cancellation and
    // accidentally turn the aborted stream into a consumed terminal error.
    terminal_hold.notify_one();
    replay.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_recorded_provider_replay_does_not_count_aborted_complete_before_terminal(
) -> TestResult<()> {
    let (recording, _run_directory) = capture_complete_recording().await?;
    let chunk_count = recording.requests[0].response.chunks.len() as u64;
    let terminal_hold = Arc::new(Notify::new());
    let mut replay = LlmHttpProxy::replay_with_terminal_hold(
        recording,
        false,
        Some(REPLAY_SECRET.to_owned()),
        terminal_hold.clone(),
    )
    .await?;
    let database = TempDatabase::new("replay-aborted-complete-terminal").map_err(|error| {
        Error::other(format!("complete-terminal replay database failed: {error}"))
    })?;
    let config = config_for_replay(database.path(), &replay.base_url(""))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database,
            config,
            replay.base_url("/v1"),
            "replay-aborted-complete-terminal",
        ),
        cancel.clone(),
    ));
    replay.wait_for_replayed_chunks(chunk_count).await?;
    cancel.notify_one();
    attempt.await.map_err(|error| {
        Error::other(format!(
            "aborted complete-terminal replay task failed: {error}"
        ))
    })??;
    if replay.replay_exhausted() {
        return Err(Error::other(
            "aborted Complete stream was counted before terminal confirmation",
        )
        .into());
    }
    terminal_hold.notify_one();
    replay.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_recorded_provider_replay_requires_transport_error_terminal_consumption(
) -> TestResult<()> {
    let (recording, _run_directory) = capture_transport_error_recording().await?;
    let terminal_hold = Arc::new(Notify::new());
    let mut replay = LlmHttpProxy::replay_with_terminal_hold(
        recording,
        false,
        Some(REPLAY_SECRET.to_owned()),
        terminal_hold.clone(),
    )
    .await?;
    let database = TempDatabase::new("replay-transport-terminal-consumption")?;
    let config = config_for_replay(database.path(), &replay.base_url(""))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database,
            config,
            replay.base_url("/v1"),
            "replay-transport-terminal-consumption",
        ),
        cancel.clone(),
    ));
    replay.wait_for_replay_terminal_hold().await?;
    cancel.notify_one();
    attempt
        .await
        .map_err(|error| Error::other(format!("transport terminal abort failed: {error}")))??;
    if replay.replay_exhausted() {
        return Err(Error::other(
            "transport-error replay was counted before terminal body consumption",
        )
        .into());
    }
    terminal_hold.notify_one();
    replay.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_recorded_provider_replay_rejects_oversized_response_cassette() -> TestResult<()> {
    let (recording, _run_directory) = capture_complete_recording().await?;
    let mut oversized = recording;
    let response = &mut oversized.requests[0].response;
    let chunk = response
        .chunks
        .first_mut()
        .ok_or_else(|| Error::other("oversized cassette fixture omitted a response chunk"))?;
    chunk.bytes_hex = "78".repeat(MAX_LLM_RESPONSE_BYTES + 1);
    chunk.sequence = 0;
    chunk.at_us = 0;
    response.chunks.truncate(1);
    response.outcome = LlmHttpResponseOutcome::Complete { done_seen: false };
    let oversized = digest_without_validation(oversized)?;
    let result = LlmHttpProxy::replay(oversized, false).await;
    let error = match result {
        Ok(_) => {
            return Err(Error::other(
                "replay accepted a digest-valid response cassette above the capture bound",
            )
            .into())
        }
        Err(error) => error,
    };
    if !error.to_string().contains("byte bound") {
        return Err(Error::other(format!(
            "oversized cassette was rejected with the wrong typed failure: {error}"
        ))
        .into());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_recorded_provider_replay_rejects_unbounded_captured_timing() -> TestResult<()> {
    let (recording, _run_directory) = capture_complete_recording().await?;
    let mut unbounded = recording;
    for chunk in &mut unbounded.requests[0].response.chunks {
        chunk.at_us = MAX_LLM_CHUNK_DELAY_US + 1;
    }
    let unbounded = digest_without_validation(unbounded)?;
    let result = LlmHttpProxy::replay(unbounded, true).await;
    let error = match result {
        Ok(_) => {
            return Err(
                Error::other("captured replay accepted an unbounded chunk timing value").into(),
            )
        }
        Err(error) => error,
    };
    if !error.to_string().contains("timing bound") {
        return Err(Error::other(format!(
            "unbounded captured timing was rejected with the wrong typed failure: {error}"
        ))
        .into());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_recorded_provider_replay_accepts_long_total_stream_with_bounded_inter_chunk_delays(
) -> TestResult<()> {
    let (recording, _run_directory) = capture_complete_recording_for(
        "e2e_recorded_provider_replay_accepts_long_total_stream_with_bounded_inter_chunk_delays",
    )
    .await?;
    let mut long_stream = recording;
    let chunks = &mut long_stream.requests[0].response.chunks;
    if chunks.len() < 2 {
        return Err(Error::other("long-stream timing fixture needs at least two chunks").into());
    }
    let bounded_gap = MAX_LLM_CHUNK_DELAY_US / 2 + 1;
    for (index, chunk) in chunks.iter_mut().enumerate() {
        chunk.at_us = bounded_gap.saturating_mul(index as u64 + 1);
    }
    if chunks.last().map_or(0, |chunk| chunk.at_us) <= MAX_LLM_CHUNK_DELAY_US {
        return Err(Error::other("long-stream timing fixture did not exceed one idle gap").into());
    }
    let long_stream = digest_without_validation(long_stream)?;
    replay_synthetic_failure(long_stream, "replay-long-total-stream-bounded-gaps").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_llm_recorder_rejects_ambiguous_attempt_identity() -> TestResult<()> {
    let mut provider = ModelFixture::start(vec![
        ModelScript::final_text("ambiguous first"),
        ModelScript::final_text("ambiguous second"),
    ])
    .await?;
    let (mut recorder, run_directory) = start_synthetic_recorder(
        provider.origin(),
        "synthetic_ambiguous_attempt_identity",
        "e2e_llm_recorder_rejects_ambiguous_attempt_identity",
    )
    .await?;

    let database_a = TempDatabase::new("recording-ambiguous-attempt-a")?;
    let config_a = config_for_replay(database_a.path(), &recorder.base_url(""))?;
    let cancel_a = Arc::new(Notify::new());
    let task_a = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database_a,
            config_a,
            recorder.base_url("/v1"),
            "recording-ambiguous-attempt-a",
        ),
        cancel_a.clone(),
    ));
    recorder.wait_for_completed_exchanges(1).await?;
    cancel_a.notify_one();
    task_a
        .await
        .map_err(|error| Error::other(format!("first ambiguous attempt failed: {error}")))??;

    let database_b = TempDatabase::new("recording-ambiguous-attempt-b")?;
    let config_b = config_for_replay(database_b.path(), &recorder.base_url(""))?;
    let cancel_b = Arc::new(Notify::new());
    let task_b = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database_b,
            config_b,
            recorder.base_url("/v1"),
            "recording-ambiguous-attempt-b",
        ),
        cancel_b.clone(),
    ));
    recorder.wait_for_completed_exchanges(2).await?;
    cancel_b.notify_one();
    task_b
        .await
        .map_err(|error| Error::other(format!("second ambiguous attempt failed: {error}")))??;
    let observed = recorder.observed_requests();
    if observed.len() != 2 || observed[0].canonical_json != observed[1].canonical_json {
        return Err(Error::other(
            "ambiguous-attempt fixture did not produce identical canonical bodies",
        )
        .into());
    }
    recorder.stop().await?;
    provider.stop().await?;
    let result = recorder.recording();
    if result
        .as_ref()
        .err()
        .and_then(|error| {
            error
                .to_string()
                .contains("ambiguous attempt identity")
                .then_some(())
        })
        .is_none()
    {
        return Err(Error::other(
            "recorder silently inferred a retry for identical logical-round bodies",
        )
        .into());
    }
    scan_llm_recording_tree(&run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_llm_recorder_rejects_interleaved_attempt_without_explicit_plan() -> TestResult<()> {
    let first_hold = ModelHold::new();
    let mut provider = ModelFixture::start(vec![
        ModelScript::hold_entered(first_hold.clone(), ModelScript::final_text("first")),
        ModelScript::final_text("second"),
    ])
    .await?;
    let (mut recorder, run_directory) = start_synthetic_recorder(
        provider.origin(),
        "synthetic_interleaved_attempt_identity",
        "e2e_llm_recorder_rejects_interleaved_attempt_without_explicit_plan",
    )
    .await?;
    let database_a = TempDatabase::new("recording-interleaved-attempt-a")?;
    let config_a = config_for_replay(database_a.path(), &recorder.base_url(""))?;
    let cancel_a = Arc::new(Notify::new());
    let task_a = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database_a,
            config_a,
            recorder.base_url("/v1"),
            "recording-interleaved-attempt-a",
        ),
        cancel_a.clone(),
    ));
    first_hold.wait_entered().await?;

    let database_b = TempDatabase::new("recording-interleaved-attempt-b")?;
    let config_b = config_for_replay(database_b.path(), &recorder.base_url(""))?;
    let mut spec_b = synthetic_spec(
        &database_b,
        config_b,
        recorder.base_url("/v1"),
        "recording-interleaved-attempt-b",
    );
    spec_b.first_prompt = "distinct interleaved logical round".to_owned();
    let cancel_b = Arc::new(Notify::new());
    let task_b = tokio::spawn(run_provider_attempt_until_cancel(spec_b, cancel_b.clone()));
    recorder.wait_for_submitted_exchanges(1).await?;
    first_hold.release();
    recorder.wait_for_submitted_exchanges(2).await?;
    cancel_a.notify_one();
    cancel_b.notify_one();
    task_a
        .await
        .map_err(|error| Error::other(format!("interleaved first task failed: {error}")))??;
    task_b
        .await
        .map_err(|error| Error::other(format!("interleaved second task failed: {error}")))??;
    recorder.stop().await?;
    provider.stop().await?;
    let error = recorder
        .recording()
        .expect_err("interleaved no-plan capture silently inferred attempt identity");
    if !error.to_string().contains("ambiguous attempt identity") {
        return Err(Error::other(format!(
            "interleaved capture returned the wrong failure class: {error}"
        ))
        .into());
    }
    scan_llm_recording_tree(&run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_llm_recording_flush_failure_blocks_live_promotion() -> TestResult<()> {
    let mut provider = ModelFixture::start(vec![ModelScript::final_text("fixture final")]).await?;
    let (mut recorder, run_directory) = start_synthetic_recorder(
        provider.origin(),
        "synthetic_flush_failure",
        "e2e_llm_recording_flush_failure_blocks_live_promotion",
    )
    .await?;
    let occupied_ingress = run_directory.join("ingress-00000000000000000000.json");
    fs::write(&occupied_ingress, b"test-owned flush collision")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&occupied_ingress, fs::Permissions::from_mode(0o600))?;
    }

    let database = TempDatabase::new("recording-flush-failure")?;
    let config = config_for_replay(database.path(), &recorder.base_url(""))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database,
            config,
            recorder.base_url("/v1"),
            "recording-flush-failure",
        ),
        cancel.clone(),
    ));
    recorder.wait_for_observed_requests(1).await?;
    if provider.request_count() != 0 {
        return Err(
            Error::other("provider request escaped after durable ingress capture failed").into(),
        );
    }
    cancel.notify_one();
    attempt
        .await
        .map_err(|error| Error::other(format!("flush-failure exercise task failed: {error}")))??;
    recorder.stop().await?;
    provider.stop().await?;

    if recorder.flush_error().is_none() {
        return Err(
            Error::other("recording ingress failure was not retained as a flush error").into(),
        );
    }
    let promotion = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("flush-failure database had no parent"))?
        .join("must-not-promote.json");
    if let Ok(recording) = recorder.recording() {
        recording.write_atomic(&promotion, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    }
    if promotion.exists() {
        return Err(Error::other("an incomplete recording was eligible for live promotion").into());
    }
    scan_llm_recording_tree(&run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_llm_recorder_terminal_flush_failure_fails_live_stream() -> TestResult<()> {
    let mut provider =
        ModelFixture::start(vec![ModelScript::final_text("terminal flush failure")]).await?;
    let (mut recorder, run_directory) = start_synthetic_recorder(
        provider.origin(),
        "synthetic_terminal_flush_failure",
        "e2e_llm_recorder_terminal_flush_failure_fails_live_stream",
    )
    .await?;
    let occupied_exchange = run_directory.join("exchange-00000000000000000000.json");
    fs::write(&occupied_exchange, b"test-owned terminal flush collision")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&occupied_exchange, fs::Permissions::from_mode(0o600))?;
    }
    let database = TempDatabase::new("recording-terminal-flush-failure")?;
    let config = config_for_replay(database.path(), &recorder.base_url("/v1"))?;
    run_provider_failure(synthetic_spec(
        &database,
        config,
        recorder.base_url("/v1"),
        "recording-terminal-flush-failure",
    ))
    .await?;
    if provider.request_count() != 1 {
        return Err(Error::other(
            "terminal flush failure did not traverse the provider boundary exactly once",
        )
        .into());
    }
    recorder.stop().await?;
    provider.stop().await?;
    let flush_error = recorder
        .flush_error()
        .ok_or_else(|| Error::other("terminal exchange write failure was not fatal"))?;
    if !flush_error.contains("recording exchange flush failed") {
        return Err(Error::other(format!(
            "terminal exchange failure lost its typed flush classification: {flush_error}"
        ))
        .into());
    }
    if recorder.recording().is_ok() {
        return Err(Error::other(
            "terminal exchange flush failure produced a promotable recording",
        )
        .into());
    }
    scan_llm_recording_tree(&run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    Ok(())
}

/// Later reproduction of the retained full-suite terminal-flush hang.  The
/// process capture is armed before Endpoint spawn and records the relation in
/// first_observed; the original Management raw remains the historical first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_later_test_reproduction_of_terminal_flush_gap_is_bounded_and_captured(
) -> TestResult<()> {
    const E2E_NAME: &str =
        "e2e_later_test_reproduction_of_terminal_flush_gap_is_bounded_and_captured";
    let mut provider =
        ModelFixture::start(vec![ModelScript::final_text("terminal flush later gap")]).await?;
    let (mut recorder, run_directory) = start_synthetic_recorder(
        provider.origin(),
        "later_test_reproduction_of_gap",
        E2E_NAME,
    )
    .await?;
    let occupied_exchange = run_directory.join("exchange-00000000000000000000.json");
    fs::write(&occupied_exchange, b"test-owned terminal flush collision")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&occupied_exchange, fs::Permissions::from_mode(0o600))?;
    }

    let database = TempDatabase::new("recording-terminal-flush-later-gap")?;
    let config = config_for_replay(database.path(), &recorder.base_url("/v1"))?;
    let process_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-recordings")
        .join("quarantine");
    let mut process_capture = ProcessCaptureSet::new(
        process_root,
        E2E_NAME,
        &[REPLAY_SECRET, TEST_CONTROLLER_SECRET],
    )?;

    let failure = run_provider_failure_with_process_capture(
        synthetic_spec(
            &database,
            config,
            recorder.base_url("/v1"),
            "recording-terminal-flush-later-gap",
        ),
        &mut process_capture,
        "endpoint-terminal-flush-later-gap",
    )
    .await;
    let recorder_requests = recorder.observed_requests();
    let provider_requests = provider.request_count();
    let recorder_stop = recorder.stop().await;
    let provider_stop = provider.stop().await;
    let raw_process = process_capture.flush(
        "RECORDER_TERMINAL_FLUSH_FAILURE",
        "later_test_reproduction_of_gap",
    )?;
    recorder_stop?;
    provider_stop?;
    failure?;
    if provider_requests != 1 || recorder_requests.len() != 1 {
        return Err(Error::other(format!(
            "terminal flush later reproduction crossed provider boundary unexpectedly (recorder={}, provider={provider_requests})",
            recorder_requests.len()
        ))
        .into());
    }
    let flush_error = recorder
        .flush_error()
        .ok_or_else(|| Error::other("later terminal flush failure was not retained"))?;
    if !flush_error.contains("recording exchange flush failed") {
        return Err(Error::other(format!(
            "later terminal flush failure had the wrong class: {flush_error}"
        ))
        .into());
    }
    if recorder.recording().is_ok() {
        return Err(
            Error::other("later terminal flush failure produced a promotable recording").into(),
        );
    }
    scan_llm_recording_tree(&run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    eprintln!(
        "later_test_reproduction_of_gap retained process observation at {}",
        raw_process.display()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_llm_recorder_stream_capture_bound_fails_closed() -> TestResult<()> {
    let mut provider =
        ModelFixture::start(vec![ModelScript::large_stream(MAX_LLM_RESPONSE_BYTES + 1)]).await?;
    let (mut recorder, run_directory) = start_synthetic_recorder(
        provider.origin(),
        "synthetic_stream_capture_bound",
        "e2e_llm_recorder_stream_capture_bound_fails_closed",
    )
    .await?;
    let database = TempDatabase::new("recording-stream-capture-bound")?;
    let config = config_for_replay(database.path(), &recorder.base_url("/v1"))?;
    run_provider_failure(synthetic_spec(
        &database,
        config,
        recorder.base_url("/v1"),
        "recording-stream-capture-bound",
    ))
    .await?;
    if provider.request_count() != 1 {
        return Err(Error::other(
            "bounded stream exercise did not traverse the provider boundary exactly once",
        )
        .into());
    }
    recorder.stop().await?;
    provider.stop().await?;
    let flush_error = recorder
        .flush_error()
        .ok_or_else(|| Error::other("oversized provider response was not rejected fail-closed"))?;
    if !flush_error.contains("capture bound") {
        return Err(Error::other(format!(
            "oversized response returned the wrong failure class: {flush_error}"
        ))
        .into());
    }
    if recorder.recording().is_ok() {
        return Err(
            Error::other("oversized provider response produced a promotable recording").into(),
        );
    }
    scan_llm_recording_tree(&run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_llm_recorder_accepts_bounded_reasoning_stream_needed_by_handoff_generation(
) -> TestResult<()> {
    const REASONING_STREAM_BYTES: usize = 5 * 1024 * 1024;
    let mut provider =
        ModelFixture::start(vec![ModelScript::large_stream(REASONING_STREAM_BYTES)]).await?;
    let (mut recorder, run_directory) = start_synthetic_recorder(
        provider.origin(),
        "synthetic_bounded_reasoning_stream",
        "e2e_llm_recorder_accepts_bounded_reasoning_stream_needed_by_handoff_generation",
    )
    .await?;
    let database = TempDatabase::new("recording-bounded-reasoning-stream")?;
    let config = config_for_replay(database.path(), &recorder.base_url("/v1"))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database,
            config,
            recorder.base_url("/v1"),
            "recording-bounded-reasoning-stream",
        ),
        cancel.clone(),
    ));
    recorder.wait_for_completed_exchanges(1).await?;
    cancel.notify_one();
    attempt
        .await
        .map_err(|error| Error::other(format!("bounded reasoning task failed: {error}")))??;
    recorder.stop().await?;
    provider.stop().await?;
    if let Some(error) = recorder.flush_error() {
        return Err(Error::other(format!(
            "bounded reasoning response failed recorder flush: {error}"
        ))
        .into());
    }
    let recording = recorder.recording()?;
    let captured_bytes = recording.requests[0]
        .response
        .chunks
        .iter()
        .map(|chunk| chunk.bytes_hex.len() / 2)
        .sum::<usize>();
    if captured_bytes != REASONING_STREAM_BYTES {
        return Err(Error::other(format!(
            "bounded reasoning response captured {captured_bytes} of {REASONING_STREAM_BYTES} bytes"
        ))
        .into());
    }
    let path = run_directory.join("recording.json");
    recording.write_atomic(&path, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    let persisted = LlmHttpRecording::load(&path)?;
    if persisted.requests[0].response.chunks.len() != recording.requests[0].response.chunks.len() {
        return Err(Error::other("persisted reasoning recording changed frame count").into());
    }
    scan_llm_recording_tree(&run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_long_run_llm_recorder_records_and_replays_reasoning_stream_above_ordinary_bound(
) -> TestResult<()> {
    const LONG_REASONING_STREAM_BYTES: usize = 9 * 1024 * 1024;
    const REASONING_FRAME_BYTES: usize = 128;
    let mut provider = ModelFixture::start(vec![ModelScript::fine_grained_stream(
        LONG_REASONING_STREAM_BYTES,
        REASONING_FRAME_BYTES,
    )])
    .await?;
    let run_directory = new_llm_recording_run_dir()?;
    let recording_id = run_directory
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::other("long-run recording id was invalid"))?
        .to_owned();
    let mut recorder = LlmHttpProxy::record_single_sequential_stream(
        provider.origin(),
        PROVIDER,
        MODEL,
        &run_directory,
        LlmHttpRecordingMetadata {
            recording_id,
            purpose: "synthetic_long_reasoning_stream".to_owned(),
            owner: "e2e_long_run_llm_recorder_records_and_replays_reasoning_stream_above_ordinary_bound"
                .to_owned(),
            boundary: "endpoint_aimux_provider_http".to_owned(),
            secret_slots: vec!["SLOT_PROVIDER_AUTHORIZATION_HEADER".to_owned()],
        },
    )
    .await?;
    let database = TempDatabase::new("recording-long-reasoning-stream")?;
    let config = config_for_replay(database.path(), &recorder.base_url("/v1"))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database,
            config,
            recorder.base_url("/v1"),
            "recording-long-reasoning-stream",
        ),
        cancel.clone(),
    ));
    recorder.wait_for_completed_exchanges(1).await?;
    cancel.notify_one();
    attempt
        .await
        .map_err(|error| Error::other(format!("long reasoning capture task failed: {error}")))??;
    recorder.stop().await?;
    provider.stop().await?;
    if let Some(error) = recorder.flush_error() {
        return Err(Error::other(format!(
            "long reasoning response failed recorder flush: {error}"
        ))
        .into());
    }
    let recording = recorder.recording()?;
    let response = &recording.requests[0].response;
    let captured_bytes = response
        .chunks
        .iter()
        .map(|chunk| chunk.bytes_hex.len() / 2)
        .sum::<usize>();
    if captured_bytes != LONG_REASONING_STREAM_BYTES
        || response.chunks.len() <= MAX_LLM_RESPONSE_CHUNKS
        || captured_bytes <= MAX_LLM_RESPONSE_BYTES
    {
        return Err(Error::other(format!(
            "long reasoning recording retained {captured_bytes} bytes in {} chunks",
            response.chunks.len()
        ))
        .into());
    }
    let path = run_directory.join("recording.json");
    recording.write_atomic(&path, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    let persisted = LlmHttpRecording::load_long_run(&path)?;
    if persisted.requests[0].response.chunks.len() != response.chunks.len() {
        return Err(Error::other("persisted long reasoning recording changed frame count").into());
    }
    replay_synthetic_failure(persisted, "replay-long-reasoning-stream").await?;
    scan_llm_recording_tree(&run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_llm_recording_promotion_is_private_then_immutable_0444() -> TestResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut provider =
        ModelFixture::start(vec![ModelScript::final_text("promotion final")]).await?;
    let (mut recorder, run_directory) = start_synthetic_recorder(
        provider.origin(),
        "synthetic_promotion_modes",
        "e2e_llm_recording_promotion_is_private_then_immutable_0444",
    )
    .await?;
    let database = TempDatabase::new("recording-promotion-modes")?;
    let config = config_for_replay(database.path(), &recorder.base_url("/v1"))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database,
            config,
            recorder.base_url("/v1"),
            "recording-promotion-modes",
        ),
        cancel.clone(),
    ));
    recorder.wait_for_completed_exchanges(1).await?;
    cancel.notify_one();
    attempt
        .await
        .map_err(|error| Error::other(format!("promotion exercise task failed: {error}")))??;
    recorder.stop().await?;
    provider.stop().await?;
    let recording = recorder.recording()?;
    let quarantine_path = run_directory.join("recording.json");
    recording.write_atomic(&quarantine_path, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    let quarantine_mode = fs::metadata(&quarantine_path)?.permissions().mode() & 0o777;
    if quarantine_mode != 0o600 {
        return Err(Error::other(format!(
            "quarantine recording mode was {quarantine_mode:04o}, expected 0600"
        ))
        .into());
    }
    let promotion = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("promotion database had no parent"))?
        .join("promoted-recording.json");
    recording.promote_immutable(&promotion, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    let promoted_mode = fs::metadata(&promotion)?.permissions().mode() & 0o777;
    if promoted_mode != 0o444 {
        return Err(Error::other(format!(
            "promoted recording mode was {promoted_mode:04o}, expected 0444"
        ))
        .into());
    }
    let original = fs::read(&promotion)?;
    let overwrite =
        recording.promote_immutable(&promotion, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET]);
    if !matches!(
        overwrite
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<std::io::Error>()),
        Some(error) if error.kind() == ErrorKind::AlreadyExists
    ) {
        return Err(Error::other("immutable promotion accepted an overwrite").into());
    }
    if fs::read(&promotion)? != original {
        return Err(Error::other("immutable promotion changed existing bytes").into());
    }
    scan_llm_recording_tree(&run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_recorded_provider_replay_is_three_immediate_one_captured_and_network_denied(
) -> TestResult<()> {
    let recording = LlmHttpRecording::load(&recording_path())?;
    if recording.requests.len() != 2 {
        return Err(
            Error::other("live provider cassette did not contain exactly two exchanges").into(),
        );
    }
    let mut sentinel = NetworkSentinel::start().await?;
    let child_environment = sentinel.child_environment();
    let primary = async {
        for index in 0..3 {
            replay_recording_roundtrip_with_environment(
                &recording,
                false,
                &format!("recorded-immediate-{index}"),
                child_environment.clone(),
            )
            .await?;
        }
        replay_recording_roundtrip_with_environment(
            &recording,
            true,
            "recorded-captured",
            child_environment,
        )
        .await
    }
    .await;
    let unexpected_requests = sentinel.unexpected_requests();
    let sentinel_stop = sentinel.stop().await;
    if unexpected_requests != 0 {
        return Err(Error::other(format!(
            "offline replay attempted {unexpected_requests} unexpected network requests"
        ))
        .into());
    }
    sentinel_stop?;
    primary
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_promoted_provider_cassette_is_immutable_and_not_quarantine() -> TestResult<()> {
    let path = recording_path();
    let recording = LlmHttpRecording::load(&path)?;
    replay_recording_roundtrip(&recording, false, "recorded-immutable").await?;
    let original_bytes = fs::read(&path)?;
    let overwrite = recording.promote_immutable(&path, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET]);
    match overwrite {
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == ErrorKind::AlreadyExists) => {}
        Err(_) => {
            return Err(Error::other(
                "existing promoted cassette was rejected with the wrong error",
            )
            .into());
        }
        Ok(_) => {
            return Err(Error::other("existing promoted cassette was overwritten").into());
        }
    }
    if fs::read(&path)? != original_bytes {
        return Err(Error::other("rejected cassette overwrite changed the fixture bytes").into());
    }
    let fixture_root = fs::canonicalize(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/provider_recordings"),
    )?;
    for path in [
        path,
        first_occurrence_path(),
        first_occurrence_sidecar_path(),
    ] {
        let canonical = fs::canonicalize(&path)?;
        if !canonical.starts_with(&fixture_root)
            || canonical
                .components()
                .any(|component| component.as_os_str() == "quarantine")
        {
            return Err(Error::other("promoted provider cassette remained in quarantine").into());
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_opencode_v1_first_occurrence_remains_replayable() -> TestResult<()> {
    replay_legacy_first_occurrence(load_legacy_first_occurrence()?).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_llm_recorder_preserves_failure_outcomes() -> TestResult<()> {
    let mut rate_limit = ModelFixture::start(
        (0..16)
            .map(|_| ModelScript::status(429))
            .collect::<Vec<_>>(),
    )
    .await?;
    let (mut recorder, run_directory) = start_synthetic_recorder(
        rate_limit.origin(),
        "synthetic_rate_limit",
        "e2e_llm_recorder_preserves_failure_outcomes",
    )
    .await?;
    let database = TempDatabase::new("recording-rate-limit")?;
    let config = config_for_replay(database.path(), &recorder.base_url(""))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database,
            config,
            recorder.base_url("/v1"),
            "recording-rate-limit",
        ),
        cancel.clone(),
    ));
    recorder.wait_for_completed_exchanges(1).await?;
    cancel.notify_one();
    attempt
        .await
        .map_err(|error| Error::other(format!("rate-limit exercise task failed: {error}")))??;
    let recording = finish_synthetic_recorder(&mut recorder, &run_directory).await?;
    if recording.requests.is_empty()
        || recording.requests.iter().any(|exchange| {
            exchange.response.status != Some(429)
                || exchange.response.content_type.is_some()
                || exchange.response.chunks.is_empty()
                || !matches!(
                    exchange.response.outcome,
                    LlmHttpResponseOutcome::Complete { done_seen: false }
                )
        })
    {
        return Err(Error::other("429/non-JSON response was not recorded exactly").into());
    }
    replay_synthetic_failure(recording, "replay-rate-limit").await?;
    rate_limit.stop().await?;

    let partial_hold = ModelHold::new();
    let mut partial =
        ModelFixture::start(vec![ModelScript::stream_failure_hold(partial_hold.clone())]).await?;
    let (mut recorder, run_directory) = start_synthetic_recorder(
        partial.origin(),
        "synthetic_partial_stream",
        "e2e_llm_recorder_preserves_failure_outcomes",
    )
    .await?;
    let database = TempDatabase::new("recording-partial-stream")?;
    let config = config_for_replay(database.path(), &recorder.base_url(""))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database,
            config,
            recorder.base_url("/v1"),
            "recording-partial-stream",
        ),
        cancel.clone(),
    ));
    partial_hold.wait_entered().await?;
    recorder.wait_for_recorded_chunks(1).await?;
    partial_hold.release();
    recorder.wait_for_completed_exchanges(1).await?;
    cancel.notify_one();
    attempt
        .await
        .map_err(|error| Error::other(format!("partial exercise task failed: {error}")))??;
    let recording = finish_synthetic_recorder(&mut recorder, &run_directory).await?;
    if !recording.requests.iter().any(|exchange| {
        !exchange.response.chunks.is_empty()
            && matches!(
                exchange.response.outcome,
                LlmHttpResponseOutcome::StreamError
            )
    }) {
        return Err(Error::other("partial stream error was not recorded").into());
    }
    replay_synthetic_failure(recording, "replay-partial-stream").await?;
    partial.stop().await?;

    let (mut recorder, run_directory) = start_synthetic_recorder(
        "http://127.0.0.1:1".to_owned(),
        "synthetic_transport_error",
        "e2e_llm_recorder_preserves_failure_outcomes",
    )
    .await?;
    let database = TempDatabase::new("recording-transport-error")?;
    let config = config_for_replay(database.path(), &recorder.base_url(""))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database,
            config,
            recorder.base_url("/v1"),
            "recording-transport-error",
        ),
        cancel.clone(),
    ));
    recorder.wait_for_completed_exchanges(1).await?;
    cancel.notify_one();
    attempt
        .await
        .map_err(|error| Error::other(format!("transport exercise task failed: {error}")))??;
    let recording = finish_synthetic_recorder(&mut recorder, &run_directory).await?;
    if recording.requests.is_empty()
        || recording.requests.iter().any(|exchange| {
            !matches!(
                exchange.response.outcome,
                LlmHttpResponseOutcome::TransportError
            )
        })
    {
        return Err(Error::other("transport errors were not recorded").into());
    }
    replay_synthetic_failure(recording, "replay-transport-error").await?;

    let hold = ModelHold::new();
    let mut held = ModelFixture::start(vec![ModelScript::stream_hold(hold.clone())]).await?;
    let (mut recorder, run_directory) = start_synthetic_recorder(
        held.origin(),
        "synthetic_client_disconnect",
        "e2e_llm_recorder_preserves_failure_outcomes",
    )
    .await?;
    let database = TempDatabase::new("recording-client-disconnect")?;
    let config = config_for_replay(database.path(), &recorder.base_url(""))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database,
            config,
            recorder.base_url("/v1"),
            "recording-client-disconnect",
        ),
        cancel.clone(),
    ));
    hold.wait_entered().await?;
    recorder.wait_for_recorded_chunks(1).await?;
    cancel.notify_one();
    attempt
        .await
        .map_err(|error| Error::other(format!("disconnect exercise task failed: {error}")))??;
    hold.release();
    held.stop().await?;
    let recording = finish_synthetic_recorder(&mut recorder, &run_directory).await?;
    if !recording.requests.iter().any(|exchange| {
        matches!(
            exchange.response.outcome,
            LlmHttpResponseOutcome::ClientDisconnect
        )
    }) {
        return Err(Error::other("client disconnect was not recorded").into());
    }
    replay_synthetic_failure(recording, "replay-client-disconnect").await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_llm_recorder_done_then_transport_disconnect_replays_as_complete() -> TestResult<()> {
    let hold = ModelHold::new();
    let mut provider =
        ModelFixture::start(vec![ModelScript::stream_done_hold(hold.clone())]).await?;
    let (mut recorder, run_directory) = start_synthetic_recorder(
        provider.origin(),
        "synthetic_done_then_disconnect",
        "e2e_llm_recorder_done_then_transport_disconnect_replays_as_complete",
    )
    .await?;
    let database = TempDatabase::new("recording-done-then-disconnect")?;
    let config = config_for_replay(database.path(), &recorder.base_url("/v1"))?;
    let cancel = Arc::new(Notify::new());
    let attempt = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database,
            config,
            recorder.base_url("/v1"),
            "recording-done-then-disconnect",
        ),
        cancel.clone(),
    ));
    hold.wait_entered().await?;
    recorder.wait_for_recorded_chunks(3).await?;
    cancel.notify_one();
    attempt.await.map_err(|error| {
        Error::other(format!("done-disconnect exercise task failed: {error}"))
    })??;
    hold.release();
    recorder.wait_for_completed_exchanges(1).await?;
    provider.stop().await?;
    let recording = finish_synthetic_recorder(&mut recorder, &run_directory).await?;
    if !recording.requests.iter().any(|exchange| {
        matches!(
            exchange.response.outcome,
            LlmHttpResponseOutcome::ClientDisconnect
        ) && exchange
            .response
            .chunks
            .iter()
            .filter_map(|chunk| decode_hex(&chunk.bytes_hex).ok())
            .any(|bytes| {
                bytes
                    .windows(b"data: [DONE]".len())
                    .any(|window| window == b"data: [DONE]")
            })
    }) {
        return Err(Error::other(
            "DONE followed by transport disconnect was not retained as raw termination",
        )
        .into());
    }
    replay_synthetic_failure(recording, "replay-done-then-disconnect").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_llm_recorder_concurrent_completions_are_durably_persisted_in_sequence(
) -> TestResult<()> {
    let first_hold = ModelHold::new();
    let mut provider = ModelFixture::start(vec![
        ModelScript::hold_entered(
            first_hold.clone(),
            ModelScript::final_text("first concurrent"),
        ),
        ModelScript::final_text("second concurrent"),
    ])
    .await?;
    let (mut recorder, run_directory) = start_synthetic_recorder_with_plan(
        provider.origin(),
        "synthetic_concurrent_completions",
        "e2e_llm_recorder_concurrent_completions_are_durably_persisted_in_sequence",
        Some(vec![
            LlmHttpAttemptPlan {
                logical_round: 0,
                wire_attempt: 0,
            },
            LlmHttpAttemptPlan {
                logical_round: 1,
                wire_attempt: 0,
            },
        ]),
    )
    .await?;

    let database_a = TempDatabase::new("recording-concurrent-a")?;
    let config_a = config_for_replay(database_a.path(), &recorder.base_url(""))?;
    let database_b = TempDatabase::new("recording-concurrent-b")?;
    let config_b = config_for_replay(database_b.path(), &recorder.base_url(""))?;
    let cancel_a = Arc::new(Notify::new());
    let cancel_b = Arc::new(Notify::new());
    let task_a = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database_a,
            config_a,
            recorder.base_url("/v1"),
            "recording-concurrent-a",
        ),
        cancel_a.clone(),
    ));
    first_hold.wait_entered().await?;
    let task_b = tokio::spawn(run_provider_attempt_until_cancel(
        synthetic_spec(
            &database_b,
            config_b,
            recorder.base_url("/v1"),
            "recording-concurrent-b",
        ),
        cancel_b.clone(),
    ));
    provider.wait_for_requests(2).await?;
    // The second response completes first and is held in the ordered pending
    // map until the first response's durable fact arrives.
    recorder.wait_for_submitted_exchanges(1).await?;
    first_hold.release();
    recorder.wait_for_completed_exchanges(2).await?;
    cancel_a.notify_one();
    cancel_b.notify_one();
    task_a
        .await
        .map_err(|error| Error::other(format!("concurrent first task failed: {error}")))??;
    task_b
        .await
        .map_err(|error| Error::other(format!("concurrent second task failed: {error}")))??;
    recorder.stop().await?;
    provider.stop().await?;
    let recording = recorder.recording()?;
    let sequences = recording
        .requests
        .iter()
        .map(|exchange| exchange.sequence)
        .collect::<Vec<_>>();
    if sequences != vec![0, 1] {
        return Err(Error::other(format!(
            "concurrent recording was not persisted in sequence: {sequences:?}"
        ))
        .into());
    }
    recording.write_atomic(
        &run_directory.join("recording.json"),
        &[REPLAY_SECRET, TEST_CONTROLLER_SECRET],
    )?;
    scan_llm_recording_tree(&run_directory, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET])?;
    Ok(())
}

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
use support::{
    canonical_json, http_client, new_llm_recording_run_dir, run_provider_attempt_until_cancel,
    run_provider_roundtrip_and_restart, scan_llm_recording_tree, sqlite_contains_secret,
    write_endpoint_config, HttpFixture, LlmHttpObservedRequest, LlmHttpProxy, LlmHttpRecording,
    LlmHttpRecordingMetadata, LlmHttpResponseOutcome, ModelFixture, ModelHold, ModelScript,
    ProviderRoundtripSpec, TempDatabase, TestResult, LLM_HTTP_RECORDING_SCHEMA,
    TEST_CONTROLLER_SECRET,
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
    if !value.len().is_multiple_of(2) {
        return Err(Error::other("legacy replay chunk encoding was invalid").into());
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|_| Error::other("legacy replay chunk encoding was invalid").into())
        })
        .collect()
}

fn config_for_replay(database: &Path) -> TestResult<PathBuf> {
    let path = write_endpoint_config(database, Vec::new(), 1)?;
    let mut config: Value = serde_json::from_slice(&fs::read(&path)?)?;
    config["provider_execution"]["adapter_kinds"] = json!(["openai_compatible"]);
    config["provider_execution"]["allowed_base_url_origins"] = json!(["http://127.0.0.1"]);
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
    let mut proxy = LlmHttpProxy::replay(recording.clone(), captured_timing).await?;
    let provider_path = recording
        .requests
        .first()
        .and_then(|exchange| exchange.request.path.strip_suffix("/chat/completions"))
        .ok_or_else(|| Error::other("provider recording path was not a chat-completions route"))?;
    let database = TempDatabase::new(label)?;
    let config = config_for_replay(database.path())?;
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
    let config = config_for_replay(database.path())?;
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
    let mut recorder = LlmHttpProxy::record(
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
    )
    .await?;
    let database = TempDatabase::new("record-pre-stream-retry")?;
    let config = config_for_replay(database.path())?;
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
    let run_directory = new_llm_recording_run_dir()?;
    let recording_id = run_directory
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::other("synthetic recording run id was invalid"))?
        .to_owned();
    let recorder = LlmHttpProxy::record(
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

async fn replay_synthetic_failure(recording: LlmHttpRecording, prefix: &str) -> TestResult<()> {
    let expected = recording.requests.len();
    let mut replay = LlmHttpProxy::replay(recording, false).await?;
    let database = TempDatabase::new(prefix)?;
    let config = config_for_replay(database.path())?;
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
    let config = config_for_replay(database.path())?;
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
    recorder.wait_for_completed_exchanges(1).await?;
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
async fn e2e_promoted_provider_cassette_is_0444_immutable_and_not_quarantine() -> TestResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let path = recording_path();
    let recording = LlmHttpRecording::load(&path)?;
    replay_recording_roundtrip(&recording, false, "recorded-immutable").await?;
    let original_bytes = fs::read(&path)?;
    let overwrite = recording.write_atomic(&path, &[REPLAY_SECRET, TEST_CONTROLLER_SECRET]);
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
        let mode = fs::metadata(&canonical)?.permissions().mode() & 0o777;
        if mode != 0o444 {
            return Err(Error::other(format!(
                "promoted provider cassette {} mode was {mode:04o}, expected 0444",
                canonical
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("<invalid>")
            ))
            .into());
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
    let config = config_for_replay(database.path())?;
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
    let config = config_for_replay(database.path())?;
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
    let config = config_for_replay(database.path())?;
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
    let config = config_for_replay(database.path())?;
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

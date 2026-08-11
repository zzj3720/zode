#![allow(dead_code)]

mod deepswe_support;
mod support;

use std::{
    env, fs,
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    extract::{Json, State},
    routing::post,
    Router,
};
use deepswe_support::{file_sha256, DeepSweEventTrace, DeepSweToolExchange};
use reqwest::StatusCode;
use serde_json::{json, Value};
use support::{
    authenticated_as, http_client, new_llm_live_recording_run_dir, require_ulid, response_text,
    scan_llm_recording_tree, spawn_db_blocking, sqlite_contains_secret, write_endpoint_config,
    HttpFixture, LlmHttpProxy, LlmHttpRecording, LlmHttpRecordingMetadata, TempDatabase,
    TestResult, TestZode, TEST_CONTROLLER_AUTHORITY, TEST_CONTROLLER_SECRET,
};
use tokio::time::{sleep, timeout};

const PROVIDER: &str = "opencode-go";
const MODEL: &str = "deepseek-v4-flash";
const PROFILE: &str = "opencode-go-deepswe";
const SUBJECT: &str = "deepswe-benchmark";
const PROVIDER_UPSTREAM_ORIGIN: &str = "https://opencode.ai";
const REPLAY_PROVIDER_KEY: &str = "deepswe-replay-provider-key";
const BENCHMARK_TIMEOUT: Duration = Duration::from_secs(5_100);
const LOCAL_REPLAY_TIMEOUT: Duration = Duration::from_secs(1_200);
const TRACKED_LLM_REPLAY: &str =
    "tests/fixtures/deepswe/anko_default_function_arguments_deepseek_v4_flash.v2.llm.json.zst";
const TRACKED_LLM_REPLAY_SHA256: &str =
    "de73313a636f29b72d2b4baf8ff727e7120dd5f026dc7cba075da8db8c2a0598";
const TRACKED_EVENT_REPLAY: &str =
    "tests/fixtures/deepswe/anko_default_function_arguments_deepseek_v4_flash.v2.events.json";
const TRACKED_EVENT_REPLAY_SHA256: &str =
    "2927398928170ac9a3a6993baf6d99b0c69357629109d92c0e9da303e0f40fec";

struct EventToolFixtureState {
    exchanges: Vec<DeepSweToolExchange>,
    next: Mutex<usize>,
    error: Mutex<Option<String>>,
}

struct EventToolFixture {
    server: HttpFixture,
    state: Arc<EventToolFixtureState>,
}

impl EventToolFixture {
    async fn start(trace: &DeepSweEventTrace) -> TestResult<Self> {
        let state = Arc::new(EventToolFixtureState {
            exchanges: trace.tool_exchanges()?,
            next: Mutex::new(0),
            error: Mutex::new(None),
        });
        let server = HttpFixture::start(
            Router::new()
                .route("/invoke", post(replay_event_tool_request))
                .with_state(state.clone()),
        )
        .await?;
        Ok(Self { server, state })
    }

    fn url(&self) -> String {
        self.server.url("/invoke")
    }

    fn assert_exhausted(&self) -> TestResult<()> {
        if let Some(error) = self
            .state
            .error
            .lock()
            .expect("event-derived tool fixture error mutex poisoned")
            .as_ref()
        {
            return Err(Error::other(error.clone()).into());
        }
        if *self
            .state
            .next
            .lock()
            .expect("event-derived tool fixture cursor mutex poisoned")
            != self.state.exchanges.len()
        {
            return Err(Error::other("DeepSWE event-derived tool replay was not exhausted").into());
        }
        Ok(())
    }

    fn assert_durable_outcomes(&self, session: &Value) -> TestResult<()> {
        let expected = self
            .state
            .exchanges
            .iter()
            .map(|exchange| exchange.result_content.as_str())
            .collect::<Vec<_>>();
        let transcript = session["transcript"]
            .as_array()
            .ok_or_else(|| Error::other("DeepSWE replay omitted the durable transcript"))?;
        let actual = transcript
            .iter()
            .filter(|message| message["role"] == "tool")
            .map(|message| {
                message["content"]
                    .as_str()
                    .ok_or_else(|| Error::other("DeepSWE replay emitted a non-text tool result"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if actual.len() != expected.len() {
            return Err(
                Error::other("DeepSWE replay did not commit every recorded tool result").into(),
            );
        }
        if actual
            .iter()
            .zip(&expected)
            .any(|(actual, expected)| *actual != *expected)
        {
            return Err(Error::other(
                "DeepSWE replay durable tool result did not match its recorded input",
            )
            .into());
        }
        let tool_calls = session["tool_calls"]
            .as_array()
            .ok_or_else(|| Error::other("DeepSWE replay omitted tool-call projections"))?;
        if tool_calls.len() != expected.len()
            || tool_calls
                .iter()
                .any(|call| call["status"] != "completed" || call["result"].is_null())
        {
            return Err(Error::other(
                "DeepSWE replay did not project every recorded tool outcome as completed",
            )
            .into());
        }
        Ok(())
    }

    async fn stop(&mut self) -> TestResult<()> {
        self.server.stop().await
    }
}

async fn replay_event_tool_request(
    State(state): State<Arc<EventToolFixtureState>>,
    Json(body): Json<Value>,
) -> (axum::http::StatusCode, Json<Value>) {
    let command = body["input"]["command"].as_str();
    let expected = {
        let mut next = state
            .next
            .lock()
            .expect("event-derived tool fixture cursor mutex poisoned");
        let expected = state.exchanges.get(*next).cloned();
        if let Some(expected) = &expected {
            if command != Some(expected.command.as_str()) {
                let mut error = state
                    .error
                    .lock()
                    .expect("event-derived tool fixture error mutex poisoned");
                if error.is_none() {
                    *error = Some("DeepSWE tool input did not match the event trace".to_owned());
                }
            } else {
                *next += 1;
            }
        }
        expected
    };
    let Some(expected) = expected else {
        let mut error = state
            .error
            .lock()
            .expect("event-derived tool fixture error mutex poisoned");
        if error.is_none() {
            *error = Some("DeepSWE event replay observed an extra tool call".to_owned());
        }
        return (
            axum::http::StatusCode::CONFLICT,
            Json(json!({"result": {"content": "event-derived tool mismatch"}})),
        );
    };
    (
        axum::http::StatusCode::OK,
        Json(json!({"result": {"content": expected.result_content}})),
    )
}

fn benchmark_state_summary(state: &Value) -> Value {
    let transcript = state["transcript"]
        .as_array()
        .map(|messages| {
            messages
                .iter()
                .rev()
                .take(6)
                .rev()
                .map(|message| {
                    json!({
                        "role": message["role"],
                        "message_id": message["message_id"],
                        "content_bytes": message["content"].as_str().map_or(0, str::len),
                        "tool_call_id": message["tool_call_id"],
                        "tool_calls": message["tool_calls"].as_array().map_or(0, Vec::len),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let tools = state["tool_calls"]
        .as_array()
        .map(|calls| {
            calls
                .iter()
                .rev()
                .take(6)
                .rev()
                .map(|call| {
                    json!({
                        "tool_call_id": call["tool_call_id"],
                        "tool_name": call["tool_name"],
                        "status": call["status"],
                        "completion_mode": call["completion_mode"],
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "session_id": state["session_id"],
        "version": state["version"],
        "status": state["status"],
        "active_activation": state["active_activation"],
        "active_model_round": state["active_model_round"],
        "wait": state["wait"],
        "pending_deliveries": state["delivery"]["pending"].as_array().map_or(0, Vec::len),
        "last_model_attempts_exhausted": state["last_model_attempts_exhausted"],
        "context_handoff": state["context_handoff"],
        "transcript_tail": transcript,
        "tool_tail": tools,
    })
}

fn required_path(name: &str) -> TestResult<PathBuf> {
    let value = env::var_os(name)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("{name} is required")))?;
    Ok(PathBuf::from(value))
}

fn provider_key(auth_file: &Path) -> TestResult<String> {
    let auth: Value = serde_json::from_slice(&fs::read(auth_file)?)?;
    auth["opencode-go"]["key"]
        .as_str()
        .filter(|key| !key.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "OpenCode Go key is unavailable").into())
}

fn benchmark_config(
    database: &Path,
    provider_origin: &str,
    shell_url: &str,
) -> TestResult<PathBuf> {
    let tool = json!({
        "name": "shell",
        "description": "Execute a shell command in the DeepSWE task container at /app. Use it to inspect files, edit the implementation, run tests, and commit the completed solution.",
        "input_schema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
            "additionalProperties": false
        },
        "completion_mode": "response",
        "auto_wait_timeout_seconds": 600,
        "recovery": {
            "on_running_restart": "unknown_outcome",
            "retry_dispatch": "never"
        },
        "adapter": {"kind": "http", "url": shell_url}
    });
    let path = write_endpoint_config(database, vec![tool], 3)?;
    let mut config: Value = serde_json::from_slice(&fs::read(&path)?)?;
    config["provider_execution"]["allowed_base_url_origins"] = json!([provider_origin]);
    // DeepSeek Flash advertises a one-million-token context and a much larger
    // output capability. Ordinary and handoff requests deliberately ask for
    // at most 128K so long reasoning can finish without reserving the model's
    // entire advertised 384K output capability from every input.
    config["runtime"]["model_request_max_output_tokens"] = json!(128_000);
    config["runtime"]["model_context_buffer_tokens"] = json!(32_000);
    config["runtime"]["model_context_handoff_generation_tokens"] = json!(128_000);
    config["runtime"]["model_context_handoff_document_tokens"] = json!(12_288);
    config["runtime"]["model_stream_idle_timeout_ms"] = json!(120_000);
    fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    Ok(path)
}

async fn public_json(
    request: reqwest::RequestBuilder,
    expected: StatusCode,
    secret: &str,
) -> TestResult<Value> {
    let response = request.send().await?;
    let status = response.status();
    let body = response_text(response).await?;
    if body.contains(secret) || body.contains(TEST_CONTROLLER_SECRET) {
        return Err(Error::other("public response exposed credential material").into());
    }
    if status != expected {
        return Err(Error::other(format!("public request returned {status}: {body}")).into());
    }
    Ok(if body.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&body)?
    })
}

async fn run_benchmark(
    instruction: &str,
    shell_url: &str,
    provider_key: &str,
    recorder: &LlmHttpProxy,
    database: &TempDatabase,
) -> TestResult<Value> {
    let provider_origin = url::Url::parse(&recorder.base_url(""))?
        .origin()
        .ascii_serialization();
    let config = benchmark_config(database.path(), &provider_origin, shell_url)?;
    let mut endpoint = TestZode::start(
        database.path(),
        &config,
        &[provider_key, TEST_CONTROLLER_SECRET],
    )
    .await?;
    let client = http_client()?;
    let primary = async {
        public_json(
            authenticated_as(
                client.put(endpoint.url(&format!("/v1/auth-replicas/{PROFILE}"))),
                SUBJECT,
            )
            .header("Idempotency-Key", "deepswe-install-provider")
            .json(&json!({
                "schema": "zode.auth-replica.install.v1",
                "authority_id": TEST_CONTROLLER_AUTHORITY,
                "provider": PROVIDER,
                "kind": "api_key",
                "revision": 1,
                "credential_schema": "openai-compatible.api-key.v1",
                "expires_at_ms": null,
                "secret": {
                    "encoding": "application/zode-secret-envelope",
                    "payload": provider_key
                }
            })),
            StatusCode::CREATED,
            provider_key,
        )
        .await?;
        let created = public_json(
            authenticated_as(client.post(endpoint.url("/v1/sessions")), SUBJECT)
                .header("Idempotency-Key", "deepswe-create-session")
                .json(&json!({
                    "model": {
                        "provider": PROVIDER,
                        "provider_execution": {
                            "schema": "zode.provider-execution.v1",
                            "revision": 1,
                            "kind": "openai_compatible",
                            "base_url": recorder.base_url("/zen/go/v1")
                        },
                        "model": MODEL,
                        "limits": {
                            "context_window_tokens": 1_000_000,
                            "max_output_tokens": 384_000
                        },
                        "auth_authority_id": TEST_CONTROLLER_AUTHORITY,
                        "auth_profile_id": PROFILE,
                        "minimum_auth_revision": 1
                    },
                    "tools": ["shell"]
                })),
            StatusCode::CREATED,
            provider_key,
        )
        .await?;
        let session_id = require_ulid(&created)?;
        let events = authenticated_as(client.get(endpoint.url("/v1/events")), SUBJECT)
            .send()
            .await?;
        if events.status() != StatusCode::OK {
            return Err(Error::other("Endpoint-wide SSE did not open").into());
        }
        let _events = events;
        public_json(
            authenticated_as(
                client.post(endpoint.url(&format!("/v1/sessions/{session_id}/messages"))),
                SUBJECT,
            )
            .header("Idempotency-Key", "deepswe-instruction")
            .json(&json!({"content": instruction})),
            StatusCode::ACCEPTED,
            provider_key,
        )
        .await?;

        let started = Instant::now();
        let mut saw_active_activation = false;
        let mut stable_idle: Option<(Instant, u64, usize)> = None;
        loop {
            let state = public_json(
                authenticated_as(
                    client.get(endpoint.url(&format!("/v1/sessions/{session_id}"))),
                    SUBJECT,
                ),
                StatusCode::OK,
                provider_key,
            )
            .await?;
            saw_active_activation |= !state["active_activation"].is_null();
            let transcript_len = state["transcript"].as_array().map_or(0, Vec::len);
            let has_assistant = state["transcript"].as_array().is_some_and(|messages| {
                messages.iter().any(|message| {
                    message["role"] == "assistant"
                        && message["content"]
                            .as_str()
                            .is_some_and(|text| !text.is_empty())
                })
            });
            let has_pending_work = !state["wait"].is_null()
                || state["delivery"]["pending"]
                    .as_array()
                    .is_some_and(|deliveries| !deliveries.is_empty())
                || state["tool_calls"]
                    .as_array()
                    .is_some_and(|calls| calls.iter().any(|call| call["status"] == "running"));
            if saw_active_activation
                && state["status"] == "idle"
                && state["active_activation"].is_null()
                && !has_pending_work
            {
                let stream_version = state["version"].as_u64().unwrap_or_default();
                let unchanged_since = match stable_idle {
                    Some((since, version, messages))
                        if version == stream_version && messages == transcript_len =>
                    {
                        since
                    }
                    _ => {
                        let since = Instant::now();
                        stable_idle = Some((since, stream_version, transcript_len));
                        since
                    }
                };
                if unchanged_since.elapsed() < Duration::from_secs(5) {
                    sleep(Duration::from_millis(250)).await;
                    continue;
                }
                if !has_assistant {
                    return Err(Error::other(format!(
                        "DeepSWE became idle without a non-empty final assistant reply: {}",
                        benchmark_state_summary(&state)
                    ))
                    .into());
                }
                return Ok(state);
            } else {
                stable_idle = None;
            }
            if started.elapsed() >= BENCHMARK_TIMEOUT {
                return Err(Error::new(ErrorKind::TimedOut, "DeepSWE agent timed out").into());
            }
            sleep(Duration::from_secs(1)).await;
        }
    }
    .await;

    let stop = endpoint.stop(&[provider_key, TEST_CONTROLLER_SECRET]).await;
    match (primary, stop) {
        (Ok(state), Ok(())) => Ok(state),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(Error::other(format!(
            "benchmark failed: {}; endpoint cleanup failed: {}",
            primary.to_string().replace(provider_key, "[redacted]"),
            cleanup.to_string().replace(provider_key, "[redacted]")
        ))
        .into()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "uses the approved OpenCode Go account and a live DeepSWE container"]
async fn e2e_live_deepswe_opencode_go_records_and_completes() -> TestResult<()> {
    let instruction_path = required_path("ZODE_DEEPSWE_INSTRUCTION_FILE")?;
    let shell_url = env::var("ZODE_DEEPSWE_SHELL_URL")?;
    let auth_file = required_path("ZODE_DEEPSWE_AUTH_FILE")?;
    let instruction = fs::read_to_string(instruction_path)?;
    let key = provider_key(&auth_file)?;
    let run_id = env::var("ZODE_DEEPSWE_RUN_ID").unwrap_or_else(|_| "deepswe-live".to_owned());
    let quarantine = new_llm_live_recording_run_dir(&run_id)?;
    let database = TempDatabase::new("deepswe-live")?;
    let mut recorder = LlmHttpProxy::record_single_sequential_stream(
        PROVIDER_UPSTREAM_ORIGIN,
        PROVIDER,
        MODEL,
        &quarantine,
        LlmHttpRecordingMetadata {
            recording_id: run_id.clone(),
            purpose: "deepswe_long_task_execution".to_owned(),
            owner: "e2e_live_deepswe_opencode_go_records_and_completes".to_owned(),
            boundary: "endpoint_aimux_provider_http".to_owned(),
            secret_slots: vec!["SLOT_PROVIDER_AUTHORIZATION_HEADER".to_owned()],
        },
    )
    .await?;

    let primary = run_benchmark(&instruction, &shell_url, &key, &recorder, &database).await;
    let mut cleanup_errors = Vec::new();
    let mut provider_recording_sha256 = None;
    if let Err(error) = recorder.stop().await {
        cleanup_errors.push(format!("recorder stop failed: {error}"));
    }
    if let Some(error) = recorder.flush_error() {
        cleanup_errors.push(format!("recorder flush failed: {error}"));
    }
    match recorder.recording() {
        Ok(recording) => {
            let recording_path = quarantine.join("recording.json");
            if let Err(error) =
                recording.write_atomic(&recording_path, &[&key, TEST_CONTROLLER_SECRET])
            {
                cleanup_errors.push(format!("recording envelope flush failed: {error}"));
            } else {
                match file_sha256(&recording_path) {
                    Ok(digest) => provider_recording_sha256 = Some(digest),
                    Err(error) => {
                        cleanup_errors.push(format!("recording envelope digest failed: {error}"))
                    }
                }
            }
            eprintln!(
                "ZODE_DEEPSWE_RECORDING run_id={} exchanges={} path={}",
                run_id,
                recording.requests.len(),
                quarantine.display()
            );
        }
        Err(error) => cleanup_errors.push(format!("recording finalization failed: {error}")),
    }
    if primary.is_ok() {
        if let Some(provider_recording_sha256) = provider_recording_sha256 {
            let database_path = database.path().to_owned();
            match spawn_db_blocking(move || {
                DeepSweEventTrace::read_stopped_database(&database_path, &provider_recording_sha256)
            })
            .await
            {
                Ok(Ok(trace)) => match trace.write_private(
                    &quarantine.join("event-trace.json"),
                    &[&key, TEST_CONTROLLER_SECRET],
                ) {
                    Ok(digest) => eprintln!(
                        "ZODE_DEEPSWE_EVENT_TRACE events={} tools={} sha256={}",
                        trace.event_count(),
                        trace.tool_count().unwrap_or_default(),
                        digest
                    ),
                    Err(error) => cleanup_errors.push(format!("event trace flush failed: {error}")),
                },
                Ok(Err(error)) => cleanup_errors.push(format!("event trace failed: {error}")),
                Err(error) => cleanup_errors.push(format!("event trace worker failed: {error}")),
            }
        } else {
            cleanup_errors.push("event trace has no provider recording digest".to_owned());
        }
    }
    if let Err(error) = scan_llm_recording_tree(&quarantine, &[&key, TEST_CONTROLLER_SECRET]) {
        cleanup_errors.push(error.to_string());
    }
    if sqlite_contains_secret(database.path(), &key).await? {
        cleanup_errors.push("provider key reached runtime SQLite".to_owned());
    }

    match (primary, cleanup_errors.is_empty()) {
        (Ok(state), true) => {
            eprintln!(
                "ZODE_DEEPSWE_COMPLETE handoff_exercised={} transcript_messages={}",
                !state["context_handoff"].is_null(),
                state["transcript"].as_array().map_or(0, Vec::len)
            );
            Ok(())
        }
        (Err(error), true) => Err(error),
        (Ok(_), false) => Err(Error::other(cleanup_errors.join("; ")).into()),
        (Err(error), false) => Err(Error::other(format!(
            "benchmark failed: {}; cleanup failed: {}",
            error.to_string().replace(&key, "[redacted]"),
            cleanup_errors.join("; ")
        ))
        .into()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "replays a retained DeepSWE recording against a real task container"]
async fn e2e_replayed_deepswe_recording_completes_through_real_endpoint() -> TestResult<()> {
    let replay_path = required_path("ZODE_DEEPSWE_REPLAY_FILE")?;
    let event_replay_path = required_path("ZODE_DEEPSWE_EVENT_REPLAY_FILE")?;
    let shell_url = env::var("ZODE_DEEPSWE_SHELL_URL")?;
    let provider_file_sha256 = file_sha256(&replay_path)?;
    let event_file_sha256 = file_sha256(&event_replay_path)?;
    let trace = DeepSweEventTrace::load(
        &event_replay_path,
        &event_file_sha256,
        &provider_file_sha256,
        &[REPLAY_PROVIDER_KEY, TEST_CONTROLLER_SECRET],
    )?;
    let recording = if replay_path.extension().and_then(|value| value.to_str()) == Some("zst") {
        support::LlmHttpRecording::load_compressed(&replay_path)?
    } else {
        support::LlmHttpRecording::load_long_run(&replay_path)?
    };
    let instruction = trace.instruction()?;
    let promotion_path = env::var_os("ZODE_DEEPSWE_PROMOTE_LLM_FILE").map(PathBuf::from);
    let promotion_recording = promotion_path.as_ref().map(|_| recording.clone());
    let exchange_count = recording.requests.len();
    let database = TempDatabase::new("deepswe-replay")?;
    let mut recorder = LlmHttpProxy::replay_with_authorization(
        recording,
        false,
        Some(REPLAY_PROVIDER_KEY.to_owned()),
    )
    .await?;

    let primary = run_benchmark(
        &instruction,
        &shell_url,
        REPLAY_PROVIDER_KEY,
        &recorder,
        &database,
    )
    .await;
    let exhausted = recorder.replay_exhausted();
    let stop = recorder.stop().await;
    if sqlite_contains_secret(database.path(), REPLAY_PROVIDER_KEY).await? {
        return Err(Error::other("replay provider key reached runtime SQLite").into());
    }
    stop?;
    let state = primary?;
    if !exhausted {
        return Err(Error::other("DeepSWE provider replay did not consume every exchange").into());
    }
    let database_path = database.path().to_owned();
    spawn_db_blocking(move || trace.assert_matches_stopped_database(&database_path)).await??;
    if let (Some(path), Some(recording)) = (promotion_path, promotion_recording) {
        recording
            .promote_immutable_compressed(&path, &[REPLAY_PROVIDER_KEY, TEST_CONTROLLER_SECRET])?;
    }
    eprintln!(
        "ZODE_DEEPSWE_REPLAY_COMPLETE exchanges={} handoff_exercised={} transcript_messages={}",
        exchange_count,
        !state["context_handoff"].is_null(),
        state["transcript"].as_array().map_or(0, Vec::len)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_recorded_deepswe_long_run_replays_through_real_endpoint() -> TestResult<()> {
    if file_sha256(Path::new(TRACKED_LLM_REPLAY))? != TRACKED_LLM_REPLAY_SHA256 {
        return Err(Error::other("DeepSWE provider cassette file digest is invalid").into());
    }
    let trace = DeepSweEventTrace::load(
        Path::new(TRACKED_EVENT_REPLAY),
        TRACKED_EVENT_REPLAY_SHA256,
        TRACKED_LLM_REPLAY_SHA256,
        &[REPLAY_PROVIDER_KEY, TEST_CONTROLLER_SECRET],
    )?;
    if trace.event_count() != 1_442 || trace.tool_count()? != 158 {
        return Err(Error::other("DeepSWE event trace has the wrong causal extent").into());
    }
    let recording = LlmHttpRecording::load_compressed(Path::new(TRACKED_LLM_REPLAY))?;
    if recording.requests.len() != 177 {
        return Err(Error::other("DeepSWE cassette has the wrong exchange count").into());
    }
    let instruction = trace.instruction()?;
    let mut shell = EventToolFixture::start(&trace).await?;
    let database = TempDatabase::new("deepswe-tracked-replay")?;
    let mut recorder = LlmHttpProxy::replay_with_authorization(
        recording,
        false,
        Some(REPLAY_PROVIDER_KEY.to_owned()),
    )
    .await?;

    let primary = timeout(
        LOCAL_REPLAY_TIMEOUT,
        run_benchmark(
            &instruction,
            &shell.url(),
            REPLAY_PROVIDER_KEY,
            &recorder,
            &database,
        ),
    )
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "tracked DeepSWE replay timed out"))?;
    let provider_exhausted = recorder.replay_exhausted();
    let shell_exhausted = shell.assert_exhausted();
    let provider_stop = recorder.stop().await;
    let shell_stop = shell.stop().await;
    if sqlite_contains_secret(database.path(), REPLAY_PROVIDER_KEY).await? {
        return Err(Error::other("replay provider key reached runtime SQLite").into());
    }
    provider_stop?;
    shell_stop?;
    shell_exhausted?;
    let state = primary?;
    if !provider_exhausted {
        return Err(Error::other("DeepSWE provider replay was not exhausted").into());
    }
    shell.assert_durable_outcomes(&state)?;
    let database_path = database.path().to_owned();
    spawn_db_blocking(move || trace.assert_matches_stopped_database(&database_path)).await??;
    if !state["context_handoff"].is_null() {
        return Err(Error::other("DeepSWE replay handed off below its context threshold").into());
    }
    Ok(())
}

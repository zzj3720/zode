#![allow(dead_code)]

mod deepswe_support;
mod support;

use std::{
    collections::HashMap,
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
use deepswe_support::{file_sha256, DeepSweEventTrace, DeepSweToolExchange, DeepSweToolOutcome};
use futures_util::StreamExt;
use reqwest::StatusCode;
use serde_json::{json, Value};
use support::{
    authenticated_as, http_client, new_llm_live_recording_run_dir, require_ulid, response_text,
    scan_llm_recording_tree, spawn_db_blocking, sqlite_contains_secret, write_endpoint_config,
    HttpFixture, LlmHttpProxy, LlmHttpRecording, LlmHttpRecordingMetadata, ModelFixture,
    ModelScript, TempDatabase, TestResult, TestZode, ToolFixture, ToolScript,
    TEST_CONTROLLER_AUTHORITY, TEST_CONTROLLER_SECRET,
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
const TRACKED_LLM_REPLAY_INDEX: &str =
    "tests/fixtures/deepswe/anko_default_function_arguments_deepseek_v4_flash.v2.llm-index.bin.zst";
const TRACKED_LLM_REPLAY_INDEX_SHA256: &str =
    "ad8628520a8619b0d649850c1b73149b0b7cd29a9f8987076f39811ff0376f41";
const TRACKED_EVENT_REPLAY: &str =
    "tests/fixtures/deepswe/anko_default_function_arguments_deepseek_v4_flash.v2.events.json";
const TRACKED_EVENT_REPLAY_SHA256: &str =
    "2927398928170ac9a3a6993baf6d99b0c69357629109d92c0e9da303e0f40fec";

struct EventToolFixtureState {
    exchanges: Vec<DeepSweToolExchange>,
    next: Mutex<usize>,
    error: Mutex<Option<String>>,
    observed_at: Mutex<Vec<Instant>>,
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
            observed_at: Mutex::new(Vec::new()),
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
        let transcript = session["transcript"]
            .as_array()
            .ok_or_else(|| Error::other("DeepSWE replay omitted the durable transcript"))?;
        let mut tool_messages = HashMap::with_capacity(self.state.exchanges.len());
        for message in transcript
            .iter()
            .filter(|message| message["role"] == "tool")
        {
            let tool_call_id = message["tool_call_id"].as_str().ok_or_else(|| {
                Error::other("DeepSWE replay durable tool result omitted its identity")
            })?;
            if tool_messages.insert(tool_call_id, message).is_some() {
                return Err(
                    Error::other("DeepSWE replay repeated a durable tool-result identity").into(),
                );
            }
        }
        if tool_messages.len() != self.state.exchanges.len() {
            return Err(
                Error::other("DeepSWE replay did not commit every recorded tool result").into(),
            );
        }
        for expected in &self.state.exchanges {
            let message = tool_messages
                .get(expected.tool_call_id.as_str())
                .ok_or_else(|| Error::other("DeepSWE replay omitted a durable tool identity"))?;
            let content = message["content"]
                .as_str()
                .ok_or_else(|| Error::other("DeepSWE replay emitted a non-text tool result"))?;
            if let DeepSweToolOutcome::Completed(expected_content) = &expected.outcome {
                if content != expected_content {
                    return Err(Error::other(
                        "DeepSWE replay durable tool result did not match its recorded input",
                    )
                    .into());
                }
            }
        }
        let projected_tools = session["tool_calls"]
            .as_array()
            .ok_or_else(|| Error::other("DeepSWE replay omitted tool-call projections"))?;
        let mut tool_calls = HashMap::with_capacity(self.state.exchanges.len());
        for call in projected_tools {
            let tool_call_id = call["tool_call_id"].as_str().ok_or_else(|| {
                Error::other("DeepSWE replay projected a tool outcome without identity")
            })?;
            if tool_calls.insert(tool_call_id, call).is_some() {
                return Err(
                    Error::other("DeepSWE replay repeated a projected tool identity").into(),
                );
            }
        }
        if tool_calls.len() != self.state.exchanges.len() {
            return Err(Error::other("DeepSWE replay omitted a projected tool outcome").into());
        }
        for expected in &self.state.exchanges {
            let call = tool_calls
                .get(expected.tool_call_id.as_str())
                .ok_or_else(|| Error::other("DeepSWE replay omitted a projected tool identity"))?;
            let valid = match &expected.outcome {
                DeepSweToolOutcome::Completed(_) => {
                    call["status"] == "completed"
                        && !call["result"].is_null()
                        && call["error"].is_null()
                }
                DeepSweToolOutcome::Failed => {
                    call["status"] == "failed"
                        && call["result"].is_null()
                        && !call["error"].is_null()
                }
                DeepSweToolOutcome::Pending => false,
            };
            if !valid {
                return Err(Error::other("DeepSWE replay projected the wrong tool outcome").into());
            }
        }
        Ok(())
    }

    fn observed_request_times(&self) -> Vec<Instant> {
        self.state
            .observed_at
            .lock()
            .expect("event-derived tool fixture observation-time mutex poisoned")
            .clone()
    }

    async fn stop(&mut self) -> TestResult<()> {
        self.server.stop().await
    }
}

async fn replay_event_tool_request(
    State(state): State<Arc<EventToolFixtureState>>,
    Json(body): Json<Value>,
) -> (axum::http::StatusCode, Json<Value>) {
    state
        .observed_at
        .lock()
        .expect("event-derived tool fixture observation-time mutex poisoned")
        .push(Instant::now());
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
    match expected.outcome {
        DeepSweToolOutcome::Completed(content) => (
            axum::http::StatusCode::OK,
            Json(json!({"result": {"content": content}})),
        ),
        DeepSweToolOutcome::Failed => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"result": {"content": "recorded tool failure"}})),
        ),
        DeepSweToolOutcome::Pending => (
            axum::http::StatusCode::CONFLICT,
            Json(json!({"result": {"content": "incomplete event trace"}})),
        ),
    }
}

fn report_boundary_gaps(provider: Vec<Instant>, tool: Vec<Instant>) -> u128 {
    let mut observations = provider
        .into_iter()
        .map(|at| (at, 'P'))
        .chain(tool.into_iter().map(|at| (at, 'T')))
        .collect::<Vec<_>>();
    observations.sort_unstable_by_key(|(at, _)| *at);
    let mut buckets = std::collections::BTreeMap::<[char; 2], Vec<u128>>::new();
    for pair in observations.windows(2) {
        buckets
            .entry([pair[0].1, pair[1].1])
            .or_default()
            .push(pair[1].0.duration_since(pair[0].0).as_micros());
    }
    let mut ordinary_total_us = 0;
    for (transition, mut gaps) in buckets {
        let quarter = (gaps.len() / 4).max(1);
        let mut first_quarter = gaps.iter().take(quarter).copied().collect::<Vec<_>>();
        let mut last_quarter = gaps.iter().rev().take(quarter).copied().collect::<Vec<_>>();
        first_quarter.sort_unstable();
        last_quarter.sort_unstable();
        let first_quarter_p50 = first_quarter[first_quarter.len() / 2];
        let last_quarter_p50 = last_quarter[last_quarter.len() / 2];
        let growth_percent = last_quarter_p50
            .saturating_mul(100)
            .checked_div(first_quarter_p50)
            .unwrap_or(u128::MAX);
        if transition != ['P', 'P'] {
            ordinary_total_us += gaps.iter().sum::<u128>();
        }
        gaps.sort_unstable();
        let percentile = |numerator: usize| {
            let index = gaps.len().saturating_sub(1).saturating_mul(numerator) / 100;
            gaps[index]
        };
        eprintln!(
            "ZODE_DEEPSWE_BOUNDARY_GAPS transition={}{} count={} total_ms={} p50_us={} p95_us={} max_us={} first_quarter_p50_us={} last_quarter_p50_us={} growth_percent={}",
            transition[0],
            transition[1],
            gaps.len(),
            gaps.iter().sum::<u128>() / 1_000,
            percentile(50),
            percentile(95),
            gaps.last().copied().unwrap_or_default(),
            first_quarter_p50,
            last_quarter_p50,
            growth_percent,
        );
    }
    ordinary_total_us
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

fn sqlite_file_set_bytes(path: &Path) -> TestResult<u64> {
    let mut total = 0_u64;
    for suffix in ["", "-wal", "-shm"] {
        let candidate = if suffix.is_empty() {
            path.to_owned()
        } else {
            let mut value = path.as_os_str().to_owned();
            value.push(suffix);
            PathBuf::from(value)
        };
        match fs::metadata(candidate) {
            Ok(metadata) => total = total.saturating_add(metadata.len()),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(total)
}

fn positive_env_u64(name: &'static str) -> TestResult<Option<u64>> {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("{name} must be a positive integer"),
                    )
                })
        })
        .transpose()
        .map_err(Into::into)
}

#[derive(Clone, Copy)]
enum ProviderTiming {
    Live,
    Replay,
}

impl ProviderTiming {
    fn apply(self, config: &mut Value) {
        if matches!(self, Self::Replay) {
            config["provider_execution"]["transport_retry"] = json!({
                "initial_delay_ms": 1
            });
        }
    }
}

fn benchmark_config(
    database: &Path,
    provider_origin: &str,
    shell_url: &str,
    provider_timing: ProviderTiming,
) -> TestResult<PathBuf> {
    let shell_description = env::var("ZODE_DEEPSWE_SHELL_DESCRIPTION").unwrap_or_else(|_| {
        "Execute a shell command in the DeepSWE task container at /app. Use it to inspect files, edit the implementation, run tests, and commit the completed solution.".to_owned()
    });
    let tool = json!({
        "name": "shell",
        "description": shell_description,
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
    provider_timing.apply(&mut config);
    // The generic E2E config snapshots every event so short snapshot tests can
    // exercise that path. A long benchmark instead inherits the production
    // policy unless a diagnostic run explicitly selects a cadence below.
    config["runtime"]["snapshot_every_events"] = Value::Null;
    if let Ok(value) = env::var("ZODE_DEEPSWE_SNAPSHOT_EVERY_EVENTS") {
        config["runtime"]["snapshot_every_events"] = if value == "off" {
            Value::Null
        } else {
            let cadence = value.parse::<u64>().map_err(|_| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "ZODE_DEEPSWE_SNAPSHOT_EVERY_EVENTS must be `off` or a positive integer",
                )
            })?;
            if cadence == 0 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "ZODE_DEEPSWE_SNAPSHOT_EVERY_EVENTS must be `off` or a positive integer",
                )
                .into());
            }
            json!(cadence)
        };
    }
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

async fn wait_for_terminal_activation(
    response: reqwest::Response,
    client: &reqwest::Client,
    session_url: &str,
    session_id: &str,
    provider_key: &str,
) -> TestResult<(String, Value)> {
    timeout(BENCHMARK_TIMEOUT, async {
        let mut stream = response.bytes_stream();
        let mut buffer = Vec::new();
        let mut saw_activation = false;
        loop {
            let chunk = stream.next().await.ok_or_else(|| {
                Error::new(
                    ErrorKind::UnexpectedEof,
                    "Endpoint-wide SSE ended before the benchmark activation finished",
                )
            })??;
            buffer.extend_from_slice(&chunk);
            while let Some(end) = buffer
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|position| position + 2)
            {
                let frame = buffer.drain(..end).collect::<Vec<_>>();
                if frame
                    .windows(provider_key.len())
                    .any(|window| window == provider_key.as_bytes())
                    || frame
                        .windows(TEST_CONTROLLER_SECRET.len())
                        .any(|window| window == TEST_CONTROLLER_SECRET.as_bytes())
                {
                    return Err(Error::other("public SSE exposed credential material").into());
                }
                let text = std::str::from_utf8(&frame)?;
                let event = text.lines().find_map(|line| line.strip_prefix("event: "));
                let data = text
                    .lines()
                    .find_map(|line| line.strip_prefix("data: "))
                    .map(serde_json::from_str::<Value>)
                    .transpose()?;
                let Some(data) = data else {
                    continue;
                };
                if data["session_id"] != session_id {
                    continue;
                }
                let kind = event.or_else(|| data["kind"].as_str());
                if kind == Some("activation_started") {
                    saw_activation = true;
                } else if kind == Some("activation_finished") {
                    if !saw_activation {
                        return Err(Error::other(
                            "benchmark activation finished before its durable start was observed",
                        )
                        .into());
                    }
                    let outcome = data["data"]["outcome"].as_str().ok_or_else(|| {
                        Error::other("benchmark activation finish omitted its durable outcome")
                    })?;
                    if outcome == "wait" {
                        // An async tool may outlive the activation that
                        // dispatched it. Its terminal delivery starts a fresh
                        // activation, so a wait boundary is not the benchmark
                        // completion boundary.
                        saw_activation = false;
                        continue;
                    }
                    let state = public_json(
                        authenticated_as(client.get(session_url), SUBJECT),
                        StatusCode::OK,
                        provider_key,
                    )
                    .await?;
                    let has_pending_work = !state["wait"].is_null()
                        || state["delivery"]["pending"]
                            .as_array()
                            .is_some_and(|deliveries| !deliveries.is_empty())
                        || state["tool_calls"].as_array().is_some_and(|calls| {
                            calls.iter().any(|call| call["status"] == "running")
                        });
                    if state["status"] != "idle"
                        || !state["active_activation"].is_null()
                        || has_pending_work
                    {
                        // A committed tool result may race the activation
                        // that consumed a sibling result. Keep the same
                        // Endpoint-wide SSE open until every durable delivery
                        // reaches a later terminal activation.
                        saw_activation = false;
                        continue;
                    }
                    return Ok((outcome.to_owned(), state));
                }
            }
        }
    })
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "DeepSWE agent timed out"))?
}

async fn wait_for_shell_responses(
    client: &reqwest::Client,
    shell_url: &str,
    expected: usize,
) -> TestResult<()> {
    let mut observation_url = url::Url::parse(shell_url)?;
    observation_url.set_path("/_zode-test/observations");
    observation_url.set_query(None);
    timeout(LOCAL_REPLAY_TIMEOUT, async {
        loop {
            let response = client.get(observation_url.clone()).send().await?;
            if response.status() != StatusCode::OK {
                return Err(
                    Error::other("DeepSWE shell observation boundary was unavailable").into(),
                );
            }
            let observation: Value = response.json().await?;
            let responses = observation["responses_written"].as_u64().ok_or_else(|| {
                Error::other("DeepSWE shell observation omitted its response count")
            })?;
            let expected = u64::try_from(expected)?;
            if responses == expected {
                return Ok(());
            }
            if responses > expected {
                return Err(Error::other(
                    "DeepSWE shell replay wrote an unexpected extra response",
                )
                .into());
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::TimedOut,
            "DeepSWE shell response barrier timed out",
        )
    })?
}

async fn wait_for_tool_terminal_event(
    response: reqwest::Response,
    session_id: String,
    tool_call_id: String,
) -> TestResult<String> {
    let mut stream = response.bytes_stream();
    let mut buffer = Vec::new();
    loop {
        let chunk = stream.next().await.ok_or_else(|| {
            Error::new(
                ErrorKind::UnexpectedEof,
                "Endpoint-wide SSE ended before the replayed tool reached a terminal state",
            )
        })??;
        buffer.extend_from_slice(&chunk);
        while let Some(end) = buffer
            .windows(2)
            .position(|window| window == b"\n\n")
            .map(|position| position + 2)
        {
            let frame = buffer.drain(..end).collect::<Vec<_>>();
            if frame
                .windows(REPLAY_PROVIDER_KEY.len())
                .any(|window| window == REPLAY_PROVIDER_KEY.as_bytes())
                || frame
                    .windows(TEST_CONTROLLER_SECRET.len())
                    .any(|window| window == TEST_CONTROLLER_SECRET.as_bytes())
            {
                return Err(Error::other("public SSE exposed credential material").into());
            }
            let text = std::str::from_utf8(&frame)?;
            let event = text.lines().find_map(|line| line.strip_prefix("event: "));
            let data = text
                .lines()
                .find_map(|line| line.strip_prefix("data: "))
                .map(serde_json::from_str::<Value>)
                .transpose()?;
            let Some(data) = data else {
                continue;
            };
            if data["session_id"] != session_id {
                continue;
            }
            let kind = event.or_else(|| data["kind"].as_str());
            if matches!(
                kind,
                Some("async_tool_call_completed" | "async_tool_call_failed")
            ) && data["data"]["tool_call_id"] == tool_call_id
            {
                return Ok(kind.expect("terminal tool event has a kind").to_owned());
            }
        }
    }
}

async fn run_benchmark(
    instruction: &str,
    shell_url: &str,
    provider_key: &str,
    provider_base_url: &str,
    database: &TempDatabase,
    provider_timing: ProviderTiming,
) -> TestResult<Value> {
    let benchmark_started = Instant::now();
    let provider_origin = url::Url::parse(provider_base_url)?
        .origin()
        .ascii_serialization();
    let config = benchmark_config(
        database.path(),
        &provider_origin,
        shell_url,
        provider_timing,
    )?;
    let mut endpoint = TestZode::start(
        database.path(),
        &config,
        &[provider_key, TEST_CONTROLLER_SECRET],
    )
    .await?;
    let endpoint_started = benchmark_started.elapsed();
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
                            "base_url": provider_base_url
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
        let message_admitted = benchmark_started.elapsed();

        let started = Instant::now();
        let session_url = endpoint.url(&format!("/v1/sessions/{session_id}"));
        let (terminal_outcome, state) = wait_for_terminal_activation(
            events,
            &client,
            &session_url,
            &session_id,
            provider_key,
        )
        .await?;
        let has_assistant = state["transcript"]
            .as_array()
            .is_some_and(|messages| messages.iter().any(|message| message["role"] == "assistant"));
        let scored_terminal = terminal_outcome == "finished" && has_assistant;
        if !scored_terminal
            || state["status"] != "idle"
            || !state["active_activation"].is_null()
        {
            return Err(Error::other(format!(
                "DeepSWE terminal event with outcome {terminal_outcome} did not converge to an idle, scoreable attempt: {}",
                benchmark_state_summary(&state)
            ))
            .into());
        }
        eprintln!(
            "ZODE_DEEPSWE_JOURNEY endpoint_start_ms={} admission_ms={} active_ms={}",
            endpoint_started.as_millis(),
            (message_admitted - endpoint_started).as_millis(),
            started.elapsed().as_millis(),
        );
        Ok(state)
    }
    .await;

    let stop = endpoint.stop(&[provider_key, TEST_CONTROLLER_SECRET]).await;
    let endpoint_stopped = benchmark_started.elapsed();
    eprintln!(
        "ZODE_DEEPSWE_JOURNEY_STOP elapsed_ms={}",
        endpoint_stopped.as_millis()
    );
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

    let provider_base_url = recorder.base_url("/zen/go/v1");
    let primary = run_benchmark(
        &instruction,
        &shell_url,
        &key,
        &provider_base_url,
        &database,
        ProviderTiming::Live,
    )
    .await;
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
async fn e2e_deepswe_tool_only_terminal_attempt_reaches_verifier_boundary() -> TestResult<()> {
    let mut model = ModelFixture::start(vec![
        ModelScript::tool_call(
            "tool-only-shell",
            "shell",
            r#"{"command":"printf tool-only"}"#,
        ),
        ModelScript::final_text(""),
    ])
    .await?;
    let mut shell = ToolFixture::start(vec![ToolScript::Response(json!({
        "status": "completed",
        "result": {"content": "tool-only-ok"}
    }))])
    .await?;
    let database = TempDatabase::new("deepswe-tool-only-terminal")?;

    let primary = run_benchmark(
        "Run one shell command and then finish without explanatory prose.",
        &shell.adapter_url(),
        REPLAY_PROVIDER_KEY,
        &model.provider_url(),
        &database,
        ProviderTiming::Live,
    )
    .await;
    let model_stop = model.stop().await;
    let shell_stop = shell.stop().await;
    model_stop?;
    shell_stop?;
    let state = primary?;

    if model.request_count() != 2 || shell.completed_count() != 1 {
        return Err(Error::other(
            "DeepSWE tool-only terminal attempt did not cross both public effect boundaries",
        )
        .into());
    }
    if state["transcript"].as_array().is_none_or(|messages| {
        messages.iter().any(|message| {
            message["role"] == "assistant"
                && message["content"]
                    .as_str()
                    .is_some_and(|content| !content.is_empty())
        })
    }) {
        return Err(Error::other(
            "DeepSWE tool-only terminal fixture unexpectedly emitted assistant prose",
        )
        .into());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_deepswe_terminal_model_failure_is_not_scoreable() -> TestResult<()> {
    let mut model = ModelFixture::start(vec![
        ModelScript::tool_call(
            "terminal-failure-shell",
            "shell",
            r#"{"command":"printf work-before-terminal-failure"}"#,
        ),
        ModelScript::status(400),
        ModelScript::status(400),
        ModelScript::status(400),
    ])
    .await?;
    let mut shell = ToolFixture::start(vec![ToolScript::Response(json!({
        "status": "completed",
        "result": {"content": "work-before-terminal-failure-ok"}
    }))])
    .await?;
    let database = TempDatabase::new("deepswe-terminal-model-failure")?;

    let primary = run_benchmark(
        "Run one shell command, then let the provider exhaust the final model step.",
        &shell.adapter_url(),
        REPLAY_PROVIDER_KEY,
        &model.provider_url(),
        &database,
        ProviderTiming::Live,
    )
    .await;
    let model_stop = model.stop().await;
    let shell_stop = shell.stop().await;
    model_stop?;
    shell_stop?;
    if model.request_count() != 4 || shell.completed_count() != 1 {
        return Err(Error::other(
            "DeepSWE terminal model failure did not cross the real provider and tool boundaries",
        )
        .into());
    }
    if primary.is_ok() {
        return Err(Error::other(
            "DeepSWE terminal provider failure was incorrectly accepted as a scoreable attempt",
        )
        .into());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_deepswe_failed_tool_outcome_is_recorded_and_replayed() -> TestResult<()> {
    const PROVIDER_FIXTURE_SHA256: &str =
        "f05477636ed4ab48678812d576b0503979edc59721ca0daf9e23781a99811bca";
    let instruction = "Run the failing shell command once, then report that it failed.";
    let scripts = || {
        vec![
            ModelScript::tool_call("failed-shell", "shell", r#"{"command":"exit 17"}"#),
            ModelScript::final_text("The shell command failed."),
        ]
    };

    let mut recording_model = ModelFixture::start(scripts()).await?;
    let mut failing_shell = ToolFixture::start(vec![ToolScript::Status(500)]).await?;
    let recording_database = TempDatabase::new("deepswe-failed-tool-recording")?;
    let recording = run_benchmark(
        instruction,
        &failing_shell.adapter_url(),
        REPLAY_PROVIDER_KEY,
        &recording_model.provider_url(),
        &recording_database,
        ProviderTiming::Replay,
    )
    .await;
    recording_model.stop().await?;
    failing_shell.stop().await?;
    let recording_state = recording?;
    let recorded_tools = recording_state["tool_calls"]
        .as_array()
        .ok_or_else(|| Error::other("DeepSWE failed-tool recording omitted tool projections"))?;
    if recorded_tools.len() != 1
        || recorded_tools[0]["status"] != "failed"
        || !recorded_tools[0]["result"].is_null()
        || recorded_tools[0]["error"].is_null()
    {
        return Err(Error::other(
            "DeepSWE failed-tool recording did not reach one durable failed outcome",
        )
        .into());
    }

    let recording_database_path = recording_database.path().to_owned();
    let trace = spawn_db_blocking(move || {
        DeepSweEventTrace::read_stopped_database(&recording_database_path, PROVIDER_FIXTURE_SHA256)
    })
    .await??;

    let mut replay_model = ModelFixture::start(scripts()).await?;
    let mut replay_shell = EventToolFixture::start(&trace).await?;
    let replay_database = TempDatabase::new("deepswe-failed-tool-replay")?;
    let replay = run_benchmark(
        instruction,
        &replay_shell.url(),
        REPLAY_PROVIDER_KEY,
        &replay_model.provider_url(),
        &replay_database,
        ProviderTiming::Replay,
    )
    .await;
    replay_model.stop().await?;
    replay_shell.stop().await?;
    let replay_state = replay?;
    replay_shell.assert_exhausted()?;
    replay_shell.assert_durable_outcomes(&replay_state)?;

    let replay_database_path = replay_database.path().to_owned();
    spawn_db_blocking(move || trace.assert_matches_stopped_database(&replay_database_path))
        .await??;
    Ok(())
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
    let mut recorder = LlmHttpProxy::replay_hashes_with_authorization(
        recording,
        false,
        Some(REPLAY_PROVIDER_KEY.to_owned()),
    )
    .await?;

    let primary = run_benchmark(
        &instruction,
        &shell_url,
        REPLAY_PROVIDER_KEY,
        &recorder.base_url("/zen/go/v1"),
        &database,
        ProviderTiming::Replay,
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
#[ignore = "replays a retained incomplete DeepSWE failure prefix in a real task container"]
async fn e2e_replayed_deepswe_returned_tool_response_reaches_durable_terminal() -> TestResult<()> {
    let replay_path = required_path("ZODE_DEEPSWE_REPLAY_FILE")?;
    let event_replay_path = required_path("ZODE_DEEPSWE_EVENT_REPLAY_FILE")?;
    let shell_url = env::var("ZODE_DEEPSWE_SHELL_URL")?;
    let provider_file_sha256 = file_sha256(&replay_path)?;
    let event_file_sha256 = file_sha256(&event_replay_path)?;
    let trace = DeepSweEventTrace::load_partial_failure_prefix(
        &event_replay_path,
        &event_file_sha256,
        &provider_file_sha256,
        &[REPLAY_PROVIDER_KEY, TEST_CONTROLLER_SECRET],
    )?;
    let exchanges = trace.tool_exchanges_with_trailing_pending()?;
    let pending_tool_call_id = trace.trailing_pending_tool_call_id()?;
    let recording = if replay_path.extension().and_then(|value| value.to_str()) == Some("zst") {
        LlmHttpRecording::load_compressed(&replay_path)?
    } else {
        LlmHttpRecording::load_long_run(&replay_path)?
    };
    if trace.event_count() != 657 || exchanges.len() != 41 || recording.requests.len() != 41 {
        return Err(
            Error::other("DeepSWE stalled failure prefix has the wrong causal extent").into(),
        );
    }
    let instruction = trace.instruction()?;
    let database = TempDatabase::new("deepswe-stalled-tool-prefix")?;
    let mut recorder = LlmHttpProxy::replay_hashes_with_authorization(
        recording,
        false,
        Some(REPLAY_PROVIDER_KEY.to_owned()),
    )
    .await?;
    let provider_origin = url::Url::parse(&recorder.base_url("/zen/go/v1"))?
        .origin()
        .ascii_serialization();
    let config = benchmark_config(
        database.path(),
        &provider_origin,
        &shell_url,
        ProviderTiming::Replay,
    )?;
    let mut endpoint = TestZode::start(
        database.path(),
        &config,
        &[REPLAY_PROVIDER_KEY, TEST_CONTROLLER_SECRET],
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
                    "payload": REPLAY_PROVIDER_KEY
                }
            })),
            StatusCode::CREATED,
            REPLAY_PROVIDER_KEY,
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
            REPLAY_PROVIDER_KEY,
        )
        .await?;
        let session_id = require_ulid(&created)?;
        let events = authenticated_as(client.get(endpoint.url("/v1/events")), SUBJECT)
            .send()
            .await?;
        if events.status() != StatusCode::OK {
            return Err(Error::other("Endpoint-wide SSE did not open").into());
        }
        let mut terminal = tokio::spawn(wait_for_tool_terminal_event(
            events,
            session_id.clone(),
            pending_tool_call_id.clone(),
        ));
        let journey = async {
            public_json(
                authenticated_as(
                    client.post(endpoint.url(&format!("/v1/sessions/{session_id}/messages"))),
                    SUBJECT,
                )
                .header("Idempotency-Key", "deepswe-instruction")
                .json(&json!({"content": instruction})),
                StatusCode::ACCEPTED,
                REPLAY_PROVIDER_KEY,
            )
            .await?;
            recorder
                .wait_for_completed_exchanges_with_timeout(41, LOCAL_REPLAY_TIMEOUT)
                .await?;
            wait_for_shell_responses(&client, &shell_url, 41).await?;
            let terminal_kind = timeout(Duration::from_secs(30), &mut terminal)
                .await
                .map_err(|_| {
                    Error::new(
                        ErrorKind::TimedOut,
                        "returned DeepSWE tool response did not reach a durable terminal event",
                    )
                })?
                .map_err(|error| {
                    Error::other(format!("tool-terminal SSE task failed: {error}"))
                })??;
            if terminal_kind != "async_tool_call_completed" {
                return Err(Error::other(
                    "replayed DeepSWE tool response reached the wrong durable terminal state",
                )
                .into());
            }
            let state = public_json(
                authenticated_as(
                    client.get(endpoint.url(&format!("/v1/sessions/{session_id}"))),
                    SUBJECT,
                ),
                StatusCode::OK,
                REPLAY_PROVIDER_KEY,
            )
            .await?;
            let terminal_projection = state["tool_calls"].as_array().and_then(|calls| {
                calls.iter().find(|call| {
                    call["tool_call_id"] == pending_tool_call_id && call["status"] == "completed"
                })
            });
            if terminal_projection.is_none() {
                return Err(Error::other(
                    "returned DeepSWE tool response was not durably projected as completed",
                )
                .into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }
        .await;
        terminal.abort();
        journey
    }
    .await;

    let endpoint_stop = endpoint
        .stop_with_output(&[REPLAY_PROVIDER_KEY, TEST_CONTROLLER_SECRET])
        .await;
    let prefix_exhausted = recorder.replay_prefix_exhausted_allowing_after_end();
    let recorder_stop = recorder.stop().await;
    let (endpoint_stdout, endpoint_stderr) = endpoint_stop?;
    for line in String::from_utf8_lossy(&endpoint_stdout)
        .lines()
        .chain(String::from_utf8_lossy(&endpoint_stderr).lines())
        .filter(|line| line.contains("background tool completion append failed"))
    {
        eprintln!("ZODE_DEEPSWE_STALLED_TOOL_RUNTIME {line}");
    }
    recorder_stop?;
    primary?;
    if !prefix_exhausted {
        return Err(
            Error::other("DeepSWE provider failure prefix was not replayed exactly").into(),
        );
    }
    if sqlite_contains_secret(database.path(), REPLAY_PROVIDER_KEY).await? {
        return Err(Error::other("replay provider key reached runtime SQLite").into());
    }
    eprintln!("ZODE_DEEPSWE_STALLED_TOOL_REPLAY_COMPLETE exchanges=41 tools=41 events=657");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_recorded_deepswe_long_run_replays_through_real_endpoint() -> TestResult<()> {
    let replay_started = Instant::now();
    let performance_budget =
        positive_env_u64("ZODE_DEEPSWE_REPLAY_MAX_MS")?.map(Duration::from_millis);
    let load_budget = positive_env_u64("ZODE_DEEPSWE_REPLAY_MAX_LOAD_MS")?;
    let ordinary_boundary_budget =
        positive_env_u64("ZODE_DEEPSWE_REPLAY_MAX_ORDINARY_BOUNDARY_MS")?;
    let fixture_start_budget = positive_env_u64("ZODE_DEEPSWE_REPLAY_MAX_FIXTURE_START_MS")?;
    let retained_request_budget =
        positive_env_u64("ZODE_DEEPSWE_REPLAY_MAX_RETAINED_REQUEST_BYTES")?;
    let database_budget = positive_env_u64("ZODE_DEEPSWE_REPLAY_MAX_DATABASE_BYTES")?;
    let trace = DeepSweEventTrace::load(
        Path::new(TRACKED_EVENT_REPLAY),
        TRACKED_EVENT_REPLAY_SHA256,
        TRACKED_LLM_REPLAY_SHA256,
        &[REPLAY_PROVIDER_KEY, TEST_CONTROLLER_SECRET],
    )?;
    if trace.event_count() != 1_442 || trace.tool_count()? != 158 {
        return Err(Error::other("DeepSWE event trace has the wrong causal extent").into());
    }
    let event_trace_loaded = replay_started.elapsed();
    let recording = LlmHttpRecording::load_pinned_compressed_hash_replay_index(
        Path::new(TRACKED_LLM_REPLAY),
        TRACKED_LLM_REPLAY_SHA256,
        Path::new(TRACKED_LLM_REPLAY_INDEX),
        TRACKED_LLM_REPLAY_INDEX_SHA256,
    )?;
    if recording.request_count() != 177 {
        return Err(Error::other("DeepSWE cassette has the wrong exchange count").into());
    }
    let fixtures_loaded = replay_started.elapsed();
    let instruction = trace.instruction()?;
    let mut shell = EventToolFixture::start(&trace).await?;
    let database = TempDatabase::new("deepswe-tracked-replay")?;
    let mut recorder = LlmHttpProxy::replay_validated_hashes_with_authorization(
        recording,
        false,
        Some(REPLAY_PROVIDER_KEY.to_owned()),
    )
    .await?;
    let retained_request_bytes = recorder
        .replay_retained_request_match_bytes()
        .ok_or_else(|| Error::other("DeepSWE provider fixture did not start in replay mode"))?;
    let fixtures_started = replay_started.elapsed();

    let primary = timeout(
        LOCAL_REPLAY_TIMEOUT,
        run_benchmark(
            &instruction,
            &shell.url(),
            REPLAY_PROVIDER_KEY,
            &recorder.base_url("/zen/go/v1"),
            &database,
            ProviderTiming::Replay,
        ),
    )
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "tracked DeepSWE replay timed out"))?;
    let journey_finished = replay_started.elapsed();
    let ordinary_boundary_us = report_boundary_gaps(
        recorder.observed_request_times(),
        shell.observed_request_times(),
    );
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
    let fixtures_stopped = replay_started.elapsed();
    let state = primary?;
    if !provider_exhausted {
        return Err(Error::other("DeepSWE provider replay was not exhausted").into());
    }
    shell.assert_durable_outcomes(&state)?;
    let database_path = database.path().to_owned();
    spawn_db_blocking(move || trace.assert_matches_stopped_database(&database_path)).await??;
    let database_bytes = sqlite_file_set_bytes(database.path())?;
    let database_verified = replay_started.elapsed();
    if !state["context_handoff"].is_null() {
        return Err(Error::other("DeepSWE replay handed off below its context threshold").into());
    }
    let elapsed = replay_started.elapsed();
    eprintln!(
        "ZODE_DEEPSWE_REPLAY_PERF elapsed_ms={} load_ms={} event_trace_load_ms={} replay_index_load_ms={} fixture_start_ms={} journey_ms={} fixture_stop_ms={} database_verify_ms={} retained_request_bytes={} database_bytes={}",
        elapsed.as_millis(),
        fixtures_loaded.as_millis(),
        event_trace_loaded.as_millis(),
        (fixtures_loaded - event_trace_loaded).as_millis(),
        (fixtures_started - fixtures_loaded).as_millis(),
        (journey_finished - fixtures_started).as_millis(),
        (fixtures_stopped - journey_finished).as_millis(),
        (database_verified - fixtures_stopped).as_millis(),
        retained_request_bytes,
        database_bytes,
    );
    if let Some(budget) = performance_budget {
        if elapsed > budget {
            return Err(Error::new(
                ErrorKind::TimedOut,
                format!(
                    "DeepSWE replay completed correctly in {} ms but exceeded the explicit {} ms performance budget",
                    elapsed.as_millis(),
                    budget.as_millis()
                ),
            )
            .into());
        }
    }
    let load_ms = fixtures_loaded.as_millis();
    if load_budget.is_some_and(|budget| load_ms > u128::from(budget)) {
        return Err(Error::new(
            ErrorKind::TimedOut,
            format!("DeepSWE replay loaded correctly but cassette validation took {load_ms} ms"),
        )
        .into());
    }
    if ordinary_boundary_budget
        .is_some_and(|budget| ordinary_boundary_us > u128::from(budget) * 1_000)
    {
        return Err(Error::new(
            ErrorKind::TimedOut,
            format!(
                "DeepSWE replay completed correctly but ordinary provider/tool boundary transitions took {} ms",
                ordinary_boundary_us / 1_000
            ),
        )
        .into());
    }
    let fixture_start_ms = (fixtures_started - fixtures_loaded).as_millis();
    if fixture_start_budget.is_some_and(|budget| fixture_start_ms > u128::from(budget)) {
        return Err(Error::new(
            ErrorKind::TimedOut,
            format!(
                "DeepSWE replay completed correctly but validated fixture startup took {fixture_start_ms} ms"
            ),
        )
        .into());
    }
    if retained_request_budget
        .is_some_and(|budget| retained_request_bytes as u128 > u128::from(budget))
    {
        return Err(Error::other(format!(
            "DeepSWE replay completed correctly but retained {retained_request_bytes} request-matching bytes"
        ))
        .into());
    }
    if database_budget.is_some_and(|budget| database_bytes > budget) {
        return Err(Error::other(format!(
            "DeepSWE replay completed correctly but retained {database_bytes} SQLite bytes"
        ))
        .into());
    }
    Ok(())
}

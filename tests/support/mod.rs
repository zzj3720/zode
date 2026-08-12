#![allow(dead_code)]

#[path = "process_capture.rs"]
pub mod process_capture;

use process_capture::{ProcessCaptureSet, ProcessObservation, ProcessStopObservation};

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    future::Future,
    io::{Error as IoError, ErrorKind, Read, Write},
    ops::Deref,
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_stream::stream;
use axum::Router;
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode as AxumStatusCode},
    response::Response as AxumResponse,
    routing::post,
};
use bincode::Options;
use bytes::Bytes;
use futures_util::StreamExt;
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader},
    net::TcpListener,
    process::Child,
    runtime::Builder,
    sync::{oneshot, watch, Notify},
    task::JoinHandle,
    time::{sleep, timeout},
};

pub type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const HTTP_RESPONSE_HEADERS_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_RESPONSE_BODY_TIMEOUT: Duration = Duration::from_secs(5);
const CHILD_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const FIXTURE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const READINESS_TIMEOUT: Duration = Duration::from_secs(10);
const LLM_UPSTREAM_HEADERS_TIMEOUT: Duration = Duration::from_secs(30);
const READY_PREFIX: &str = "ZODE_READY ";

pub const TEST_CONTROLLER_AUTHORITY: &str = "controller-e2e";
pub const TEST_CONTROLLER_SECRET: &str = "controller-secret-e2e";
pub const TEST_SUBJECT: &str = "subject-e2e";
pub const TEST_AUTH_PROFILE: &str = "profile-e2e";
pub const TEST_PROVIDER_SECRET: &str = "provider-secret-e2e";

type ChildOutputTask = JoinHandle<std::io::Result<Vec<u8>>>;

/// Shared real-process harness for provider tests. The only variation between
/// live and replay is the transport URL injected into the endpoint config.
pub struct TestZode {
    child: Option<Child>,
    pid: Option<u32>,
    base_url: String,
    stdout_drain: Option<ChildOutputTask>,
    stderr_drain: Option<ChildOutputTask>,
}

impl TestZode {
    pub async fn start(database: &Path, config: &Path, forbidden: &[&str]) -> TestResult<Self> {
        Self::start_with_environment(database, config, forbidden, &[]).await
    }

    pub async fn start_with_environment(
        database: &Path,
        config: &Path,
        forbidden: &[&str],
        environment: &[(String, String)],
    ) -> TestResult<Self> {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_zode"));
        command
            .arg("--config")
            .arg(config)
            .arg("--database")
            .arg(database)
            .arg("--listen")
            .arg("127.0.0.1:0")
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for variable in [
            "OPENCODE_API_KEY",
            "DEEPSEEK_API_KEY",
            "OPENAI_API_KEY",
            "OPENROUTER_API_KEY",
            "ANTHROPIC_API_KEY",
            "GOOGLE_API_KEY",
            "GEMINI_API_KEY",
            "MISTRAL_API_KEY",
            "TOGETHER_API_KEY",
            "XAI_API_KEY",
            "GROQ_API_KEY",
            "COHERE_API_KEY",
        ] {
            command.env_remove(variable);
        }
        for (name, value) in environment {
            command.env(name, value);
        }
        let mut child = command.spawn()?;
        let pid = child
            .id()
            .ok_or_else(|| IoError::other("zode process did not expose a pid"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| IoError::other("zode stdout was unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| IoError::other("zode stderr was unavailable"))?;
        let stderr_drain = tokio::spawn(drain_child_output(stderr));
        let mut stdout_reader = BufReader::new(stdout);
        let mut readiness_line = String::new();
        let readiness = match timeout(
            READINESS_TIMEOUT,
            stdout_reader.read_line(&mut readiness_line),
        )
        .await
        {
            Ok(Ok(0)) => {
                return failed_zode_start(
                    "zode exited before readiness",
                    child,
                    stdout_reader,
                    stderr_drain,
                    forbidden,
                )
                .await;
            }
            Ok(Ok(_)) => readiness_line.trim_end().to_owned(),
            Ok(Err(error)) => {
                return failed_zode_start(
                    format!("zode readiness output failed: {error}"),
                    child,
                    stdout_reader,
                    stderr_drain,
                    forbidden,
                )
                .await;
            }
            Err(_) => {
                return failed_zode_start(
                    "zode readiness timed out",
                    child,
                    stdout_reader,
                    stderr_drain,
                    forbidden,
                )
                .await;
            }
        };
        if assert_child_output_secret_free(readiness.as_bytes(), forbidden).is_err() {
            return failed_zode_start(
                "zode readiness output contained credential material",
                child,
                stdout_reader,
                stderr_drain,
                forbidden,
            )
            .await;
        }
        let base_url = match readiness.strip_prefix(READY_PREFIX) {
            Some(value) if !value.trim().is_empty() => value.trim().to_owned(),
            _ => {
                return failed_zode_start(
                    "zode readiness line was invalid",
                    child,
                    stdout_reader,
                    stderr_drain,
                    forbidden,
                )
                .await;
            }
        };
        let stdout_drain = tokio::spawn(drain_child_output(stdout_reader));
        Ok(Self {
            child: Some(child),
            pid: Some(pid),
            base_url,
            stdout_drain: Some(stdout_drain),
            stderr_drain: Some(stderr_drain),
        })
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    pub async fn stop(&mut self, forbidden: &[&str]) -> TestResult<()> {
        self.stop_inner(forbidden).await.map(|_| ())
    }

    pub async fn stop_with_process_capture(
        &mut self,
        capture: &mut ProcessCaptureSet,
        process_name: &str,
        forbidden: &[&str],
    ) -> TestResult<()> {
        let stopped = self.stop_inner(forbidden).await?;
        let pid = stopped
            .pid
            .ok_or_else(|| IoError::other("zode process observation had no pid"))?;
        capture.capture_process(ProcessObservation {
            name: process_name.to_owned(),
            stdout: stopped.stdout,
            stderr: stopped.stderr,
            exit_code: stopped.status.code(),
            signal: process_signal(stopped.status),
            termination: if stopped.status.code().is_some() {
                "natural_exit".to_owned()
            } else {
                "signal_termination".to_owned()
            },
            stop: Some(ProcessStopObservation {
                observed_pids: vec![pid],
                reaped_pids: vec![pid],
                leaked_pids: Vec::new(),
                timed_out: false,
                flush_status: "ok".to_owned(),
                proof: true,
            }),
        })
    }

    async fn stop_inner(&mut self, forbidden: &[&str]) -> TestResult<TestZodeStop> {
        let mut errors = Vec::new();
        let status = if let Some(child) = self.child.take() {
            match kill_and_reap(child).await {
                Ok(status) => Some(status),
                Err(error) => {
                    errors.push(format!("child reap failed: {error}"));
                    None
                }
            }
        } else {
            None
        };
        let pid = self.pid.take();
        let stdout = match self.stdout_drain.take() {
            Some(task) => match collect_child_output(task).await {
                Ok(output) => output,
                Err(error) => {
                    errors.push(format!("stdout collection failed: {error}"));
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
        let stderr = match self.stderr_drain.take() {
            Some(task) => match collect_child_output(task).await {
                Ok(output) => output,
                Err(error) => {
                    errors.push(format!("stderr collection failed: {error}"));
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
        if assert_child_output_secret_free(&stdout, forbidden).is_err()
            || assert_child_output_secret_free(&stderr, forbidden).is_err()
        {
            errors.push("child output contained credential material".to_owned());
        }
        if errors.is_empty() {
            status
                .map(|status| TestZodeStop {
                    pid,
                    status,
                    stdout,
                    stderr,
                })
                .ok_or_else(|| IoError::other("zode process had no exit status").into())
        } else {
            Err(IoError::other(errors.join("; ")).into())
        }
    }
}

struct TestZodeStop {
    pid: Option<u32>,
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn process_signal(status: std::process::ExitStatus) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map(|signal| match signal {
            2 => "SIGINT".to_owned(),
            9 => "SIGKILL".to_owned(),
            15 => "SIGTERM".to_owned(),
            other => format!("SIG{other}"),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

impl Drop for TestZode {
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

async fn fail_zode_start<R>(
    child: Child,
    stdout: BufReader<R>,
    stderr: ChildOutputTask,
    forbidden: &[&str],
) -> TestResult<()>
where
    R: AsyncRead + Unpin,
{
    let _ = kill_and_reap(child).await;
    let stdout = drain_child_output(stdout).await?;
    let stderr = collect_child_output(stderr).await?;
    assert_child_output_secret_free(&stdout, forbidden)?;
    assert_child_output_secret_free(&stderr, forbidden)?;
    Ok(())
}

async fn failed_zode_start<R, M>(
    message: M,
    child: Child,
    stdout: BufReader<R>,
    stderr: ChildOutputTask,
    forbidden: &[&str],
) -> TestResult<TestZode>
where
    R: AsyncRead + Unpin,
    M: Into<String>,
{
    let message = message.into();
    match fail_zode_start(child, stdout, stderr, forbidden).await {
        Ok(()) => Err(IoError::other(message).into()),
        Err(error) => Err(IoError::other(format!("{message}; cleanup failed: {error}")).into()),
    }
}

async fn drain_child_output<R>(mut reader: R) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::new();
    reader.read_to_end(&mut output).await?;
    Ok(output)
}

async fn collect_child_output(task: ChildOutputTask) -> TestResult<Vec<u8>> {
    let joined = timeout(CHILD_SHUTDOWN_TIMEOUT, task)
        .await
        .map_err(|_| IoError::other("zode child output drain timed out"))?;
    Ok(joined.map_err(|_| IoError::other("zode child output drain task failed"))??)
}

fn assert_child_output_secret_free(output: &[u8], forbidden: &[&str]) -> TestResult<()> {
    let text = String::from_utf8_lossy(output);
    if forbidden
        .iter()
        .filter(|marker| !marker.is_empty())
        .any(|marker| text.contains(marker))
    {
        return Err(IoError::other("zode child output contained credential material").into());
    }
    Ok(())
}

pub struct ProviderRoundtripSpec {
    pub database: PathBuf,
    pub config: PathBuf,
    pub provider_base_url: String,
    pub provider: String,
    pub model: String,
    pub profile: String,
    pub subject: String,
    pub provider_secret: String,
    pub first_prompt: String,
    pub first_marker: String,
    pub restart_prompt: String,
    pub restart_marker: String,
    pub idempotency_prefix: String,
    pub forbidden: Vec<String>,
    pub child_environment: Vec<(String, String)>,
}

pub async fn run_provider_roundtrip_and_restart(spec: ProviderRoundtripSpec) -> TestResult<()> {
    let client = http_client()?;
    let mut server = None;
    let primary = async {
        server = Some(start_roundtrip_zode(&spec).await?);
        let current = server.as_ref().expect("provider test zode was installed");
        install_roundtrip_replica(&client, current, &spec).await?;
        let session_id = create_roundtrip_session(
            &client,
            current,
            &spec,
            &format!("{}-create", spec.idempotency_prefix),
        )
        .await?;
        let mut events = open_roundtrip_events(&client, current, &spec, &session_id).await?;
        post_roundtrip_message(
            &client,
            current,
            &spec,
            &session_id,
            &format!("{}-message", spec.idempotency_prefix),
            &spec.first_prompt,
        )
        .await?;
        wait_for_roundtrip_assistant(&mut events, &session_id, &spec.first_marker).await?;
        let first_state = read_roundtrip_session(&client, current, &spec, &session_id).await?;
        assert_roundtrip_transcript(&first_state, &spec.first_marker)?;

        let mut first = server.take().expect("provider test zode was installed");
        first.stop(&roundtrip_forbidden(&spec)).await?;
        assert_provider_secret_absent_from_sqlite(&spec).await?;

        server = Some(start_roundtrip_zode(&spec).await?);
        let current = server.as_ref().expect("provider test zode was restarted");
        let restarted_state = read_roundtrip_session(&client, current, &spec, &session_id).await?;
        assert_roundtrip_transcript(&restarted_state, &spec.first_marker)?;
        let restart_session_id = create_roundtrip_session(
            &client,
            current,
            &spec,
            &format!("{}-restart-create", spec.idempotency_prefix),
        )
        .await?;
        if restart_session_id == session_id {
            return Err(IoError::other("provider restart reused the original session id").into());
        }
        let mut events =
            open_roundtrip_events(&client, current, &spec, &restart_session_id).await?;
        post_roundtrip_message(
            &client,
            current,
            &spec,
            &restart_session_id,
            &format!("{}-restart-message", spec.idempotency_prefix),
            &spec.restart_prompt,
        )
        .await?;
        wait_for_roundtrip_assistant(&mut events, &restart_session_id, &spec.restart_marker)
            .await?;
        let restart_state =
            read_roundtrip_session(&client, current, &spec, &restart_session_id).await?;
        assert_roundtrip_transcript(&restart_state, &spec.restart_marker)?;

        let mut restarted = server.take().expect("provider test zode was restarted");
        restarted.stop(&roundtrip_forbidden(&spec)).await?;
        assert_provider_secret_absent_from_sqlite(&spec).await?;
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    }
    .await;

    let mut cleanup_errors = Vec::new();
    if let Some(mut current) = server.take() {
        if let Err(error) = current.stop(&roundtrip_forbidden(&spec)).await {
            cleanup_errors.push(error.to_string());
        }
    }
    if let Err(error) = assert_provider_secret_absent_from_sqlite(&spec).await {
        cleanup_errors.push(error.to_string());
    }
    merge_test_errors(primary, cleanup_errors, "provider roundtrip")
}

pub async fn run_provider_failure(spec: ProviderRoundtripSpec) -> TestResult<()> {
    run_provider_failure_or_cancel(spec, None, None).await
}

pub async fn run_provider_attempt_until_cancel(
    spec: ProviderRoundtripSpec,
    cancel: std::sync::Arc<Notify>,
) -> TestResult<()> {
    run_provider_failure_or_cancel(spec, Some(cancel), None).await
}

pub async fn run_provider_failure_with_process_capture(
    spec: ProviderRoundtripSpec,
    capture: &mut ProcessCaptureSet,
    process_name: &str,
) -> TestResult<()> {
    run_provider_failure_or_cancel(spec, None, Some((capture, process_name))).await
}

async fn run_provider_failure_or_cancel(
    spec: ProviderRoundtripSpec,
    cancel: Option<std::sync::Arc<Notify>>,
    mut process_capture: Option<(&mut ProcessCaptureSet, &str)>,
) -> TestResult<()> {
    let client = http_client()?;
    let mut server = None;
    let primary = async {
        if let Some((capture, _)) = process_capture.as_mut() {
            capture.capture_config("endpoint-runtime-config", &fs::read(&spec.config)?)?;
        }
        server = Some(start_roundtrip_zode(&spec).await?);
        let current = server
            .as_ref()
            .expect("provider failure zode was installed");
        install_roundtrip_replica(&client, current, &spec).await?;
        let session_id = create_roundtrip_session(
            &client,
            current,
            &spec,
            &format!("{}-create", spec.idempotency_prefix),
        )
        .await?;
        let mut events = open_roundtrip_events(&client, current, &spec, &session_id).await?;
        post_roundtrip_message(
            &client,
            current,
            &spec,
            &session_id,
            &format!("{}-message", spec.idempotency_prefix),
            &spec.first_prompt,
        )
        .await?;
        if let Some(cancel) = cancel {
            timeout(Duration::from_secs(30), cancel.notified())
                .await
                .map_err(|_| IoError::new(ErrorKind::TimedOut, "provider cancel timed out"))?;
        } else {
            wait_for_roundtrip_failure(&mut events).await?;
        }
        let mut current = server.take().expect("provider failure zode was installed");
        if let Some((capture, process_name)) = process_capture.as_mut() {
            current
                .stop_with_process_capture(capture, process_name, &roundtrip_forbidden(&spec))
                .await?;
        } else {
            current.stop(&roundtrip_forbidden(&spec)).await?;
        }
        assert_provider_secret_absent_from_sqlite(&spec).await?;
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    }
    .await;

    let mut cleanup_errors = Vec::new();
    if let Some(mut current) = server.take() {
        let stop = if let Some((capture, process_name)) = process_capture.as_mut() {
            current
                .stop_with_process_capture(capture, process_name, &roundtrip_forbidden(&spec))
                .await
        } else {
            current.stop(&roundtrip_forbidden(&spec)).await
        };
        if let Err(error) = stop {
            cleanup_errors.push(error.to_string());
        }
    }
    if let Err(error) = assert_provider_secret_absent_from_sqlite(&spec).await {
        cleanup_errors.push(error.to_string());
    }
    merge_test_errors(primary, cleanup_errors, "provider failure exercise")
}

fn roundtrip_forbidden(spec: &ProviderRoundtripSpec) -> Vec<&str> {
    spec.forbidden.iter().map(String::as_str).collect()
}

async fn start_roundtrip_zode(spec: &ProviderRoundtripSpec) -> TestResult<TestZode> {
    TestZode::start_with_environment(
        &spec.database,
        &spec.config,
        &roundtrip_forbidden(spec),
        &spec.child_environment,
    )
    .await
}

async fn assert_provider_secret_absent_from_sqlite(spec: &ProviderRoundtripSpec) -> TestResult<()> {
    if sqlite_contains_secret(&spec.database, &spec.provider_secret).await? {
        return Err(IoError::other("provider credential reached runtime SQLite").into());
    }
    Ok(())
}

async fn install_roundtrip_replica(
    client: &Client,
    server: &TestZode,
    spec: &ProviderRoundtripSpec,
) -> TestResult<()> {
    let response = authenticated_as(
        client.put(server.url(&format!("/v1/auth-replicas/{}", spec.profile))),
        &spec.subject,
    )
    .header(
        "Idempotency-Key",
        format!("{}-replica", spec.idempotency_prefix),
    )
    .json(&json!({
        "schema": "zode.auth-replica.install.v1",
        "authority_id": TEST_CONTROLLER_AUTHORITY,
        "provider": spec.provider,
        "kind": "api_key",
        "revision": 1,
        "credential_schema": "openai-compatible.api-key.v1",
        "expires_at_ms": null,
        "secret": {
            "encoding": "application/zode-secret-envelope",
            "payload": spec.provider_secret
        }
    }))
    .send_with_timeout()
    .await?;
    let (status, _) = safe_roundtrip_response(response, spec).await?;
    if !matches!(status, StatusCode::OK | StatusCode::CREATED) {
        return Err(
            IoError::other(format!("provider replica install returned HTTP {status}")).into(),
        );
    }
    Ok(())
}

async fn create_roundtrip_session(
    client: &Client,
    server: &TestZode,
    spec: &ProviderRoundtripSpec,
    idempotency_key: &str,
) -> TestResult<String> {
    let response = authenticated_as(client.post(server.url("/v1/sessions")), &spec.subject)
        .header("Idempotency-Key", idempotency_key)
        .json(&json!({
            "model": {
                "provider": spec.provider,
                "provider_execution": {
                    "schema": "zode.provider-execution.v1",
                    "revision": 1,
                    "kind": "openai_compatible",
                    "base_url": spec.provider_base_url
                },
                "model": spec.model,
                "auth_authority_id": TEST_CONTROLLER_AUTHORITY,
                "auth_profile_id": spec.profile,
                "minimum_auth_revision": 1
            }
        }))
        .send_with_timeout()
        .await?;
    let (status, body) = safe_roundtrip_response(response, spec).await?;
    if status != StatusCode::CREATED {
        return Err(
            IoError::other(format!("provider session create returned HTTP {status}")).into(),
        );
    }
    require_ulid(&serde_json::from_str(&body)?)
}

async fn post_roundtrip_message(
    client: &Client,
    server: &TestZode,
    spec: &ProviderRoundtripSpec,
    session_id: &str,
    idempotency_key: &str,
    prompt: &str,
) -> TestResult<()> {
    let response = authenticated_as(
        client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))),
        &spec.subject,
    )
    .header("Idempotency-Key", idempotency_key)
    .json(&json!({"content": prompt}))
    .send_with_timeout()
    .await?;
    let (status, _) = safe_roundtrip_response(response, spec).await?;
    if status != StatusCode::ACCEPTED {
        return Err(IoError::other(format!("provider message returned HTTP {status}")).into());
    }
    Ok(())
}

async fn read_roundtrip_session(
    client: &Client,
    server: &TestZode,
    spec: &ProviderRoundtripSpec,
    session_id: &str,
) -> TestResult<Value> {
    let response = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}"))),
        &spec.subject,
    )
    .send_with_timeout()
    .await?;
    let (status, body) = safe_roundtrip_response(response, spec).await?;
    if status != StatusCode::OK {
        return Err(IoError::other(format!("provider session read returned HTTP {status}")).into());
    }
    Ok(serde_json::from_str(&body)?)
}

pub(crate) struct ProviderRoundtripSse {
    stream: futures_util::stream::BoxStream<'static, Result<Bytes, reqwest::Error>>,
    buffer: Vec<u8>,
    forbidden: Vec<String>,
}

async fn open_roundtrip_events(
    client: &Client,
    server: &TestZode,
    spec: &ProviderRoundtripSpec,
    _session_id: &str,
) -> TestResult<ProviderRoundtripSse> {
    let response = authenticated_as(client.get(server.url("/v1/events")), &spec.subject)
        .send_with_timeout()
        .await?;
    ensure_roundtrip_headers_secret_free(&response, &spec.forbidden)?;
    if response.status() != StatusCode::OK {
        let status = response.status();
        let _ = safe_roundtrip_response(response, spec).await?;
        return Err(IoError::other(format!("provider SSE returned HTTP {status}")).into());
    }
    Ok(ProviderRoundtripSse {
        stream: response.bytes_stream().boxed(),
        buffer: Vec::new(),
        forbidden: spec.forbidden.clone(),
    })
}

async fn wait_for_roundtrip_assistant(
    events: &mut ProviderRoundtripSse,
    session_id: &str,
    marker: &str,
) -> TestResult<()> {
    loop {
        let frame = events.next().await?;
        if frame.0 == "assistant_message_committed"
            || frame.1["kind"] == "assistant_message_committed"
        {
            if frame.1["session_id"] != session_id {
                continue;
            }
            if !frame.1.to_string().contains(marker) {
                return Err(IoError::other("provider assistant event was invalid").into());
            }
            return Ok(());
        }
    }
}

pub async fn wait_for_roundtrip_failure(events: &mut ProviderRoundtripSse) -> TestResult<()> {
    timeout(Duration::from_secs(30), async {
        for _ in 0..128 {
            let frame = events.next().await?;
            if frame.0 == "model_attempt_failed" || frame.1["kind"] == "model_attempt_failed" {
                if frame.1["data"]["error"]["class"].as_str().is_none() {
                    return Err(
                        IoError::other("provider failure event omitted its error class").into(),
                    );
                }
                return Ok(());
            }
        }
        Err(IoError::other("provider failure event was not observed").into())
    })
    .await
    .map_err(|_| IoError::new(ErrorKind::TimedOut, "provider failure event timed out"))?
}

impl ProviderRoundtripSse {
    async fn next(&mut self) -> TestResult<(String, Value)> {
        loop {
            if let Some(end) = self.buffer.windows(2).position(|window| window == b"\n\n") {
                let frame = self.buffer.drain(..end + 2).collect::<Vec<_>>();
                assert_forbidden_bytes(&frame, &self.forbidden)?;
                let text = std::str::from_utf8(&frame)?;
                let mut event = None;
                let mut data = None;
                let mut id = None;
                for line in text.lines() {
                    if let Some(value) = line.strip_prefix("id: ") {
                        id = Some(value);
                    } else if let Some(value) = line.strip_prefix("event: ") {
                        event = Some(value.to_owned());
                    } else if let Some(value) = line.strip_prefix("data: ") {
                        data = Some(serde_json::from_str(value)?);
                    }
                }
                if let (Some(id), Some(event), Some(data)) = (id, event, data) {
                    id.parse::<u64>().map_err(|_| {
                        IoError::other("provider SSE returned a non-numeric event id")
                    })?;
                    return Ok((event, data));
                }
            }
            let chunk = timeout(Duration::from_secs(30), self.stream.next())
                .await
                .map_err(|_| IoError::new(ErrorKind::TimedOut, "provider SSE frame timed out"))?
                .ok_or_else(|| {
                    IoError::new(ErrorKind::UnexpectedEof, "provider SSE ended early")
                })??;
            self.buffer.extend_from_slice(&chunk);
        }
    }
}

async fn safe_roundtrip_response(
    response: Response,
    spec: &ProviderRoundtripSpec,
) -> TestResult<(StatusCode, String)> {
    ensure_roundtrip_headers_secret_free(&response, &spec.forbidden)?;
    let status = response.status();
    let body = response_text(response).await?;
    assert_forbidden_bytes(body.as_bytes(), &spec.forbidden)?;
    Ok((status, body))
}

fn assert_forbidden_bytes(bytes: &[u8], forbidden: &[String]) -> TestResult<()> {
    if forbidden
        .iter()
        .filter(|marker| !marker.is_empty())
        .any(|marker| {
            bytes
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        })
    {
        return Err(IoError::other("provider observation contained credential material").into());
    }
    Ok(())
}

fn ensure_roundtrip_headers_secret_free(
    response: &Response,
    forbidden: &[String],
) -> TestResult<()> {
    for value in response.headers().values() {
        assert_forbidden_bytes(value.as_bytes(), forbidden)?;
    }
    Ok(())
}

fn assert_roundtrip_transcript(session: &Value, marker: &str) -> TestResult<()> {
    let found = session["transcript"].as_array().is_some_and(|messages| {
        messages.iter().any(|message| {
            message["role"] == "assistant"
                && message["content"]
                    .as_str()
                    .is_some_and(|content| content.contains(marker))
        })
    });
    if !found {
        return Err(
            IoError::other("provider transcript missed the expected assistant marker").into(),
        );
    }
    Ok(())
}

fn merge_test_errors(
    primary: TestResult<()>,
    cleanup_errors: Vec<String>,
    context: &str,
) -> TestResult<()> {
    match (primary, cleanup_errors.is_empty()) {
        (Ok(()), true) => Ok(()),
        (Ok(()), false) => Err(IoError::other(format!(
            "{context} cleanup failed: {}",
            cleanup_errors.join("; ")
        ))
        .into()),
        (Err(error), true) => Err(error),
        (Err(error), false) => Err(IoError::other(format!(
            "{context} failed: {error}; cleanup failed: {}",
            cleanup_errors.join("; ")
        ))
        .into()),
    }
}

pub fn authenticated(request: RequestBuilder) -> RequestBuilder {
    authenticated_as(request, TEST_SUBJECT)
}

pub fn authenticated_as(request: RequestBuilder, subject: &str) -> RequestBuilder {
    request
        .header("Authorization", format!("Bearer {TEST_CONTROLLER_SECRET}"))
        .header("Zode-Subject", subject)
}

pub fn is_crockford_ulid(value: &str) -> bool {
    value.len() == 26
        && value
            .chars()
            .all(|character| "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(character))
}

pub fn require_ulid(body: &Value) -> TestResult<String> {
    let session_id = body["session_id"]
        .as_str()
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "create response has no session_id"))?;
    if !is_crockford_ulid(session_id) {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            format!("session id is not an uppercase Crockford ULID: {session_id}"),
        )
        .into());
    }
    Ok(session_id.to_owned())
}

pub fn write_endpoint_config(
    database: &Path,
    tools: Vec<Value>,
    max_attempts: u64,
) -> TestResult<PathBuf> {
    let root = database
        .parent()
        .ok_or_else(|| IoError::other("temporary database has no parent directory"))?;
    fs::create_dir_all(root.join("credentials"))?;
    fs::create_dir_all(root.join("blobs"))?;
    let controller_secret = root.join("controller.secret");
    fs::write(&controller_secret, TEST_CONTROLLER_SECRET)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&controller_secret)?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&controller_secret, permissions)?;
    }
    let config = json!({
        "schema": "zode.config.v1",
        "listen": "127.0.0.1:0",
        "runtime_store": {"kind": "sqlite", "path": database},
        "credential_replica_store": {"kind": "files", "directory": "credentials"},
        "blob_store": {"kind": "files", "directory": "blobs"},
        "controller_auth": [{
            "authority_id": TEST_CONTROLLER_AUTHORITY,
            "revision": 1,
            "kind": "bearer_secret_file",
            "secret_file": "controller.secret"
        }],
        "runtime": {
            "tool_foreground_ms": 100,
            "model_step_max_attempts": max_attempts,
            "model_retry_base_ms": 1,
            "model_retry_max_ms": 10,
            "snapshot_every_events": 1
        },
        "provider_execution": {
            "adapter_kinds": ["openai_compatible"],
            "allowed_base_url_origins": ["http://127.0.0.1"]
        },
        "callback": {
            "allowed_public_origins": ["http://127.0.0.1"]
        },
        "tools": tools
    });
    let path = root.join("runtime-config.json");
    fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    Ok(path)
}

pub async fn install_test_replica(
    client: &Client,
    base_url: &str,
    idempotency_key: &str,
) -> TestResult<Value> {
    let response =
        authenticated(client.put(format!("{base_url}/v1/auth-replicas/{TEST_AUTH_PROFILE}")))
            .header("Idempotency-Key", idempotency_key)
            .json(&json!({
                "schema": "zode.auth-replica.install.v1",
                "authority_id": TEST_CONTROLLER_AUTHORITY,
                "provider": "fixture-provider",
                "kind": "api_key",
                "revision": 1,
                "credential_schema": "openai-compatible.api-key.v1",
                "expires_at_ms": null,
                "secret": {
                    "encoding": "application/zode-secret-envelope",
                    "payload": TEST_PROVIDER_SECRET
                }
            }))
            .send_with_timeout()
            .await?;
    let status = response.status();
    assert_response_headers_secret_free(&response, &[TEST_PROVIDER_SECRET]);
    let body_text = response_text(response).await?;
    if status != StatusCode::OK && status != StatusCode::CREATED {
        let safe_body = body_text.replace(TEST_PROVIDER_SECRET, "[redacted]");
        return Err(IoError::other(format!(
            "credential replica install did not succeed: {status} {safe_body}"
        ))
        .into());
    }
    let body: Value = serde_json::from_str(&body_text).map_err(|error| {
        IoError::other(format!(
            "credential replica install returned non-JSON success: {status} {error}"
        ))
    })?;
    if body.to_string().contains(TEST_PROVIDER_SECRET) {
        return Err(
            IoError::other("credential replica response leaked the installed secret").into(),
        );
    }
    Ok(body)
}

pub fn http_client() -> TestResult<Client> {
    Ok(Client::builder()
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .build()?)
}

pub async fn http_send(request: RequestBuilder) -> TestResult<Response> {
    Ok(timeout(HTTP_RESPONSE_HEADERS_TIMEOUT, request.send()).await??)
}

pub async fn response_json(response: Response) -> TestResult<Value> {
    Ok(timeout(HTTP_RESPONSE_BODY_TIMEOUT, response.json::<Value>()).await??)
}

pub async fn response_text(response: Response) -> TestResult<String> {
    Ok(timeout(HTTP_RESPONSE_BODY_TIMEOUT, response.text()).await??)
}

pub fn assert_response_headers_secret_free(response: &Response, markers: &[&str]) {
    for value in response.headers().values() {
        for marker in markers {
            let marker = marker.as_bytes();
            assert!(
                !marker.is_empty()
                    && !value
                        .as_bytes()
                        .windows(marker.len())
                        .any(|window| window == marker),
                "public response header contained a secret marker"
            );
        }
    }
}

pub async fn response_bytes(response: Response) -> TestResult<bytes::Bytes> {
    Ok(timeout(HTTP_RESPONSE_BODY_TIMEOUT, response.bytes()).await??)
}

pub trait HttpRequestExt {
    fn send_with_timeout(
        self,
    ) -> Pin<Box<dyn Future<Output = TestResult<Response>> + Send + 'static>>;
}

impl HttpRequestExt for RequestBuilder {
    fn send_with_timeout(
        self,
    ) -> Pin<Box<dyn Future<Output = TestResult<Response>> + Send + 'static>> {
        Box::pin(http_send(self))
    }
}

pub struct ConfiguredServer {
    child: Option<Child>,
    base_url: String,
    exit_status: Option<std::process::ExitStatus>,
}

pub enum PathBarrierStart {
    Ready(ConfiguredServer),
    ActiveNonzero(String),
    TimeoutOrHarness(String),
}

struct PathBarrierFailure {
    child_exit_after_action: Option<bool>,
    message: String,
}

impl ConfiguredServer {
    pub async fn start(database_path: &Path, config_path: &Path) -> TestResult<Self> {
        Self::start_with_readiness_timeout(database_path, config_path, READINESS_TIMEOUT).await
    }

    pub async fn start_with_readiness_timeout(
        database_path: &Path,
        config_path: &Path,
        readiness_timeout: Duration,
    ) -> TestResult<Self> {
        Self::start_with_readiness_timeout_and_env(
            database_path,
            config_path,
            readiness_timeout,
            &[],
        )
        .await
    }

    pub async fn start_with_readiness_timeout_and_env(
        database_path: &Path,
        config_path: &Path,
        readiness_timeout: Duration,
        environment: &[(&str, &Path)],
    ) -> TestResult<Self> {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_zode"));
        for (name, value) in environment {
            command.env(name, value);
        }
        let mut child = command
            .arg("--config")
            .arg(config_path)
            .arg("--database")
            .arg(database_path)
            .arg("--listen")
            .arg("127.0.0.1:0")
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let pid = match child.id() {
            Some(pid) => pid,
            None => {
                let _ = kill_and_reap(child).await;
                return Err(IoError::other("zode process did not expose a pid").into());
            }
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let _ = kill_and_reap(child).await;
                return Err(IoError::other("zode readiness output was unavailable").into());
            }
        };
        let mut lines = BufReader::new(stdout).lines();
        let line = match timeout(readiness_timeout, lines.next_line()).await {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) => {
                let exit_status = kill_and_reap(child).await?;
                let outcome = if exit_status.success() {
                    "zero"
                } else {
                    "non-zero"
                };
                return Err(IoError::new(
                    ErrorKind::UnexpectedEof,
                    format!(
                        "zode pid {pid} exited before readiness with {outcome} process status {exit_status}"
                    ),
                )
                .into());
            }
            Ok(Err(error)) => {
                let exit_status = kill_and_reap(child).await?;
                let outcome = if exit_status.success() {
                    "zero"
                } else {
                    "non-zero"
                };
                return Err(IoError::other(format!(
                    "zode pid {pid} readiness output failed ({error}); child exited with {outcome} process status {exit_status}"
                ))
                .into());
            }
            Err(_) => {
                let exit_status = kill_and_reap(child).await?;
                return Err(IoError::new(
                    ErrorKind::TimedOut,
                    format!(
                        "zode pid {pid} did not become ready before the readiness deadline; child was force-killed with status {exit_status}"
                    ),
                )
                .into());
            }
        };
        let Some(base_url) = line.strip_prefix(READY_PREFIX) else {
            let exit_status = kill_and_reap(child).await?;
            return Err(IoError::other(format!(
                "invalid zode readiness line; child ended with status {exit_status}"
            ))
            .into());
        };
        Ok(Self {
            child: Some(child),
            base_url: base_url.trim().to_owned(),
            exit_status: None,
        })
    }

    pub async fn start_with_path_barrier<F>(
        database_path: &Path,
        config_path: &Path,
        readiness_timeout: Duration,
        barrier_path: &Path,
        barrier_action: F,
    ) -> PathBarrierStart
    where
        F: FnOnce() -> std::io::Result<()> + Send + 'static,
    {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_zode"));
        let mut child = match command
            .arg("--config")
            .arg(config_path)
            .arg("--database")
            .arg(database_path)
            .arg("--listen")
            .arg("127.0.0.1:0")
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => return PathBarrierStart::TimeoutOrHarness(error.to_string()),
        };
        let pid = match child.id() {
            Some(pid) => pid,
            None => {
                let _ = kill_and_reap(child).await;
                return PathBarrierStart::TimeoutOrHarness(
                    "zode process did not expose a pid".to_owned(),
                );
            }
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let _ = kill_and_reap(child).await;
                return PathBarrierStart::TimeoutOrHarness(
                    "zode readiness output was unavailable".to_owned(),
                );
            }
        };
        let mut lines = BufReader::new(stdout).lines();
        let barrier_path = barrier_path.to_owned();
        let result = timeout(readiness_timeout, async {
            let mut barrier = Box::pin(wait_for_path(barrier_path));
            tokio::select! {
                biased;
                line = lines.next_line() => {
                    let line = line.map_err(|error| PathBarrierFailure {
                        child_exit_after_action: None,
                        message: format!("readiness output failed before the path barrier: {error}"),
                    })?;
                    let Some(line) = line else {
                        return Err(PathBarrierFailure {
                            child_exit_after_action: None,
                            message: "zode exited before the path barrier".to_owned(),
                        });
                    };
                    Err(PathBarrierFailure {
                        child_exit_after_action: None,
                        message: format!("zode reached readiness before the path barrier: {line}"),
                    })
                }
                barrier_result = &mut barrier => {
                    barrier_result.map_err(|error| PathBarrierFailure {
                        child_exit_after_action: None,
                        message: format!("path barrier failed: {error}"),
                    })?;
                    tokio::task::spawn_blocking(barrier_action)
                        .await
                        .map_err(|error| PathBarrierFailure {
                            child_exit_after_action: None,
                            message: format!("path barrier action task failed: {error}"),
                        })?
                        .map_err(|error| PathBarrierFailure {
                            child_exit_after_action: None,
                            message: format!("path barrier action failed: {error}"),
                        })?;
                    let line = lines.next_line().await.map_err(|error| PathBarrierFailure {
                        child_exit_after_action: Some(false),
                        message: format!("readiness output failed after the path barrier: {error}"),
                    })?;
                    let Some(line) = line else {
                        return Err(PathBarrierFailure {
                            child_exit_after_action: Some(true),
                            message: "zode exited after the path barrier".to_owned(),
                        });
                    };
                    let Some(base_url) = line.strip_prefix(READY_PREFIX) else {
                        return Err(PathBarrierFailure {
                            child_exit_after_action: Some(false),
                            message: "invalid zode readiness line after the path barrier"
                                .to_owned(),
                        });
                    };
                    Ok(base_url.trim().to_owned())
                }
            }
        })
        .await;
        match result {
            Ok(Ok(base_url)) => PathBarrierStart::Ready(Self {
                child: Some(child),
                base_url,
                exit_status: None,
            }),
            Ok(Err(failure)) => path_barrier_failure(child, failure).await,
            Err(_) => match kill_and_reap(child).await {
                Ok(status) => PathBarrierStart::TimeoutOrHarness(format!(
                    "zode pid {pid} did not complete the path-barrier readiness deadline; child was force-killed with status {status}"
                )),
                Err(error) => PathBarrierStart::TimeoutOrHarness(format!(
                    "path barrier cleanup failed: {error}"
                )),
            },
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    pub async fn stop(&mut self) -> TestResult<()> {
        if let Some(child) = self.child.take() {
            self.exit_status = Some(kill_and_reap(child).await?);
        }
        Ok(())
    }
}

impl Drop for ConfiguredServer {
    fn drop(&mut self) {
        reap_child_on_drop(self.child.take());
    }
}

async fn path_barrier_failure(child: Child, failure: PathBarrierFailure) -> PathBarrierStart {
    match kill_and_reap(child).await {
        Ok(status) if failure.child_exit_after_action == Some(true) && !status.success() => {
            PathBarrierStart::ActiveNonzero(format!(
                "{}; path barrier action completed; child ended with non-zero status {status}",
                failure.message
            ))
        }
        Ok(status) => PathBarrierStart::TimeoutOrHarness(format!(
            "{}; child ended with status {status}",
            failure.message
        )),
        Err(error) => PathBarrierStart::TimeoutOrHarness(format!(
            "{}; child cleanup failed: {error}",
            failure.message
        )),
    }
}

async fn wait_for_path(path: PathBuf) -> TestResult<()> {
    loop {
        match fs::symlink_metadata(&path) {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                tokio::task::yield_now().await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

pub struct HttpFixture {
    base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<std::io::Result<()>>>,
}

impl HttpFixture {
    pub async fn start(router: Router) -> TestResult<Self> {
        let listener = timeout(
            HTTP_RESPONSE_HEADERS_TIMEOUT,
            TcpListener::bind("127.0.0.1:0"),
        )
        .await??;
        let address = listener.local_addr()?;
        let (shutdown, shutdown_signal) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = shutdown_signal.await;
                })
                .await
        });
        Ok(Self {
            base_url: format!("http://{address}"),
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    pub async fn stop(&mut self) -> TestResult<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            await_fixture_task(task).await?;
        }
        Ok(())
    }
}

async fn await_fixture_task(mut task: JoinHandle<std::io::Result<()>>) -> TestResult<()> {
    match timeout(FIXTURE_SHUTDOWN_TIMEOUT, &mut task).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(error))) => Err(IoError::other(format!("fixture worker failed: {error}")).into()),
        Ok(Err(error)) if error.is_cancelled() => {
            Err(IoError::other("fixture task cancelled").into())
        }
        Ok(Err(error)) => Err(IoError::other(format!("fixture task failed: {error}")).into()),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(IoError::new(ErrorKind::TimedOut, "fixture did not stop").into())
        }
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub const LLM_HTTP_RECORDING_SCHEMA: &str = "zode.llm-http-recording.v1";
pub const HTTP_INCIDENT_RECORDING_SCHEMA: &str = "zode.http-incident-recording.v1";
/// Schema for an ignored, test-only public-boundary exchange retained while
/// reproducing a recorder evidence gap.  This is never linked from
/// production code and is intentionally separate from the LLM cassette
/// envelope.
pub const PUBLIC_HTTP_GAP_RECORDING_SCHEMA: &str = "zode.public-http-gap-recording.v1";
const MAX_LLM_RECORDING_BYTES: u64 = 64 * 1024 * 1024;
// A long recorded agent run repeats its growing request context on every wire
// exchange, so its private pre-promotion envelope can exceed the ordinary
// cassette bound even when every individual request and response stays
// bounded. Only the DeepSWE promotion/replay path uses this larger read bound;
// tracked fixtures remain compressed and ordinary cassettes keep the smaller
// limit above.
const MAX_LLM_LONG_RUN_RECORDING_BYTES: u64 = 256 * 1024 * 1024;
const MAX_LLM_COMPRESSED_RECORDING_BYTES: u64 = 16 * 1024 * 1024;
const LLM_COMPRESSED_RECORDING_LEVEL: i32 = 19;
pub const MAX_LLM_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
// Reasoning-capable providers can emit one SSE frame per short reasoning token.
// Keep the byte ceiling authoritative while allowing a bounded long-task stream
// to reach that ceiling instead of failing first on harmless frame granularity.
const MAX_LLM_RESPONSE_CHUNKS: usize = 65_536;
pub const MAX_LLM_CHUNK_DELAY_US: u64 = 60_000_000;
const MAX_PUBLIC_HTTP_GAP_BODY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LlmHttpRecording {
    pub schema: String,
    pub recording_id: String,
    pub purpose: String,
    pub owner: String,
    pub boundary: String,
    pub secret_slots: Vec<String>,
    pub provider: String,
    pub model: String,
    pub requests: Vec<LlmHttpRecordingExchange>,
    pub envelope_sha256: String,
}

pub struct ValidatedLlmHttpRecording(LlmHttpHashReplayRecording);

impl ValidatedLlmHttpRecording {
    pub fn request_count(&self) -> usize {
        self.0.exchanges.len()
    }

    fn into_hash_replay(self) -> TestResult<LlmHttpHashReplayRecording> {
        Ok(self.0)
    }

    fn from_validated(recording: LlmHttpRecording) -> TestResult<Self> {
        PinnedLlmHttpHashReplayIndex::from_recording(&recording, [0; 32])?
            .into_hash_replay_inner(None, false)
    }
}

const LLM_HTTP_HASH_REPLAY_INDEX_SCHEMA: &str = "zode.llm-http-hash-replay-index.v2";

#[derive(Deserialize, Serialize)]
struct PinnedLlmHttpHashReplayIndex {
    schema: String,
    source_file_sha256: [u8; 32],
    requires_authorization: bool,
    request_templates: Vec<LlmHttpReplayRequestTemplate>,
    response_templates: Vec<LlmHttpReplayResponseTemplate>,
    exchanges: Vec<LlmHttpIndexedReplayExchange>,
    chunks: Vec<LlmHttpIndexedReplayChunk>,
    response_bytes: Vec<u8>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
struct LlmHttpReplayRequestTemplate {
    method: String,
    path: String,
    semantic_headers: Vec<LlmHttpHeader>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
struct LlmHttpReplayResponseTemplate {
    status: Option<u16>,
    content_type: Option<String>,
    semantic_headers: Vec<LlmHttpHeader>,
    outcome: LlmHttpReplayOutcome,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
enum LlmHttpReplayOutcome {
    Complete { done_seen: bool },
    ClientDisconnect,
    TransportError,
    StreamError,
    CaptureBoundExceeded,
}

impl From<&LlmHttpResponseOutcome> for LlmHttpReplayOutcome {
    fn from(outcome: &LlmHttpResponseOutcome) -> Self {
        match outcome {
            LlmHttpResponseOutcome::Complete { done_seen } => Self::Complete {
                done_seen: *done_seen,
            },
            LlmHttpResponseOutcome::ClientDisconnect => Self::ClientDisconnect,
            LlmHttpResponseOutcome::TransportError => Self::TransportError,
            LlmHttpResponseOutcome::StreamError => Self::StreamError,
            LlmHttpResponseOutcome::CaptureBoundExceeded => Self::CaptureBoundExceeded,
        }
    }
}

impl From<LlmHttpReplayOutcome> for LlmHttpResponseOutcome {
    fn from(outcome: LlmHttpReplayOutcome) -> Self {
        match outcome {
            LlmHttpReplayOutcome::Complete { done_seen } => Self::Complete { done_seen },
            LlmHttpReplayOutcome::ClientDisconnect => Self::ClientDisconnect,
            LlmHttpReplayOutcome::TransportError => Self::TransportError,
            LlmHttpReplayOutcome::StreamError => Self::StreamError,
            LlmHttpReplayOutcome::CaptureBoundExceeded => Self::CaptureBoundExceeded,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct LlmHttpIndexedReplayExchange {
    sequence: u64,
    logical_round: u64,
    wire_attempt: u64,
    request_template: u16,
    raw_body_sha256: [u8; 32],
    response_template: u16,
    first_chunk: u32,
    chunk_count: u32,
    first_byte: u32,
    byte_count: u32,
    done_seen: bool,
}

#[derive(Deserialize, Serialize)]
struct LlmHttpIndexedReplayChunk {
    at_us: u64,
    end_byte: u32,
}

impl PinnedLlmHttpHashReplayIndex {
    fn from_recording(
        recording: &LlmHttpRecording,
        source_file_sha256: [u8; 32],
    ) -> TestResult<Self> {
        let mut request_templates = Vec::new();
        let mut response_templates = Vec::new();
        let mut exchanges = Vec::with_capacity(recording.requests.len());
        let mut chunks = Vec::new();
        let mut response_bytes = Vec::new();
        for exchange in &recording.requests {
            let request_template = LlmHttpReplayRequestTemplate {
                method: exchange.request.method.clone(),
                path: exchange.request.path.clone(),
                semantic_headers: exchange.request.semantic_headers.clone(),
            };
            let request_template = intern_template(&mut request_templates, request_template)?;
            let response_template = LlmHttpReplayResponseTemplate {
                status: exchange.response.status,
                content_type: exchange.response.content_type.clone(),
                semantic_headers: exchange.response.semantic_headers.clone(),
                outcome: (&exchange.response.outcome).into(),
            };
            let response_template = intern_template(&mut response_templates, response_template)?;
            let first_chunk = u32::try_from(chunks.len())?;
            let first_byte = u32::try_from(response_bytes.len())?;
            for chunk in &exchange.response.chunks {
                response_bytes.extend_from_slice(&hex_decode(&chunk.bytes_hex)?);
                chunks.push(LlmHttpIndexedReplayChunk {
                    at_us: chunk.at_us,
                    end_byte: u32::try_from(response_bytes.len())?,
                });
            }
            exchanges.push(LlmHttpIndexedReplayExchange {
                sequence: exchange.sequence,
                logical_round: exchange.logical_round,
                wire_attempt: exchange.wire_attempt,
                request_template,
                raw_body_sha256: decode_sha256(&exchange.request.raw_body_sha256)?,
                response_template,
                first_chunk,
                chunk_count: u32::try_from(exchange.response.chunks.len())?,
                first_byte,
                byte_count: u32::try_from(response_bytes.len())? - first_byte,
                done_seen: chunks_contain_done(&exchange.response.chunks),
            });
        }
        Ok(Self {
            schema: LLM_HTTP_HASH_REPLAY_INDEX_SCHEMA.to_owned(),
            source_file_sha256,
            requires_authorization: !recording.secret_slots.is_empty(),
            request_templates,
            response_templates,
            exchanges,
            chunks,
            response_bytes,
        })
    }

    fn into_hash_replay(
        self,
        expected_source_sha256: &str,
    ) -> TestResult<ValidatedLlmHttpRecording> {
        self.into_hash_replay_inner(Some(decode_sha256(expected_source_sha256)?), true)
    }

    fn into_hash_replay_inner(
        self,
        expected_source_sha256: Option<[u8; 32]>,
        require_authorization: bool,
    ) -> TestResult<ValidatedLlmHttpRecording> {
        if self.schema != LLM_HTTP_HASH_REPLAY_INDEX_SCHEMA
            || expected_source_sha256.is_some_and(|expected| self.source_file_sha256 != expected)
            || (require_authorization && !self.requires_authorization)
            || self.exchanges.len() > 1024
            || self.request_templates.is_empty()
            || self.response_templates.is_empty()
            || self.request_templates.len() > usize::from(u16::MAX)
            || self.response_templates.len() > usize::from(u16::MAX)
        {
            return Err(IoError::other("pinned LLM replay index metadata is invalid").into());
        }

        for template in &self.request_templates {
            if template.method != "POST" || !path_is_secret_safe(&template.path) {
                return Err(IoError::other("pinned LLM request is not canonical").into());
            }
            validate_headers(&template.semantic_headers, true)?;
        }
        for template in &self.response_templates {
            validate_replay_response_template(template)?;
        }
        let mut previous_round = None;
        let mut previous_attempt = None;
        let mut next_chunk = 0usize;
        let mut next_byte = 0usize;
        for (index, exchange) in self.exchanges.iter().enumerate() {
            if exchange.sequence != index as u64 {
                return Err(IoError::other("pinned LLM request is not canonical").into());
            }
            match (previous_round, previous_attempt) {
                (None, None) if exchange.logical_round == 0 && exchange.wire_attempt == 0 => {}
                (Some(round), Some(attempt)) if exchange.logical_round == round => {
                    if exchange.wire_attempt != attempt + 1 {
                        return Err(IoError::other("pinned LLM attempts are not ordered").into());
                    }
                }
                (Some(round), Some(_))
                    if exchange.logical_round == round + 1 && exchange.wire_attempt == 0 => {}
                _ => {
                    return Err(IoError::other("pinned LLM rounds are not ordered").into());
                }
            }
            previous_round = Some(exchange.logical_round);
            previous_attempt = Some(exchange.wire_attempt);
            let template = self
                .response_templates
                .get(usize::from(exchange.response_template))
                .ok_or_else(|| IoError::other("pinned LLM response template is invalid"))?;
            if self
                .request_templates
                .get(usize::from(exchange.request_template))
                .is_none()
            {
                return Err(IoError::other("pinned LLM request template is invalid").into());
            }
            let first_chunk = usize::try_from(exchange.first_chunk)?;
            let chunk_count = usize::try_from(exchange.chunk_count)?;
            let first_byte = usize::try_from(exchange.first_byte)?;
            let byte_count = usize::try_from(exchange.byte_count)?;
            if first_chunk != next_chunk || first_byte != next_byte {
                return Err(IoError::other("pinned LLM replay ranges are not contiguous").into());
            }
            let chunk_end = first_chunk
                .checked_add(chunk_count)
                .ok_or_else(|| IoError::other("pinned LLM chunk range overflowed"))?;
            let byte_end = first_byte
                .checked_add(byte_count)
                .ok_or_else(|| IoError::other("pinned LLM byte range overflowed"))?;
            let response_chunks = self
                .chunks
                .get(first_chunk..chunk_end)
                .ok_or_else(|| IoError::other("pinned LLM chunk range is invalid"))?;
            let response_bytes = self
                .response_bytes
                .get(first_byte..byte_end)
                .ok_or_else(|| IoError::other("pinned LLM byte range is invalid"))?;
            validate_indexed_response(
                template,
                response_chunks,
                first_byte,
                response_bytes,
                exchange.done_seen,
            )?;
            next_chunk = chunk_end;
            next_byte = byte_end;
        }
        if next_chunk != self.chunks.len() || next_byte != self.response_bytes.len() {
            return Err(IoError::other("pinned LLM replay index has unused data").into());
        }
        let retained_request_match_bytes = self
            .request_templates
            .iter()
            .map(LlmHttpReplayRequestTemplate::retained_bytes)
            .sum::<usize>()
            + self.exchanges.len() * (32 + 2);
        Ok(ValidatedLlmHttpRecording(LlmHttpHashReplayRecording {
            requires_authorization: self.requires_authorization,
            request_templates: self.request_templates.into_boxed_slice(),
            response_templates: self.response_templates.into_boxed_slice(),
            exchanges: self.exchanges.into_boxed_slice(),
            chunks: self.chunks.into_boxed_slice(),
            response_bytes: Bytes::from(self.response_bytes),
            retained_request_match_bytes,
        }))
    }
}

fn intern_template<T: PartialEq>(templates: &mut Vec<T>, value: T) -> TestResult<u16> {
    if let Some(index) = templates.iter().position(|template| template == &value) {
        return Ok(u16::try_from(index)?);
    }
    let index = u16::try_from(templates.len())?;
    templates.push(value);
    Ok(index)
}

struct LlmHttpHashReplayRecording {
    requires_authorization: bool,
    request_templates: Box<[LlmHttpReplayRequestTemplate]>,
    response_templates: Box<[LlmHttpReplayResponseTemplate]>,
    exchanges: Box<[LlmHttpIndexedReplayExchange]>,
    chunks: Box<[LlmHttpIndexedReplayChunk]>,
    response_bytes: Bytes,
    retained_request_match_bytes: usize,
}

impl LlmHttpReplayRequestTemplate {
    fn retained_bytes(&self) -> usize {
        self.method.len()
            + self.path.len()
            + self
                .semantic_headers
                .iter()
                .map(|header| header.name.len() + header.value.len())
                .sum::<usize>()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LlmHttpRecordingExchange {
    pub sequence: u64,
    pub logical_round: u64,
    pub wire_attempt: u64,
    pub request: LlmHttpRecordingRequest,
    pub response: LlmHttpRecordingResponse,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LlmHttpRecordingRequest {
    pub method: String,
    pub path: String,
    pub semantic_headers: Vec<LlmHttpHeader>,
    pub raw_body_hex: String,
    pub canonical_json: Option<String>,
    pub raw_body_sha256: String,
    pub canonical_json_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LlmHttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LlmHttpResponseOutcome {
    Complete { done_seen: bool },
    ClientDisconnect,
    TransportError,
    StreamError,
    CaptureBoundExceeded,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LlmHttpRecordingResponse {
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub semantic_headers: Vec<LlmHttpHeader>,
    pub chunks: Vec<LlmHttpRecordingChunk>,
    pub outcome: LlmHttpResponseOutcome,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LlmHttpRecordingChunk {
    pub kind: LlmHttpChunkKind,
    pub sequence: u64,
    pub at_us: u64,
    pub bytes_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LlmHttpChunkKind {
    Body,
    Sse,
}

#[derive(Clone, Debug)]
pub struct LlmHttpObservedRequest {
    pub method: String,
    pub path: String,
    pub semantic_headers: Vec<LlmHttpHeader>,
    pub raw_body_hex: String,
    pub canonical_json: Option<String>,
}

#[derive(Clone, Debug)]
pub struct LlmHttpRecordingMetadata {
    pub recording_id: String,
    pub purpose: String,
    pub owner: String,
    pub boundary: String,
    pub secret_slots: Vec<String>,
}

/// The capture owner may provide the attempt identity explicitly when request
/// bodies are not sufficient to distinguish logical rounds (for example,
/// repeated prompts after a restart).  Entries are indexed by wire sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LlmHttpAttemptPlan {
    pub logical_round: u64,
    pub wire_attempt: u64,
}

impl LlmHttpRecording {
    fn retained_request_match_bytes(&self) -> usize {
        self.requests
            .iter()
            .map(|exchange| {
                let request = &exchange.request;
                request.method.len()
                    + request.path.len()
                    + request
                        .semantic_headers
                        .iter()
                        .map(|header| header.name.len() + header.value.len())
                        .sum::<usize>()
                    + request.raw_body_hex.len()
                    + request.canonical_json.as_ref().map_or(0, String::len)
                    + request.raw_body_sha256.len()
                    + request
                        .canonical_json_sha256
                        .as_ref()
                        .map_or(0, String::len)
            })
            .sum()
    }

    pub fn load(path: &Path) -> TestResult<Self> {
        Self::load_with_bound(path, MAX_LLM_RECORDING_BYTES)
    }

    pub fn load_long_run(path: &Path) -> TestResult<Self> {
        Self::load_with_bound(path, MAX_LLM_LONG_RUN_RECORDING_BYTES)
    }

    pub fn load_compressed(path: &Path) -> TestResult<Self> {
        let file = fs::File::open(path)?;
        if file.metadata()?.len() > MAX_LLM_COMPRESSED_RECORDING_BYTES {
            return Err(IoError::other("compressed LLM recording exceeds its size bound").into());
        }
        let decoder = zstd::stream::read::Decoder::new(file)?;
        let mut bytes = Vec::new();
        decoder
            .take(MAX_LLM_LONG_RUN_RECORDING_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_LLM_LONG_RUN_RECORDING_BYTES {
            return Err(IoError::other("expanded LLM recording exceeds its size bound").into());
        }
        let recording: Self = serde_json::from_slice(&bytes)?;
        recording.validate()?;
        Ok(recording)
    }

    pub fn load_compressed_validated(path: &Path) -> TestResult<ValidatedLlmHttpRecording> {
        ValidatedLlmHttpRecording::from_validated(Self::load_compressed(path)?)
    }

    /// Loads a compact replay index whose own pinned digest and source-cassette
    /// digest bind it to the immutable full recording. Runtime replay need not
    /// repeatedly decompress and parse the growing request bodies.
    pub fn load_pinned_compressed_hash_replay_index(
        source_path: &Path,
        expected_source_sha256: &'static str,
        index_path: &Path,
        expected_index_sha256: &'static str,
    ) -> TestResult<ValidatedLlmHttpRecording> {
        let source = fs::read(source_path)?;
        if source.len() as u64 > MAX_LLM_COMPRESSED_RECORDING_BYTES {
            return Err(IoError::other("compressed LLM recording exceeds its size bound").into());
        }
        if sha256_hex(&source) != expected_source_sha256 {
            return Err(IoError::other("pinned LLM recording file digest is invalid").into());
        }
        let compressed_index = fs::read(index_path)?;
        if compressed_index.len() as u64 > MAX_LLM_COMPRESSED_RECORDING_BYTES
            || sha256_hex(&compressed_index) != expected_index_sha256
        {
            return Err(IoError::other("pinned LLM replay index digest is invalid").into());
        }
        let decoder = zstd::stream::read::Decoder::new(compressed_index.as_slice())?;
        let mut bytes = Vec::new();
        decoder
            .take(MAX_LLM_LONG_RUN_RECORDING_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_LLM_LONG_RUN_RECORDING_BYTES {
            return Err(IoError::other("expanded LLM replay index exceeds its size bound").into());
        }
        let index: PinnedLlmHttpHashReplayIndex = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .reject_trailing_bytes()
            .with_limit(MAX_LLM_LONG_RUN_RECORDING_BYTES)
            .deserialize(&bytes)?;
        index.into_hash_replay(expected_source_sha256)
    }

    pub fn promote_compressed_hash_replay_index(
        source_path: &Path,
        expected_source_sha256: &str,
        index_path: &Path,
        forbidden: &[&str],
    ) -> TestResult<u64> {
        let source = fs::read(source_path)?;
        if source.len() as u64 > MAX_LLM_COMPRESSED_RECORDING_BYTES
            || sha256_hex(&source) != expected_source_sha256
        {
            return Err(IoError::other("pinned LLM recording file digest is invalid").into());
        }
        let recording = Self::load_compressed(source_path)?;
        let index = PinnedLlmHttpHashReplayIndex::from_recording(
            &recording,
            decode_sha256(expected_source_sha256)?,
        )?;
        let bytes = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .serialize(&index)?;
        for marker in forbidden.iter().filter(|marker| !marker.is_empty()) {
            if bytes_contain(&bytes, marker.as_bytes()) {
                return Err(IoError::other(
                    "LLM replay index contained forbidden credential material",
                )
                .into());
            }
        }
        promote_immutable_compressed_bytes(index_path, &bytes)
    }

    fn load_with_bound(path: &Path, max_bytes: u64) -> TestResult<Self> {
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(max_bytes + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > max_bytes {
            return Err(IoError::other("LLM recording exceeds its size bound").into());
        }
        let recording: Self = serde_json::from_slice(&bytes)?;
        recording.validate()?;
        Ok(recording)
    }

    pub fn with_digest(mut self) -> TestResult<Self> {
        self.envelope_sha256.clear();
        let preimage = serde_json::to_vec(&self)?;
        self.envelope_sha256 = sha256_hex(&preimage);
        self.validate()?;
        Ok(self)
    }

    /// Write a quarantined recording with exclusive creation and restrictive
    /// permissions.  Promotion uses [`Self::promote_immutable`] so a raw
    /// capture can never accidentally become a tracked fixture.
    pub fn write_atomic(&self, path: &Path, forbidden: &[&str]) -> TestResult<u64> {
        self.write_atomic_with_mode(path, forbidden, 0o600)
    }

    /// Promote a secret-scanned recording into an immutable tracked fixture.
    /// The temporary file is flushed while private, then changed to `0444`
    /// before it is linked into place.  The destination is created with
    /// `hard_link`, so an existing path (including a concurrent creator) is
    /// never overwritten.
    pub fn promote_immutable(&self, path: &Path, forbidden: &[&str]) -> TestResult<u64> {
        self.write_atomic_with_mode(path, forbidden, 0o444)
    }

    pub fn promote_immutable_compressed(&self, path: &Path, forbidden: &[&str]) -> TestResult<u64> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        for marker in forbidden.iter().filter(|marker| !marker.is_empty()) {
            if bytes_contain(&bytes, marker.as_bytes()) {
                return Err(IoError::other(
                    "LLM recording contained forbidden credential material",
                )
                .into());
            }
        }
        promote_immutable_compressed_bytes(path, &bytes)
    }

    fn write_atomic_with_mode(
        &self,
        path: &Path,
        forbidden: &[&str],
        final_mode: u32,
    ) -> TestResult<u64> {
        let recording = self.clone().with_digest()?;
        let bytes = serde_json::to_vec_pretty(&recording)?;
        for marker in forbidden.iter().filter(|marker| !marker.is_empty()) {
            if bytes_contain(&bytes, marker.as_bytes()) {
                return Err(IoError::other(
                    "LLM recording contained forbidden credential material",
                )
                .into());
            }
        }
        let parent = path
            .parent()
            .ok_or_else(|| IoError::other("LLM recording path has no parent"))?;
        fs::create_dir_all(parent)?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| IoError::other("LLM recording file name is invalid"))?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let temporary = parent.join(format!(".{file_name}.tmp-{}-{nonce}", std::process::id()));
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        drop(file);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(error) =
                fs::set_permissions(&temporary, fs::Permissions::from_mode(final_mode))
                    .and_then(|_| fs::File::open(&temporary)?.sync_all())
            {
                let _ = fs::remove_file(&temporary);
                return Err(error.into());
            }
            // Persist the permission transition before exposing the file via
            // the destination hard link.
        }
        if let Err(error) = fs::hard_link(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(if error.kind() == ErrorKind::AlreadyExists {
                IoError::new(
                    ErrorKind::AlreadyExists,
                    "tracked LLM recording is immutable",
                )
            } else {
                error
            }
            .into());
        }
        fs::remove_file(&temporary)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(bytes.len() as u64)
    }

    pub fn validate(&self) -> TestResult<()> {
        if self.schema != LLM_HTTP_RECORDING_SCHEMA
            || self.recording_id.is_empty()
            || self.purpose.is_empty()
            || self.owner.is_empty()
            || self.boundary.is_empty()
            || self.secret_slots.is_empty()
            || self.provider.is_empty()
            || self.model.is_empty()
            || self.recording_id.len() > 256
            || self.purpose.len() > 256
            || self.owner.len() > 256
            || self.boundary.len() > 256
            || self.provider.len() > 256
            || self.model.len() > 256
            || self.secret_slots.len() > 32
            || self.requests.len() > 1024
            || self.envelope_sha256 != self.envelope_digest()
        {
            return Err(IoError::other("LLM recording metadata is invalid").into());
        }
        if self.secret_slots.iter().enumerate().any(|(index, slot)| {
            slot.is_empty()
                || slot.len() > 128
                || !slot.starts_with("SLOT_")
                || self.secret_slots[..index].contains(slot)
        }) {
            return Err(IoError::other("LLM recording secret slots are invalid").into());
        }
        let mut next_sequence = 0;
        let mut previous_round = None;
        let mut previous_attempt = None;
        for exchange in &self.requests {
            if exchange.sequence != next_sequence
                || exchange.request.method != "POST"
                || !path_is_secret_safe(&exchange.request.path)
            {
                return Err(IoError::other("LLM recording request is not canonical").into());
            }
            match (previous_round, previous_attempt) {
                (None, None) if exchange.logical_round == 0 && exchange.wire_attempt == 0 => {}
                (Some(round), Some(attempt)) if exchange.logical_round == round => {
                    if exchange.wire_attempt != attempt + 1 {
                        return Err(
                            IoError::other("LLM recording wire attempts are not ordered").into(),
                        );
                    }
                }
                (Some(round), Some(_))
                    if exchange.logical_round == round + 1 && exchange.wire_attempt == 0 => {}
                _ => {
                    return Err(
                        IoError::other("LLM recording logical rounds are not ordered").into(),
                    );
                }
            }
            previous_round = Some(exchange.logical_round);
            previous_attempt = Some(exchange.wire_attempt);
            next_sequence = next_sequence.saturating_add(1);
            validate_headers(&exchange.request.semantic_headers, true)?;
            let raw_body = hex_decode(&exchange.request.raw_body_hex)?;
            let canonical_valid = match (
                &exchange.request.canonical_json,
                &exchange.request.canonical_json_sha256,
            ) {
                (Some(canonical), Some(digest)) => {
                    canonical_json_from_str(canonical)? == *canonical
                        && canonical_json(&raw_body)? == *canonical
                        && sha256_hex(canonical.as_bytes()) == *digest
                }
                (None, None) => serde_json::from_slice::<Value>(&raw_body).is_err(),
                _ => false,
            };
            if !canonical_valid || sha256_hex(&raw_body) != exchange.request.raw_body_sha256 {
                return Err(IoError::other("LLM recording request digest is invalid").into());
            }
            validate_response(&exchange.response)?;
        }
        Ok(())
    }

    fn envelope_digest(&self) -> String {
        #[derive(Serialize)]
        struct UnsignedRecording<'a> {
            schema: &'a str,
            recording_id: &'a str,
            purpose: &'a str,
            owner: &'a str,
            boundary: &'a str,
            secret_slots: &'a [String],
            provider: &'a str,
            model: &'a str,
            requests: &'a [LlmHttpRecordingExchange],
            envelope_sha256: &'static str,
        }
        let unsigned = UnsignedRecording {
            schema: &self.schema,
            recording_id: &self.recording_id,
            purpose: &self.purpose,
            owner: &self.owner,
            boundary: &self.boundary,
            secret_slots: &self.secret_slots,
            provider: &self.provider,
            model: &self.model,
            requests: &self.requests,
            envelope_sha256: "",
        };
        let mut hasher = Sha256::new();
        let encoded = {
            let mut writer = Sha256Writer(&mut hasher);
            serde_json::to_writer(&mut writer, &unsigned)
        };
        encoded
            .map(|()| format!("{:x}", hasher.finalize()))
            .unwrap_or_default()
    }
}

fn promote_immutable_compressed_bytes(path: &Path, bytes: &[u8]) -> TestResult<u64> {
    let parent = path
        .parent()
        .ok_or_else(|| IoError::other("LLM recording path has no parent"))?;
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| IoError::other("LLM recording file name is invalid"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temporary = parent.join(format!(".{file_name}.tmp-{}-{nonce}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let prepare = (|| -> TestResult<u64> {
        let file = options.open(&temporary)?;
        let mut encoder = zstd::stream::write::Encoder::new(file, LLM_COMPRESSED_RECORDING_LEVEL)?;
        encoder.include_checksum(true)?;
        encoder.write_all(bytes)?;
        let file = encoder.finish()?;
        file.sync_all()?;
        drop(file);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o444))?;
            fs::File::open(&temporary)?.sync_all()?;
        }
        Ok(fs::metadata(&temporary)?.len())
    })();
    let compressed_bytes = match prepare {
        Ok(compressed_bytes) => compressed_bytes,
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    };
    if let Err(error) = fs::hard_link(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(if error.kind() == ErrorKind::AlreadyExists {
            IoError::new(
                ErrorKind::AlreadyExists,
                "tracked compressed LLM recording is immutable",
            )
        } else {
            error
        }
        .into());
    }
    fs::remove_file(&temporary)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(compressed_bytes)
}

struct Sha256Writer<'a>(&'a mut Sha256);

impl Write for Sha256Writer<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validate_headers(headers: &[LlmHttpHeader], request: bool) -> TestResult<()> {
    let mut previous = None;
    for header in headers {
        if header.name != header.name.to_ascii_lowercase()
            || header.name.is_empty()
            || header.value.is_empty()
            || header.value.len() > 256
            || !header.value.is_ascii()
            || header.value.bytes().any(|byte| byte.is_ascii_control())
            || header.name == "authorization"
            || header.name == "cookie"
            || header.name.contains("token")
            || header.name.contains("secret")
            || (!matches!(header.name.as_str(), "accept" | "content-type") && request)
            || (!request && !matches!(header.name.as_str(), "content-type" | "retry-after"))
        {
            return Err(IoError::other("LLM recording headers are not secret-safe").into());
        }
        if previous.is_some_and(|previous| previous >= &header.name) {
            return Err(IoError::other("LLM recording headers are not sorted").into());
        }
        previous = Some(&header.name);
    }
    Ok(())
}

fn validate_response(response: &LlmHttpRecordingResponse) -> TestResult<()> {
    match &response.outcome {
        LlmHttpResponseOutcome::TransportError => {
            if response.status.is_some()
                || response.content_type.is_some()
                || !response.semantic_headers.is_empty()
                || !response.chunks.is_empty()
            {
                return Err(IoError::other("LLM transport outcome has response data").into());
            }
        }
        LlmHttpResponseOutcome::Complete { done_seen } => {
            validate_http_response(response)?;
            if *done_seen != chunks_contain_done(&response.chunks) {
                return Err(IoError::other("LLM complete outcome has invalid DONE marker").into());
            }
        }
        LlmHttpResponseOutcome::ClientDisconnect => {
            if response.status.is_some() {
                validate_http_response(response)?;
            } else if response.content_type.is_some()
                || !response.semantic_headers.is_empty()
                || !response.chunks.is_empty()
            {
                return Err(
                    IoError::other("LLM pre-response disconnect has response metadata").into(),
                );
            }
        }
        LlmHttpResponseOutcome::StreamError | LlmHttpResponseOutcome::CaptureBoundExceeded => {
            validate_http_response(response)?
        }
    }
    if response.chunks.len() > MAX_LLM_RESPONSE_CHUNKS {
        return Err(IoError::other("LLM response capture chunk bound exceeded").into());
    }
    let mut response_bytes = 0usize;
    for (index, chunk) in response.chunks.iter().enumerate() {
        let previous_at_us = if index == 0 {
            0
        } else {
            response.chunks[index - 1].at_us
        };
        if chunk.at_us < previous_at_us || chunk.at_us - previous_at_us > MAX_LLM_CHUNK_DELAY_US {
            return Err(IoError::other("LLM response captured timing bound exceeded").into());
        }
        let bytes = hex_decode(&chunk.bytes_hex)?;
        response_bytes = response_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| IoError::other("LLM response capture byte bound exceeded"))?;
        if response_bytes > MAX_LLM_RESPONSE_BYTES {
            return Err(IoError::other("LLM response capture byte bound exceeded").into());
        }
        if chunk.sequence != index as u64
            || (is_event_stream_content_type(response.content_type.as_deref())
                && chunk.kind != LlmHttpChunkKind::Sse)
            || (!is_event_stream_content_type(response.content_type.as_deref())
                && chunk.kind != LlmHttpChunkKind::Body)
        {
            return Err(IoError::other("LLM response chunks are not ordered").into());
        }
    }
    Ok(())
}

fn validate_replay_response_template(template: &LlmHttpReplayResponseTemplate) -> TestResult<()> {
    let response = LlmHttpRecordingResponse {
        status: template.status,
        content_type: template.content_type.clone(),
        semantic_headers: template.semantic_headers.clone(),
        chunks: Vec::new(),
        outcome: template.outcome.into(),
    };
    match template.outcome {
        LlmHttpReplayOutcome::TransportError => {
            if response.status.is_some()
                || response.content_type.is_some()
                || !response.semantic_headers.is_empty()
            {
                return Err(IoError::other("LLM transport outcome has response data").into());
            }
        }
        LlmHttpReplayOutcome::ClientDisconnect if response.status.is_none() => {
            if response.content_type.is_some() || !response.semantic_headers.is_empty() {
                return Err(
                    IoError::other("LLM pre-response disconnect has response metadata").into(),
                );
            }
        }
        _ => validate_http_response(&response)?,
    }
    Ok(())
}

fn validate_indexed_response(
    template: &LlmHttpReplayResponseTemplate,
    chunks: &[LlmHttpIndexedReplayChunk],
    first_byte: usize,
    response_bytes: &[u8],
    done_seen: bool,
) -> TestResult<()> {
    if chunks.len() > MAX_LLM_RESPONSE_CHUNKS || response_bytes.len() > MAX_LLM_RESPONSE_BYTES {
        return Err(IoError::other("LLM response capture bound exceeded").into());
    }
    let response_end = first_byte
        .checked_add(response_bytes.len())
        .ok_or_else(|| IoError::other("LLM response byte range overflowed"))?;
    let mut previous_at_us = 0;
    let mut previous_end = first_byte;
    for chunk in chunks {
        let end = usize::try_from(chunk.end_byte)?;
        if chunk.at_us < previous_at_us
            || chunk.at_us - previous_at_us > MAX_LLM_CHUNK_DELAY_US
            || end < previous_end
            || end > response_end
        {
            return Err(IoError::other("LLM indexed response chunk is invalid").into());
        }
        previous_at_us = chunk.at_us;
        previous_end = end;
    }
    if previous_end != response_end {
        return Err(IoError::other("LLM indexed response byte range is incomplete").into());
    }
    let contains_done = response_bytes
        .windows(b"data: [DONE]".len())
        .any(|window| window == b"data: [DONE]");
    if contains_done != done_seen
        || matches!(
            template.outcome,
            LlmHttpReplayOutcome::Complete {
                done_seen: expected
            } if expected != done_seen
        )
        || (matches!(template.outcome, LlmHttpReplayOutcome::TransportError)
            && (!chunks.is_empty() || !response_bytes.is_empty()))
    {
        return Err(IoError::other("LLM indexed response outcome is inconsistent").into());
    }
    Ok(())
}

fn is_pre_stream_retryable_response(response: &LlmHttpRecordingResponse) -> bool {
    response
        .status
        .is_some_and(|status| status == 408 || status == 429 || (500..=599).contains(&status))
        && response.content_type.is_none()
        && matches!(
            response.outcome,
            LlmHttpResponseOutcome::Complete { done_seen: false }
        )
}

fn validate_http_response(response: &LlmHttpRecordingResponse) -> TestResult<()> {
    if response.status.is_none_or(|status| status == 0) {
        return Err(IoError::other("LLM response metadata is invalid").into());
    }
    validate_headers(&response.semantic_headers, false)?;
    let content_type = response
        .semantic_headers
        .iter()
        .find(|header| header.name == "content-type")
        .map(|header| header.value.as_str());
    if content_type != response.content_type.as_deref() {
        return Err(IoError::other("LLM response content type header is inconsistent").into());
    }
    Ok(())
}

fn is_event_stream_content_type(value: Option<&str>) -> bool {
    value
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("text/event-stream"))
}

fn path_is_secret_safe(path: &str) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    let Some((_, query)) = path.split_once('?') else {
        return true;
    };
    const FORBIDDEN_QUERY_KEYS: [&str; 9] = [
        "authorization",
        "assertion",
        "bearer",
        "code",
        "credential",
        "key",
        "password",
        "secret",
        "token",
    ];
    query.split('&').all(|pair| {
        let key = pair
            .split('=')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        !FORBIDDEN_QUERY_KEYS
            .iter()
            .any(|marker| key.contains(marker))
    })
}

fn chunks_contain_done(chunks: &[LlmHttpRecordingChunk]) -> bool {
    let mut bytes = Vec::new();
    for chunk in chunks {
        if let Ok(chunk) = hex_decode(&chunk.bytes_hex) {
            bytes.extend_from_slice(&chunk);
        }
    }
    bytes
        .windows(b"data: [DONE]".len())
        .any(|window| window == b"data: [DONE]")
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn decode_sha256(value: &str) -> TestResult<[u8; 32]> {
    if value.len() != 64 {
        return Err(IoError::other("SHA-256 digest has the wrong length").into());
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])
            .ok_or_else(|| IoError::other("SHA-256 digest encoding is invalid"))?;
        let low = hex_nibble(pair[1])
            .ok_or_else(|| IoError::other("SHA-256 digest encoding is invalid"))?;
        digest[index] = (high << 4) | low;
    }
    Ok(digest)
}

pub fn canonical_json(body: &[u8]) -> TestResult<String> {
    canonical_json_from_value(&serde_json::from_slice(body)?)
}

fn canonical_json_from_str(body: &str) -> TestResult<String> {
    canonical_json_from_value(&serde_json::from_str(body)?)
}

fn canonical_json_from_value(value: &Value) -> TestResult<String> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            Ok(serde_json::to_string(value)?)
        }
        Value::Array(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json_from_value)
                .collect::<TestResult<Vec<_>>>()?
                .join(",")
        )),
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let fields = keys
                .into_iter()
                .map(|key| {
                    Ok(format!(
                        "{}:{}",
                        serde_json::to_string(key)?,
                        canonical_json_from_value(&values[key])?
                    ))
                })
                .collect::<TestResult<Vec<_>>>()?;
            Ok(format!("{{{}}}", fields.join(",")))
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn hex_decode(value: &str) -> TestResult<Vec<u8>> {
    if !value.is_ascii() || !value.len().is_multiple_of(2) {
        return Err(IoError::other("LLM recording chunk encoding is invalid").into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])
                .ok_or_else(|| IoError::other("LLM recording chunk encoding is invalid"))?;
            let low = hex_nibble(pair[1])
                .ok_or_else(|| IoError::other("LLM recording chunk encoding is invalid"))?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[derive(Clone)]
enum LlmHttpProxyMode {
    Record {
        upstream_base_url: String,
        provider: String,
        model: String,
        metadata: LlmHttpRecordingMetadata,
        sink: std::sync::Arc<RecordingSink>,
    },
    Replay {
        recording: LlmHttpReplayRecording,
        captured_timing: bool,
        expected_authorization: Option<String>,
        terminal_hold: Option<std::sync::Arc<Notify>>,
    },
}

#[derive(Clone)]
enum LlmHttpReplayRecording {
    Full(std::sync::Arc<LlmHttpRecording>),
    Hashes(std::sync::Arc<LlmHttpHashReplayRecording>),
}

impl LlmHttpReplayRecording {
    fn request_count(&self) -> usize {
        match self {
            Self::Full(recording) => recording.requests.len(),
            Self::Hashes(recording) => recording.exchanges.len(),
        }
    }

    fn response_status(&self, index: usize) -> Option<u16> {
        match self {
            Self::Full(recording) => recording
                .requests
                .get(index)
                .and_then(|exchange| exchange.response.status),
            Self::Hashes(recording) => recording
                .response_template(index)
                .and_then(|template| template.status),
        }
    }

    fn response_content_type(&self, index: usize) -> Option<&str> {
        match self {
            Self::Full(recording) => recording
                .requests
                .get(index)
                .and_then(|exchange| exchange.response.content_type.as_deref()),
            Self::Hashes(recording) => recording
                .response_template(index)
                .and_then(|template| template.content_type.as_deref()),
        }
    }

    fn response_headers(&self, index: usize) -> Option<&[LlmHttpHeader]> {
        match self {
            Self::Full(recording) => recording
                .requests
                .get(index)
                .map(|exchange| exchange.response.semantic_headers.as_slice()),
            Self::Hashes(recording) => recording
                .response_template(index)
                .map(|template| template.semantic_headers.as_slice()),
        }
    }

    fn response_outcome(&self, index: usize) -> Option<LlmHttpReplayOutcome> {
        match self {
            Self::Full(recording) => recording
                .requests
                .get(index)
                .map(|exchange| (&exchange.response.outcome).into()),
            Self::Hashes(recording) => recording
                .response_template(index)
                .map(|template| template.outcome),
        }
    }

    fn response_chunk_count(&self, index: usize) -> Option<usize> {
        match self {
            Self::Full(recording) => recording
                .requests
                .get(index)
                .map(|exchange| exchange.response.chunks.len()),
            Self::Hashes(recording) => recording
                .exchanges
                .get(index)
                .and_then(|exchange| usize::try_from(exchange.chunk_count).ok()),
        }
    }

    fn response_chunk(&self, index: usize, chunk_index: usize) -> TestResult<Option<(u64, Bytes)>> {
        match self {
            Self::Full(recording) => recording
                .requests
                .get(index)
                .and_then(|exchange| exchange.response.chunks.get(chunk_index))
                .map(|chunk| Ok((chunk.at_us, Bytes::from(hex_decode(&chunk.bytes_hex)?))))
                .transpose(),
            Self::Hashes(recording) => recording.response_chunk(index, chunk_index).map(Some),
        }
    }

    fn response_done_seen(&self, index: usize) -> bool {
        match self {
            Self::Full(recording) => recording
                .requests
                .get(index)
                .is_some_and(|exchange| chunks_contain_done(&exchange.response.chunks)),
            Self::Hashes(recording) => recording
                .exchanges
                .get(index)
                .is_some_and(|exchange| exchange.done_seen),
        }
    }

    fn request_matches(
        &self,
        index: usize,
        method: &str,
        path: &str,
        semantic_headers: &[LlmHttpHeader],
        body: &[u8],
    ) -> bool {
        match self {
            Self::Full(recording) => recording.requests.get(index).is_some_and(|exchange| {
                exchange.request.method == method
                    && exchange.request.path == path
                    && exchange.request.semantic_headers == semantic_headers
                    && exchange.request.raw_body_sha256 == sha256_hex(body)
            }),
            Self::Hashes(recording) => {
                recording.request_matches(index, method, path, semantic_headers, body)
            }
        }
    }

    fn requires_authorization(&self) -> bool {
        match self {
            Self::Full(recording) => !recording.secret_slots.is_empty(),
            Self::Hashes(recording) => recording.requires_authorization,
        }
    }

    fn retains_observed_bodies(&self) -> bool {
        matches!(self, Self::Full(_))
    }

    fn retained_request_match_bytes(&self) -> usize {
        match self {
            Self::Full(recording) => recording.retained_request_match_bytes(),
            Self::Hashes(recording) => recording.retained_request_match_bytes,
        }
    }

    fn full(&self) -> Option<&LlmHttpRecording> {
        match self {
            Self::Full(recording) => Some(recording),
            Self::Hashes(_) => None,
        }
    }
}

impl LlmHttpHashReplayRecording {
    fn response_template(&self, index: usize) -> Option<&LlmHttpReplayResponseTemplate> {
        let exchange = self.exchanges.get(index)?;
        self.response_templates
            .get(usize::from(exchange.response_template))
    }

    fn request_matches(
        &self,
        index: usize,
        method: &str,
        path: &str,
        semantic_headers: &[LlmHttpHeader],
        body: &[u8],
    ) -> bool {
        let Some(exchange) = self.exchanges.get(index) else {
            return false;
        };
        let Some(template) = self
            .request_templates
            .get(usize::from(exchange.request_template))
        else {
            return false;
        };
        template.method == method
            && template.path == path
            && template.semantic_headers == semantic_headers
            && exchange.raw_body_sha256 == sha256(body)
    }

    fn response_chunk(&self, index: usize, chunk_index: usize) -> TestResult<(u64, Bytes)> {
        let exchange = self
            .exchanges
            .get(index)
            .ok_or_else(|| IoError::other("LLM replay response index is invalid"))?;
        let first_chunk = usize::try_from(exchange.first_chunk)?;
        let chunk_count = usize::try_from(exchange.chunk_count)?;
        if chunk_index >= chunk_count {
            return Err(IoError::other("LLM replay chunk index is invalid").into());
        }
        let absolute_chunk = first_chunk + chunk_index;
        let chunk = self
            .chunks
            .get(absolute_chunk)
            .ok_or_else(|| IoError::other("LLM replay chunk range is invalid"))?;
        let start = if chunk_index == 0 {
            usize::try_from(exchange.first_byte)?
        } else {
            usize::try_from(
                self.chunks
                    .get(absolute_chunk - 1)
                    .ok_or_else(|| IoError::other("LLM replay chunk start is invalid"))?
                    .end_byte,
            )?
        };
        let end = usize::try_from(chunk.end_byte)?;
        if start > end || end > self.response_bytes.len() {
            return Err(IoError::other("LLM replay chunk bytes are invalid").into());
        }
        Ok((chunk.at_us, self.response_bytes.slice(start..end)))
    }
}

struct RecordingSink {
    directory: PathBuf,
    requires_authorization: bool,
    single_sequential_stream: bool,
    attempt_plan: Option<Vec<LlmHttpAttemptPlan>>,
    next_sequence: AtomicU64,
    chunk_count: AtomicU64,
    submitted_count: AtomicU64,
    chunk_seen: Notify,
    submitted_seen: Notify,
    exchange_seen: Notify,
    state: std::sync::Mutex<RecordingSinkState>,
    flush_error: std::sync::Mutex<Option<String>>,
}

struct RecordingSinkState {
    next_finalize: u64,
    pending: BTreeMap<u64, LlmHttpRecordingExchange>,
    finalized: Vec<LlmHttpRecordingExchange>,
    logical: Option<(String, u64, u64, bool)>,
    // A no-plan capture must observe exchanges in wire-arrival order.  A
    // completion with a lower sequence means two logical attempts were
    // interleaved and body-based inference can no longer be trusted.
    last_submitted_sequence: Option<u64>,
    // A request is allocated before its response headers/body are complete.
    // Keep that durable in-flight fact separate from `active_sequences`,
    // which is only used for no-plan attempt identity ambiguity.
    in_flight_sequences: BTreeSet<u64>,
    active_sequences: BTreeSet<u64>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct LlmHttpIngress {
    schema: &'static str,
    sequence: u64,
    method: String,
    path: String,
    raw_body_hex: String,
    raw_body_sha256: String,
}

impl RecordingSink {
    fn new(
        directory: PathBuf,
        attempt_plan: Option<Vec<LlmHttpAttemptPlan>>,
        requires_authorization: bool,
        single_sequential_stream: bool,
    ) -> TestResult<Self> {
        fs::create_dir_all(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            directory,
            requires_authorization,
            single_sequential_stream,
            attempt_plan,
            next_sequence: AtomicU64::new(0),
            chunk_count: AtomicU64::new(0),
            submitted_count: AtomicU64::new(0),
            chunk_seen: Notify::new(),
            submitted_seen: Notify::new(),
            exchange_seen: Notify::new(),
            state: std::sync::Mutex::new(RecordingSinkState {
                next_finalize: 0,
                pending: BTreeMap::new(),
                finalized: Vec::new(),
                logical: None,
                last_submitted_sequence: None,
                in_flight_sequences: BTreeSet::new(),
                active_sequences: BTreeSet::new(),
            }),
            flush_error: std::sync::Mutex::new(None),
        })
    }

    fn allocate_sequence(&self) -> u64 {
        self.next_sequence.fetch_add(1, Ordering::SeqCst)
    }

    fn begin_sequence(&self, sequence: u64) {
        let mut state = self
            .state
            .lock()
            .expect("LLM recording sink mutex poisoned");
        state.in_flight_sequences.insert(sequence);
        if self.attempt_plan.is_none() {
            state.active_sequences.insert(sequence);
        }
    }

    fn note_chunk(&self) {
        self.chunk_count.fetch_add(1, Ordering::SeqCst);
        self.chunk_seen.notify_waiters();
    }

    async fn wait_for_chunks(&self, expected: u64) -> TestResult<()> {
        timeout(HTTP_RESPONSE_HEADERS_TIMEOUT, async {
            loop {
                let notified = self.chunk_seen.notified();
                if self.chunk_count.load(Ordering::SeqCst) >= expected {
                    return;
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| IoError::new(ErrorKind::TimedOut, "recording chunk barrier timed out"))?;
        Ok(())
    }

    async fn wait_for_exchanges(&self, expected: usize) -> TestResult<()> {
        timeout(HTTP_RESPONSE_HEADERS_TIMEOUT, async {
            loop {
                let notified = self.exchange_seen.notified();
                if self
                    .state
                    .lock()
                    .expect("LLM recording sink mutex poisoned")
                    .finalized
                    .len()
                    >= expected
                {
                    return;
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| IoError::new(ErrorKind::TimedOut, "recording exchange barrier timed out"))?;
        Ok(())
    }

    async fn wait_for_submitted(&self, expected: usize) -> TestResult<()> {
        timeout(HTTP_RESPONSE_HEADERS_TIMEOUT, async {
            loop {
                let notified = self.submitted_seen.notified();
                if self.submitted_count.load(Ordering::SeqCst) >= expected as u64 {
                    return;
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| IoError::new(ErrorKind::TimedOut, "recording submit barrier timed out"))?;
        Ok(())
    }

    fn record_ingress(&self, sequence: u64, method: &str, path: &str, raw_body: &[u8]) {
        let file_path = self
            .directory
            .join(format!("ingress-{:020}.json", sequence));
        let ingress = LlmHttpIngress {
            schema: LLM_HTTP_RECORDING_SCHEMA,
            sequence,
            method: method.to_owned(),
            path: path.to_owned(),
            raw_body_hex: hex_encode(raw_body),
            raw_body_sha256: sha256_hex(raw_body),
        };
        if let Err(error) = write_restricted_json_new(&file_path, &ingress) {
            self.fail_flush(&format!("recording ingress flush failed: {error}"));
        }
    }

    fn fail_flush(&self, message: &str) {
        let mut flush_error = self
            .flush_error
            .lock()
            .expect("LLM recording flush mutex poisoned");
        if flush_error.is_none() {
            *flush_error = Some(message.to_owned());
        }
    }

    fn submit(&self, exchange: LlmHttpRecordingExchange) -> TestResult<()> {
        let mut state = self
            .state
            .lock()
            .expect("LLM recording sink mutex poisoned");
        let mut exchange = exchange;
        state.in_flight_sequences.remove(&exchange.sequence);
        let mut ambiguous_completion = false;
        let mut attempt_plan_error = false;
        if self.attempt_plan.is_none() {
            ambiguous_completion = state.active_sequences.len() > 1
                || state
                    .last_submitted_sequence
                    .is_some_and(|previous| exchange.sequence < previous);
            state.active_sequences.remove(&exchange.sequence);
            if ambiguous_completion {
                self.fail_flush("ambiguous attempt identity; provide an explicit attempt plan");
            }
        }
        let (logical_round, wire_attempt) = if let Some(plan) = &self.attempt_plan {
            match plan.get(exchange.sequence as usize).copied() {
                Some(attempt) => (attempt.logical_round, attempt.wire_attempt),
                None => {
                    attempt_plan_error = true;
                    self.fail_flush(&format!(
                        "recording attempt plan omitted sequence {}",
                        exchange.sequence
                    ));
                    (exchange.logical_round, exchange.wire_attempt)
                }
            }
        } else {
            if ambiguous_completion {
                // Preserve the caller-supplied envelope facts, but do not
                // infer a logical round once completion order is ambiguous.
                (exchange.logical_round, exchange.wire_attempt)
            } else {
                let logical_key = exchange
                    .request
                    .canonical_json
                    .clone()
                    .unwrap_or_else(|| exchange.request.raw_body_sha256.clone());
                match state.logical.as_mut() {
                    Some((previous, round, attempt, previous_retryable))
                        if previous == &logical_key =>
                    {
                        if !*previous_retryable && !self.single_sequential_stream {
                            ambiguous_completion = true;
                            self.fail_flush(
                                "ambiguous attempt identity; provide an explicit attempt plan",
                            );
                        }
                        if *previous_retryable || self.single_sequential_stream {
                            *attempt = attempt.saturating_add(1);
                        } else {
                            *attempt = 0;
                        }
                        *previous_retryable = is_pre_stream_retryable_response(&exchange.response);
                        (*round, *attempt)
                    }
                    Some((previous, round, attempt, previous_retryable)) => {
                        *round = round.saturating_add(1);
                        *attempt = 0;
                        *previous = logical_key;
                        *previous_retryable = is_pre_stream_retryable_response(&exchange.response);
                        (*round, 0)
                    }
                    None => {
                        let retryable = is_pre_stream_retryable_response(&exchange.response);
                        state.logical = Some((logical_key, 0, 0, retryable));
                        (0, 0)
                    }
                }
            }
        };
        if self.attempt_plan.is_none() {
            state.last_submitted_sequence = Some(exchange.sequence);
        }
        exchange.logical_round = logical_round;
        exchange.wire_attempt = wire_attempt;
        // Seal every completed exchange immediately. Ordered projection below
        // is only for the in-memory envelope; a later sequence must survive a
        // recorder crash while an earlier stream is still held.
        let path = self
            .directory
            .join(format!("exchange-{:020}.json", exchange.sequence));
        if let Err(error) = write_restricted_json_new(&path, &exchange) {
            let message = format!("recording exchange flush failed: {error}");
            self.fail_flush(&message);
            return Err(IoError::other(message).into());
        }
        // Expose the completion barrier only after the per-exchange durable
        // fact has been written (or its fatal flush error has been latched).
        self.submitted_count.fetch_add(1, Ordering::SeqCst);
        self.submitted_seen.notify_waiters();
        state.pending.insert(exchange.sequence, exchange);
        let previous_len = state.finalized.len();
        loop {
            let next_finalize = state.next_finalize;
            let Some(exchange) = state.pending.remove(&next_finalize) else {
                break;
            };
            state.finalized.push(exchange);
            state.next_finalize = state.next_finalize.saturating_add(1);
        }
        if state.finalized.len() != previous_len {
            self.exchange_seen.notify_waiters();
        }
        if attempt_plan_error {
            Err(IoError::other("recording attempt plan omitted an exchange sequence").into())
        } else if ambiguous_completion {
            Err(
                IoError::other("ambiguous attempt identity; provide an explicit attempt plan")
                    .into(),
            )
        } else {
            Ok(())
        }
    }

    fn finalized(&self) -> Vec<LlmHttpRecordingExchange> {
        self.state
            .lock()
            .expect("LLM recording sink mutex poisoned")
            .finalized
            .clone()
    }

    fn flush_error(&self) -> Option<String> {
        let explicit = self
            .flush_error
            .lock()
            .expect("LLM recording flush mutex poisoned")
            .clone();
        if explicit.is_some() {
            return explicit;
        }
        let allocated = self.next_sequence.load(Ordering::SeqCst);
        let state = self
            .state
            .lock()
            .expect("LLM recording sink mutex poisoned");
        if !state.in_flight_sequences.is_empty() {
            return None;
        }
        if state.pending.is_empty() && state.finalized.len() as u64 == allocated {
            None
        } else {
            Some(format!(
                "recording finalized {} of {allocated} allocated exchanges",
                state.finalized.len()
            ))
        }
    }
}

fn write_restricted_json_new<T: Serialize>(path: &Path, value: &T) -> TestResult<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    let parent = path
        .parent()
        .ok_or_else(|| IoError::other("recording fact path has no parent"))?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[derive(Serialize)]
struct PublicHttpGapRequest {
    method: String,
    path: String,
    body_hex: String,
    body_sha256: String,
    authorization: String,
}

#[derive(Serialize)]
struct PublicHttpGapResponse {
    status: u16,
    body_hex: String,
    body_sha256: String,
}

#[derive(Serialize)]
struct PublicHttpGapRecording {
    schema: &'static str,
    version: u32,
    recording_id: String,
    e2e_name: String,
    relation: String,
    boundary: String,
    first_observed: String,
    request: PublicHttpGapRequest,
    response: PublicHttpGapResponse,
    envelope_sha256: String,
}

/// Input to one public HTTP request/response evidence-gap capture.
pub struct PublicHttpGapExchange<'a> {
    pub e2e_name: &'a str,
    pub relation: &'a str,
    pub boundary: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub request_body: &'a [u8],
    pub response_status: u16,
    pub response_body: &'a [u8],
}

/// Persist one public HTTP request/response observed while reproducing a
/// test-only evidence gap. Authorization is represented only by its named
/// synthetic slot; body bytes are bounded and the file is create-new,
/// restrictive, and fsync'd before the path is returned.
pub fn persist_public_http_gap_exchange(
    run_directory: &Path,
    exchange: PublicHttpGapExchange<'_>,
) -> TestResult<PathBuf> {
    if exchange.request_body.len() > MAX_PUBLIC_HTTP_GAP_BODY_BYTES
        || exchange.response_body.len() > MAX_PUBLIC_HTTP_GAP_BODY_BYTES
    {
        return Err(IoError::other("public HTTP gap exchange exceeded body bound").into());
    }
    let metadata = fs::symlink_metadata(run_directory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(IoError::other("public HTTP gap run directory was not a directory").into());
    }
    let recording_id = run_directory
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| IoError::other("public HTTP gap run directory had no recording id"))?
        .to_owned();
    let mut recording = PublicHttpGapRecording {
        schema: PUBLIC_HTTP_GAP_RECORDING_SCHEMA,
        version: 1,
        recording_id,
        e2e_name: exchange.e2e_name.to_owned(),
        relation: exchange.relation.to_owned(),
        boundary: exchange.boundary.to_owned(),
        first_observed: "session_create_http_422_before_provider_exchange".to_owned(),
        request: PublicHttpGapRequest {
            method: exchange.method.to_owned(),
            path: exchange.path.to_owned(),
            body_hex: hex_encode(exchange.request_body),
            body_sha256: sha256_hex(exchange.request_body),
            authorization: "SLOT_CONTROLLER_AUTHORIZATION_HEADER".to_owned(),
        },
        response: PublicHttpGapResponse {
            status: exchange.response_status,
            body_hex: hex_encode(exchange.response_body),
            body_sha256: sha256_hex(exchange.response_body),
        },
        envelope_sha256: String::new(),
    };
    let preimage = serde_json::to_vec(&recording)?;
    recording.envelope_sha256 = sha256_hex(&preimage);
    let path = run_directory.join("public-http-gap.json");
    write_restricted_json_new(&path, &recording)?;
    Ok(path)
}

fn sync_directory(path: &Path) -> TestResult<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

pub fn new_llm_recording_run_dir() -> TestResult<PathBuf> {
    new_llm_recording_directory("quarantine", None)
}

pub fn new_llm_live_recording_run_dir(run_id: &str) -> TestResult<PathBuf> {
    if run_id.is_empty()
        || Path::new(run_id).components().count() != 1
        || run_id == "."
        || run_id == ".."
    {
        return Err(IoError::other("live recording run id is invalid").into());
    }
    new_llm_recording_directory("live", Some(run_id))
}

fn new_llm_recording_directory(class: &str, run_id: Option<&str>) -> TestResult<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-recordings")
        .join(class);
    fs::create_dir_all(&root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    }
    sync_directory(&root)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let attempts = if run_id.is_some() { 1 } else { 128 };
    for attempt in 0..attempts {
        let name = run_id.map_or_else(
            || format!("run-{}-{}-{attempt}", std::process::id(), nonce),
            |run_id| {
                if attempt == 0 {
                    run_id.to_owned()
                } else {
                    format!("{run_id}-{attempt}")
                }
            },
        );
        let directory = root.join(name);
        match fs::create_dir(&directory) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
                }
                sync_directory(&directory)?;
                sync_directory(&root)?;
                return Ok(directory);
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists && run_id.is_none() => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(IoError::other("could not allocate a unique LLM recording run directory").into())
}

pub fn scan_llm_recording_tree(directory: &Path, forbidden: &[&str]) -> TestResult<()> {
    let root_metadata = fs::symlink_metadata(directory)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(IoError::other("recording quarantine root was not a directory").into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = root_metadata.permissions().mode() & 0o777;
        if mode != 0o700 {
            return Err(IoError::other(format!(
                "recording quarantine directory had mode {mode:04o}, expected 0700"
            ))
            .into());
        }
    }
    let mut stack = vec![directory.to_owned()];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(IoError::other("recording tree contained a symlink").into());
            }
            if metadata.is_dir() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = metadata.permissions().mode() & 0o777;
                    if mode != 0o700 {
                        return Err(IoError::other(format!(
                            "recording quarantine directory had mode {mode:04o}, expected 0700"
                        ))
                        .into());
                    }
                }
                stack.push(path);
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode() & 0o777;
                if mode != 0o600 {
                    return Err(IoError::other(format!(
                        "recording quarantine file had mode {mode:04o}, expected 0600"
                    ))
                    .into());
                }
            }
            let bytes = fs::read(path)?;
            for marker in forbidden.iter().filter(|marker| !marker.is_empty()) {
                if bytes_contain(&bytes, marker.as_bytes()) {
                    return Err(IoError::other(
                        "LLM recording quarantine contained secret material",
                    )
                    .into());
                }
            }
        }
    }
    Ok(())
}

struct LlmHttpProxyState {
    client: Client,
    mode: LlmHttpProxyMode,
    observed: std::sync::Mutex<Vec<LlmHttpObservedRequest>>,
    observed_at: std::sync::Mutex<Vec<Instant>>,
    observed_seen: Notify,
    replay_chunk_count: AtomicU64,
    replay_chunk_seen: Notify,
    replay_terminal_waiting: AtomicU64,
    replay_terminal_seen: Notify,
    next_replay: std::sync::Mutex<usize>,
    replay_completed: std::sync::Mutex<usize>,
    replay_error: std::sync::Mutex<Option<String>>,
    replay_completion_seen: Notify,
}

pub struct LlmHttpProxy {
    server: HttpFixture,
    state: std::sync::Arc<LlmHttpProxyState>,
}

struct LlmHttpRecordMode {
    attempt_plan: Option<Vec<LlmHttpAttemptPlan>>,
    requires_authorization: bool,
    single_sequential_stream: bool,
}

impl LlmHttpProxy {
    pub async fn record(
        upstream_base_url: impl Into<String>,
        provider: impl Into<String>,
        model: impl Into<String>,
        quarantine_directory: impl Into<PathBuf>,
        metadata: LlmHttpRecordingMetadata,
    ) -> TestResult<Self> {
        Self::record_with_attempt_plan(
            upstream_base_url,
            provider,
            model,
            quarantine_directory,
            metadata,
            None,
        )
        .await
    }

    /// Start a recorder with a caller-owned, sequence-indexed attempt plan.
    /// This avoids guessing logical rounds from request-body equality.
    pub async fn record_with_attempt_plan(
        upstream_base_url: impl Into<String>,
        provider: impl Into<String>,
        model: impl Into<String>,
        quarantine_directory: impl Into<PathBuf>,
        metadata: LlmHttpRecordingMetadata,
        attempt_plan: Option<Vec<LlmHttpAttemptPlan>>,
    ) -> TestResult<Self> {
        let requires_authorization = metadata.boundary.to_ascii_lowercase().contains("provider")
            || metadata
                .secret_slots
                .iter()
                .any(|slot| slot.to_ascii_uppercase().contains("AUTHORIZATION"));
        Self::record_with_attempt_plan_and_authorization(
            upstream_base_url,
            provider,
            model,
            quarantine_directory,
            metadata,
            attempt_plan,
            requires_authorization,
        )
        .await
    }

    /// Start a recorder with an explicit authentication requirement.  The
    /// flag is deliberately independent of the synthetic slot spelling so a
    /// provider-specific slot such as `SLOT_PROVIDER_AUTH` cannot silently
    /// disable Authorization capture/replay checks.
    pub async fn record_with_attempt_plan_and_authorization(
        upstream_base_url: impl Into<String>,
        provider: impl Into<String>,
        model: impl Into<String>,
        quarantine_directory: impl Into<PathBuf>,
        metadata: LlmHttpRecordingMetadata,
        attempt_plan: Option<Vec<LlmHttpAttemptPlan>>,
        requires_authorization: bool,
    ) -> TestResult<Self> {
        Self::record_with_inference_mode(
            upstream_base_url,
            provider,
            model,
            quarantine_directory,
            metadata,
            LlmHttpRecordMode {
                attempt_plan,
                requires_authorization,
                single_sequential_stream: false,
            },
        )
        .await
    }

    /// Record one sequential model-request stream whose identical adjacent
    /// requests are semantic retries of the same live in-memory request. This mode is
    /// for a single live Endpoint session: concurrent requests still fail
    /// closed, while an HTTP 200 response rejected by model-output validation
    /// can be retained as the preceding wire attempt.
    pub async fn record_single_sequential_stream(
        upstream_base_url: impl Into<String>,
        provider: impl Into<String>,
        model: impl Into<String>,
        quarantine_directory: impl Into<PathBuf>,
        metadata: LlmHttpRecordingMetadata,
    ) -> TestResult<Self> {
        let requires_authorization = metadata.boundary.to_ascii_lowercase().contains("provider")
            || metadata
                .secret_slots
                .iter()
                .any(|slot| slot.to_ascii_uppercase().contains("AUTHORIZATION"));
        Self::record_with_inference_mode(
            upstream_base_url,
            provider,
            model,
            quarantine_directory,
            metadata,
            LlmHttpRecordMode {
                attempt_plan: None,
                requires_authorization,
                single_sequential_stream: true,
            },
        )
        .await
    }

    async fn record_with_inference_mode(
        upstream_base_url: impl Into<String>,
        provider: impl Into<String>,
        model: impl Into<String>,
        quarantine_directory: impl Into<PathBuf>,
        metadata: LlmHttpRecordingMetadata,
        mode: LlmHttpRecordMode,
    ) -> TestResult<Self> {
        let sink = std::sync::Arc::new(RecordingSink::new(
            quarantine_directory.into(),
            mode.attempt_plan,
            mode.requires_authorization,
            mode.single_sequential_stream,
        )?);
        Self::start(LlmHttpProxyMode::Record {
            upstream_base_url: upstream_base_url.into(),
            provider: provider.into(),
            model: model.into(),
            metadata,
            sink,
        })
        .await
    }

    /// Compatibility replay has no out-of-band credential binding.  A
    /// recording that declares secret slots therefore fails closed on its
    /// first request; callers replaying a provider cassette must use
    /// `replay_with_authorization(Some(...))` so the live Authorization value
    /// is explicitly bound without being serialized into the cassette.
    pub async fn replay(recording: LlmHttpRecording, captured_timing: bool) -> TestResult<Self> {
        Self::replay_with_authorization(recording, captured_timing, None).await
    }

    /// Replay with an out-of-band authorization binding. The expected value
    /// remains in the test process and is never serialized into a cassette.
    pub async fn replay_with_authorization(
        recording: LlmHttpRecording,
        captured_timing: bool,
        expected_authorization: Option<String>,
    ) -> TestResult<Self> {
        recording.validate()?;
        Self::start(LlmHttpProxyMode::Replay {
            recording: LlmHttpReplayRecording::Full(std::sync::Arc::new(recording)),
            captured_timing,
            expected_authorization,
            terminal_hold: None,
        })
        .await
    }

    /// Exact replay for large cassettes whose caller needs request timing and
    /// count but does not inspect duplicate in-memory copies of request bodies.
    /// The already-validated cassette and each incoming raw body are matched by
    /// SHA-256, preserving exact-byte semantics without hex/canonical-JSON
    /// expansion on every request.
    pub async fn replay_hashes_with_authorization(
        recording: LlmHttpRecording,
        captured_timing: bool,
        expected_authorization: Option<String>,
    ) -> TestResult<Self> {
        recording.validate()?;
        Self::replay_validated_hashes_with_authorization(
            ValidatedLlmHttpRecording::from_validated(recording)?,
            captured_timing,
            expected_authorization,
        )
        .await
    }

    pub async fn replay_validated_hashes_with_authorization(
        recording: ValidatedLlmHttpRecording,
        captured_timing: bool,
        expected_authorization: Option<String>,
    ) -> TestResult<Self> {
        Self::start(LlmHttpProxyMode::Replay {
            recording: LlmHttpReplayRecording::Hashes(std::sync::Arc::new(
                recording.into_hash_replay()?,
            )),
            captured_timing,
            expected_authorization,
            terminal_hold: None,
        })
        .await
    }

    /// Test-only barrier that pauses replay after all recorded chunks have
    /// been emitted and before the response terminal outcome is delivered.
    /// It makes a client abort at that exact boundary deterministic.
    pub async fn replay_with_terminal_hold(
        recording: LlmHttpRecording,
        captured_timing: bool,
        expected_authorization: Option<String>,
        terminal_hold: std::sync::Arc<Notify>,
    ) -> TestResult<Self> {
        recording.validate()?;
        Self::start(LlmHttpProxyMode::Replay {
            recording: LlmHttpReplayRecording::Full(std::sync::Arc::new(recording)),
            captured_timing,
            expected_authorization,
            terminal_hold: Some(terminal_hold),
        })
        .await
    }

    async fn start(mode: LlmHttpProxyMode) -> TestResult<Self> {
        let client = Client::builder()
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let state = std::sync::Arc::new(LlmHttpProxyState {
            client,
            mode,
            observed: std::sync::Mutex::new(Vec::new()),
            observed_at: std::sync::Mutex::new(Vec::new()),
            observed_seen: Notify::new(),
            replay_chunk_count: AtomicU64::new(0),
            replay_chunk_seen: Notify::new(),
            replay_terminal_waiting: AtomicU64::new(0),
            replay_terminal_seen: Notify::new(),
            next_replay: std::sync::Mutex::new(0),
            replay_completed: std::sync::Mutex::new(0),
            replay_error: std::sync::Mutex::new(None),
            replay_completion_seen: Notify::new(),
        });
        let router = Router::new()
            .fallback(llm_http_proxy_request)
            .with_state(state.clone());
        let server = HttpFixture::start(router).await?;
        Ok(Self { server, state })
    }

    pub fn base_url(&self, path: &str) -> String {
        self.server.url(path)
    }

    pub fn recording(&self) -> TestResult<LlmHttpRecording> {
        let recording = match &self.state.mode {
            LlmHttpProxyMode::Record {
                provider,
                model,
                metadata,
                sink,
                ..
            } => {
                if let Some(error) = sink.flush_error() {
                    return Err(IoError::other(error).into());
                }
                LlmHttpRecording {
                    schema: LLM_HTTP_RECORDING_SCHEMA.to_owned(),
                    recording_id: metadata.recording_id.clone(),
                    purpose: metadata.purpose.clone(),
                    owner: metadata.owner.clone(),
                    boundary: metadata.boundary.clone(),
                    secret_slots: metadata.secret_slots.clone(),
                    provider: provider.clone(),
                    model: model.clone(),
                    requests: sink.finalized(),
                    envelope_sha256: String::new(),
                }
            }
            LlmHttpProxyMode::Replay { recording, .. } => recording
                .full()
                .cloned()
                .ok_or_else(|| IoError::other("hash replay does not retain a full recording"))?,
        };
        recording.with_digest()
    }

    pub fn flush_error(&self) -> Option<String> {
        match &self.state.mode {
            LlmHttpProxyMode::Record { sink, .. } => sink.flush_error(),
            LlmHttpProxyMode::Replay { .. } => None,
        }
    }

    pub fn observed_requests(&self) -> Vec<LlmHttpObservedRequest> {
        self.state
            .observed
            .lock()
            .expect("LLM proxy observed mutex poisoned")
            .clone()
    }

    pub fn observed_request_times(&self) -> Vec<Instant> {
        self.state
            .observed_at
            .lock()
            .expect("LLM proxy observation-time mutex poisoned")
            .clone()
    }

    pub fn replay_retained_request_match_bytes(&self) -> Option<usize> {
        match &self.state.mode {
            LlmHttpProxyMode::Replay { recording, .. } => {
                Some(recording.retained_request_match_bytes())
            }
            LlmHttpProxyMode::Record { .. } => None,
        }
    }

    pub async fn wait_for_recorded_chunks(&self, expected: u64) -> TestResult<()> {
        match &self.state.mode {
            LlmHttpProxyMode::Record { sink, .. } => sink.wait_for_chunks(expected).await,
            LlmHttpProxyMode::Replay { .. } => {
                Err(IoError::other("replay proxy has no recording chunk barrier").into())
            }
        }
    }

    pub async fn wait_for_replayed_chunks(&self, expected: u64) -> TestResult<()> {
        match &self.state.mode {
            LlmHttpProxyMode::Replay { .. } => {
                timeout(HTTP_RESPONSE_HEADERS_TIMEOUT, async {
                    loop {
                        let notified = self.state.replay_chunk_seen.notified();
                        if self.state.replay_chunk_count.load(Ordering::SeqCst) >= expected {
                            return;
                        }
                        notified.await;
                    }
                })
                .await
                .map_err(|_| IoError::new(ErrorKind::TimedOut, "replay chunk barrier timed out"))?;
                Ok(())
            }
            LlmHttpProxyMode::Record { .. } => {
                Err(IoError::other("recording proxy has no replay chunk barrier").into())
            }
        }
    }

    pub async fn wait_for_replay_terminal_hold(&self) -> TestResult<()> {
        timeout(HTTP_RESPONSE_HEADERS_TIMEOUT, async {
            loop {
                let notified = self.state.replay_terminal_seen.notified();
                if self.state.replay_terminal_waiting.load(Ordering::SeqCst) > 0 {
                    return;
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| IoError::new(ErrorKind::TimedOut, "replay terminal barrier timed out"))?;
        Ok(())
    }

    pub async fn wait_for_observed_requests(&self, expected: usize) -> TestResult<()> {
        timeout(HTTP_RESPONSE_HEADERS_TIMEOUT, async {
            loop {
                let notified = self.state.observed_seen.notified();
                if self
                    .state
                    .observed
                    .lock()
                    .expect("LLM proxy observed mutex poisoned")
                    .len()
                    >= expected
                {
                    return;
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| IoError::new(ErrorKind::TimedOut, "recording request barrier timed out"))?;
        Ok(())
    }

    pub async fn wait_for_submitted_exchanges(&self, expected: usize) -> TestResult<()> {
        match &self.state.mode {
            LlmHttpProxyMode::Record { sink, .. } => sink.wait_for_submitted(expected).await,
            LlmHttpProxyMode::Replay { .. } => {
                Err(IoError::other("replay proxy has no recording submit barrier").into())
            }
        }
    }

    pub async fn wait_for_completed_exchanges(&self, expected: usize) -> TestResult<()> {
        match &self.state.mode {
            LlmHttpProxyMode::Record { sink, .. } => sink.wait_for_exchanges(expected).await,
            LlmHttpProxyMode::Replay { .. } => {
                timeout(HTTP_RESPONSE_HEADERS_TIMEOUT, async {
                    loop {
                        let notified = self.state.replay_completion_seen.notified();
                        if *self
                            .state
                            .replay_completed
                            .lock()
                            .expect("LLM replay completion mutex poisoned")
                            >= expected
                        {
                            return;
                        }
                        notified.await;
                    }
                })
                .await
                .map_err(|_| {
                    IoError::new(ErrorKind::TimedOut, "replay exchange barrier timed out")
                })?;
                Ok(())
            }
        }
    }

    pub fn replay_exhausted(&self) -> bool {
        match &self.state.mode {
            LlmHttpProxyMode::Replay { recording, .. } => {
                *self
                    .state
                    .next_replay
                    .lock()
                    .expect("LLM proxy replay mutex poisoned")
                    == recording.request_count()
                    && *self
                        .state
                        .replay_completed
                        .lock()
                        .expect("LLM replay completion mutex poisoned")
                        == recording.request_count()
                    && self
                        .state
                        .replay_error
                        .lock()
                        .expect("LLM replay error mutex poisoned")
                        .is_none()
            }
            LlmHttpProxyMode::Record { .. } => true,
        }
    }

    pub async fn stop(&mut self) -> TestResult<()> {
        self.server.stop().await
    }
}

impl Drop for LlmHttpProxy {
    fn drop(&mut self) {
        self.server.shutdown.take();
    }
}

async fn llm_http_proxy_request(
    State(state): State<std::sync::Arc<LlmHttpProxyState>>,
    request: Request,
) -> AxumResponse {
    let mode = state.mode.clone();
    match mode {
        LlmHttpProxyMode::Record {
            upstream_base_url, ..
        } => record_llm_http_request(state, request, upstream_base_url).await,
        LlmHttpProxyMode::Replay {
            recording,
            captured_timing,
            expected_authorization,
            terminal_hold,
        } => {
            replay_llm_http_request(
                state,
                request,
                recording,
                captured_timing,
                expected_authorization,
                terminal_hold,
            )
            .await
        }
    }
}

struct LlmHttpStreamCapture {
    sink: std::sync::Arc<RecordingSink>,
    sequence: u64,
    logical_round: u64,
    wire_attempt: u64,
    request: LlmHttpRecordingRequest,
    status: Option<u16>,
    content_type: Option<String>,
    response_headers: Vec<LlmHttpHeader>,
    chunks: Vec<LlmHttpRecordingChunk>,
    response_bytes: usize,
    stream_error: bool,
    bound_exceeded: bool,
    finished: bool,
}

impl LlmHttpStreamCapture {
    fn persist(&mut self, outcome: LlmHttpResponseOutcome) -> TestResult<()> {
        self.finished = true;
        self.sink.submit(LlmHttpRecordingExchange {
            sequence: self.sequence,
            logical_round: self.logical_round,
            wire_attempt: self.wire_attempt,
            request: self.request.clone(),
            response: LlmHttpRecordingResponse {
                status: self.status,
                content_type: self.content_type.clone(),
                semantic_headers: self.response_headers.clone(),
                chunks: self.chunks.clone(),
                outcome,
            },
        })
    }

    fn finish(mut self, outcome: LlmHttpResponseOutcome) -> TestResult<()> {
        self.persist(outcome)
    }
}

impl Drop for LlmHttpStreamCapture {
    fn drop(&mut self) {
        if !self.finished {
            let outcome = LlmHttpResponseOutcome::ClientDisconnect;
            let _ = self.persist(outcome);
        }
    }
}

fn semantic_headers(headers: &HeaderMap, request: bool) -> Vec<LlmHttpHeader> {
    let names = if request {
        ["accept", "content-type"].as_slice()
    } else {
        ["content-type"].as_slice()
    };
    names
        .iter()
        .filter_map(|name| {
            headers.get(*name).and_then(|value| {
                value.to_str().ok().map(|value| LlmHttpHeader {
                    name: (*name).to_owned(),
                    value: value.to_owned(),
                })
            })
        })
        .collect()
}

fn response_content_type(
    headers: &HeaderMap,
) -> (Option<String>, Vec<LlmHttpHeader>, Option<String>) {
    let content_type = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let retry_after = headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut semantic_headers = Vec::new();
    if let Some(value) = &content_type {
        semantic_headers.push(LlmHttpHeader {
            name: "content-type".to_owned(),
            value: value.clone(),
        });
    }
    if let Some(value) = &retry_after {
        semantic_headers.push(LlmHttpHeader {
            name: "retry-after".to_owned(),
            value: value.clone(),
        });
    }
    (content_type, semantic_headers, retry_after)
}

fn make_request(
    method: &str,
    path: &str,
    headers: &HeaderMap,
    raw_body: &[u8],
    canonical_json: Option<String>,
) -> LlmHttpRecordingRequest {
    LlmHttpRecordingRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        semantic_headers: semantic_headers(headers, true),
        raw_body_hex: hex_encode(raw_body),
        canonical_json_sha256: canonical_json
            .as_ref()
            .map(|canonical| sha256_hex(canonical.as_bytes())),
        canonical_json,
        raw_body_sha256: sha256_hex(raw_body),
    }
}

async fn record_llm_http_request(
    state: std::sync::Arc<LlmHttpProxyState>,
    request: Request,
    upstream_base_url: String,
) -> AxumResponse {
    let sink = match &state.mode {
        LlmHttpProxyMode::Record { sink, .. } => sink.clone(),
        LlmHttpProxyMode::Replay { .. } => unreachable!("replay request entered record path"),
    };
    let sequence = sink.allocate_sequence();
    let method_name = request.method().as_str().to_owned();
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| request.uri().path())
        .to_owned();
    let headers = request.headers().clone();
    if !path_is_secret_safe(&path) {
        sink.fail_flush("provider request path contained a credential-bearing query");
        return llm_proxy_error(AxumStatusCode::SERVICE_UNAVAILABLE);
    }
    if sink.requires_authorization && headers.get(header::AUTHORIZATION).is_none() {
        sink.fail_flush("provider request omitted the required authorization slot");
        return llm_proxy_error(AxumStatusCode::SERVICE_UNAVAILABLE);
    }
    let body = match to_bytes(request.into_body(), 4 * 1024 * 1024).await {
        Ok(body) => body,
        Err(_) => {
            sink.record_ingress(sequence, &method_name, &path, &[]);
            sink.fail_flush("provider request body could not be captured exactly");
            return llm_proxy_error(AxumStatusCode::PAYLOAD_TOO_LARGE);
        }
    };
    let canonical_body = canonical_json(&body).ok();
    let request_record = make_request(&method_name, &path, &headers, &body, canonical_body.clone());
    state
        .observed
        .lock()
        .expect("LLM proxy observed mutex poisoned")
        .push(LlmHttpObservedRequest {
            method: method_name.clone(),
            path: path.clone(),
            semantic_headers: request_record.semantic_headers.clone(),
            raw_body_hex: request_record.raw_body_hex.clone(),
            canonical_json: canonical_body.clone(),
        });
    state
        .observed_at
        .lock()
        .expect("LLM proxy observation-time mutex poisoned")
        .push(Instant::now());
    state.observed_seen.notify_waiters();

    sink.record_ingress(sequence, &method_name, &path, &body);

    // The ingress fact is the durable proof that this exchange can be
    // replayed.  Never send a provider request after that write failed.  The
    // observation above is retained solely as a barrier proving the request
    // reached the recorder, even when the durable write deliberately fails.
    sink.begin_sequence(sequence);
    if sink.flush_error().is_some() {
        return llm_proxy_error(AxumStatusCode::SERVICE_UNAVAILABLE);
    }

    if canonical_body.is_none() {
        let submit_result = sink.submit(LlmHttpRecordingExchange {
            sequence,
            logical_round: 0,
            wire_attempt: 0,
            request: request_record,
            response: LlmHttpRecordingResponse {
                status: Some(AxumStatusCode::BAD_REQUEST.as_u16()),
                content_type: None,
                semantic_headers: Vec::new(),
                chunks: Vec::new(),
                outcome: LlmHttpResponseOutcome::Complete { done_seen: false },
            },
        });
        if submit_result.is_err() {
            return llm_proxy_error(AxumStatusCode::SERVICE_UNAVAILABLE);
        }
        return llm_proxy_error(AxumStatusCode::BAD_REQUEST);
    }

    let mut capture = LlmHttpStreamCapture {
        sink,
        sequence,
        logical_round: 0,
        wire_attempt: 0,
        request: request_record,
        status: None,
        content_type: None,
        response_headers: Vec::new(),
        chunks: Vec::new(),
        response_bytes: 0,
        stream_error: false,
        bound_exceeded: false,
        finished: false,
    };

    let upstream_url = format!("{}{}", upstream_base_url.trim_end_matches('/'), path);
    let method = match reqwest::Method::from_bytes(method_name.as_bytes()) {
        Ok(method) => method,
        Err(_) => {
            if capture
                .finish(LlmHttpResponseOutcome::TransportError)
                .is_err()
            {
                return llm_proxy_error(AxumStatusCode::SERVICE_UNAVAILABLE);
            }
            return llm_proxy_error(AxumStatusCode::BAD_REQUEST);
        }
    };
    let mut outbound = state.client.request(method, upstream_url).body(body);
    if let Some(value) = headers.get(header::AUTHORIZATION) {
        outbound = outbound.header(reqwest::header::AUTHORIZATION, value.clone());
    }
    if let Some(value) = headers.get(header::CONTENT_TYPE) {
        outbound = outbound.header(reqwest::header::CONTENT_TYPE, value.clone());
    }
    if let Some(value) = headers.get(header::ACCEPT) {
        outbound = outbound.header(reqwest::header::ACCEPT, value.clone());
    }
    let response = match timeout(LLM_UPSTREAM_HEADERS_TIMEOUT, outbound.send()).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) | Err(_) => {
            if capture
                .finish(LlmHttpResponseOutcome::TransportError)
                .is_err()
            {
                return llm_proxy_error(AxumStatusCode::SERVICE_UNAVAILABLE);
            }
            return llm_proxy_error(AxumStatusCode::BAD_GATEWAY);
        }
    };
    let (content_type, response_headers, retry_after) = response_content_type(response.headers());
    let status = response.status().as_u16();
    let response_started = Instant::now();
    let mut upstream_stream = response.bytes_stream();
    capture.status = Some(status);
    capture.content_type = content_type.clone();
    capture.response_headers = response_headers;
    let stream = stream! {
        let mut capture = capture;
        let mut pending_sse_tail = Vec::new();
        let mut deferred_terminal_chunks = Vec::new();
        let mut terminal_deferred = false;
        while let Some(chunk) = upstream_stream.next().await {
            match chunk {
                Ok(bytes) => {
                    if capture.chunks.len() >= MAX_LLM_RESPONSE_CHUNKS
                        || capture
                            .response_bytes
                            .saturating_add(bytes.len())
                            > MAX_LLM_RESPONSE_BYTES
                    {
                        capture.bound_exceeded = true;
                        capture.sink.fail_flush(&format!(
                            "recording response capture bound exceeded ({} chunks/{} bytes)",
                            MAX_LLM_RESPONSE_CHUNKS, MAX_LLM_RESPONSE_BYTES
                        ));
                        break;
                    }
                    capture.response_bytes = capture.response_bytes.saturating_add(bytes.len());
                    let kind = if is_event_stream_content_type(capture.content_type.as_deref()) {
                        LlmHttpChunkKind::Sse
                    } else {
                        LlmHttpChunkKind::Body
                    };
                    capture.chunks.push(LlmHttpRecordingChunk {
                        kind,
                        sequence: capture.chunks.len() as u64,
                        at_us: response_started
                            .elapsed()
                            .as_micros()
                            .try_into()
                            .unwrap_or(u64::MAX),
                        bytes_hex: hex_encode(&bytes),
                    });
                    capture.sink.note_chunk();
                    if is_event_stream_content_type(capture.content_type.as_deref()) {
                        // Keep a short rolling suffix so a transport split in
                        // `data: [DONE]` cannot expose the terminal marker
                        // before the complete exchange is durably sealed.
                        if terminal_deferred {
                            deferred_terminal_chunks.push(bytes);
                        } else {
                            let mut candidate = Vec::with_capacity(
                                pending_sse_tail.len().saturating_add(bytes.len()),
                            );
                            candidate.extend_from_slice(&pending_sse_tail);
                            candidate.extend_from_slice(&bytes);
                            pending_sse_tail.clear();
                            let marker = b"data: [DONE]";
                            if let Some(start) = candidate
                                .windows(marker.len())
                                .position(|window| window == marker)
                            {
                                if start > 0 {
                                    yield Ok::<Bytes, std::io::Error>(Bytes::copy_from_slice(
                                        &candidate[..start],
                                    ));
                                }
                                terminal_deferred = true;
                                deferred_terminal_chunks
                                    .push(Bytes::copy_from_slice(&candidate[start..]));
                            } else {
                                let suffix_len = marker.len().saturating_sub(1);
                                let split = candidate.len().saturating_sub(suffix_len);
                                if split > 0 {
                                    yield Ok::<Bytes, std::io::Error>(Bytes::copy_from_slice(
                                        &candidate[..split],
                                    ));
                                }
                                pending_sse_tail.extend_from_slice(&candidate[split..]);
                            }
                        }
                    } else {
                        yield Ok::<Bytes, std::io::Error>(bytes);
                    }
                }
                Err(_) => {
                    capture.stream_error = true;
                    break;
                }
            }
        }
        let stream_failed = capture.stream_error;
        let bound_exceeded = capture.bound_exceeded;
        let done_seen = chunks_contain_done(&capture.chunks);
        if let Err(error) = capture.finish(if bound_exceeded {
            LlmHttpResponseOutcome::CaptureBoundExceeded
        } else if stream_failed {
            LlmHttpResponseOutcome::StreamError
        } else if done_seen {
            LlmHttpResponseOutcome::Complete { done_seen: true }
        } else {
            LlmHttpResponseOutcome::Complete { done_seen: false }
        }) {
            yield Err(std::io::Error::other(error.to_string()));
            return;
        }
        if !bound_exceeded && !stream_failed {
            if !pending_sse_tail.is_empty() {
                yield Ok::<Bytes, std::io::Error>(Bytes::from(std::mem::take(
                    &mut pending_sse_tail,
                )));
            }
            for bytes in deferred_terminal_chunks {
                yield Ok::<Bytes, std::io::Error>(bytes);
            }
        }
        if bound_exceeded {
            yield Err(std::io::Error::other("recording response capture bound exceeded"));
        } else if stream_failed {
            yield Err(std::io::Error::other("upstream stream failed"));
        }
    };
    let mut builder = AxumResponse::builder()
        .status(AxumStatusCode::from_u16(status).unwrap_or(AxumStatusCode::BAD_GATEWAY));
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(retry_after) = retry_after {
        builder = builder.header("retry-after", retry_after);
    }
    builder
        .body(Body::from_stream(stream))
        .expect("LLM recording proxy response builds")
}

async fn replay_llm_http_request(
    state: std::sync::Arc<LlmHttpProxyState>,
    request: Request,
    recording: LlmHttpReplayRecording,
    captured_timing: bool,
    expected_authorization: Option<String>,
    terminal_hold: Option<std::sync::Arc<Notify>>,
) -> AxumResponse {
    let method = request.method().as_str().to_owned();
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| request.uri().path())
        .to_owned();
    if !path_is_secret_safe(&path) {
        record_replay_error(
            &state,
            "provider request path contained a credential-bearing query",
        );
        return llm_proxy_error(AxumStatusCode::CONFLICT);
    }
    let headers = request.headers().clone();
    let body = match to_bytes(request.into_body(), 4 * 1024 * 1024).await {
        Ok(body) => body,
        Err(_) => return llm_proxy_error(AxumStatusCode::BAD_REQUEST),
    };
    let semantic_headers = semantic_headers(&headers, true);
    if expected_authorization.is_some() || recording.requires_authorization() {
        if expected_authorization.is_none() {
            record_replay_error(&state, "replay requires an explicit authorization binding");
            return llm_proxy_error(AxumStatusCode::CONFLICT);
        }
        let authorization = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty());
        // Authorization values are intentionally not part of the cassette.
        // Replay still proves the provider boundary was authenticated, while
        // rejecting a synthetic slot accidentally sent as a literal value.
        let bound_value_matches = expected_authorization.as_deref().is_none_or(|expected| {
            authorization.is_some_and(|actual| actual == format!("Bearer {expected}"))
        });
        if authorization.is_none()
            || authorization.is_some_and(|value| value.contains("SLOT_"))
            || !bound_value_matches
        {
            record_replay_error(&state, "provider request did not supply authorization slot");
            return llm_proxy_error(AxumStatusCode::CONFLICT);
        }
    }
    let (raw_body_hex, canonical_body) = if recording.retains_observed_bodies() {
        (hex_encode(&body), canonical_json(&body).ok())
    } else {
        (String::new(), None)
    };
    state
        .observed
        .lock()
        .expect("LLM proxy observed mutex poisoned")
        .push(LlmHttpObservedRequest {
            method: method.clone(),
            path: path.clone(),
            semantic_headers: semantic_headers.clone(),
            raw_body_hex,
            canonical_json: canonical_body,
        });
    state
        .observed_at
        .lock()
        .expect("LLM proxy observation-time mutex poisoned")
        .push(Instant::now());
    state.observed_seen.notify_waiters();
    let expected_index = {
        let mut next = state
            .next_replay
            .lock()
            .expect("LLM proxy replay mutex poisoned");
        if *next >= recording.request_count() {
            record_replay_error(&state, "unexpected provider request after cassette end");
            return llm_proxy_error(AxumStatusCode::CONFLICT);
        }
        if !recording.request_matches(*next, &method, &path, &semantic_headers, &body) {
            record_replay_error(&state, "provider request did not match cassette");
            return llm_proxy_error(AxumStatusCode::CONFLICT);
        }
        let expected_index = *next;
        *next += 1;
        expected_index
    };
    let outcome = recording
        .response_outcome(expected_index)
        .expect("matched replay request has a response");
    if matches!(outcome, LlmHttpReplayOutcome::TransportError) {
        let state_for_stream = state.clone();
        if terminal_hold.is_some() {
            state_for_stream
                .replay_terminal_waiting
                .fetch_add(1, Ordering::SeqCst);
            state_for_stream.replay_terminal_seen.notify_waiters();
        }
        let stream = stream! {
            if let Some(hold) = terminal_hold {
                hold.notified().await;
            }
            // Headers alone do not consume a transport failure.  Count the
            // exchange only when the terminal body error is ready to be
            // delivered; a client abort while the hold is active leaves it
            // unconsumed.
            *state_for_stream
                .replay_completed
                .lock()
                .expect("LLM replay completion mutex poisoned") += 1;
            state_for_stream.replay_completion_seen.notify_waiters();
            yield Err::<Bytes, std::io::Error>(std::io::Error::other(
                "LLM recording transport error",
            ));
        };
        return AxumResponse::builder()
            .status(AxumStatusCode::BAD_GATEWAY)
            .body(Body::from_stream(stream))
            .expect("LLM transport-error replay response builds");
    }
    let status = recording
        .response_status(expected_index)
        .unwrap_or(AxumStatusCode::BAD_GATEWAY.as_u16());
    let response_content_type = recording
        .response_content_type(expected_index)
        .map(str::to_owned);
    let retry_after = recording
        .response_headers(expected_index)
        .expect("matched replay request has response headers")
        .iter()
        .find(|header| header.name == "retry-after")
        .map(|header| header.value.clone());
    let state_for_stream = state.clone();
    let recording_for_stream = recording.clone();
    let stream = stream! {
        let started = Instant::now();
        let total_chunks = recording_for_stream
            .response_chunk_count(expected_index)
            .expect("matched replay request has a streaming response");
        let terminal_required = matches!(
            outcome,
            LlmHttpReplayOutcome::StreamError
                | LlmHttpReplayOutcome::ClientDisconnect
                | LlmHttpReplayOutcome::CaptureBoundExceeded
        ) && !matches!(
            outcome,
            LlmHttpReplayOutcome::ClientDisconnect
                if recording_for_stream.response_done_seen(expected_index)
        );
        let mut completion = ReplayCompletion::new(state_for_stream.clone());
        if total_chunks == 0 {
            completion.all_chunks_emitted = true;
        }
        for index in 0..total_chunks {
            let (at_us, bytes) = match recording_for_stream
                .response_chunk(expected_index, index)
            {
                Ok(Some(chunk)) => chunk,
                _ => {
                    yield Err(std::io::Error::other("LLM recording chunk is invalid"));
                    return;
                }
            };
            if captured_timing {
                let target = Duration::from_micros(at_us);
                let elapsed = started.elapsed();
                if target > elapsed {
                    sleep(target - elapsed).await;
                }
            }
            state_for_stream
                .replay_chunk_count
                .fetch_add(1, Ordering::SeqCst);
            state_for_stream.replay_chunk_seen.notify_waiters();
            yield Ok::<Bytes, std::io::Error>(bytes);
            completion.all_chunks_emitted = index + 1 == total_chunks;
        }
        if let Some(hold) = terminal_hold {
            state_for_stream
                .replay_terminal_waiting
                .fetch_add(1, Ordering::SeqCst);
            state_for_stream.replay_terminal_seen.notify_waiters();
            hold.notified().await;
        }
        if terminal_required {
            // Mark the terminal error before yielding it. If the client aborts
            // at the final chunk, the stream is dropped before this point and
            // ReplayCompletion must remain uncompleted.
            completion.terminal_error_emitted = true;
            let message = if matches!(outcome, LlmHttpReplayOutcome::CaptureBoundExceeded) {
                "LLM recording response capture bound exceeded"
            } else {
                "LLM recording response disconnected"
            };
            yield Err(std::io::Error::other(message));
            completion.complete();
        } else {
            // A legacy/recorded disconnect after DONE maps to the model's
            // complete-after-DONE projection while retaining raw termination
            // in the cassette.
            completion.complete();
        }
    };
    let mut builder = AxumResponse::builder()
        .status(AxumStatusCode::from_u16(status).unwrap_or(AxumStatusCode::BAD_GATEWAY));
    if let Some(content_type) = response_content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(retry_after) = retry_after {
        builder = builder.header("retry-after", retry_after);
    }
    builder
        .body(Body::from_stream(stream))
        .expect("LLM replay proxy response builds")
}

fn record_replay_error(state: &LlmHttpProxyState, message: &str) {
    let mut error = state
        .replay_error
        .lock()
        .expect("LLM replay error mutex poisoned");
    if error.is_none() {
        *error = Some(message.to_owned());
    }
}

struct ReplayCompletion {
    state: std::sync::Arc<LlmHttpProxyState>,
    all_chunks_emitted: bool,
    terminal_error_emitted: bool,
    completed: bool,
}

impl ReplayCompletion {
    fn new(state: std::sync::Arc<LlmHttpProxyState>) -> Self {
        Self {
            state,
            all_chunks_emitted: false,
            terminal_error_emitted: false,
            completed: false,
        }
    }

    fn complete(&mut self) {
        if !self.completed {
            *self
                .state
                .replay_completed
                .lock()
                .expect("LLM replay completion mutex poisoned") += 1;
            self.state.replay_completion_seen.notify_waiters();
            self.completed = true;
        }
    }
}

impl Drop for ReplayCompletion {
    fn drop(&mut self) {
        // A normal Complete response is counted only after the generator
        // reaches its terminal branch.  Dropping after the last yielded
        // chunk but before that branch is an aborted transport, not an
        // exhausted replay.  A terminal error has already been emitted when
        // `terminal_error_emitted` is set, so it remains safe to account for
        // that case if the client drops immediately after receiving it.
        if self.all_chunks_emitted && self.terminal_error_emitted {
            self.complete();
        }
    }
}

fn llm_proxy_error(status: AxumStatusCode) -> AxumResponse {
    AxumResponse::builder()
        .status(status)
        .body(Body::from("provider recording proxy error"))
        .expect("LLM proxy error response builds")
}

#[derive(Clone)]
pub enum ModelScript {
    Hold {
        release: std::sync::Arc<Notify>,
        then: Box<ModelScript>,
    },
    HoldEntered {
        hold: ModelHold,
        then: Box<ModelScript>,
    },
    StreamHold {
        hold: ModelHold,
    },
    StreamDoneHold {
        hold: ModelHold,
    },
    StreamFailureHold {
        hold: ModelHold,
    },
    LargeStream {
        bytes: usize,
    },
    CleanEof {
        text: String,
    },
    Final {
        text: String,
    },
    FinalWithUsage {
        text: String,
        input_tokens: u32,
        output_tokens: u32,
    },
    ToolCall {
        tool_call_id: String,
        tool_name: String,
        arguments: String,
    },
    ToolCallWithUsage {
        tool_call_id: String,
        tool_name: String,
        arguments: String,
        input_tokens: u32,
        output_tokens: u32,
    },
    ToolCalls(Vec<ToolCallScript>),
    Status(u16),
    PartialFailure {
        text: String,
        tool_call_id: String,
        tool_name: String,
        arguments: String,
    },
}

#[derive(Clone)]
pub struct ModelHold {
    entered: watch::Sender<bool>,
    released: watch::Sender<bool>,
}

impl ModelHold {
    pub fn new() -> Self {
        let (entered, _) = watch::channel(false);
        let (released, _) = watch::channel(false);
        Self { entered, released }
    }

    pub async fn wait_entered(&self) -> TestResult<()> {
        let mut entered = self.entered.subscribe();
        timeout(HTTP_RESPONSE_HEADERS_TIMEOUT, async {
            while !*entered.borrow() {
                entered
                    .changed()
                    .await
                    .map_err(|_| IoError::other("model fixture hold-entered latch closed"))?;
            }
            Ok::<(), IoError>(())
        })
        .await
        .map_err(|_| {
            IoError::new(
                ErrorKind::TimedOut,
                "model fixture HoldEntered barrier timed out",
            )
        })??;
        Ok(())
    }

    pub fn release(&self) {
        self.released.send_replace(true);
    }
}

#[derive(Clone)]
pub struct ToolCallScript {
    pub tool_call_id: String,
    pub tool_name: String,
    pub arguments: String,
}

impl ToolCallScript {
    pub fn new(
        tool_call_id: impl Into<String>,
        tool_name: impl Into<String>,
        arguments: impl Into<String>,
    ) -> Self {
        Self {
            tool_call_id: tool_call_id.into(),
            tool_name: tool_name.into(),
            arguments: arguments.into(),
        }
    }
}

impl ModelScript {
    pub fn hold(release: std::sync::Arc<Notify>, then: Self) -> Self {
        Self::Hold {
            release,
            then: Box::new(then),
        }
    }

    pub fn hold_entered(hold: ModelHold, then: Self) -> Self {
        Self::HoldEntered {
            hold,
            then: Box::new(then),
        }
    }

    pub fn stream_hold(hold: ModelHold) -> Self {
        Self::StreamHold { hold }
    }

    pub fn stream_done_hold(hold: ModelHold) -> Self {
        Self::StreamDoneHold { hold }
    }

    pub fn stream_failure_hold(hold: ModelHold) -> Self {
        Self::StreamFailureHold { hold }
    }

    pub fn large_stream(bytes: usize) -> Self {
        Self::LargeStream { bytes }
    }

    pub fn clean_eof(text: impl Into<String>) -> Self {
        Self::CleanEof { text: text.into() }
    }

    pub fn final_text(text: impl Into<String>) -> Self {
        Self::Final { text: text.into() }
    }

    pub fn final_text_with_usage(
        text: impl Into<String>,
        input_tokens: u32,
        output_tokens: u32,
    ) -> Self {
        Self::FinalWithUsage {
            text: text.into(),
            input_tokens,
            output_tokens,
        }
    }

    pub fn tool_call(
        tool_call_id: impl Into<String>,
        tool_name: impl Into<String>,
        arguments: impl Into<String>,
    ) -> Self {
        Self::ToolCall {
            tool_call_id: tool_call_id.into(),
            tool_name: tool_name.into(),
            arguments: arguments.into(),
        }
    }

    pub fn tool_call_with_usage(
        tool_call_id: impl Into<String>,
        tool_name: impl Into<String>,
        arguments: impl Into<String>,
        input_tokens: u32,
        output_tokens: u32,
    ) -> Self {
        Self::ToolCallWithUsage {
            tool_call_id: tool_call_id.into(),
            tool_name: tool_name.into(),
            arguments: arguments.into(),
            input_tokens,
            output_tokens,
        }
    }

    pub fn tool_calls(calls: Vec<ToolCallScript>) -> Self {
        Self::ToolCalls(calls)
    }

    pub fn status(status: u16) -> Self {
        Self::Status(status)
    }

    pub fn partial_failure(
        text: impl Into<String>,
        tool_call_id: impl Into<String>,
        tool_name: impl Into<String>,
        arguments: impl Into<String>,
    ) -> Self {
        Self::PartialFailure {
            text: text.into(),
            tool_call_id: tool_call_id.into(),
            tool_name: tool_name.into(),
            arguments: arguments.into(),
        }
    }
}

struct ModelState {
    scripts: std::sync::Mutex<Vec<ModelScript>>,
    handoff_document: Option<String>,
    handoff_requests: AtomicU64,
    hold_handoff_requests: std::sync::Mutex<Vec<ModelHold>>,
    hold_after_handoff: std::sync::Mutex<Option<ModelHold>>,
    requests: std::sync::Mutex<Vec<Value>>,
    headers: std::sync::Mutex<Vec<Value>>,
    request_phase: std::sync::Mutex<ModelRequestPhase>,
    request_seen: Notify,
}

#[derive(Default)]
struct ModelRequestPhase {
    sealed: bool,
    violations: usize,
}

pub struct ModelFixture {
    server: HttpFixture,
    state: std::sync::Arc<ModelState>,
}

impl ModelFixture {
    pub async fn start(scripts: Vec<ModelScript>) -> TestResult<Self> {
        Self::start_inner(scripts, None, Vec::new(), None).await
    }

    pub async fn start_with_handoff(
        scripts: Vec<ModelScript>,
        document: impl Into<String>,
    ) -> TestResult<Self> {
        Self::start_inner(scripts, Some(document.into()), Vec::new(), None).await
    }

    pub async fn start_with_handoff_hold(
        scripts: Vec<ModelScript>,
        document: impl Into<String>,
        hold_after_handoff: ModelHold,
    ) -> TestResult<Self> {
        Self::start_inner(
            scripts,
            Some(document.into()),
            Vec::new(),
            Some(hold_after_handoff),
        )
        .await
    }

    pub async fn start_with_handoff_request_holds(
        scripts: Vec<ModelScript>,
        document: impl Into<String>,
        hold_handoff_requests: Vec<ModelHold>,
    ) -> TestResult<Self> {
        Self::start_inner(scripts, Some(document.into()), hold_handoff_requests, None).await
    }

    async fn start_inner(
        scripts: Vec<ModelScript>,
        handoff_document: Option<String>,
        hold_handoff_requests: Vec<ModelHold>,
        hold_after_handoff: Option<ModelHold>,
    ) -> TestResult<Self> {
        let state = std::sync::Arc::new(ModelState {
            scripts: std::sync::Mutex::new(scripts),
            handoff_document,
            handoff_requests: AtomicU64::new(0),
            hold_handoff_requests: std::sync::Mutex::new(hold_handoff_requests),
            hold_after_handoff: std::sync::Mutex::new(hold_after_handoff),
            requests: std::sync::Mutex::new(Vec::new()),
            headers: std::sync::Mutex::new(Vec::new()),
            request_phase: std::sync::Mutex::new(ModelRequestPhase::default()),
            request_seen: Notify::new(),
        });
        let router = Router::new()
            .route("/v1/chat/completions", post(model_request))
            .with_state(state.clone());
        let server = HttpFixture::start(router).await?;
        Ok(Self { server, state })
    }

    pub fn provider_url(&self) -> String {
        self.server.url("/v1")
    }

    pub fn origin(&self) -> String {
        self.server.url("")
    }

    pub fn request_count(&self) -> usize {
        self.state
            .requests
            .lock()
            .expect("model fixture request mutex poisoned")
            .len()
    }

    pub fn handoff_request_count(&self) -> u64 {
        self.state.handoff_requests.load(Ordering::SeqCst)
    }

    pub fn conversation_request_count(&self) -> usize {
        self.request_count()
            .saturating_sub(self.handoff_request_count() as usize)
    }

    pub fn request(&self, index: usize) -> Option<Value> {
        self.state
            .requests
            .lock()
            .expect("model fixture request mutex poisoned")
            .get(index)
            .cloned()
    }

    pub fn request_headers(&self, index: usize) -> Option<Value> {
        self.state
            .headers
            .lock()
            .expect("model fixture header mutex poisoned")
            .get(index)
            .cloned()
    }

    pub async fn wait_for_requests(&self, expected: usize) -> TestResult<()> {
        timeout(HTTP_RESPONSE_HEADERS_TIMEOUT, async {
            loop {
                if self.request_count() >= expected {
                    return;
                }
                self.state.request_seen.notified().await;
            }
        })
        .await
        .map_err(|_| {
            IoError::new(
                ErrorKind::TimedOut,
                "model fixture request barrier timed out",
            )
        })?;
        Ok(())
    }

    pub fn seal_request_phase(&self) -> usize {
        // The fixture always acquires requests before request_phase. No path
        // may take the inverse nested order.
        let request_count = self
            .state
            .requests
            .lock()
            .expect("model fixture request mutex poisoned")
            .len();
        let mut phase = self
            .state
            .request_phase
            .lock()
            .expect("model fixture request phase mutex poisoned");
        phase.sealed = true;
        request_count
    }

    pub fn open_request_phase(&self) {
        self.state
            .request_phase
            .lock()
            .expect("model fixture request phase mutex poisoned")
            .sealed = false;
    }

    pub fn request_phase_violations(&self) -> usize {
        self.state
            .request_phase
            .lock()
            .expect("model fixture request phase mutex poisoned")
            .violations
    }

    pub async fn stop(&mut self) -> TestResult<()> {
        self.server.stop().await
    }
}

impl Drop for ModelFixture {
    fn drop(&mut self) {
        if let Some(task) = self.server.task.take() {
            task.abort();
        }
        self.server.shutdown.take();
    }
}

async fn model_request(
    State(state): State<std::sync::Arc<ModelState>>,
    headers: HeaderMap,
    body: Bytes,
) -> AxumResponse {
    let request = serde_json::from_slice::<Value>(&body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()));
    let is_handoff = value_contains_string(
        &request,
        "Write a standalone handoff document for a fresh agent context",
    );
    {
        // Keep the requests -> phase lock order and end both guards before
        // this async handler reaches its await point.
        let mut requests = state
            .requests
            .lock()
            .expect("model fixture request mutex poisoned");
        let mut phase = state
            .request_phase
            .lock()
            .expect("model fixture request phase mutex poisoned");
        requests.push(request);
        if phase.sealed {
            phase.violations += 1;
        }
    }
    state
        .headers
        .lock()
        .expect("model fixture header mutex poisoned")
        .push(Value::Object(
            headers
                .iter()
                .filter_map(|(name, value)| {
                    Some((
                        name.as_str().to_owned(),
                        Value::String(value.to_str().ok()?.to_owned()),
                    ))
                })
                .collect(),
        ));
    state.request_seen.notify_waiters();
    if is_handoff {
        if let Some(document) = &state.handoff_document {
            state.handoff_requests.fetch_add(1, Ordering::SeqCst);
            let hold = {
                let mut holds = state
                    .hold_handoff_requests
                    .lock()
                    .expect("model fixture handoff hold mutex poisoned");
                (!holds.is_empty()).then(|| holds.remove(0))
            };
            let encoded_document = serde_json::to_string(&json!({
                "schema": "zode.context-handoff-document.v1",
                "document": document,
            }))
            .expect("fixture handoff document encodes");
            let script = match hold {
                Some(hold) => {
                    ModelScript::hold_entered(hold, ModelScript::final_text(encoded_document))
                }
                None => ModelScript::final_text(encoded_document),
            };
            return execute_model_script(script).await;
        }
    }
    if state.handoff_requests.load(Ordering::SeqCst) > 0 {
        let hold = {
            state
                .hold_after_handoff
                .lock()
                .expect("model fixture post-handoff hold mutex poisoned")
                .take()
        };
        if let Some(hold) = hold {
            return execute_model_script(ModelScript::stream_hold(hold)).await;
        }
    }
    let script = {
        let mut scripts = state
            .scripts
            .lock()
            .expect("model fixture script mutex poisoned");
        if scripts.is_empty() {
            ModelScript::final_text("fixture final")
        } else {
            scripts.remove(0)
        }
    };
    execute_model_script(script).await
}

fn value_contains_string(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(text) => text.contains(needle),
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_string(value, needle)),
        Value::Object(values) => values
            .values()
            .any(|value| value_contains_string(value, needle)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

async fn execute_model_script(mut script: ModelScript) -> AxumResponse {
    loop {
        match script {
            ModelScript::Hold { release, then } => {
                release.notified().await;
                script = *then;
            }
            ModelScript::HoldEntered { hold, then } => {
                hold.entered.send_replace(true);
                let mut released = hold.released.subscribe();
                while !*released.borrow() {
                    if released.changed().await.is_err() {
                        return AxumResponse::builder()
                            .status(AxumStatusCode::SERVICE_UNAVAILABLE)
                            .body(Body::from("fixture hold was released unexpectedly"))
                            .expect("model fixture hold response builds");
                    }
                }
                script = *then;
            }
            ModelScript::StreamHold { hold } => return model_stream_hold(hold),
            ModelScript::StreamDoneHold { hold } => return model_stream_done_hold(hold),
            ModelScript::StreamFailureHold { hold } => return model_stream_failure_hold(hold),
            ModelScript::LargeStream { bytes } => return model_large_stream(bytes),
            ModelScript::CleanEof { text } => {
                return model_stream(vec![sse_chunk(json!({
                    "choices": [{
                        "delta": {"reasoning_content": text},
                        "finish_reason": null
                    }]
                }))]);
            }
            ModelScript::Final { text } => return model_stream(final_chunks(&text)),
            ModelScript::FinalWithUsage {
                text,
                input_tokens,
                output_tokens,
            } => {
                return model_stream(final_chunks_with_usage(&text, input_tokens, output_tokens));
            }
            ModelScript::ToolCall {
                tool_call_id,
                tool_name,
                arguments,
            } => return model_stream(tool_chunks(&tool_call_id, &tool_name, &arguments)),
            ModelScript::ToolCallWithUsage {
                tool_call_id,
                tool_name,
                arguments,
                input_tokens,
                output_tokens,
            } => {
                return model_stream(tool_chunks_with_usage(
                    &tool_call_id,
                    &tool_name,
                    &arguments,
                    input_tokens,
                    output_tokens,
                ));
            }
            ModelScript::ToolCalls(calls) => return model_stream(tool_batch_chunks(&calls)),
            ModelScript::Status(status) => {
                let status =
                    AxumStatusCode::from_u16(status).unwrap_or(AxumStatusCode::SERVICE_UNAVAILABLE);
                return AxumResponse::builder()
                    .status(status)
                    .body(Body::from("fixture status"))
                    .expect("model fixture response builds");
            }
            ModelScript::PartialFailure {
                text,
                tool_call_id,
                tool_name,
                arguments,
            } => {
                return model_stream_with_failure(partial_chunks(
                    &text,
                    &tool_call_id,
                    &tool_name,
                    &arguments,
                ));
            }
        }
    }
}

fn model_stream(chunks: Vec<bytes::Bytes>) -> AxumResponse {
    let body = stream! {
        for chunk in chunks {
            yield Ok::<bytes::Bytes, std::io::Error>(chunk);
        }
    };
    AxumResponse::builder()
        .status(AxumStatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(body))
        .expect("model fixture stream response builds")
}

fn model_large_stream(bytes: usize) -> AxumResponse {
    const CHUNK_BYTES: usize = 1024;
    let mut remaining = bytes;
    let mut chunks = Vec::new();
    while remaining > 0 {
        let length = remaining.min(CHUNK_BYTES);
        let mut frame = vec![b'x'; length];
        if length >= 3 {
            frame[0] = b':';
            frame[length - 2] = b'\n';
            frame[length - 1] = b'\n';
        }
        chunks.push(bytes::Bytes::from(frame));
        remaining -= length;
    }
    model_stream(chunks)
}

fn model_stream_with_failure(chunks: Vec<bytes::Bytes>) -> AxumResponse {
    let body = stream! {
        for chunk in chunks {
            yield Ok::<bytes::Bytes, std::io::Error>(chunk);
        }
        yield Err(std::io::Error::other("fixture stream interrupted"));
    };
    AxumResponse::builder()
        .status(AxumStatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(body))
        .expect("model fixture failure response builds")
}

fn model_stream_hold(hold: ModelHold) -> AxumResponse {
    let body = stream! {
        yield Ok::<bytes::Bytes, std::io::Error>(sse_chunk(json!({
            "choices": [{"delta": {"content": "partial before disconnect"}, "finish_reason": null}]
        })));
        hold.entered.send_replace(true);
        let mut released = hold.released.subscribe();
        while !*released.borrow() {
            if released.changed().await.is_err() {
                return;
            }
        }
        yield Ok::<bytes::Bytes, std::io::Error>(sse_chunk(json!({
            "choices": [{"delta": {}, "finish_reason": "stop"}]
        })));
        yield Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::from_static(b"data: [DONE]\n\n"));
    };
    AxumResponse::builder()
        .status(AxumStatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(body))
        .expect("model fixture held stream response builds")
}

fn model_stream_done_hold(hold: ModelHold) -> AxumResponse {
    let body = stream! {
        for chunk in final_chunks("done before disconnect") {
            yield Ok::<bytes::Bytes, std::io::Error>(chunk);
        }
        hold.entered.send_replace(true);
        let mut released = hold.released.subscribe();
        while !*released.borrow() {
            if released.changed().await.is_err() {
                return;
            }
        }
    };
    AxumResponse::builder()
        .status(AxumStatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(body))
        .expect("model fixture done-hold stream response builds")
}

fn model_stream_failure_hold(hold: ModelHold) -> AxumResponse {
    let body = stream! {
        yield Ok::<bytes::Bytes, std::io::Error>(sse_chunk(json!({
            "choices": [{"delta": {"content": "partial before stream error"}, "finish_reason": null}]
        })));
        hold.entered.send_replace(true);
        let mut released = hold.released.subscribe();
        while !*released.borrow() {
            if released.changed().await.is_err() {
                return;
            }
        }
        yield Err(std::io::Error::other("fixture stream interrupted after barrier"));
    };
    AxumResponse::builder()
        .status(AxumStatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(body))
        .expect("model fixture held failure stream response builds")
}

fn final_chunks(text: &str) -> Vec<bytes::Bytes> {
    vec![
        sse_chunk(json!({
            "choices": [{"delta": {"content": text}, "finish_reason": null}]
        })),
        sse_chunk(json!({
            "choices": [{"delta": {}, "finish_reason": "stop"}]
        })),
        bytes::Bytes::from_static(b"data: [DONE]\n\n"),
    ]
}

fn final_chunks_with_usage(text: &str, input_tokens: u32, output_tokens: u32) -> Vec<bytes::Bytes> {
    vec![
        sse_chunk(json!({
            "choices": [{"delta": {"content": text}, "finish_reason": null}]
        })),
        sse_chunk(json!({
            "choices": [{"delta": {}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": input_tokens,
                "completion_tokens": output_tokens,
                "total_tokens": input_tokens.saturating_add(output_tokens)
            }
        })),
        bytes::Bytes::from_static(b"data: [DONE]\n\n"),
    ]
}

fn tool_chunks(tool_call_id: &str, tool_name: &str, arguments: &str) -> Vec<bytes::Bytes> {
    tool_batch_chunks(&[ToolCallScript::new(tool_call_id, tool_name, arguments)])
}

fn tool_chunks_with_usage(
    tool_call_id: &str,
    tool_name: &str,
    arguments: &str,
    input_tokens: u32,
    output_tokens: u32,
) -> Vec<bytes::Bytes> {
    let mut chunks = tool_chunks(tool_call_id, tool_name, arguments);
    chunks[1] = sse_chunk(json!({
        "choices": [{"delta": {}, "finish_reason": "tool_calls"}],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": input_tokens.saturating_add(output_tokens)
        }
    }));
    chunks
}

fn tool_batch_chunks(calls: &[ToolCallScript]) -> Vec<bytes::Bytes> {
    let tool_calls = calls
        .iter()
        .enumerate()
        .map(|(index, call)| {
            json!({
                "index": index,
                "id": call.tool_call_id,
                "type": "function",
                "function": {"name": call.tool_name, "arguments": call.arguments}
            })
        })
        .collect::<Vec<_>>();
    vec![
        sse_chunk(json!({
            "choices": [{"delta": {"tool_calls": tool_calls}, "finish_reason": null}]
        })),
        sse_chunk(json!({
            "choices": [{"delta": {}, "finish_reason": "tool_calls"}]
        })),
        bytes::Bytes::from_static(b"data: [DONE]\n\n"),
    ]
}

fn partial_chunks(
    text: &str,
    tool_call_id: &str,
    tool_name: &str,
    arguments: &str,
) -> Vec<bytes::Bytes> {
    vec![
        sse_chunk(json!({
            "choices": [{"delta": {"content": text}, "finish_reason": null}]
        })),
        sse_chunk(json!({
            "choices": [{"delta": {"tool_calls": [{
                "index": 0,
                "id": tool_call_id,
                "type": "function",
                "function": {"name": tool_name, "arguments": arguments}
            }]}, "finish_reason": null}]
        })),
    ]
}

fn sse_chunk(value: Value) -> bytes::Bytes {
    bytes::Bytes::from(format!("data: {}\n\n", value))
}

#[derive(Clone)]
pub enum ToolScript {
    Response(Value),
    Hold {
        release: std::sync::Arc<Notify>,
        response: Value,
    },
    Status(u16),
}

pub struct ToolFixture {
    server: HttpFixture,
    state: std::sync::Arc<ToolState>,
}

struct ToolState {
    scripts: std::sync::Mutex<Vec<ToolScript>>,
    invocations: std::sync::Mutex<Vec<Value>>,
    headers: std::sync::Mutex<Vec<Value>>,
    completed: std::sync::Mutex<usize>,
    invocation_seen: Notify,
    completion_seen: Notify,
}

impl ToolFixture {
    pub async fn start(scripts: Vec<ToolScript>) -> TestResult<Self> {
        let state = std::sync::Arc::new(ToolState {
            scripts: std::sync::Mutex::new(scripts),
            invocations: std::sync::Mutex::new(Vec::new()),
            headers: std::sync::Mutex::new(Vec::new()),
            completed: std::sync::Mutex::new(0),
            invocation_seen: Notify::new(),
            completion_seen: Notify::new(),
        });
        let router = Router::new()
            .route("/invoke", post(tool_request))
            .with_state(state.clone());
        let server = HttpFixture::start(router).await?;
        Ok(Self { server, state })
    }

    pub fn adapter_url(&self) -> String {
        self.server.url("/invoke")
    }

    pub fn invocation_count(&self) -> usize {
        self.state
            .invocations
            .lock()
            .expect("tool fixture invocation mutex poisoned")
            .len()
    }

    pub fn invocations(&self) -> Vec<Value> {
        self.state
            .invocations
            .lock()
            .expect("tool fixture invocation mutex poisoned")
            .clone()
    }

    pub fn invocation_headers(&self) -> Vec<Value> {
        self.state
            .headers
            .lock()
            .expect("tool fixture header mutex poisoned")
            .clone()
    }

    pub fn completed_count(&self) -> usize {
        *self
            .state
            .completed
            .lock()
            .expect("tool fixture completion mutex poisoned")
    }

    pub async fn wait_for_completions(&self, expected: usize) -> TestResult<()> {
        timeout(HTTP_RESPONSE_HEADERS_TIMEOUT, async {
            loop {
                if self.completed_count() >= expected {
                    return;
                }
                self.state.completion_seen.notified().await;
            }
        })
        .await
        .map_err(|_| {
            IoError::new(
                ErrorKind::TimedOut,
                "tool fixture completion barrier timed out",
            )
        })?;
        Ok(())
    }

    pub async fn wait_for_invocations(&self, expected: usize) -> TestResult<()> {
        timeout(HTTP_RESPONSE_HEADERS_TIMEOUT, async {
            loop {
                if self.invocation_count() >= expected {
                    return;
                }
                self.state.invocation_seen.notified().await;
            }
        })
        .await
        .map_err(|_| {
            IoError::new(
                ErrorKind::TimedOut,
                "tool fixture invocation barrier timed out",
            )
        })?;
        Ok(())
    }

    pub async fn stop(&mut self) -> TestResult<()> {
        self.server.stop().await
    }
}

impl Drop for ToolFixture {
    fn drop(&mut self) {
        if let Some(task) = self.server.task.take() {
            task.abort();
        }
        self.server.shutdown.take();
    }
}

async fn tool_request(
    State(state): State<std::sync::Arc<ToolState>>,
    headers: HeaderMap,
    body: Bytes,
) -> AxumResponse {
    let invocation = serde_json::from_slice::<Value>(&body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()));
    state
        .invocations
        .lock()
        .expect("tool fixture invocation mutex poisoned")
        .push(invocation);
    state
        .headers
        .lock()
        .expect("tool fixture header mutex poisoned")
        .push(Value::Object(
            headers
                .iter()
                .filter_map(|(name, value)| {
                    Some((
                        name.as_str().to_owned(),
                        Value::String(value.to_str().ok()?.to_owned()),
                    ))
                })
                .collect(),
        ));
    state.invocation_seen.notify_waiters();
    let script = {
        let mut scripts = state
            .scripts
            .lock()
            .expect("tool fixture script mutex poisoned");
        if scripts.is_empty() {
            ToolScript::Response(json!({
                "status": "completed",
                "result": {"content": "done"}
            }))
        } else {
            scripts.remove(0)
        }
    };
    let response = match script {
        ToolScript::Response(value) => json_response(AxumStatusCode::OK, value),
        ToolScript::Hold { release, response } => {
            release.notified().await;
            json_response(AxumStatusCode::OK, response)
        }
        ToolScript::Status(status) => {
            let status =
                AxumStatusCode::from_u16(status).unwrap_or(AxumStatusCode::SERVICE_UNAVAILABLE);
            AxumResponse::builder()
                .status(status)
                .body(Body::from("fixture tool status"))
                .expect("tool fixture response builds")
        }
    };
    *state
        .completed
        .lock()
        .expect("tool fixture completion mutex poisoned") += 1;
    state.completion_seen.notify_waiters();
    response
}

fn json_response(status: AxumStatusCode, value: Value) -> AxumResponse {
    AxumResponse::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(value.to_string()))
        .expect("tool fixture json response builds")
}

pub async fn kill_and_reap(mut child: Child) -> TestResult<std::process::ExitStatus> {
    if child.try_wait()?.is_none() {
        let _ = timeout(CHILD_SHUTDOWN_TIMEOUT, child.kill()).await;
    }
    Ok(timeout(CHILD_SHUTDOWN_TIMEOUT, child.wait()).await??)
}

pub fn reap_child_on_drop(child: Option<Child>) {
    let Some(child) = child else {
        return;
    };
    // Drop may run while Tokio is shutting down.  Calling `block_on` on the
    // current runtime from that path can wait forever while the runtime waits
    // for this Drop, leaving a real child unreaped and hiding the original
    // readiness failure.  Always use a private current-thread runtime so
    // cleanup is independent of the caller's scheduler lifecycle.
    let join = std::thread::spawn(move || {
        let Ok(runtime) = Builder::new_current_thread().enable_all().build() else {
            return;
        };
        let _ = runtime.block_on(kill_and_reap(child));
    });
    let _ = join.join();
}

pub fn spawn_db_blocking<T, F, E>(operation: F) -> JoinHandle<Result<T, E>>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, E> + Send + 'static,
    E: Send + 'static,
{
    tokio::task::spawn_blocking(operation)
}

pub async fn db_blocking<T, F>(operation: F) -> TestResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> rusqlite::Result<T> + Send + 'static,
{
    Ok(spawn_db_blocking(operation).await??)
}

pub async fn sqlite_contains_secret(path: &Path, secret: &str) -> TestResult<bool> {
    let path = path.to_owned();
    let secret = secret.to_owned();
    spawn_db_blocking(move || -> TestResult<bool> {
        for suffix in ["", "-wal", "-journal", "-shm"] {
            let candidate = if suffix.is_empty() {
                path.clone()
            } else {
                let mut name = path.as_os_str().to_os_string();
                name.push(suffix);
                PathBuf::from(name)
            };
            match file_contains_marker(&candidate, secret.as_bytes()) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }

        let connection = rusqlite::Connection::open(path)?;
        let mut table_statement = connection.prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )?;
        let table_names = table_statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for table in table_names {
            let quoted_table = format!("\"{}\"", table.replace('\"', "\"\""));
            let mut column_statement =
                connection.prepare(&format!("PRAGMA table_info({quoted_table})"))?;
            let column_names = column_statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for column in column_names {
                let quoted_column = format!("\"{}\"", column.replace('\"', "\"\""));
                let query = format!("SELECT CAST({quoted_column} AS BLOB) FROM {quoted_table}");
                let mut value_statement = connection.prepare(&query)?;
                let mut rows = value_statement.query([])?;
                while let Some(row) = rows.next()? {
                    let value: Option<Vec<u8>> = row.get(0)?;
                    if value
                        .as_deref()
                        .is_some_and(|value| String::from_utf8_lossy(value).contains(&secret))
                    {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    })
    .await?
}

fn file_contains_marker(path: &Path, marker: &[u8]) -> std::io::Result<bool> {
    if marker.is_empty() {
        return Ok(false);
    }
    let mut file = fs::File::open(path)?;
    let mut buffer = [0_u8; 16 * 1024];
    let mut overlap = Vec::new();
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            return Ok(false);
        }
        overlap.extend_from_slice(&buffer[..count]);
        if bytes_contain(&overlap, marker) {
            return Ok(true);
        }
        let retained = marker.len().saturating_sub(1).min(overlap.len());
        overlap.drain(..overlap.len() - retained);
    }
}

pub struct TempDatabase {
    directory: PathBuf,
    path: PathBuf,
}

impl TempDatabase {
    pub fn new(label: &str) -> TestResult<Self> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let directory =
            std::env::temp_dir().join(format!("zode-review-{label}-{}-{now}", std::process::id()));
        fs::create_dir(&directory)?;
        let path = directory.join("runtime.sqlite");
        Ok(Self { directory, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Deref for TempDatabase {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.path()
    }
}

impl AsRef<Path> for TempDatabase {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

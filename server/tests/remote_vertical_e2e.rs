use std::{
    collections::BTreeSet,
    env,
    fs::{self, OpenOptions},
    io::{Error, ErrorKind, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH}};

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header, HeaderMap, Method, StatusCode as AxumStatusCode, Uri},
    response::Response as AxumResponse,
    routing::{get, post},
    Router};
use futures_util::StreamExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    net::TcpListener,
    process::{Child, Command},
    sync::{oneshot, Notify},
    task::JoinHandle,
    time::timeout};

const TEST_SUBJECT: &str = "remote-vertical-human";
const TEST_AUDIENCE: &str = "zode-server-remote-e2e";
const SERVER_AUTHORITY: &str = "server-remote-vertical-e2e";
const ENDPOINT_CONTROL_SECRET: &str = "remote-endpoint-control-secret-e2e";
const PROVIDER_KEY: &str = "remote-provider-api-key-e2e";
const PROVIDER_NAME: &str = "fixture-provider";
const PROFILE_LABEL: &str = "remote-vertical-profile";
const MODEL_NAME: &str = "fixture-model";
const ASSISTANT_TEXT: &str = "REMOTE_OK";
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const SSE_TIMEOUT: Duration = Duration::from_secs(15);
const ENDPOINT_CREATE_CASSETTE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/remote_vertical_endpoint_create.incident.json"
);

const ACCESS_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEArXMZzRpkHwtdgWw+vPxg8LKx71TV9jIqaLp3v1vZAGOf+0U1
GZwbztbax5t0n2x+uuK2sT3FZXe6Tgx8VIG4d33VxSc/KY3Mc4H4idhj/F24asrU
q72wOZMQY7lthi2pLKdFB8j9zjg9TBvlywxZGeg2MyJ5iBAho0h4FdxCuoOe7IZh
zmuoQwIt++SDjQPNz4WiHLAEQUkomCOKEUWAtCuh+M2m6Djd8sQ0nyc1VzDad4IW
DOL00WRsgRJ0up0LBL3FFaaIYzOTtyePhaJHxnpdsCTTTe7Qy7YGXcA8jHLtz+PZ
iImAd/6sR/f10jp8lhIqegcSLT0xvHgsSln5XwIDAQABAoIBAE+hxwg35Byuopzf
XgR1GGqZmACp4du412iip4Sm/f9kPdhmQ0VBOzEgymwXDpl8/cf+e2LvWbfGmrXn
nJNNxSuzDZiI9sI0tFeZpcpfmzQLsTXybmZ03bnpL36hbMvMHd3+4735xLDPeDD/
o+Yvgp7W0j9yxfo2ccMd6+gZaldngZgwNc1TPctRbPFAPz8CQvXw42gFfiL8m1SQ
pvhKW/gOvrCjU5nhf0CvGkdWy/cWHWn+U9p6nRRa4KtpKtDiaOqiHmIFhrEB3bmY
EJhfkqLM3xy1IfL8ujFCADFz1tKb3qDLxAla1XzdQ2SoHbswrXJelQmUQSlmGwbL
x8AKopECgYEA303tGIA2pvsxRo72m0qHiX4rbk42RdDkDdcGhS8sT4rNIJbJCiPS
hl5/n3FnzAroIgmVU9goCAPhKqJY5kwEyoTrlutc57Fbtj59ROrPrFlpPxzf7q5b
OnXwwyKusI2QanSADuXrRqHrpH2UuS9nM3IqXrpZxDN1qjiwziHcs/ECgYEAxth6
Snq1gPv/TkI/BCs2CTE9Q04YflI36iHxA6IKlvaciW2slYq8AHqVMKeHmD9Wjggt
VDNOKewE9OTBGet48Ggbt4REZ/YllxH/hWOBRciCUWcdEaXc0xjCuBVN8cjKxet0
1cANrCAqiVeFq67SndxQCzgCvOv495LDb8WPkk8CgYEArVmVQXvm8WH3Mssw7gTB
ix8DIDJfN3ueTpAqY6HnSCh8bVwg3VpJyD373Q7wgRnGcwX1go0/Jlm8ppg5Yy6I
WZ8uNI6qJMMuax+/p4yRgz410eTcgjGgaJW+Pf3ilvSOs9WUw/wA1WhFwgArQEdo
Wiu6cKdBoGpCYc54ksz+xEECgYEArKDDimV9rb0YqJhanQPmpZRZ21SxbvlyEZHl
64GCMA1pWOYeLrWDAedqHhNTZJmYSzZOJAtmkH6WzwTJn/cNx6iaZ3gs6xSHDeBS
NTttv2eTu5gJZIjabWnRon7cbEwlvi3sAKX7OLO0OggBxErCDsp1s0etGNbEDisc
AK1DN4ECgYB9MzecbpjV2vpAO2N5Jlq8Uz1Hn336TWz0m/ry5pgPlsV1N4Hxnaap
iyeBodLuKel+lwNVfYDJxBot2NHNf6hnQ4eeQbNZOEQTGNpUNsln1x51q4OxcG+o
dpkxaugCqD59pJh3CzzQZJDBU3CJXckyZk2Z6PWkLKXKLDLR5JW9UA==
-----END RSA PRIVATE KEY-----"#;

const ACCESS_JWK: &str = r#"{
  "keys": [{
    "kty": "RSA",
    "kid": "remote-vertical-key",
    "use": "sig",
    "alg": "RS256",
    "n": "rXMZzRpkHwtdgWw-vPxg8LKx71TV9jIqaLp3v1vZAGOf-0U1GZwbztbax5t0n2x-uuK2sT3FZXe6Tgx8VIG4d33VxSc_KY3Mc4H4idhj_F24asrUq72wOZMQY7lthi2pLKdFB8j9zjg9TBvlywxZGeg2MyJ5iBAho0h4FdxCuoOe7IZhzmuoQwIt--SDjQPNz4WiHLAEQUkomCOKEUWAtCuh-M2m6Djd8sQ0nyc1VzDad4IWDOL00WRsgRJ0up0LBL3FFaaIYzOTtyePhaJHxnpdsCTTTe7Qy7YGXcA8jHLtz-PZiImAd_6sR_f10jp8lhIqegcSLT0xvHgsSln5Xw",
    "e": "AQAB"
  }]
}"#;

#[derive(Clone)]
struct ProviderState {
    authorization_headers: Arc<Mutex<Vec<String>>>,
    requests: Arc<Mutex<Vec<Value>>>,
    request_seen: Arc<Notify>}

#[derive(Clone)]
struct JwksState {
    requests: Arc<Mutex<Vec<(String, String)>>>,
    request_seen: Arc<Notify>}

struct FixtureServer {
    base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>}

impl FixtureServer {
    async fn start(router: Router) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = signal.await;
                })
                .await;
        });
        Ok(Self {
            base_url: format!("http://{address}"),
            shutdown: Some(shutdown),
            task: Some(task)})
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            timeout(Duration::from_secs(2), task)
                .await
                .map_err(|_| Error::new(ErrorKind::TimedOut, "fixture shutdown timed out"))??;
        }
        Ok(())
    }
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn fake_provider_chat(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    body: Bytes,
) -> AxumResponse {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    state
        .authorization_headers
        .lock()
        .expect("provider fixture mutex poisoned")
        .push(authorization);
    state
        .requests
        .lock()
        .expect("provider fixture request mutex poisoned")
        .push(serde_json::from_slice(&body).unwrap_or(Value::Null));
    state.request_seen.notify_waiters();
    let body = concat!(
        "data: {\"choices\":[{\"delta\":{\"content\":\"REMOTE_OK\"},\"finish_reason\":null}]}\n\n",
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    AxumResponse::builder()
        .status(AxumStatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from(body))
        .expect("provider fixture response builds")
}

async fn fake_jwks(State(state): State<JwksState>, method: Method, uri: Uri) -> AxumResponse {
    state
        .requests
        .lock()
        .expect("JWKS fixture mutex poisoned")
        .push((method.to_string(), uri.path().to_owned()));
    state.request_seen.notify_waiters();
    AxumResponse::builder()
        .status(AxumStatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(ACCESS_JWK))
        .expect("JWKS fixture response builds")
}

async fn start_provider(
) -> Result<(FixtureServer, ProviderState), Box<dyn std::error::Error + Send + Sync>> {
    let state = ProviderState {
        authorization_headers: Arc::new(Mutex::new(Vec::new())),
        requests: Arc::new(Mutex::new(Vec::new())),
        request_seen: Arc::new(Notify::new())};
    let router = Router::new()
        .route("/v1/chat/completions", post(fake_provider_chat))
        .with_state(state.clone());
    Ok((FixtureServer::start(router).await?, state))
}

async fn start_jwks() -> Result<(FixtureServer, JwksState), Box<dyn std::error::Error + Send + Sync>>
{
    let state = JwksState {
        requests: Arc::new(Mutex::new(Vec::new())),
        request_seen: Arc::new(Notify::new())};
    let server = FixtureServer::start(
        Router::new()
            .route("/jwks", get(fake_jwks))
            .with_state(state.clone()),
    )
    .await?;
    Ok((server, state))
}

async fn wait_for_provider_requests(
    state: &ProviderState,
    expected: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    timeout(HTTP_TIMEOUT, async {
        loop {
            if state
                .authorization_headers
                .lock()
                .expect("provider fixture mutex poisoned")
                .len()
                >= expected
            {
                return;
            }
            state.request_seen.notified().await;
        }
    })
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "provider request barrier timed out"))?;
    Ok(())
}

async fn wait_for_jwks_requests(
    state: &JwksState,
    expected: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    timeout(HTTP_TIMEOUT, async {
        loop {
            if state
                .requests
                .lock()
                .expect("JWKS fixture mutex poisoned")
                .len()
                >= expected
            {
                return;
            }
            state.request_seen.notified().await;
        }
    })
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "JWKS request barrier timed out"))?;
    Ok(())
}

async fn stop_child(child: &mut Child) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // Let SQLite flush its WAL and release the ownership lock before the
        // restart assertion.  Escalate only when the real process ignores the
        // ordinary shutdown signal.
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
    #[cfg(not(unix))]
    let _ = child.start_kill();
    if timeout(Duration::from_secs(5), child.wait()).await.is_err() {
        let _ = child.start_kill();
        timeout(Duration::from_secs(5), child.wait())
            .await
            .map_err(|_| Error::new(ErrorKind::TimedOut, "child reap timed out"))??;
    }
    Ok(())
}

struct ReadyProcess {
    child: Option<Child>,
    base_url: String,
    logs: Arc<Mutex<Vec<u8>>>,
    drainers: Vec<JoinHandle<()>>}

async fn join_output_drainers(drainers: &mut Vec<JoinHandle<()>>) {
    for drainer in drainers.drain(..) {
        let _ = timeout(Duration::from_secs(1), drainer).await;
    }
}

impl ReadyProcess {
    async fn spawn(
        program: &Path,
        arguments: &[String],
        ready_prefix: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut command = Command::new(program);
        command
            .args(arguments)
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let logs = Arc::new(Mutex::new(Vec::new()));
        let mut drainers = Vec::new();
        if let Some(mut stderr) = child.stderr.take() {
            let logs_for_stderr = logs.clone();
            drainers.push(tokio::spawn(async move {
                let mut bytes = Vec::new();
                let _ = stderr.read_to_end(&mut bytes).await;
                logs_for_stderr
                    .lock()
                    .expect("child log mutex poisoned")
                    .extend_from_slice(&bytes);
            }));
        }
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let _ = stop_child(&mut child).await;
                join_output_drainers(&mut drainers).await;
                return Err(Error::other("child stdout was not piped").into());
            }
        };
        let mut lines = BufReader::new(stdout).lines();
        let line = match timeout(READY_TIMEOUT, lines.next_line()).await {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) => {
                let _ = stop_child(&mut child).await;
                join_output_drainers(&mut drainers).await;
                return Err(
                    Error::other("child exited before readiness with non-zero status").into(),
                );
            }
            Ok(Err(error)) => {
                let _ = stop_child(&mut child).await;
                join_output_drainers(&mut drainers).await;
                return Err(Error::other(format!("child readiness read failed: {error}")).into());
            }
            Err(_) => {
                let _ = stop_child(&mut child).await;
                join_output_drainers(&mut drainers).await;
                return Err(Error::new(ErrorKind::TimedOut, "child did not become ready").into());
            }
        };
        let base_url = match line.strip_prefix(ready_prefix) {
            Some(base_url) => base_url.trim().to_owned(),
            None => {
                let _ = stop_child(&mut child).await;
                join_output_drainers(&mut drainers).await;
                return Err(Error::other("child readiness line had an unexpected prefix").into());
            }
        };
        if base_url.is_empty() {
            let _ = stop_child(&mut child).await;
            join_output_drainers(&mut drainers).await;
            return Err(Error::other("child readiness line omitted base URL").into());
        }
        let logs_for_stdout = logs.clone();
        drainers.push(tokio::spawn(async move {
            let mut lines = lines;
            while let Ok(Some(line)) = lines.next_line().await {
                let mut logs = logs_for_stdout.lock().expect("child log mutex poisoned");
                logs.extend_from_slice(line.as_bytes());
                logs.push(b'\n');
            }
        }));
        Ok(Self {
            child: Some(child),
            base_url,
            logs,
            drainers})
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(mut child) = self.child.take() {
            stop_child(&mut child).await?;
        }
        join_output_drainers(&mut self.drainers).await;
        Ok(())
    }

    fn logs(&self) -> Vec<u8> {
        self.logs.lock().expect("child log mutex poisoned").clone()
    }
}

impl Drop for ReadyProcess {
    fn drop(&mut self) {
        for drainer in self.drainers.drain(..) {
            drainer.abort();
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = std::thread::Builder::new()
                .name("remote-e2e-child-reaper".to_owned())
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build();
                    if let Ok(runtime) = runtime {
                        let _ = runtime.block_on(async move { child.wait().await });
                    }
                })
                .and_then(|thread| {
                    thread
                        .join()
                        .map_err(|_| Error::other("child reaper panicked"))
                });
        }
    }
}

fn write_endpoint_config(
    root: &Path,
    database: &Path,
    provider_origin: &str,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    fs::create_dir_all(root.join("credentials"))?;
    fs::create_dir_all(root.join("blobs"))?;
    let controller_secret = root.join("controller.secret");
    fs::write(&controller_secret, ENDPOINT_CONTROL_SECRET)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&controller_secret)?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&controller_secret, permissions)?;
    }
    let value = json!({
        "schema": "zode.config.v1",
        "listen": "127.0.0.1:0",
        "runtime_store": {"kind": "sqlite", "path": database},
        "credential_replica_store": {"kind": "files", "directory": "credentials"},
        "blob_store": {"kind": "files", "directory": "blobs"},

        "runtime": {
            "tool_foreground_ms": 100,
            "model_step_max_attempts": 1,
            "model_retry_base_ms": 1,
            "model_retry_max_ms": 10,
            "snapshot_every_events": 1
        },
        "provider_execution": {
            "adapter_kinds": ["openai_compatible"],
            "allowed_base_url_origins": [provider_origin]
        },
        "callback": {"allowed_public_origins": [provider_origin]},
        "tools": []
    });
    let path = root.join("endpoint-config.json");
    fs::write(&path, serde_json::to_vec_pretty(&value)?)?;
    Ok(path)
}

fn write_server_config(
    root: &Path,
    issuer: &str,
    jwks_url: &str,
) -> Result<(PathBuf, PathBuf, PathBuf), Box<dyn std::error::Error + Send + Sync>> {
    let management_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let management_port = management_listener.local_addr()?.port();
    drop(management_listener);
    let callback_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let callback_port = callback_listener.local_addr()?.port();
    drop(callback_listener);
    let database = root.join("server.sqlite3");
    let secrets = root.join("server-secrets");
    let subject_key = root.join("subject.key");
    fs::create_dir_all(&secrets)?;
    fs::write(&subject_key, [0x42_u8; 32])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&subject_key)?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&subject_key, permissions)?;
    }
    let config = json!({
        "schema": "zode.server-config.v1",
        "listen": format!("127.0.0.1:{management_port}"),
        "management_origin": format!("http://127.0.0.1:{management_port}"),
        "callback_origin": format!("http://127.0.0.1:{callback_port}"),
        "server_authority_id": SERVER_AUTHORITY,
        "deployment": "server_only",
        "ui_mode": "api_only",
        "control_database": database,
        "secret_directory": secrets,
        "access": {
            "issuer": issuer,
            "audiences": [TEST_AUDIENCE],
            "jwks_url": jwks_url,
            "subject_key_file": subject_key,
            "subject_key_version": 1
        }
    });
    let path = root.join("server-config.json");
    fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    Ok((path, database, secrets))
}

fn access_assertion(issuer: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let claims = json!({
        "iss": issuer,
        "aud": [TEST_AUDIENCE],
        "sub": TEST_SUBJECT,
        "type": "app",
        "iat": now,
        "nbf": now.saturating_sub(1),
        "exp": now + 300
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("remote-vertical-key".to_owned());
    Ok(encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(ACCESS_PRIVATE_KEY.as_bytes())?,
    )?)
}

fn authenticated(request: RequestBuilder, assertion: &str) -> RequestBuilder {
    request.header("Cf-Access-Jwt-Assertion", assertion)
}

fn scan_bytes(bytes: &[u8], marker: &str) -> bool {
    let marker = marker.as_bytes();
    !marker.is_empty() && bytes.windows(marker.len()).any(|window| window == marker)
}

async fn read_response(
    response: reqwest::Response,
    markers: &[&str],
) -> Result<(StatusCode, String), Box<dyn std::error::Error + Send + Sync>> {
    for value in response.headers().values() {
        for marker in markers {
            if scan_bytes(value.as_bytes(), marker) {
                return Err(
                    Error::other("public response header contained a secret marker").into(),
                );
            }
        }
    }
    let status = response.status();
    let body = timeout(HTTP_TIMEOUT, response.text()).await??;
    if let Some(marker_index) = markers.iter().position(|marker| body.contains(marker)) {
        return Err(Error::other(format!(
            "public response body contained forbidden marker index {marker_index}"
        ))
        .into());
    }
    Ok((status, body))
}

fn parse_json(body: &str, label: &str) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    serde_json::from_str(body)
        .map_err(|_| Error::new(ErrorKind::InvalidData, format!("{label} was not JSON")).into())
}

fn require_exact_object_keys(
    value: &Value,
    expected: &[&str],
    label: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let object = value
        .as_object()
        .ok_or_else(|| Error::other(format!("{label} was not an object")))?;
    let mut actual = object.keys().map(String::as_str).collect::<Vec<_>>();
    actual.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    if actual != expected {
        return Err(Error::other(format!("{label} had unknown or missing fields")).into());
    }
    Ok(())
}

fn marker_refs(markers: &[String]) -> Vec<&str> {
    markers.iter().map(String::as_str).collect()
}

fn is_crockford_ulid(value: &str) -> bool {
    value.len() == 26
        && value.chars().all(|character| {
            matches!(
                character,
                '0'..='9'
                    | 'A'
                    | 'B'
                    | 'C'
                    | 'D'
                    | 'E'
                    | 'F'
                    | 'G'
                    | 'H'
                    | 'J'
                    | 'K'
                    | 'M'
                    | 'N'
                    | 'P'
                    | 'Q'
                    | 'R'
                    | 'S'
                    | 'T'
                    | 'V'
                    | 'W'
                    | 'X'
                    | 'Y'
                    | 'Z'
            )
        })
}

fn load_endpoint_create_cassette() -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let bytes = fs::read(ENDPOINT_CREATE_CASSETTE)?;
    if scan_bytes(&bytes, PROVIDER_KEY) || scan_bytes(&bytes, ENDPOINT_CONTROL_SECRET) {
        return Err(Error::other("tracked cassette contained a raw credential").into());
    }
    let cassette: Value = serde_json::from_slice(&bytes)?;
    require_exact_object_keys(
        &cassette,
        &[
            "boundary",
            "canonical_fingerprint",
            "first_failure",
            "owner",
            "recording_id",
            "request",
            "response",
            "schema",
            "slots",
            "version",
            "whole_digest"],
        "remote vertical cassette",
    )?;
    if cassette["schema"] != "zode.http-incident-recording.v1"
        || cassette["version"] != 1
        || cassette["recording_id"] != "remote-vertical-endpoint-create-first-404"
        || cassette["owner"]
            != "e2e_remote_server_configure_once_distributes_and_runs_session_without_session_storage"
        || cassette["boundary"] != "management_http"
        || cassette["slots"]
            != json!([
                "SLOT_ACCESS_ASSERTION",
                "SLOT_ENDPOINT_BASE_URL",
                "SLOT_ENDPOINT_CONTROL_SECRET"
            ])
        || cassette["whole_digest"]
            != "sha256:9a8b252ae79576ced67f8ec79efd7c8dce761dc0455c862158aede96710dff07"
    {
        return Err(Error::other("remote vertical cassette metadata was invalid").into());
    }
    require_exact_object_keys(
        &cassette["first_failure"],
        &["body", "error_code", "status"],
        "remote vertical first failure",
    )?;
    if cassette["first_failure"]["status"] != 404
        || cassette["first_failure"]["error_code"] != "missing_public_endpoint_route"
        || cassette["first_failure"]["body"] != ""
    {
        return Err(Error::other("remote vertical first failure was changed").into());
    }
    require_exact_object_keys(
        &cassette["request"],
        &["body", "headers", "method", "path"],
        "remote vertical request",
    )?;
    require_exact_object_keys(
        &cassette["request"]["headers"],
        &["Cf-Access-Jwt-Assertion", "Idempotency-Key"],
        "remote vertical request headers",
    )?;
    require_exact_object_keys(
        &cassette["request"]["body"],
        &["base_url", "control_auth", "label"],
        "remote vertical request body",
    )?;
    require_exact_object_keys(
        &cassette["request"]["body"]["control_auth"],
        &["kind", "secret"],
        "remote vertical control auth",
    )?;
    if cassette["request"]["method"] != "POST"
        || cassette["request"]["path"] != "/v1/endpoints"
        || cassette["request"]["headers"]["Cf-Access-Jwt-Assertion"] != "SLOT_ACCESS_ASSERTION"
        || cassette["request"]["headers"]["Idempotency-Key"] != "remote-endpoint-add"
        || cassette["request"]["body"]["label"] != "Remote fixture endpoint"
        || cassette["request"]["body"]["base_url"] != "SLOT_ENDPOINT_BASE_URL"
        || cassette["request"]["body"]["control_auth"]["kind"] != "bearer"
        || cassette["request"]["body"]["control_auth"]["secret"] != "SLOT_ENDPOINT_CONTROL_SECRET"
    {
        return Err(Error::other("remote vertical cassette request was changed").into());
    }
    require_exact_object_keys(
        &cassette["response"],
        &["body", "headers", "status"],
        "remote vertical response",
    )?;
    if cassette["response"]["status"] != 404
        || cassette["response"]["headers"] != json!({})
        || cassette["response"]["body"] != ""
    {
        return Err(Error::other("remote vertical cassette response was changed").into());
    }
    require_exact_object_keys(
        &cassette["canonical_fingerprint"],
        &["algorithm", "request", "response"],
        "remote vertical cassette fingerprints",
    )?;
    if cassette["canonical_fingerprint"]["algorithm"] != "sha256"
        || cassette["canonical_fingerprint"]["request"]
            != "8b6a60f2cca94b8f06e8893b48d2eb85d160b6c35d59485ffa1db39bbdaf349d"
        || cassette["canonical_fingerprint"]["response"]
            != "1bbf1252fa0fff9ec6de376b3aa38ea1abd9419e7ca4b27fad3276cc774c2557"
    {
        return Err(Error::other("remote vertical cassette fingerprints were changed").into());
    }
    Ok(cassette)
}

fn capture_first_exchange(
    request: &Value,
    response_status: StatusCode,
    response_body: &str,
    forbidden: &[&str],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if env::var_os("ZODE_CAPTURE_FIRST_OCCURRENCE").is_none() {
        return Ok(());
    }
    let quarantine = env::temp_dir().join("zode-e2e-quarantine");
    fs::create_dir_all(&quarantine)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&quarantine)?.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&quarantine, permissions)?;
    }
    let path = quarantine.join(
        "e2e_remote_server_configure_once_distributes_and_runs_session_without_session_storage.first.json",
    );
    if path.exists() {
        return Err(Error::other("refusing to overwrite first-occurrence quarantine").into());
    }
    fn redact(value: &mut Value, replacements: &[(&str, &str)]) {
        match value {
            Value::String(text) => {
                for (secret, slot) in replacements {
                    if text == secret {
                        *text = (*slot).to_owned();
                        break;
                    }
                }
            }
            Value::Array(values) => values
                .iter_mut()
                .for_each(|value| redact(value, replacements)),
            Value::Object(values) => {
                for (key, value) in values.iter_mut() {
                    if key == "Cf-Access-Jwt-Assertion" {
                        *value = Value::String("SLOT_ACCESS_ASSERTION".to_owned());
                    } else if key == "base_url" {
                        *value = Value::String("SLOT_ENDPOINT_BASE_URL".to_owned());
                    } else {
                        redact(value, replacements);
                    }
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    let mut safe_request = request.clone();
    redact(
        &mut safe_request,
        &[
            (ENDPOINT_CONTROL_SECRET, "SLOT_ENDPOINT_CONTROL_SECRET"),
            (PROVIDER_KEY, "SLOT_PROVIDER_KEY")],
    );
    let raw = json!({
        "schema": "zode.http-incident-recording.v1",
        "version": 1,
        "recording_id": "remote-vertical-endpoint-create-first-occurrence",
        "owner": "e2e_remote_server_configure_once_distributes_and_runs_session_without_session_storage",
        "boundary": "management_http",
        "first_failure": {"status": response_status.as_u16(), "error_code": "observed_first_failure"},
        "slots": ["SLOT_ACCESS_ASSERTION", "SLOT_ENDPOINT_BASE_URL", "SLOT_ENDPOINT_CONTROL_SECRET", "SLOT_PROVIDER_KEY"],
        "request": safe_request,
        "response": {"status": response_status.as_u16(), "body": response_body}
    });
    let bytes = serde_json::to_vec(&raw)?;
    if bytes.contains(&0) || forbidden.iter().any(|marker| scan_bytes(&bytes, marker)) {
        return Err(Error::other("remote vertical capture retained a credential").into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&path)?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&path, permissions)?;
    }
    Ok(())
}

async fn public_json(
    request: RequestBuilder,
    markers: &[&str],
    label: &str,
) -> Result<(StatusCode, String, Value), Box<dyn std::error::Error + Send + Sync>> {
    let response = timeout(HTTP_TIMEOUT, request.send()).await??;
    let (status, body) = read_response(response, markers)
        .await
        .map_err(|error| Error::other(format!("{label}: {error}")))?;
    let value = parse_json(&body, label)?;
    Ok((status, body, value))
}

fn require_status(
    status: StatusCode,
    expected: StatusCode,
    label: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if status != expected {
        return Err(Error::other(format!("{label} returned {status}, expected {expected}")).into());
    }
    Ok(())
}

struct ReplicaReadyExpectation<'a> {
    profile_id: &'a str,
    endpoint_id: &'a str,
    provider: &'a str,
    revision: u64}

async fn wait_for_replica_ready(
    client: &Client,
    server_url: &str,
    assertion: &str,
    expected: ReplicaReadyExpectation<'_>,
    markers: &[&str],
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    timeout(Duration::from_secs(15), async {
        loop {
            let request = authenticated(
                client.get(format!(
                    "{server_url}/v1/auth-profiles/{}/replicas",
                    expected.profile_id
                )),
                assertion,
            );
            let (status, _body, value) =
                public_json(request, markers, "replica distribution response").await?;
            if status == StatusCode::OK {
                if let Some(item) = value["items"].as_array().and_then(|items| {
                    items
                        .iter()
                        .find(|item| item["endpoint_id"] == expected.endpoint_id)
                }) {
                    if item["status"] == "ready"
                        && item["auth_profile_id"] == expected.profile_id
                        && item["authority_id"] == SERVER_AUTHORITY
                        && item["provider"] == expected.provider
                        && item["revision"] == expected.revision
                    {
                        return Ok::<Value, Box<dyn std::error::Error + Send + Sync>>(value);
                    }
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::TimedOut,
            "replica distribution did not become ready",
        )
    })?
}

async fn add_remote_endpoint(
    client: &Client,
    server_url: &str,
    assertion: &str,
    label: &str,
    base_url: &str,
    idempotency_key: &str,
    markers: &[&str],
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let request = authenticated(
        client
            .post(format!("{server_url}/v1/endpoints"))
            .header("Idempotency-Key", idempotency_key),
        assertion,
    )
    .json(&json!({
        "label": label,
        "base_url": base_url,
        "control_auth": {"kind": "bearer", "secret": ENDPOINT_CONTROL_SECRET}
    }));
    let (status, _body, value) = public_json(request, markers, label).await?;
    require_status(status, StatusCode::CREATED, label)?;
    value["endpoint_id"]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| Error::other(format!("{label} omitted Endpoint-owned identity")).into())
}

async fn wait_for_replica_states(
    client: &Client,
    server_url: &str,
    assertion: &str,
    profile_id: &str,
    expected: &[(&str, &str, u64)],
    markers: &[&str],
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    timeout(Duration::from_secs(15), async {
        loop {
            let request = authenticated(
                client.get(format!(
                    "{server_url}/v1/auth-profiles/{profile_id}/replicas"
                )),
                assertion,
            );
            let (status, _body, value) =
                public_json(request, markers, "replica state convergence").await?;
            if status == StatusCode::OK {
                let matches = expected
                    .iter()
                    .all(|(endpoint_id, expected_status, revision)| {
                        value["items"].as_array().is_some_and(|items| {
                            items.iter().any(|item| {
                                item["endpoint_id"] == *endpoint_id
                                    && item["status"] == *expected_status
                                    && item["revision"] == *revision
                                    && item["auth_profile_id"] == profile_id
                                    && item["authority_id"] == SERVER_AUTHORITY
                                    && item["provider"] == PROVIDER_NAME
                            })
                        })
                    });
                if matches {
                    return Ok::<Value, Box<dyn std::error::Error + Send + Sync>>(value);
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "replica states did not converge"))?
}

fn preserve_sharing_failure(
    request_body: &Value,
    status: StatusCode,
    response_body: &str,
    forbidden: &[&str],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if status == StatusCode::ACCEPTED {
        return Ok(());
    }
    let quarantine = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")))
        .join("target/test-recordings/quarantine");
    fs::create_dir_all(&quarantine)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700))?;
    }
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::other("system time preceded UNIX epoch"))?
        .as_millis();
    let path = quarantine.join(format!(
        "auth-profile-sharing-first-{observed_at}-{}.json",
        std::process::id()
    ));
    let value = json!({
        "schema": "zode.http-first-occurrence.v1",
        "owner": "e2e_auth_profile_sharing_removal_survives_offline_endpoint_and_server_restart",
        "boundary": "management_http",
        "request": {
            "method": "PUT",
            "path": "/v1/auth-profiles/SLOT_PROFILE_ID/sharing",
            "headers": {
                "Cf-Access-Jwt-Assertion": "SLOT_ACCESS_ASSERTION",
                "Idempotency-Key": "sharing-remove-offline-endpoint"
            },
            "body": request_body
        },
        "response": {"status": status.as_u16(), "body": response_body}
    });
    let bytes = serde_json::to_vec_pretty(&value)?;
    if forbidden.iter().any(|marker| scan_bytes(&bytes, marker)) {
        return Err(Error::other("sharing first occurrence retained a forbidden marker").into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

async fn open_endpoint_events(
    client: &Client,
    server_url: &str,
    assertion: &str,
    endpoint_id: &str,
    last_event_id: Option<&str>,
    markers: &[&str],
) -> Result<reqwest::Response, Box<dyn std::error::Error + Send + Sync>> {
    let mut request = authenticated(
        client.get(format!("{server_url}/v1/endpoints/{endpoint_id}/events")),
        assertion,
    );
    if let Some(last_event_id) = last_event_id {
        request = request.header("Last-Event-ID", last_event_id);
    }
    let response = timeout(HTTP_TIMEOUT, request.send()).await??;
    for value in response.headers().values() {
        for marker in markers {
            if scan_bytes(value.as_bytes(), marker) {
                return Err(Error::other("SSE response header contained a secret marker").into());
            }
        }
    }
    require_status(response.status(), StatusCode::OK, "Endpoint SSE")?;
    Ok(response)
}

async fn read_assistant_event(
    response: reqwest::Response,
    markers: &[&str],
    expected_content: &str,
) -> Result<(String, Value), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = response.bytes_stream();
    let mut buffer = Vec::new();
    timeout(SSE_TIMEOUT, async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if markers.iter().any(|marker| scan_bytes(&chunk, marker)) {
                return Err(Error::other("SSE frame contained a secret marker").into());
            }
            buffer.extend_from_slice(&chunk);
            while let Some(end) = buffer.windows(2).position(|window| window == b"\n\n") {
                let frame: Vec<u8> = buffer.drain(..end + 2).collect();
                if markers.iter().any(|marker| scan_bytes(&frame, marker)) {
                    return Err(Error::other("SSE frame contained a secret marker").into());
                }
                let event_id = frame
                    .split(|byte| *byte == b'\n')
                    .find_map(|line| line.strip_prefix(b"id: "))
                    .map(|line| String::from_utf8_lossy(line).into_owned());
                let data = frame
                    .split(|byte| *byte == b'\n')
                    .filter_map(|line| line.strip_prefix(b"data: "))
                    .map(|line| String::from_utf8_lossy(line).into_owned())
                    .collect::<Vec<_>>()
                    .join("\n");
                if data.is_empty() || data == "[DONE]" {
                    continue;
                }
                let value: Value = match serde_json::from_str(&data) {
                    Ok(value) => value,
                    Err(_) => continue};
                if (value["kind"] == "assistant_message_committed"
                    || value["event_type"] == "assistant_message_committed")
                    && value["data"]["message"]["content"] == expected_content
                {
                    let event_id = event_id.ok_or_else(|| {
                        Error::other("assistant SSE frame omitted its durable event id")
                    })?;
                    return Ok::<(String, Value), Box<dyn std::error::Error + Send + Sync>>((
                        event_id, value,
                    ));
                }
            }
        }
        Err(Error::new(
            ErrorKind::UnexpectedEof,
            "Endpoint SSE ended before assistant commit",
        )
        .into())
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::TimedOut,
            "Endpoint SSE assistant barrier timed out",
        )
    })?
}

async fn scan_tree_for_markers(
    root: PathBuf,
    markers: Vec<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        fn walk(path: &Path, markers: &[String]) -> std::io::Result<()> {
            if path.is_dir() {
                for entry in fs::read_dir(path)? {
                    walk(&entry?.path(), markers)?;
                }
            } else if path.is_file() {
                let bytes = fs::read(path)?;
                if let Some(marker_index) =
                    markers.iter().position(|marker| scan_bytes(&bytes, marker))
                {
                    return Err(Error::other(format!(
                        "server-owned file contained forbidden marker index {marker_index}: {}",
                        path.display()
                    )));
                }
            }
            Ok(())
        }
        if root.exists() {
            walk(&root, &markers)?;
        }
        Ok(())
    })
    .await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_remote_server_configure_once_distributes_and_runs_session_without_session_storage(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let endpoint_binary = env::var_os("ZODE_ENDPOINT_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")))
                .join("target/debug/zode")
        });
    if !endpoint_binary.is_file() {
        return Err(Error::other(format!(
            "real zode Endpoint binary is missing: {}",
            endpoint_binary.display()
        ))
        .into());
    }
    let server_binary = env::var_os("CARGO_BIN_EXE_zode-server")
        .or_else(|| env::var_os("CARGO_BIN_EXE_zode_server"))
        .ok_or_else(|| Error::other("server test binary path was not provided by Cargo"))?;
    let server_binary = PathBuf::from(server_binary);
    let temp = TempDir::new()?;
    let (mut provider, provider_state) = start_provider().await?;
    let (mut jwks, jwks_state) = start_jwks().await?;
    let provider_origin = provider.base_url.clone();
    let provider_base_url = provider.url("/v1");
    let endpoint_root = temp.path().join("endpoint");
    fs::create_dir_all(&endpoint_root)?;
    let endpoint_database = endpoint_root.join("endpoint.sqlite3");
    let endpoint_config =
        write_endpoint_config(&endpoint_root, &endpoint_database, &provider_origin)?;
    let mut endpoint = ReadyProcess::spawn(
        &endpoint_binary,
        &[
            "--config".to_owned(),
            endpoint_config.to_string_lossy().into_owned(),
            "--database".to_owned(),
            endpoint_database.to_string_lossy().into_owned(),
            "--listen".to_owned(),
            "127.0.0.1:0".to_owned()],
        "ZODE_READY ",
    )
    .await
    .map_err(|error| Error::other(format!("Endpoint process failed to start: {error}")))?;
    let jwks_url = jwks.url("/jwks");
    let issuer = format!("{}/", jwks.base_url);
    let (server_config, server_database, server_secrets) =
        write_server_config(temp.path(), &issuer, &jwks_url)?;
    let mut server = ReadyProcess::spawn(
        &server_binary,
        &[
            "--config".to_owned(),
            server_config.to_string_lossy().into_owned()],
        "ZODE_SERVER_READY ",
    )
    .await
    .map_err(|error| Error::other(format!("Server process failed to start: {error}")))?;
    let assertion = access_assertion(&issuer)?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .build()?;
    let marker_values = vec![
        PROVIDER_KEY.to_owned(),
        ENDPOINT_CONTROL_SECRET.to_owned(),
        assertion.clone(),
        TEST_SUBJECT.to_owned(),
        "remote-endpoint-add".to_owned(),
        "remote-provider-descriptor".to_owned(),
        "remote-profile-create".to_owned(),
        "remote-session-create".to_owned(),
        "remote-session-model-selection".to_owned(),
        "remote-session-model-selection-replay".to_owned(),
        "remote-session-message".to_owned(),
        "remote-session-follow-up".to_owned(),
        "remote-profile-delete".to_owned()];
    let cassette = load_endpoint_create_cassette()?;
    let request_path = cassette["request"]["path"]
        .as_str()
        .ok_or_else(|| Error::other("remote vertical cassette omitted request path"))?;
    let request_key = cassette["request"]["headers"]["Idempotency-Key"]
        .as_str()
        .ok_or_else(|| Error::other("remote vertical cassette omitted idempotency key"))?;
    if cassette["request"]["headers"]["Cf-Access-Jwt-Assertion"] != "SLOT_ACCESS_ASSERTION" {
        return Err(Error::other("remote vertical cassette omitted access assertion slot").into());
    }
    let mut add_endpoint_body = cassette["request"]["body"].clone();
    add_endpoint_body["base_url"] = Value::String(endpoint.base_url.clone());
    add_endpoint_body["control_auth"]["secret"] = Value::String(ENDPOINT_CONTROL_SECRET.to_owned());

    let add_endpoint = authenticated(
        client
            .post(format!("{}{request_path}", server.base_url))
            .header("Idempotency-Key", request_key),
        &assertion,
    )
    .json(&add_endpoint_body);
    let response = timeout(HTTP_TIMEOUT, add_endpoint.send()).await??;
    let (status, body) = read_response(response, &marker_refs(&marker_values)).await?;
    if status != StatusCode::NOT_FOUND {
        wait_for_jwks_requests(&jwks_state, 1).await?;
    }
    capture_first_exchange(
        &json!({
            "method": "POST",
            "path": request_path,
            "headers": {
                "Idempotency-Key": request_key,
                "Cf-Access-Jwt-Assertion": assertion
            },
            "body": add_endpoint_body
        }),
        status,
        &body,
        &[assertion.as_str(), ENDPOINT_CONTROL_SECRET, PROVIDER_KEY],
    )?;
    let recorded_failure_matches = status.as_u16() as u64 == cassette["response"]["status"]
        && cassette["response"]["body"].as_str() == Some(body.as_str())
        && cassette["first_failure"]["status"] == cassette["response"]["status"]
        && cassette["first_failure"]["body"] == cassette["response"]["body"];
    if status == StatusCode::NOT_FOUND && !recorded_failure_matches {
        return Err(Error::other("remote vertical observed 404 did not match its cassette").into());
    }
    if recorded_failure_matches {
        return Err(Error::other(
            "remote endpoint create reproduced the recorded 404 before the target 201/JWKS assertion",
        )
        .into());
    }
    require_status(status, StatusCode::CREATED, "remote endpoint create")?;
    let endpoint_record = parse_json(&body, "endpoint create")?;
    let endpoint_id = endpoint_record["endpoint_id"]
        .as_str()
        .ok_or_else(|| Error::other("Server endpoint response omitted Endpoint-owned ID"))?
        .to_owned();
    if body.contains(ENDPOINT_CONTROL_SECRET) {
        return Err(Error::other("Server endpoint response leaked control secret").into());
    }

    let endpoint_replay = authenticated(
        client
            .post(format!("{}{request_path}", server.base_url))
            .header("Idempotency-Key", request_key),
        &assertion,
    )
    .json(&add_endpoint_body);
    let (replay_status, replay_body) = read_response(
        timeout(HTTP_TIMEOUT, endpoint_replay.send()).await??,
        &marker_refs(&marker_values),
    )
    .await?;
    require_status(
        replay_status,
        StatusCode::CREATED,
        "remote endpoint create replay",
    )?;
    if replay_body != body {
        return Err(Error::other("remote endpoint create replay changed its body").into());
    }

    let descriptor = authenticated(
        client
            .put(format!("{}/v1/providers/{PROVIDER_NAME}", server.base_url))
            .header("Idempotency-Key", "remote-provider-descriptor"),
        &assertion,
    )
    .json(&json!({
        "kind": "openai_compatible",
        "base_url": provider_base_url,
        "models": [MODEL_NAME],
        "model_limits": {
            (MODEL_NAME): {
                "context_window_tokens": 1_000_000,
                "max_output_tokens": 384_000
            }
        },
        "options": {}
    }));
    let (status, _body, descriptor_value) = public_json(
        descriptor,
        &marker_refs(&marker_values),
        "provider descriptor",
    )
    .await?;
    require_status(status, StatusCode::OK, "provider descriptor")?;
    if descriptor_value["provider"] != PROVIDER_NAME
        || descriptor_value["kind"] != "openai_compatible"
        || descriptor_value["base_url"] != provider_base_url
        || descriptor_value["models"] != json!([MODEL_NAME])
        || descriptor_value["model_limits"][MODEL_NAME]["context_window_tokens"] != 1_000_000
        || descriptor_value["model_limits"][MODEL_NAME]["max_output_tokens"] != 384_000
    {
        return Err(Error::other("provider descriptor was not persisted exactly").into());
    }
    let descriptor_revision = descriptor_value["revision"]
        .as_u64()
        .ok_or_else(|| Error::other("provider descriptor omitted immutable revision"))?;

    let profile = authenticated(
        client
            .post(format!(
                "{}/v1/providers/{PROVIDER_NAME}/auth-profiles",
                server.base_url
            ))
            .header("Idempotency-Key", "remote-profile-create"),
        &assertion,
    )
    .json(&json!({
        "kind": "api_key",
        "label": PROFILE_LABEL,
        "api_key": PROVIDER_KEY,
        "make_default": false,
        "sharing": {"mode": "selected", "endpoint_ids": [endpoint_id]}
    }));
    let (status, _body, profile_value) =
        public_json(profile, &marker_refs(&marker_values), "provider profile").await?;
    require_status(status, StatusCode::CREATED, "provider profile")?;
    if profile_value["provider"] != PROVIDER_NAME
        || profile_value["revision"] != 1
        || profile_value["status"] != "pending"
    {
        return Err(Error::other("provider profile metadata was not exact").into());
    }
    let profile_id = profile_value["auth_profile_id"]
        .as_str()
        .ok_or_else(|| Error::other("provider profile omitted profile ID"))?
        .to_owned();
    let profile_revision = profile_value["revision"]
        .as_u64()
        .ok_or_else(|| Error::other("provider profile omitted revision"))?;

    let _replica_state = wait_for_replica_ready(
        &client,
        &server.base_url,
        &assertion,
        ReplicaReadyExpectation {
            profile_id: &profile_id,
            endpoint_id: &endpoint_id,
            provider: PROVIDER_NAME,
            revision: profile_revision},
        &marker_refs(&marker_values),
    )
    .await?;

    let model = json!({
        "provider": PROVIDER_NAME,
        "model": MODEL_NAME,
        "provider_execution": {
            "schema": "zode.provider-execution.v1",
            "revision": descriptor_revision,
            "kind": "openai_compatible",
            "base_url": provider_base_url,
            "options": {}
        },
        "limits": {
            "context_window_tokens": 1_000_000,
            "max_output_tokens": 384_000
        },
        "auth_profile_id": profile_id,
        "minimum_auth_revision": profile_revision
    });
    let create = authenticated(
        client
            .post(format!(
                "{}/v1/endpoints/{endpoint_id}/sessions",
                server.base_url
            ))
            .header("Idempotency-Key", "remote-session-create"),
        &assertion,
    )
    .json(&json!({}));
    let (status, _create_body, create_value) = public_json(
        create,
        &marker_refs(&marker_values),
        "remote session create",
    )
    .await?;
    require_status(status, StatusCode::CREATED, "remote session create")?;
    let session_id = create_value["session_id"]
        .as_str()
        .ok_or_else(|| Error::other("Endpoint session create omitted session ID"))?
        .to_owned();
    if session_id.is_empty() {
        return Err(Error::other("Endpoint session ID was empty").into());
    }
    if !is_crockford_ulid(&session_id) {
        return Err(Error::other("Endpoint session ID was not an uppercase Crockford ULID").into());
    }
    let model_selection = authenticated(
        client
            .put(format!(
                "{}/v1/endpoints/{endpoint_id}/sessions/{session_id}/model",
                server.base_url
            ))
            .header("Idempotency-Key", "remote-session-model-selection"),
        &assertion,
    )
    .json(&model);
    let (status, model_selection_body, model_selection_value) = public_json(
        model_selection,
        &marker_refs(&marker_values),
        "remote session model selection",
    )
    .await?;
    require_status(
        status,
        StatusCode::ACCEPTED,
        "remote session model selection",
    )?;
    if model_selection_value["schema"] != "zode.command.v1"
        || model_selection_value["session_id"] != session_id
        || model_selection_value["accepted"] != true
    {
        return Err(Error::other("remote session model selection response was not exact").into());
    }

    let model_selection_replay = authenticated(
        client
            .put(format!(
                "{}/v1/endpoints/{endpoint_id}/sessions/{session_id}/model",
                server.base_url
            ))
            .header("Idempotency-Key", "remote-session-model-selection"),
        &assertion,
    )
    .json(&model);
    let (replay_status, replay_body) = read_response(
        timeout(HTTP_TIMEOUT, model_selection_replay.send()).await??,
        &marker_refs(&marker_values),
    )
    .await?;
    require_status(
        replay_status,
        StatusCode::ACCEPTED,
        "remote session model selection replay",
    )?;
    if replay_body != model_selection_body {
        return Err(Error::other("remote session model selection replay changed its body").into());
    }

    let (status, _body, selected_session) = public_json(
        authenticated(
            client.get(format!(
                "{}/v1/endpoints/{endpoint_id}/sessions/{session_id}",
                server.base_url
            )),
            &assertion,
        ),
        &marker_refs(&marker_values),
        "selected remote session read",
    )
    .await?;
    require_status(status, StatusCode::OK, "selected remote session read")?;
    if selected_session["model"]["provider"] != PROVIDER_NAME
        || selected_session["model"]["model"] != MODEL_NAME
        || selected_session["model"]["provider_execution_revision"] != descriptor_revision
        || selected_session["model"]["auth_profile_id"] != profile_id
        || selected_session["model"]["limits"]["context_window_tokens"] != 1_000_000
        || selected_session["model"]["limits"]["max_output_tokens"] != 384_000
    {
        return Err(Error::other("remote session model selection was not durable").into());
    }

    let message = authenticated(
        client
            .post(format!(
                "{}/v1/endpoints/{endpoint_id}/sessions/{session_id}/messages",
                server.base_url
            ))
            .header("Idempotency-Key", "remote-session-message"),
        &assertion,
    )
    .json(&json!({"content": "Reply with exactly REMOTE_OK"}));
    let initial_sse = open_endpoint_events(
        &client,
        &server.base_url,
        &assertion,
        &endpoint_id,
        None,
        &marker_refs(&marker_values),
    )
    .await?;
    let (status, _body, _message_value) =
        public_json(message, &marker_refs(&marker_values), "remote message").await?;
    require_status(status, StatusCode::ACCEPTED, "remote message")?;
    wait_for_provider_requests(&provider_state, 1).await?;
    let (first_event_id, assistant_event) =
        read_assistant_event(initial_sse, &marker_refs(&marker_values), ASSISTANT_TEXT).await?;
    let first_event_position = first_event_id.parse::<u64>().map_err(|_| {
        Error::other("initial remote assistant event id was not a numeric durable cursor")
    })?;
    if assistant_event.to_string().contains(PROVIDER_KEY) {
        return Err(Error::other("assistant event contained provider credential").into());
    }
    let (status, _body, session_value) = public_json(
        authenticated(
            client.get(format!(
                "{}/v1/endpoints/{endpoint_id}/sessions/{session_id}",
                server.base_url
            )),
            &assertion,
        ),
        &marker_refs(&marker_values),
        "remote session read",
    )
    .await?;
    require_status(status, StatusCode::OK, "remote session read")?;
    let transcript = session_value["transcript"]
        .as_array()
        .ok_or_else(|| Error::other("remote session read omitted transcript"))?;
    if !transcript
        .iter()
        .any(|message| message["role"] == "assistant" && message["content"] == ASSISTANT_TEXT)
    {
        return Err(
            Error::other("remote session transcript omitted the fake provider assistant").into(),
        );
    }
    let provider_headers = provider_state
        .authorization_headers
        .lock()
        .expect("provider fixture mutex poisoned")
        .clone();
    if provider_headers.len() != 1 || provider_headers[0] != format!("Bearer {PROVIDER_KEY}") {
        return Err(
            Error::other("fake provider did not receive the distributed credential").into(),
        );
    }

    let id_only = authenticated(
        client.get(format!("{}/v1/sessions/{session_id}", server.base_url)),
        &assertion,
    );
    let (status, _body) = read_response(
        timeout(HTTP_TIMEOUT, id_only.send()).await??,
        &marker_refs(&marker_values),
    )
    .await?;
    require_status(
        status,
        StatusCode::NOT_FOUND,
        "ID-only Server session route",
    )?;

    server.stop().await?;
    let server_logs_before_restart = server.logs();
    let mut restarted_server = ReadyProcess::spawn(
        &server_binary,
        &[
            "--config".to_owned(),
            server_config.to_string_lossy().into_owned()],
        "ZODE_SERVER_READY ",
    )
    .await
    .map_err(|error| Error::other(format!("restarted Server process failed to start: {error}")))?;
    let (status, _body, restarted_session) = public_json(
        authenticated(
            client.get(format!(
                "{}/v1/endpoints/{endpoint_id}/sessions/{session_id}",
                restarted_server.base_url
            )),
            &assertion,
        ),
        &marker_refs(&marker_values),
        "restarted remote session read",
    )
    .await?;
    require_status(status, StatusCode::OK, "restarted remote session read")?;
    if restarted_session["session_id"] != session_id {
        return Err(Error::other("restarted Server changed the Endpoint session ID").into());
    }
    let follow_up_sse = open_endpoint_events(
        &client,
        &restarted_server.base_url,
        &assertion,
        &endpoint_id,
        Some(&first_event_id),
        &marker_refs(&marker_values),
    )
    .await?;
    let follow_up = authenticated(
        client
            .post(format!(
                "{}/v1/endpoints/{endpoint_id}/sessions/{session_id}/messages",
                restarted_server.base_url
            ))
            .header("Idempotency-Key", "remote-session-follow-up"),
        &assertion,
    )
    .json(&json!({"content": "Reply with exactly REMOTE_OK"}));
    let (status, _body, _follow_up_value) = public_json(
        follow_up,
        &marker_refs(&marker_values),
        "restarted remote message",
    )
    .await?;
    require_status(status, StatusCode::ACCEPTED, "restarted remote message")?;
    wait_for_provider_requests(&provider_state, 2).await?;
    let (second_event_id, follow_up_event) =
        read_assistant_event(follow_up_sse, &marker_refs(&marker_values), ASSISTANT_TEXT).await?;
    let second_event_position = second_event_id.parse::<u64>().map_err(|_| {
        Error::other("follow-up assistant event id was not a numeric durable cursor")
    })?;
    if second_event_position <= first_event_position {
        return Err(Error::other("SSE Last-Event-ID replay did not advance").into());
    }
    if follow_up_event.to_string().contains(PROVIDER_KEY) {
        return Err(Error::other("follow-up assistant event contained provider credential").into());
    }
    let (status, _body, final_session) = public_json(
        authenticated(
            client.get(format!(
                "{}/v1/endpoints/{endpoint_id}/sessions/{session_id}",
                restarted_server.base_url
            )),
            &assertion,
        ),
        &marker_refs(&marker_values),
        "final remote session read",
    )
    .await?;
    require_status(status, StatusCode::OK, "final remote session read")?;
    let final_transcript = final_session["transcript"]
        .as_array()
        .ok_or_else(|| Error::other("final remote session read omitted transcript"))?;
    let assistants = final_transcript
        .iter()
        .filter(|message| message["role"] == "assistant")
        .collect::<Vec<_>>();
    if assistants.len() != 2
        || assistants
            .iter()
            .any(|message| message["content"] != ASSISTANT_TEXT)
    {
        return Err(
            Error::other("final remote transcript did not contain two exact assistants").into(),
        );
    }
    let provider_requests = provider_state
        .requests
        .lock()
        .expect("provider fixture request mutex poisoned")
        .clone();
    if provider_requests.len() != 2
        || provider_requests
            .iter()
            .any(|request| request["model"] != MODEL_NAME || request["stream"] != true)
    {
        return Err(
            Error::other("fake provider did not receive two complete model requests").into(),
        );
    }
    let second_messages = provider_requests[1]["messages"]
        .as_array()
        .ok_or_else(|| Error::other("second provider request omitted messages"))?;
    let first_assistant = second_messages
        .iter()
        .position(|message| message["role"] == "assistant" && message["content"] == ASSISTANT_TEXT)
        .ok_or_else(|| Error::other("second provider request omitted prior assistant context"))?;
    let second_user = second_messages
        .iter()
        .enumerate()
        .find(|(position, message)| {
            *position > first_assistant
                && message["role"] == "user"
                && message["content"] == "Reply with exactly REMOTE_OK"
        })
        .map(|(position, _)| position)
        .ok_or_else(|| Error::other("second provider request omitted follow-up input"))?;
    if first_assistant >= second_user {
        return Err(Error::other("second provider request had the wrong transcript order").into());
    }
    let provider_headers = provider_state
        .authorization_headers
        .lock()
        .expect("provider fixture mutex poisoned")
        .clone();
    if provider_headers
        != vec![
            format!("Bearer {PROVIDER_KEY}"),
            format!("Bearer {PROVIDER_KEY}")]
    {
        return Err(
            Error::other("fake provider did not receive the credential on both requests").into(),
        );
    }

    let delete_profile = authenticated(
        client
            .delete(format!(
                "{}/v1/providers/{PROVIDER_NAME}/auth-profiles/{profile_id}",
                restarted_server.base_url
            ))
            .header("Idempotency-Key", "remote-profile-delete"),
        &assertion,
    );
    let (status, _body, deleted_profile) = public_json(
        delete_profile,
        &marker_refs(&marker_values),
        "remote profile delete",
    )
    .await?;
    require_status(status, StatusCode::OK, "remote profile delete")?;
    if deleted_profile["provider"] != PROVIDER_NAME
        || deleted_profile["auth_profile_id"] != profile_id
        || !matches!(
            deleted_profile["status"].as_str(),
            Some("deleted") | Some("removal_pending")
        )
    {
        return Err(Error::other("remote profile delete response was not exact").into());
    }

    let model_selection_after_delete = authenticated(
        client
            .put(format!(
                "{}/v1/endpoints/{endpoint_id}/sessions/{session_id}/model",
                restarted_server.base_url
            ))
            .header("Idempotency-Key", "remote-session-model-selection"),
        &assertion,
    )
    .json(&model);
    let (replayed_after_delete_status, replayed_after_delete_body) = read_response(
        timeout(HTTP_TIMEOUT, model_selection_after_delete.send()).await??,
        &marker_refs(&marker_values),
    )
    .await?;
    require_status(
        replayed_after_delete_status,
        StatusCode::ACCEPTED,
        "remote session model selection replay after profile delete",
    )?;
    if replayed_after_delete_body != model_selection_body {
        return Err(Error::other(
            "remote session model replay after profile delete changed its body",
        )
        .into());
    }

    restarted_server.stop().await?;
    let server_logs_after_restart = restarted_server.logs();
    endpoint.stop().await?;
    provider.stop().await?;
    jwks.stop().await?;
    let mut persisted_markers = marker_values;
    persisted_markers.push(session_id);
    scan_tree_for_markers(server_database.clone(), persisted_markers.clone()).await?;
    scan_tree_for_markers(
        server_database.with_extension("sqlite3-wal"),
        persisted_markers.clone(),
    )
    .await?;
    scan_tree_for_markers(
        server_database.with_extension("sqlite3-shm"),
        persisted_markers.clone(),
    )
    .await?;
    scan_tree_for_markers(server_secrets, persisted_markers.clone()).await?;
    if persisted_markers.iter().any(|marker| {
        scan_bytes(&server_logs_before_restart, marker)
            || scan_bytes(&server_logs_after_restart, marker)
    }) {
        return Err(Error::other("Server output contained a forbidden marker").into());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_auth_profile_sharing_removal_survives_offline_endpoint_and_server_restart(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let endpoint_binary = env::var_os("ZODE_ENDPOINT_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")))
                .join("target/debug/zode")
        });
    if !endpoint_binary.is_file() {
        return Err(Error::other(format!(
            "real zode Endpoint binary is missing: {}",
            endpoint_binary.display()
        ))
        .into());
    }
    let server_binary = env::var_os("CARGO_BIN_EXE_zode-server")
        .or_else(|| env::var_os("CARGO_BIN_EXE_zode_server"))
        .map(PathBuf::from)
        .ok_or_else(|| Error::other("server test binary path was not provided by Cargo"))?;
    let temp = TempDir::new()?;
    let (mut provider, provider_state) = start_provider().await?;
    let (mut jwks, _jwks_state) = start_jwks().await?;
    let provider_origin = provider.base_url.clone();
    let provider_base_url = provider.url("/v1");

    let endpoint_a_root = temp.path().join("endpoint-a");
    let endpoint_a_database = endpoint_a_root.join("endpoint.sqlite3");
    let endpoint_a_config =
        write_endpoint_config(&endpoint_a_root, &endpoint_a_database, &provider_origin)?;
    let mut endpoint_a = ReadyProcess::spawn(
        &endpoint_binary,
        &[
            "--config".to_owned(),
            endpoint_a_config.to_string_lossy().into_owned(),
            "--database".to_owned(),
            endpoint_a_database.to_string_lossy().into_owned(),
            "--listen".to_owned(),
            "127.0.0.1:0".to_owned()],
        "ZODE_READY ",
    )
    .await?;
    let endpoint_a_listen = endpoint_a
        .base_url
        .strip_prefix("http://")
        .ok_or_else(|| Error::other("Endpoint A readiness URL was not loopback HTTP"))?
        .to_owned();

    let endpoint_b_root = temp.path().join("endpoint-b");
    let endpoint_b_database = endpoint_b_root.join("endpoint.sqlite3");
    let endpoint_b_config =
        write_endpoint_config(&endpoint_b_root, &endpoint_b_database, &provider_origin)?;
    let mut endpoint_b = ReadyProcess::spawn(
        &endpoint_binary,
        &[
            "--config".to_owned(),
            endpoint_b_config.to_string_lossy().into_owned(),
            "--database".to_owned(),
            endpoint_b_database.to_string_lossy().into_owned(),
            "--listen".to_owned(),
            "127.0.0.1:0".to_owned()],
        "ZODE_READY ",
    )
    .await?;

    let issuer = format!("{}/", jwks.base_url);
    let (server_config, server_database, server_secrets) =
        write_server_config(temp.path(), &issuer, &jwks.url("/jwks"))?;
    let mut server = ReadyProcess::spawn(
        &server_binary,
        &[
            "--config".to_owned(),
            server_config.to_string_lossy().into_owned()],
        "ZODE_SERVER_READY ",
    )
    .await?;
    let assertion = access_assertion(&issuer)?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .build()?;
    let marker_values = vec![
        PROVIDER_KEY.to_owned(),
        ENDPOINT_CONTROL_SECRET.to_owned(),
        assertion.clone(),
        TEST_SUBJECT.to_owned(),
        "sharing-endpoint-a".to_owned(),
        "sharing-endpoint-b".to_owned(),
        "sharing-provider-descriptor".to_owned(),
        "sharing-profile-create".to_owned(),
        "sharing-all-current-session-create".to_owned(),
        "sharing-all-current-session-model".to_owned(),
        "sharing-remove-offline-endpoint".to_owned(),
        "sharing-noop".to_owned(),
        "sharing-session-b-create".to_owned(),
        "sharing-session-b-model".to_owned(),
        "sharing-session-b-message".to_owned(),
        "sharing-session-a-create".to_owned(),
        "sharing-session-a-model".to_owned()];
    let markers = marker_refs(&marker_values);

    let endpoint_a_id = add_remote_endpoint(
        &client,
        &server.base_url,
        &assertion,
        "Sharing Endpoint A",
        &endpoint_a.base_url,
        "sharing-endpoint-a",
        &markers,
    )
    .await?;
    let endpoint_b_id = add_remote_endpoint(
        &client,
        &server.base_url,
        &assertion,
        "Sharing Endpoint B",
        &endpoint_b.base_url,
        "sharing-endpoint-b",
        &markers,
    )
    .await?;

    let descriptor = authenticated(
        client
            .put(format!("{}/v1/providers/{PROVIDER_NAME}", server.base_url))
            .header("Idempotency-Key", "sharing-provider-descriptor"),
        &assertion,
    )
    .json(&json!({
        "kind": "openai_compatible",
        "base_url": provider_base_url,
        "models": [MODEL_NAME],
        "options": {}
    }));
    let (status, _body, descriptor_value) =
        public_json(descriptor, &markers, "sharing provider descriptor").await?;
    require_status(status, StatusCode::OK, "sharing provider descriptor")?;
    let descriptor_revision = descriptor_value["revision"]
        .as_u64()
        .ok_or_else(|| Error::other("sharing provider descriptor omitted revision"))?;

    let profile = authenticated(
        client
            .post(format!(
                "{}/v1/providers/{PROVIDER_NAME}/auth-profiles",
                server.base_url
            ))
            .header("Idempotency-Key", "sharing-profile-create"),
        &assertion,
    )
    .json(&json!({
        "kind": "api_key",
        "label": "sharing-profile",
        "api_key": PROVIDER_KEY,
        "make_default": false,
        "sharing": {"mode": "all_current", "endpoint_ids": []}
    }));
    let (status, _body, profile_value) =
        public_json(profile, &markers, "sharing profile create").await?;
    require_status(status, StatusCode::CREATED, "sharing profile create")?;
    let profile_id = profile_value["auth_profile_id"]
        .as_str()
        .ok_or_else(|| Error::other("sharing profile omitted identity"))?
        .to_owned();
    let shared_endpoint_ids = profile_value["sharing"]["endpoint_ids"]
        .as_array()
        .ok_or_else(|| Error::other("all-current profile omitted expanded Endpoint IDs"))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    if profile_value["sharing"]["mode"] != "all_current"
        || shared_endpoint_ids != BTreeSet::from([endpoint_a_id.as_str(), endpoint_b_id.as_str()])
    {
        return Err(
            Error::other("all-current profile did not freeze the current Endpoints").into(),
        );
    }
    wait_for_replica_ready(
        &client,
        &server.base_url,
        &assertion,
        ReplicaReadyExpectation {
            profile_id: &profile_id,
            endpoint_id: &endpoint_a_id,
            provider: PROVIDER_NAME,
            revision: 1},
        &markers,
    )
    .await?;
    wait_for_replica_ready(
        &client,
        &server.base_url,
        &assertion,
        ReplicaReadyExpectation {
            profile_id: &profile_id,
            endpoint_id: &endpoint_b_id,
            provider: PROVIDER_NAME,
            revision: 1},
        &markers,
    )
    .await?;

    let initial_model = json!({
        "provider": PROVIDER_NAME,
        "model": MODEL_NAME,
        "provider_execution": {
            "schema": "zode.provider-execution.v1",
            "revision": descriptor_revision,
            "kind": "openai_compatible",
            "base_url": provider_base_url,
            "options": {}
        },
        "auth_profile_id": profile_id,
        "minimum_auth_revision": 1
    });
    let (status, _body, initial_session) = public_json(
        authenticated(
            client
                .post(format!(
                    "{}/v1/endpoints/{endpoint_a_id}/sessions",
                    server.base_url
                ))
                .header("Idempotency-Key", "sharing-all-current-session-create"),
            &assertion,
        )
        .json(&json!({})),
        &markers,
        "all-current Endpoint session create",
    )
    .await?;
    require_status(
        status,
        StatusCode::CREATED,
        "all-current Endpoint session create",
    )?;
    let initial_session_id = initial_session["session_id"]
        .as_str()
        .ok_or_else(|| Error::other("all-current Endpoint session omitted ID"))?;
    let (status, _body, _value) = public_json(
        authenticated(
            client
                .put(format!(
                    "{}/v1/endpoints/{endpoint_a_id}/sessions/{initial_session_id}/model",
                    server.base_url
                ))
                .header("Idempotency-Key", "sharing-all-current-session-model"),
            &assertion,
        )
        .json(&initial_model),
        &markers,
        "all-current Endpoint model selection",
    )
    .await?;
    require_status(
        status,
        StatusCode::ACCEPTED,
        "all-current Endpoint model selection",
    )?;

    endpoint_a.stop().await?;
    let sharing_body = json!({"mode": "selected", "endpoint_ids": [&endpoint_b_id]});
    let response = authenticated(
        client
            .put(format!(
                "{}/v1/auth-profiles/{profile_id}/sharing",
                server.base_url
            ))
            .header("Idempotency-Key", "sharing-remove-offline-endpoint"),
        &assertion,
    )
    .json(&sharing_body)
    .send()
    .await?;
    let (sharing_status, sharing_response_body) = read_response(response, &markers).await?;
    preserve_sharing_failure(
        &sharing_body,
        sharing_status,
        &sharing_response_body,
        &[&assertion, ENDPOINT_CONTROL_SECRET, PROVIDER_KEY],
    )?;
    require_status(
        sharing_status,
        StatusCode::ACCEPTED,
        "offline sharing removal",
    )?;
    let sharing_value = parse_json(&sharing_response_body, "offline sharing removal")?;
    let sharing_revision = sharing_value["revision"]
        .as_u64()
        .filter(|revision| *revision > 1)
        .ok_or_else(|| Error::other("sharing removal did not advance profile sequence"))?;
    if sharing_value["schema"] != "zode.auth-profile.v1"
        || sharing_value["auth_profile_id"] != profile_id
        || sharing_value["sharing"]["mode"] != "selected"
        || sharing_value["sharing"]["endpoint_ids"] != json!([endpoint_b_id])
    {
        return Err(Error::other("sharing removal response was not the admitted profile").into());
    }

    server.stop().await?;
    server = ReadyProcess::spawn(
        &server_binary,
        &[
            "--config".to_owned(),
            server_config.to_string_lossy().into_owned()],
        "ZODE_SERVER_READY ",
    )
    .await?;
    wait_for_replica_states(
        &client,
        &server.base_url,
        &assertion,
        &profile_id,
        &[
            (&endpoint_a_id, "unreachable", sharing_revision),
            (&endpoint_b_id, "ready", sharing_revision)],
        &markers,
    )
    .await?;

    endpoint_a = ReadyProcess::spawn(
        &endpoint_binary,
        &[
            "--config".to_owned(),
            endpoint_a_config.to_string_lossy().into_owned(),
            "--database".to_owned(),
            endpoint_a_database.to_string_lossy().into_owned(),
            "--listen".to_owned(),
            endpoint_a_listen],
        "ZODE_READY ",
    )
    .await?;
    wait_for_replica_states(
        &client,
        &server.base_url,
        &assertion,
        &profile_id,
        &[
            (&endpoint_a_id, "removed", sharing_revision),
            (&endpoint_b_id, "ready", sharing_revision)],
        &markers,
    )
    .await?;

    let replay = authenticated(
        client
            .put(format!(
                "{}/v1/auth-profiles/{profile_id}/sharing",
                server.base_url
            ))
            .header("Idempotency-Key", "sharing-remove-offline-endpoint"),
        &assertion,
    )
    .json(&sharing_body);
    let (replay_status, replay_body) =
        read_response(timeout(HTTP_TIMEOUT, replay.send()).await??, &markers).await?;
    require_status(replay_status, StatusCode::ACCEPTED, "sharing replay")?;
    if replay_body != sharing_response_body {
        return Err(Error::other("sharing replay changed the original response").into());
    }

    let conflict = authenticated(
        client
            .put(format!(
                "{}/v1/auth-profiles/{profile_id}/sharing",
                server.base_url
            ))
            .header("Idempotency-Key", "sharing-remove-offline-endpoint"),
        &assertion,
    )
    .json(&json!({"mode": "none", "endpoint_ids": []}));
    let (conflict_status, _body) =
        read_response(timeout(HTTP_TIMEOUT, conflict.send()).await??, &markers).await?;
    require_status(
        conflict_status,
        StatusCode::CONFLICT,
        "sharing changed-body replay",
    )?;

    let noop = authenticated(
        client
            .put(format!(
                "{}/v1/auth-profiles/{profile_id}/sharing",
                server.base_url
            ))
            .header("Idempotency-Key", "sharing-noop"),
        &assertion,
    )
    .json(&sharing_body);
    let (noop_status, _body, noop_value) = public_json(noop, &markers, "sharing no-op").await?;
    require_status(noop_status, StatusCode::ACCEPTED, "sharing no-op")?;
    if noop_value["revision"] != sharing_revision {
        return Err(Error::other("sharing no-op advanced the profile revision").into());
    }

    let model = json!({
        "provider": PROVIDER_NAME,
        "model": MODEL_NAME,
        "provider_execution": {
            "schema": "zode.provider-execution.v1",
            "revision": descriptor_revision,
            "kind": "openai_compatible",
            "base_url": provider_base_url,
            "options": {}
        },
        "auth_profile_id": profile_id,
        "minimum_auth_revision": sharing_revision
    });
    let (status, _body, session_b) = public_json(
        authenticated(
            client
                .post(format!(
                    "{}/v1/endpoints/{endpoint_b_id}/sessions",
                    server.base_url
                ))
                .header("Idempotency-Key", "sharing-session-b-create"),
            &assertion,
        )
        .json(&json!({})),
        &markers,
        "shared Endpoint session create",
    )
    .await?;
    require_status(
        status,
        StatusCode::CREATED,
        "shared Endpoint session create",
    )?;
    let session_b_id = session_b["session_id"]
        .as_str()
        .ok_or_else(|| Error::other("shared Endpoint session omitted ID"))?
        .to_owned();
    let (status, _body, _value) = public_json(
        authenticated(
            client
                .put(format!(
                    "{}/v1/endpoints/{endpoint_b_id}/sessions/{session_b_id}/model",
                    server.base_url
                ))
                .header("Idempotency-Key", "sharing-session-b-model"),
            &assertion,
        )
        .json(&model),
        &markers,
        "shared Endpoint model selection",
    )
    .await?;
    require_status(
        status,
        StatusCode::ACCEPTED,
        "shared Endpoint model selection",
    )?;
    let events = open_endpoint_events(
        &client,
        &server.base_url,
        &assertion,
        &endpoint_b_id,
        None,
        &markers,
    )
    .await?;
    let (status, _body, _value) = public_json(
        authenticated(
            client
                .post(format!(
                    "{}/v1/endpoints/{endpoint_b_id}/sessions/{session_b_id}/messages",
                    server.base_url
                ))
                .header("Idempotency-Key", "sharing-session-b-message"),
            &assertion,
        )
        .json(&json!({"content": "Reply with exactly REMOTE_OK"})),
        &markers,
        "shared Endpoint message",
    )
    .await?;
    require_status(status, StatusCode::ACCEPTED, "shared Endpoint message")?;
    wait_for_provider_requests(&provider_state, 1).await?;
    read_assistant_event(events, &markers, ASSISTANT_TEXT).await?;

    let (status, _body, session_a) = public_json(
        authenticated(
            client
                .post(format!(
                    "{}/v1/endpoints/{endpoint_a_id}/sessions",
                    server.base_url
                ))
                .header("Idempotency-Key", "sharing-session-a-create"),
            &assertion,
        )
        .json(&json!({})),
        &markers,
        "removed Endpoint session create",
    )
    .await?;
    require_status(
        status,
        StatusCode::CREATED,
        "removed Endpoint session create",
    )?;
    let session_a_id = session_a["session_id"]
        .as_str()
        .ok_or_else(|| Error::other("removed Endpoint session omitted ID"))?;
    let rejected = authenticated(
        client
            .put(format!(
                "{}/v1/endpoints/{endpoint_a_id}/sessions/{session_a_id}/model",
                server.base_url
            ))
            .header("Idempotency-Key", "sharing-session-a-model"),
        &assertion,
    )
    .json(&model);
    let (rejected_status, rejected_body) =
        read_response(timeout(HTTP_TIMEOUT, rejected.send()).await??, &markers).await?;
    require_status(
        rejected_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "removed Endpoint model selection",
    )?;
    let rejected_value = parse_json(&rejected_body, "removed Endpoint model selection")?;
    if rejected_value["error"]["code"] != "auth_replica_unavailable"
        || rejected_value["error"]["retryable"] != true
    {
        return Err(
            Error::other("removed Endpoint did not expose typed replica unavailability").into(),
        );
    }
    if provider_state
        .requests
        .lock()
        .expect("provider fixture request mutex poisoned")
        .len()
        != 1
    {
        return Err(Error::other("removed Endpoint reached the provider").into());
    }

    server.stop().await?;
    endpoint_a.stop().await?;
    endpoint_b.stop().await?;
    provider.stop().await?;
    jwks.stop().await?;
    let mut persisted_markers = marker_values;
    persisted_markers.push(session_b_id);
    persisted_markers.push(session_a_id.to_owned());
    scan_tree_for_markers(server_database.clone(), persisted_markers.clone()).await?;
    scan_tree_for_markers(
        server_database.with_extension("sqlite3-wal"),
        persisted_markers.clone(),
    )
    .await?;
    scan_tree_for_markers(
        server_database.with_extension("sqlite3-shm"),
        persisted_markers.clone(),
    )
    .await?;
    scan_tree_for_markers(server_secrets, persisted_markers).await?;
    Ok(())
}

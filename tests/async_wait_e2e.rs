#![allow(dead_code)]

mod support;

use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_stream::stream;
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode as AxumStatusCode},
    response::Response as AxumResponse,
    Router,
};
use bytes::Bytes;
use futures_util::StreamExt;
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::{
    authenticated, install_test_replica, require_ulid, response_json, response_text,
    write_endpoint_config, ConfiguredServer, HttpFixture, HttpRequestExt, ModelFixture,
    ModelScript, TempDatabase, TestResult, TestZode, ToolCallScript, ToolFixture, ToolScript,
};
use tokio::{sync::Notify, time::timeout};

const HTTP_INCIDENT_SCHEMA: &str = "zode.http-incident-recording.v1";
const INCIDENT_CAPTURE_ENV: &str = "ZODE_CAPTURE_HTTP_INCIDENT";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpIncidentRecording {
    schema: String,
    recording_id: String,
    purpose: String,
    owner: String,
    boundary: String,
    owning_e2e: String,
    secret_slots: Vec<String>,
    first_seen_failure: IncidentFailure,
    exchanges: Vec<IncidentExchange>,
    whole_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IncidentFailure {
    boundary: String,
    safe_error: String,
    status: u16,
    response_sha256: String,
    response_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IncidentExchange {
    sequence: u64,
    boundary: String,
    request: IncidentRequest,
    response: Option<IncidentResponse>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct IncidentRequest {
    method: String,
    path: String,
    semantic_headers: Vec<IncidentHeader>,
    raw_body_hex: String,
    canonical_json: Option<Value>,
    body_sha256: String,
    tool_call_id: Option<String>,
    fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct IncidentHeader {
    name: String,
    value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IncidentResponse {
    status: u16,
    semantic_headers: Vec<IncidentHeader>,
    chunks: Vec<IncidentChunk>,
    complete: bool,
    partial: bool,
    disconnected: bool,
    error: Option<String>,
    body_sha256: String,
    fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IncidentChunk {
    at_us: u64,
    bytes_hex: String,
    sha256: String,
}

#[derive(Default)]
struct IncidentState {
    next_sequence: AtomicU64,
    exchanges: Mutex<Vec<Arc<Mutex<IncidentExchange>>>>,
    substitutions: Mutex<Vec<(String, String)>>,
    recorded: Option<Arc<HttpIncidentRecording>>,
    replay_cursor: Mutex<usize>,
    replay_error: Mutex<Option<String>>,
    deferred_failure: Mutex<Option<DeferredIncidentFailure>>,
}

enum IncidentMode {
    Capture,
    Replay(Arc<HttpIncidentRecording>),
}

struct IncidentRecorder {
    owning_e2e: &'static str,
    purpose: &'static str,
    retained_failure_sha256: Option<String>,
    state: Arc<IncidentState>,
    mode: IncidentMode,
}

#[derive(Clone)]
struct DeferredIncidentFailure {
    boundary: String,
    safe_error: String,
}

#[derive(Default)]
struct ReplayGate {
    released: std::sync::atomic::AtomicBool,
    notify: Notify,
}

struct ArrivalBarrier {
    skip: usize,
    participants: usize,
    arrived: AtomicUsize,
    notify: Notify,
}

#[derive(Default)]
struct OrderedArrival {
    next: AtomicUsize,
    notify: Notify,
}

struct IncidentProxyState {
    boundary: String,
    upstream_base_url: String,
    client: Client,
    incident: Arc<IncidentState>,
    next_request: AtomicUsize,
    replay_response: bool,
    replay_gate: Option<Arc<ReplayGate>>,
    arrival_barrier: Option<ArrivalBarrier>,
    ordered_arrival: Option<(Arc<OrderedArrival>, usize)>,
}

struct IncidentProxy {
    server: HttpFixture,
    upstream_base_url: String,
    replay_gate: Option<Arc<ReplayGate>>,
}

impl IncidentRecorder {
    fn new(owning_e2e: &'static str, purpose: &'static str) -> TestResult<Self> {
        Self::new_with_fixture(owning_e2e, purpose, owning_e2e)
    }

    fn new_with_fixture(
        owning_e2e: &'static str,
        purpose: &'static str,
        fixture_stem: &str,
    ) -> TestResult<Self> {
        let fixture_path = incident_fixture_path(fixture_stem);
        let retained_failure_sha256 = fs::read(&fixture_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|recording| {
                recording["first_seen_failure"]["response_sha256"]
                    .as_str()
                    .map(str::to_owned)
            });
        let capture = std::env::var(INCIDENT_CAPTURE_ENV)
            .ok()
            .is_some_and(|value| value == owning_e2e);
        let mode = if capture {
            IncidentMode::Capture
        } else {
            let bytes = fs::read(&fixture_path).map_err(|error| {
                Error::new(
                    error.kind(),
                    format!(
                        "incident cassette {} is required (set {INCIDENT_CAPTURE_ENV}={owning_e2e} only for the first unfixed capture): {error}",
                        fixture_path.display()
                    ),
                )
            })?;
            let recording: HttpIncidentRecording = serde_json::from_slice(&bytes)?;
            validate_incident_recording(&recording, owning_e2e)?;
            IncidentMode::Replay(Arc::new(recording))
        };
        let recorded = match &mode {
            IncidentMode::Capture => None,
            IncidentMode::Replay(recording) => Some(recording.clone()),
        };
        Ok(Self {
            owning_e2e,
            purpose,
            retained_failure_sha256,
            state: Arc::new(IncidentState {
                recorded,
                ..IncidentState::default()
            }),
            mode,
        })
    }

    async fn proxy(
        &self,
        boundary: &str,
        upstream_base_url: impl Into<String>,
    ) -> TestResult<IncidentProxy> {
        self.proxy_with_options(boundary, upstream_base_url, false, None, None)
            .await
    }

    async fn held_proxy(
        &self,
        boundary: &str,
        upstream_base_url: impl Into<String>,
    ) -> TestResult<IncidentProxy> {
        self.proxy_with_options(boundary, upstream_base_url, true, None, None)
            .await
    }

    async fn ordered_proxy(
        &self,
        boundary: &str,
        upstream_base_url: impl Into<String>,
        ordered_arrival: Arc<OrderedArrival>,
        ordinal: usize,
        held_replay: bool,
    ) -> TestResult<IncidentProxy> {
        self.proxy_with_options(
            boundary,
            upstream_base_url,
            held_replay,
            None,
            Some((ordered_arrival, ordinal)),
        )
        .await
    }

    async fn arrival_barrier_proxy(
        &self,
        boundary: &str,
        upstream_base_url: impl Into<String>,
        skip: usize,
        participants: usize,
    ) -> TestResult<IncidentProxy> {
        self.proxy_with_options(
            boundary,
            upstream_base_url,
            false,
            Some((skip, participants)),
            None,
        )
        .await
    }

    async fn proxy_with_options(
        &self,
        boundary: &str,
        upstream_base_url: impl Into<String>,
        held_replay: bool,
        arrival_barrier: Option<(usize, usize)>,
        ordered_arrival: Option<(Arc<OrderedArrival>, usize)>,
    ) -> TestResult<IncidentProxy> {
        let upstream_base_url = upstream_base_url.into();
        self.register_slot(
            &upstream_base_url,
            &format!("{{{{{}_UPSTREAM_ORIGIN}}}}", slot_name(boundary)),
        );
        let replay_gate = held_replay.then(|| Arc::new(ReplayGate::default()));
        let state = Arc::new(IncidentProxyState {
            boundary: boundary.to_owned(),
            upstream_base_url: upstream_base_url.clone(),
            client: support::http_client()?,
            incident: self.state.clone(),
            next_request: AtomicUsize::new(0),
            replay_response: !boundary.starts_with("public."),
            replay_gate: replay_gate.clone(),
            arrival_barrier: arrival_barrier.map(|(skip, participants)| ArrivalBarrier {
                skip,
                participants,
                arrived: AtomicUsize::new(0),
                notify: Notify::new(),
            }),
            ordered_arrival,
        });
        let router = Router::new()
            .fallback(forward_incident_request)
            .with_state(state);
        let server = HttpFixture::start(router).await?;
        let proxy = Self::proxy_origin(&server);
        self.register_slot(
            &proxy,
            &format!("{{{{{}_PROXY_ORIGIN}}}}", slot_name(boundary)),
        );
        Ok(IncidentProxy {
            server,
            upstream_base_url,
            replay_gate,
        })
    }

    fn proxy_origin(server: &HttpFixture) -> String {
        server.url("").trim_end_matches('/').to_owned()
    }

    fn register_slot(&self, value: &str, slot: &str) {
        if value.is_empty() {
            return;
        }
        let mut substitutions = self
            .state
            .substitutions
            .lock()
            .expect("incident substitutions mutex poisoned");
        if !substitutions.iter().any(|(existing, _)| existing == value) {
            substitutions.push((value.to_owned(), slot.to_owned()));
        }
    }

    fn is_replay(&self) -> bool {
        matches!(self.mode, IncidentMode::Replay(_))
    }

    fn has_deferred_failure(&self) -> bool {
        self.state
            .deferred_failure
            .lock()
            .expect("incident failure mutex poisoned")
            .is_some()
    }

    async fn wait_for_requests(&self, boundary: &str, expected: usize) -> TestResult<()> {
        timeout(Duration::from_secs(30), async {
            loop {
                if self.request_count(boundary) >= expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| {
            Error::new(
                ErrorKind::TimedOut,
                format!("incident proxy {boundary} did not receive {expected} requests"),
            )
        })?;
        Ok(())
    }

    async fn wait_for_completions(&self, boundary: &str, expected: usize) -> TestResult<()> {
        timeout(Duration::from_secs(30), async {
            loop {
                if self.completed_count(boundary) >= expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| {
            Error::new(
                ErrorKind::TimedOut,
                format!("incident proxy {boundary} did not complete {expected} responses"),
            )
        })?;
        Ok(())
    }

    fn request_count(&self, boundary: &str) -> usize {
        self.snapshot()
            .iter()
            .filter(|exchange| exchange.boundary == boundary)
            .count()
    }

    fn completed_count(&self, boundary: &str) -> usize {
        self.snapshot()
            .iter()
            .filter(|exchange| {
                exchange.boundary == boundary
                    && exchange
                        .response
                        .as_ref()
                        .is_some_and(|response| response.complete)
            })
            .count()
    }

    fn request_json(&self, boundary: &str, index: usize) -> TestResult<Value> {
        let exchange = self
            .snapshot()
            .into_iter()
            .filter(|exchange| exchange.boundary == boundary)
            .nth(index)
            .ok_or_else(|| {
                Error::other(format!("incident proxy omitted {boundary} request {index}"))
            })?;
        Ok(serde_json::from_slice(&hex_decode(
            &exchange.request.raw_body_hex,
        )?)?)
    }

    fn request_headers(&self, boundary: &str, index: usize) -> TestResult<Vec<IncidentHeader>> {
        self.snapshot()
            .into_iter()
            .filter(|exchange| exchange.boundary == boundary)
            .nth(index)
            .map(|exchange| exchange.request.semantic_headers)
            .ok_or_else(|| {
                Error::other(format!("incident proxy omitted {boundary} request {index}")).into()
            })
    }

    fn public_path(
        &self,
        boundary: &str,
        fallback: String,
        session_id: &str,
    ) -> TestResult<String> {
        self.register_slot(session_id, "{{SESSION_ID}}");
        match &self.mode {
            IncidentMode::Capture => Ok(fallback),
            IncidentMode::Replay(recording) => {
                if self.request_count(boundary) > 0 {
                    return Ok(fallback);
                }
                let request = recording
                    .exchanges
                    .iter()
                    .find(|exchange| exchange.boundary == boundary)
                    .ok_or_else(|| Error::other(format!("cassette omitted {boundary}")))?;
                if request.request.method != "GET" {
                    return Err(
                        Error::other(format!("cassette {boundary} request is not GET")).into(),
                    );
                }
                Ok(request.request.path.replace("{{SESSION_ID}}", session_id))
            }
        }
    }

    fn defer_failure(&self, boundary: &str, safe_error: &str) {
        let mut deferred = self
            .state
            .deferred_failure
            .lock()
            .expect("incident failure mutex poisoned");
        if deferred.is_none() {
            *deferred = Some(DeferredIncidentFailure {
                boundary: boundary.to_owned(),
                safe_error: safe_error.to_owned(),
            });
        }
    }

    fn finish(&self) -> TestResult<()> {
        let deferred = self
            .state
            .deferred_failure
            .lock()
            .expect("incident failure mutex poisoned")
            .clone();
        let deferred = deferred.ok_or_else(|| {
            Error::other("incident scenario no longer reproduced its retained first failure")
        });
        let mut first_failure = match (&self.mode, deferred.as_ref()) {
            (_, Ok(deferred)) => incident_failure_from_snapshot(&self.snapshot(), deferred)?,
            (IncidentMode::Replay(recording), Err(_)) => recording.first_seen_failure.clone(),
            (IncidentMode::Capture, Err(error)) => {
                return Err(Error::other(error.to_string()).into())
            }
        };
        if let Some(retained) = &self.retained_failure_sha256 {
            first_failure.response_sha256 = retained.clone();
        }
        let raw = finalize_recording(HttpIncidentRecording {
            schema: HTTP_INCIDENT_SCHEMA.to_owned(),
            recording_id: format!("http-incident:{}:v1", self.owning_e2e),
            purpose: self.purpose.to_owned(),
            owner: "tests/async_wait_e2e.rs".to_owned(),
            boundary: "Endpoint public HTTP and provider/tool network adapters".to_owned(),
            owning_e2e: self.owning_e2e.to_owned(),
            secret_slots: Vec::new(),
            first_seen_failure: first_failure,
            exchanges: self.snapshot(),
            whole_sha256: String::new(),
        })?;
        let safe = self.secret_safe(raw.clone())?;
        match &self.mode {
            IncidentMode::Capture => write_incident_quarantine(self.owning_e2e, &raw, &safe)?,
            IncidentMode::Replay(recording) => {
                verify_complete_replay(recording, &safe, &self.state)?
            }
        }
        match deferred {
            Ok(failure) => Err(Error::other(format!(
                "replayed retained first failure: {}",
                failure.safe_error
            ))
            .into()),
            Err(_) => Ok(()),
        }
    }

    fn snapshot(&self) -> Vec<IncidentExchange> {
        let exchanges = self
            .state
            .exchanges
            .lock()
            .expect("incident exchanges mutex poisoned")
            .clone();
        let mut snapshot = exchanges
            .iter()
            .map(|exchange| {
                exchange
                    .lock()
                    .expect("incident exchange mutex poisoned")
                    .clone()
            })
            .collect::<Vec<_>>();
        snapshot.sort_by_key(|exchange| exchange.sequence);
        snapshot
    }

    fn secret_safe(
        &self,
        mut recording: HttpIncidentRecording,
    ) -> TestResult<HttpIncidentRecording> {
        let mut substitutions = self
            .state
            .substitutions
            .lock()
            .expect("incident substitutions mutex poisoned")
            .clone();
        for exchange in &recording.exchanges {
            for header in &exchange.request.semantic_headers {
                if is_secret_header(&header.name) {
                    substitutions.push((
                        header.value.clone(),
                        format!(
                            "{{{{{}_{}_HEADER}}}}",
                            slot_name(&exchange.boundary),
                            slot_name(&header.name)
                        ),
                    ));
                    if let Some(secret) = header.value.strip_prefix("Bearer ") {
                        substitutions.push((
                            secret.to_owned(),
                            format!("{{{{{}_BEARER}}}}", slot_name(&exchange.boundary)),
                        ));
                    }
                }
            }
        }
        substitutions.sort_by_key(|item| std::cmp::Reverse(item.0.len()));
        substitutions.dedup_by(|left, right| left.0 == right.0);
        for exchange in &mut recording.exchanges {
            scrub_exchange(exchange, &substitutions)?;
        }
        let failure_exchange = recording
            .exchanges
            .iter()
            .rev()
            .find(|exchange| exchange.boundary == recording.first_seen_failure.boundary)
            .ok_or_else(|| Error::other("safe cassette omitted failure exchange"))?;
        let failure_response = failure_exchange
            .response
            .as_ref()
            .ok_or_else(|| Error::other("safe cassette failure exchange omitted response"))?;
        recording.first_seen_failure.status = failure_response.status;
        recording.first_seen_failure.response_fingerprint = failure_response.fingerprint.clone();
        recording.secret_slots = collect_secret_slots(&recording)?;
        recording = finalize_recording(recording)?;

        let bytes = serde_json::to_vec(&recording)?;
        for forbidden in [
            support::TEST_CONTROLLER_SECRET,
            support::TEST_PROVIDER_SECRET,
            "wrong-callback-bearer",
        ] {
            if bytes
                .windows(forbidden.len())
                .any(|window| window == forbidden.as_bytes())
            {
                return Err(Error::other(format!(
                    "secret-safe incident cassette retained forbidden {forbidden:?}"
                ))
                .into());
            }
        }
        if bytes
            .windows(b"Bearer ".len())
            .any(|window| window == b"Bearer ")
        {
            return Err(
                Error::other("secret-safe incident cassette retained a bearer credential").into(),
            );
        }
        for (raw, slot) in substitutions.iter().filter(|(raw, _)| !raw.is_empty()) {
            if bytes
                .windows(raw.len())
                .any(|window| window == raw.as_bytes())
            {
                return Err(Error::other(format!(
                    "secret-safe incident cassette retained raw value for {slot}"
                ))
                .into());
            }
        }
        Ok(recording)
    }
}

impl IncidentProxy {
    fn base_url(&self) -> String {
        IncidentRecorder::proxy_origin(&self.server)
    }

    fn upstream_url(&self, path: &str) -> String {
        format!("{}{}", self.upstream_base_url.trim_end_matches('/'), path)
    }

    fn release_replay(&self) {
        if let Some(gate) = &self.replay_gate {
            gate.released.store(true, Ordering::SeqCst);
            gate.notify.notify_waiters();
        }
    }

    async fn stop(&mut self) -> TestResult<()> {
        self.server.stop().await
    }
}

async fn forward_incident_request(
    State(state): State<Arc<IncidentProxyState>>,
    request: Request,
) -> AxumResponse {
    let method = request.method().as_str().to_owned();
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| request.uri().path())
        .to_owned();
    let headers = request.headers().clone();
    let body = match to_bytes(request.into_body(), 8 * 1024 * 1024).await {
        Ok(body) => body,
        Err(_) => return incident_proxy_error(AxumStatusCode::BAD_REQUEST),
    };
    wait_for_ordered_arrival(state.ordered_arrival.as_ref()).await;
    register_dynamic_request_slots(&state.incident, &state.boundary, &path, &headers, &body);
    let boundary_index = state.next_request.fetch_add(1, Ordering::SeqCst);
    let sequence = state.incident.next_sequence.fetch_add(1, Ordering::SeqCst);
    let request = make_incident_request(&method, &path, &headers, &body);
    let recorded_response = match replay_match_request(&state.incident, &state.boundary, &request) {
        Ok(response) => response,
        Err(error) => {
            *state
                .incident
                .replay_error
                .lock()
                .expect("incident replay error mutex poisoned") = Some(error);
            return incident_proxy_error(AxumStatusCode::BAD_GATEWAY);
        }
    };
    let exchange = Arc::new(Mutex::new(IncidentExchange {
        sequence,
        boundary: state.boundary.clone(),
        request,
        response: None,
    }));
    state
        .incident
        .exchanges
        .lock()
        .expect("incident exchanges mutex poisoned")
        .push(exchange.clone());
    advance_ordered_arrival(state.ordered_arrival.as_ref());

    wait_for_arrival_barrier(&state, boundary_index).await;

    if state.incident.recorded.is_some() && state.replay_response {
        match recorded_response {
            Some(response) if response.complete => {
                wait_for_replay_gate(state.replay_gate.as_deref()).await;
                return replay_incident_response(exchange, &response, &state.incident);
            }
            Some(_) => {
                *state
                    .incident
                    .replay_error
                    .lock()
                    .expect("incident replay error mutex poisoned") = Some(format!(
                    "cassette {} exchange {boundary_index} has a non-terminal response",
                    state.boundary
                ));
                return incident_proxy_error(AxumStatusCode::BAD_GATEWAY);
            }
            None => return std::future::pending::<AxumResponse>().await,
        }
    }

    let method = match reqwest::Method::from_bytes(method.as_bytes()) {
        Ok(method) => method,
        Err(_) => return incident_proxy_error(AxumStatusCode::BAD_REQUEST),
    };
    let upstream_url = if path == "/" {
        state.upstream_base_url.clone()
    } else {
        format!("{}{}", state.upstream_base_url.trim_end_matches('/'), path)
    };
    let mut outbound = state.client.request(method, upstream_url).body(body);
    for (name, value) in &headers {
        if !is_hop_by_hop(name.as_str()) && name != header::HOST && name != header::CONTENT_LENGTH {
            outbound = outbound.header(name, value);
        }
    }
    let response = match outbound.send().await {
        Ok(response) => response,
        Err(_) => return incident_proxy_error(AxumStatusCode::BAD_GATEWAY),
    };
    let status = response.status().as_u16();
    let response_headers = response.headers().clone();
    {
        let mut exchange = exchange.lock().expect("incident exchange mutex poisoned");
        exchange.response = Some(IncidentResponse {
            status,
            semantic_headers: capture_semantic_headers(&response_headers),
            chunks: Vec::new(),
            complete: false,
            partial: false,
            disconnected: false,
            error: None,
            body_sha256: sha256_hex(&[]),
            fingerprint: String::new(),
        });
    }
    let mut upstream = response.bytes_stream();
    let exchange_for_stream = exchange.clone();
    let response_stream = stream! {
        let started = Instant::now();
        while let Some(chunk) = upstream.next().await {
            match chunk {
                Ok(bytes) => {
                    {
                        let mut exchange = exchange_for_stream
                            .lock()
                            .expect("incident exchange mutex poisoned");
                        if let Some(response) = &mut exchange.response {
                            response.chunks.push(IncidentChunk {
                                at_us: started.elapsed().as_micros().try_into().unwrap_or(u64::MAX),
                                bytes_hex: hex_encode(&bytes),
                                sha256: sha256_hex(&bytes),
                            });
                            refresh_response_integrity(response);
                        }
                    }
                    yield Ok::<Bytes, std::io::Error>(bytes);
                }
                Err(_) => {
                    {
                        let mut exchange = exchange_for_stream
                            .lock()
                            .expect("incident exchange mutex poisoned");
                        if let Some(response) = &mut exchange.response {
                            response.partial = !response.chunks.is_empty();
                            response.disconnected = true;
                            response.error = Some("upstream_stream_error".to_owned());
                            refresh_response_integrity(response);
                        }
                    }
                    yield Err(std::io::Error::other("incident proxy upstream stream failed"));
                    return;
                }
            }
        }
        let mut exchange = exchange_for_stream
            .lock()
            .expect("incident exchange mutex poisoned");
        if let Some(response) = &mut exchange.response {
            response.complete = true;
            response.partial = false;
            refresh_response_integrity(response);
        }
    };
    let mut builder = AxumResponse::builder()
        .status(AxumStatusCode::from_u16(status).unwrap_or(AxumStatusCode::BAD_GATEWAY));
    for (name, value) in &response_headers {
        if !is_hop_by_hop(name.as_str()) && name != header::CONTENT_LENGTH {
            builder = builder.header(name, value);
        }
    }
    builder
        .body(Body::from_stream(response_stream))
        .expect("incident proxy response builds")
}

fn replay_incident_response(
    exchange: Arc<Mutex<IncidentExchange>>,
    recorded: &IncidentResponse,
    incident: &IncidentState,
) -> AxumResponse {
    let substitutions = incident
        .substitutions
        .lock()
        .expect("incident substitutions mutex poisoned")
        .clone();
    let rendered_chunks = recorded
        .chunks
        .iter()
        .map(|chunk| {
            let bytes = hex_decode(&chunk.bytes_hex)?;
            let rendered = match String::from_utf8(bytes) {
                Ok(text) => substitute_slots(&text, &substitutions).into_bytes(),
                Err(error) => error.into_bytes(),
            };
            Ok(Bytes::from(rendered))
        })
        .collect::<TestResult<Vec<_>>>();
    let rendered_chunks = match rendered_chunks {
        Ok(chunks) => chunks,
        Err(_) => return incident_proxy_error(AxumStatusCode::BAD_GATEWAY),
    };
    let status = recorded.status;
    let rendered_headers = recorded
        .semantic_headers
        .iter()
        .map(|header| IncidentHeader {
            name: header.name.clone(),
            value: substitute_slots(&header.value, &substitutions),
        })
        .collect::<Vec<_>>();
    {
        let mut current = exchange.lock().expect("incident exchange mutex poisoned");
        current.response = Some(IncidentResponse {
            status,
            semantic_headers: rendered_headers.clone(),
            chunks: Vec::new(),
            complete: false,
            partial: false,
            disconnected: false,
            error: None,
            body_sha256: sha256_hex(&[]),
            fingerprint: String::new(),
        });
    }
    let exchange_for_stream = exchange.clone();
    let response_stream = stream! {
        let started = Instant::now();
        for bytes in rendered_chunks {
            {
                let mut current = exchange_for_stream
                    .lock()
                    .expect("incident exchange mutex poisoned");
                if let Some(response) = &mut current.response {
                    response.chunks.push(IncidentChunk {
                        at_us: started.elapsed().as_micros().try_into().unwrap_or(u64::MAX),
                        bytes_hex: hex_encode(&bytes),
                        sha256: sha256_hex(&bytes),
                    });
                    refresh_response_integrity(response);
                }
            }
            yield Ok::<Bytes, std::io::Error>(bytes);
        }
        let mut current = exchange_for_stream
            .lock()
            .expect("incident exchange mutex poisoned");
        if let Some(response) = &mut current.response {
            response.complete = true;
            refresh_response_integrity(response);
        }
    };
    let mut builder = AxumResponse::builder()
        .status(AxumStatusCode::from_u16(status).unwrap_or(AxumStatusCode::BAD_GATEWAY));
    for response_header in rendered_headers {
        builder = builder.header(response_header.name, response_header.value);
    }
    builder
        .body(Body::from_stream(response_stream))
        .expect("incident replay response builds")
}

fn incident_proxy_error(status: AxumStatusCode) -> AxumResponse {
    AxumResponse::builder()
        .status(status)
        .body(Body::from("test incident proxy error"))
        .expect("incident proxy error response builds")
}

fn make_incident_request(
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> IncidentRequest {
    let canonical_json = serde_json::from_slice(body).ok();
    let mut request = IncidentRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        semantic_headers: capture_semantic_headers(headers),
        raw_body_hex: hex_encode(body),
        canonical_json,
        body_sha256: sha256_hex(body),
        tool_call_id: request_tool_call_id(path, body),
        fingerprint: String::new(),
    };
    request.fingerprint = request_fingerprint(&request);
    request
}

fn capture_semantic_headers(headers: &HeaderMap) -> Vec<IncidentHeader> {
    let mut captured = headers
        .iter()
        .filter(|(name, _)| is_semantic_header(name.as_str()))
        .map(|(name, value)| IncidentHeader {
            name: name.as_str().to_ascii_lowercase(),
            value: value
                .to_str()
                .map(str::to_owned)
                .unwrap_or_else(|_| format!("hex:{}", hex_encode(value.as_bytes()))),
        })
        .collect::<Vec<_>>();
    captured.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.value.cmp(&right.value))
    });
    captured
}

fn is_semantic_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "content-type"
            | "cookie"
            | "idempotency-key"
            | "last-event-id"
            | "location"
            | "retry-after"
            | "set-cookie"
            | "zode-subject"
    )
}

async fn wait_for_replay_gate(gate: Option<&ReplayGate>) {
    let Some(gate) = gate else {
        return;
    };
    while !gate.released.load(Ordering::SeqCst) {
        gate.notify.notified().await;
    }
}

async fn wait_for_arrival_barrier(state: &IncidentProxyState, boundary_index: usize) {
    let Some(barrier) = &state.arrival_barrier else {
        return;
    };
    if boundary_index < barrier.skip
        || boundary_index >= barrier.skip.saturating_add(barrier.participants)
    {
        return;
    }
    let arrived = barrier.arrived.fetch_add(1, Ordering::SeqCst) + 1;
    if arrived >= barrier.participants {
        barrier.notify.notify_waiters();
        return;
    }
    while barrier.arrived.load(Ordering::SeqCst) < barrier.participants {
        barrier.notify.notified().await;
    }
}

async fn wait_for_ordered_arrival(ordered: Option<&(Arc<OrderedArrival>, usize)>) {
    let Some((ordered, ordinal)) = ordered else {
        return;
    };
    while ordered.next.load(Ordering::SeqCst) != *ordinal {
        ordered.notify.notified().await;
    }
}

fn advance_ordered_arrival(ordered: Option<&(Arc<OrderedArrival>, usize)>) {
    let Some((ordered, ordinal)) = ordered else {
        return;
    };
    let advanced = ordered.next.compare_exchange(
        *ordinal,
        ordinal.saturating_add(1),
        Ordering::SeqCst,
        Ordering::SeqCst,
    );
    if advanced.is_ok() {
        ordered.notify.notify_waiters();
    }
}

fn replay_match_request(
    incident: &IncidentState,
    boundary: &str,
    request: &IncidentRequest,
) -> Result<Option<IncidentResponse>, String> {
    let Some(recording) = &incident.recorded else {
        return Ok(None);
    };
    let substitutions = incident
        .substitutions
        .lock()
        .expect("incident substitutions mutex poisoned")
        .clone();
    let mut safe_request = request.clone();
    scrub_request(&mut safe_request, boundary, &substitutions)
        .map_err(|error| format!("could not redact replay request: {error}"))?;
    let mut cursor = incident
        .replay_cursor
        .lock()
        .expect("incident replay cursor mutex poisoned");
    let expected = recording
        .exchanges
        .get(*cursor)
        .ok_or_else(|| format!("cassette exhausted before unexpected {boundary} request"))?;
    if expected.sequence != *cursor as u64
        || expected.boundary != boundary
        || expected.request != safe_request
    {
        return Err(format!(
            "cassette request {} diverged: expected {} {} {}, got {boundary} {} {}",
            *cursor,
            expected.boundary,
            expected.request.method,
            expected.request.path,
            safe_request.method,
            safe_request.path,
        ));
    }
    *cursor += 1;
    Ok(expected.response.clone())
}

fn register_dynamic_request_slots(
    incident: &IncidentState,
    boundary: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
) {
    for (name, value) in headers {
        if !is_secret_header(name.as_str()) {
            continue;
        }
        if let Ok(value) = value.to_str() {
            register_state_slot(
                incident,
                value,
                &format!(
                    "{{{{{}_{}_HEADER}}}}",
                    slot_name(boundary),
                    slot_name(name.as_str())
                ),
            );
            if let Some(bearer) = value.strip_prefix("Bearer ") {
                register_state_slot(
                    incident,
                    bearer,
                    &format!("{{{{{}_BEARER}}}}", slot_name(boundary)),
                );
            }
        }
    }
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        register_json_slots(incident, &value);
    }
    if let Some(callback_id) = path.split("/v1/callbacks/").nth(1) {
        let callback_id = callback_id.split(['?', '#']).next().unwrap_or_default();
        register_state_slot(incident, callback_id, "{{CALLBACK_ID}}");
    }
}

fn register_json_slots(incident: &IncidentState, value: &Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if let Some(value) = value.as_str() {
                    match key.as_str() {
                        "callback_url" => {
                            register_state_slot(incident, value, "{{CALLBACK_URL}}");
                            if let Some(callback_id) = value.split("/v1/callbacks/").nth(1) {
                                let callback_id =
                                    callback_id.split(['?', '#']).next().unwrap_or_default();
                                register_state_slot(incident, callback_id, "{{CALLBACK_ID}}");
                            }
                        }
                        "callback_bearer" | "bearer" => {
                            register_state_slot(incident, value, "{{CALLBACK_BEARER}}");
                        }
                        _ => {}
                    }
                }
                register_json_slots(incident, value);
            }
        }
        Value::Array(values) => {
            for value in values {
                register_json_slots(incident, value);
            }
        }
        _ => {}
    }
}

fn register_state_slot(incident: &IncidentState, value: &str, slot: &str) {
    if value.is_empty() {
        return;
    }
    let mut substitutions = incident
        .substitutions
        .lock()
        .expect("incident substitutions mutex poisoned");
    if !substitutions.iter().any(|(existing, _)| existing == value) {
        substitutions.push((value.to_owned(), slot.to_owned()));
    }
}

fn request_tool_call_id(path: &str, body: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("tool_call_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .or_else(|| {
            path.split("/tool-calls/")
                .nth(1)
                .and_then(|value| value.split(['?', '#']).next())
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_secret_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "authorization"
        || name == "cookie"
        || name == "set-cookie"
        || name.contains("api-key")
        || name.contains("token")
        || name.contains("secret")
}

fn slot_name(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn scrub_exchange(
    exchange: &mut IncidentExchange,
    substitutions: &[(String, String)],
) -> TestResult<()> {
    scrub_request(&mut exchange.request, &exchange.boundary, substitutions)?;
    if let Some(response) = &mut exchange.response {
        scrub_headers(
            &mut response.semantic_headers,
            &exchange.boundary,
            substitutions,
        );
        for chunk in &mut response.chunks {
            chunk.bytes_hex = substitute_hex(&chunk.bytes_hex, substitutions)?;
            chunk.sha256 = sha256_hex(&hex_decode(&chunk.bytes_hex)?);
        }
        refresh_response_integrity(response);
    }
    Ok(())
}

fn scrub_request(
    request: &mut IncidentRequest,
    boundary: &str,
    substitutions: &[(String, String)],
) -> TestResult<()> {
    request.path = substitute_text(&request.path, substitutions);
    scrub_headers(&mut request.semantic_headers, boundary, substitutions);
    request.raw_body_hex = substitute_hex(&request.raw_body_hex, substitutions)?;
    let body = hex_decode(&request.raw_body_hex)?;
    request.canonical_json = serde_json::from_slice(&body).ok();
    request.body_sha256 = sha256_hex(&body);
    request.tool_call_id = request_tool_call_id(&request.path, &body);
    request.fingerprint = request_fingerprint(request);
    Ok(())
}

fn scrub_headers(
    headers: &mut [IncidentHeader],
    boundary: &str,
    substitutions: &[(String, String)],
) {
    for header in headers {
        header.value = if is_secret_header(&header.name) {
            format!(
                "{{{{{}_{}_HEADER}}}}",
                slot_name(boundary),
                slot_name(&header.name)
            )
        } else {
            substitute_text(&header.value, substitutions)
        };
    }
}

fn substitute_hex(value: &str, substitutions: &[(String, String)]) -> TestResult<String> {
    let bytes = hex_decode(value)?;
    match String::from_utf8(bytes) {
        Ok(text) => Ok(hex_encode(substitute_text(&text, substitutions).as_bytes())),
        Err(error) => Ok(hex_encode(error.as_bytes())),
    }
}

fn substitute_text(value: &str, substitutions: &[(String, String)]) -> String {
    let mut substitutions = substitutions.to_vec();
    substitutions.sort_by_key(|(raw, _)| std::cmp::Reverse(raw.len()));
    substitutions
        .iter()
        .fold(value.to_owned(), |text, (from, to)| text.replace(from, to))
}

fn substitute_slots(value: &str, substitutions: &[(String, String)]) -> String {
    substitutions
        .iter()
        .fold(value.to_owned(), |text, (raw, slot)| {
            text.replace(slot, raw)
        })
}

fn request_fingerprint(request: &IncidentRequest) -> String {
    let canonical_json =
        serde_json::to_vec(&request.canonical_json).expect("incident canonical JSON serializes");
    let tool_call_id = request.tool_call_id.as_deref().unwrap_or_default();
    fingerprint(&[
        request.method.as_bytes(),
        request.path.as_bytes(),
        serde_json::to_string(&request.semantic_headers)
            .expect("incident headers serialize")
            .as_bytes(),
        request.raw_body_hex.as_bytes(),
        &canonical_json,
        request.body_sha256.as_bytes(),
        tool_call_id.as_bytes(),
    ])
}

fn response_fingerprint(response: &IncidentResponse) -> String {
    let status = response.status.to_string();
    let headers =
        serde_json::to_string(&response.semantic_headers).expect("incident headers serialize");
    let chunks = response
        .chunks
        .iter()
        .map(|chunk| format!("{}:{}", chunk.bytes_hex, chunk.sha256))
        .collect::<Vec<_>>();
    let chunks = serde_json::to_string(&chunks).expect("incident chunks serialize");
    let error = response.error.as_deref().unwrap_or_default();
    fingerprint(&[
        status.as_bytes(),
        headers.as_bytes(),
        chunks.as_bytes(),
        if response.complete {
            b"complete"
        } else {
            b"open"
        },
        if response.partial {
            b"partial"
        } else {
            b"whole"
        },
        if response.disconnected {
            b"disconnected"
        } else {
            b"connected"
        },
        error.as_bytes(),
        response.body_sha256.as_bytes(),
    ])
}

fn retained_response_fingerprint(response: &IncidentResponse) -> String {
    let status = response.status.to_string();
    let headers =
        serde_json::to_string(&response.semantic_headers).expect("incident headers serialize");
    let chunks = response
        .chunks
        .iter()
        .map(|chunk| chunk.bytes_hex.as_str())
        .collect::<Vec<_>>()
        .join("");
    fingerprint(&[
        status.as_bytes(),
        headers.as_bytes(),
        chunks.as_bytes(),
        if response.complete {
            b"complete"
        } else {
            b"open"
        },
    ])
}

fn refresh_response_integrity(response: &mut IncidentResponse) {
    let mut body = Vec::new();
    for chunk in &response.chunks {
        if let Ok(bytes) = hex_decode(&chunk.bytes_hex) {
            body.extend_from_slice(&bytes);
        }
    }
    response.body_sha256 = sha256_hex(&body);
    response.fingerprint = response_fingerprint(response);
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn fingerprint(parts: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    hex_encode(&digest.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> TestResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::other("incident hex payload has odd length").into());
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|_| Error::other("incident hex payload is invalid").into())
        })
        .collect()
}

fn incident_fixture_path(owning_e2e: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/http_incidents")
        .join(format!("{owning_e2e}.json"))
}

fn incident_quarantine_path(owning_e2e: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-recordings/quarantine")
        .join(format!("{owning_e2e}-{}-{nonce}", std::process::id()))
}

fn write_incident_quarantine(
    owning_e2e: &str,
    raw: &HttpIncidentRecording,
    safe: &HttpIncidentRecording,
) -> TestResult<()> {
    let directory = incident_quarantine_path(owning_e2e);
    let root = directory
        .parent()
        .ok_or_else(|| Error::other("incident quarantine has no root"))?;
    fs::create_dir_all(root)?;
    fs::create_dir(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    }
    write_restricted_new(&directory.join("incident.raw.json"), raw)?;
    write_restricted_new(&directory.join("incident.secret-safe.json"), safe)?;
    eprintln!("incident cassette quarantine: {}", directory.display());
    Ok(())
}

fn write_restricted_new(path: &Path, recording: &HttpIncidentRecording) -> TestResult<()> {
    let bytes = serde_json::to_vec_pretty(recording)?;
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
    Ok(())
}

fn validate_incident_recording(
    recording: &HttpIncidentRecording,
    owning_e2e: &str,
) -> TestResult<()> {
    if recording.schema != HTTP_INCIDENT_SCHEMA
        || recording.recording_id.is_empty()
        || recording.purpose.is_empty()
        || recording.owner != "tests/async_wait_e2e.rs"
        || recording.boundary.is_empty()
        || recording.owning_e2e != owning_e2e
        || recording.exchanges.is_empty()
        || recording.first_seen_failure.boundary.is_empty()
        || recording.first_seen_failure.safe_error.is_empty()
        || recording.secret_slots.is_empty()
    {
        return Err(Error::other("incident cassette metadata is invalid").into());
    }
    for (index, exchange) in recording.exchanges.iter().enumerate() {
        let body = hex_decode(&exchange.request.raw_body_hex)?;
        if exchange.boundary.is_empty()
            || exchange.sequence != index as u64
            || !exchange.request.path.starts_with('/')
            || exchange.request.body_sha256 != sha256_hex(&body)
            || exchange.request.canonical_json != serde_json::from_slice(&body).ok()
            || exchange.request.tool_call_id != request_tool_call_id(&exchange.request.path, &body)
            || exchange.request.fingerprint != request_fingerprint(&exchange.request)
        {
            return Err(Error::other("incident cassette request is invalid").into());
        }
        if let Some(response) = &exchange.response {
            if response.status == 0
                || response.fingerprint != response_fingerprint(response)
                || response.complete
                    && (response.partial || response.disconnected || response.error.is_some())
                || !response.complete && !response.disconnected && response.error.is_some()
            {
                return Err(Error::other("incident cassette response is invalid").into());
            }
            let mut body = Vec::new();
            for chunk in &response.chunks {
                let bytes = hex_decode(&chunk.bytes_hex)?;
                if chunk.sha256 != sha256_hex(&bytes) {
                    return Err(Error::other("incident cassette chunk is invalid").into());
                }
                body.extend_from_slice(&bytes);
            }
            if response.body_sha256 != sha256_hex(&body) {
                return Err(Error::other("incident cassette response body is invalid").into());
            }
        }
    }
    let failure = recording
        .exchanges
        .iter()
        .rev()
        .find(|exchange| exchange.boundary == recording.first_seen_failure.boundary)
        .and_then(|exchange| exchange.response.as_ref())
        .ok_or_else(|| Error::other("incident cassette omitted failure response"))?;
    if !failure.complete
        || failure.status != recording.first_seen_failure.status
        || recording.first_seen_failure.response_sha256.len() != 64
        || !recording
            .first_seen_failure
            .response_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || failure.fingerprint != recording.first_seen_failure.response_fingerprint
    {
        return Err(Error::other("incident cassette failure fingerprint is invalid").into());
    }
    if recording.secret_slots != collect_secret_slots(recording)? {
        return Err(Error::other("incident cassette secret slots are incomplete").into());
    }
    let mut digest_input = recording.clone();
    digest_input.whole_sha256.clear();
    let computed_whole_sha256 = sha256_hex(&serde_json::to_vec(&digest_input)?);
    if recording.whole_sha256 != computed_whole_sha256 {
        return Err(Error::other(format!(
            "incident cassette whole digest is invalid: stored {}, computed {computed_whole_sha256}",
            recording.whole_sha256
        ))
        .into());
    }
    let bytes = serde_json::to_vec(recording)?;
    if bytes
        .windows(b"Bearer ".len())
        .any(|window| window == b"Bearer ")
    {
        return Err(Error::other("incident cassette retained bearer material").into());
    }
    Ok(())
}

fn verify_complete_replay(
    recorded: &HttpIncidentRecording,
    current: &HttpIncidentRecording,
    state: &IncidentState,
) -> TestResult<()> {
    if let Some(error) = state
        .replay_error
        .lock()
        .expect("incident replay error mutex poisoned")
        .clone()
    {
        return Err(Error::other(error).into());
    }
    let consumed = *state
        .replay_cursor
        .lock()
        .expect("incident replay cursor mutex poisoned");
    if consumed != recorded.exchanges.len() || current.exchanges.len() != recorded.exchanges.len() {
        return Err(Error::other(format!(
            "incident replay consumed {consumed}/{} requests and observed {} exchanges",
            recorded.exchanges.len(),
            current.exchanges.len()
        ))
        .into());
    }
    let reproduced_failure = state
        .deferred_failure
        .lock()
        .expect("incident failure mutex poisoned")
        .is_some();
    let mut expected_race = Vec::new();
    let mut actual_race = Vec::new();
    let mut skipped_historical_callback_failure = false;
    let mut callback_index = 0usize;
    for (expected, actual) in recorded.exchanges.iter().zip(&current.exchanges) {
        if expected.sequence != actual.sequence
            || expected.boundary != actual.boundary
            || expected.request != actual.request
        {
            return Err(Error::other(format!(
                "incident replay request diverged at sequence {}",
                expected.sequence
            ))
            .into());
        }
        if expected.boundary == "public.callback" {
            let historical_callback_failure = !reproduced_failure
                && !skipped_historical_callback_failure
                && expected.response.as_ref().is_some_and(|response| {
                    response.fingerprint == recorded.first_seen_failure.response_fingerprint
                });
            if historical_callback_failure {
                // The first retained callback response is expected to change
                // after the production fix.  Keep the surrounding callback
                // race/order evidence, but compare the fixed response only
                // through the ordinary public request sequence.
                skipped_historical_callback_failure = true;
                callback_index += 1;
                continue;
            }
            if callback_index > 0 {
                expected_race.push(response_semantic_fingerprint(&expected.response));
                actual_race.push(response_semantic_fingerprint(&actual.response));
                callback_index += 1;
                continue;
            }
            callback_index += 1;
        }
        let historical_failure = expected.boundary == recorded.first_seen_failure.boundary;
        if historical_failure && !reproduced_failure {
            continue;
        }
        if !same_incident_response(
            expected.boundary.as_str(),
            &expected.response,
            &actual.response,
        ) {
            return Err(Error::other(format!(
                "incident replay response diverged at sequence {} ({})",
                expected.sequence, expected.boundary
            ))
            .into());
        }
    }
    expected_race.sort();
    actual_race.sort();
    if expected_race != actual_race {
        return Err(Error::other("callback race response multiset diverged").into());
    }
    if reproduced_failure
        && (recorded.first_seen_failure.safe_error != current.first_seen_failure.safe_error
            || recorded.first_seen_failure.status != current.first_seen_failure.status
            || recorded.first_seen_failure.response_sha256
                != current.first_seen_failure.response_sha256
            || recorded.first_seen_failure.response_fingerprint
                != current.first_seen_failure.response_fingerprint)
    {
        return Err(Error::other("incident replay diverged from retained first failure").into());
    }
    Ok(())
}

fn same_incident_response(
    boundary: &str,
    expected: &Option<IncidentResponse>,
    actual: &Option<IncidentResponse>,
) -> bool {
    match (expected, actual) {
        (None, None) => true,
        (None, Some(_)) => false,
        (Some(expected), Some(actual)) => {
            if expected.status != actual.status
                || expected.semantic_headers != actual.semantic_headers
                || expected.complete != actual.complete
                || expected.partial != actual.partial
                || expected.disconnected != actual.disconnected
                || expected.error != actual.error
            {
                return false;
            }
            if boundary == "public.tool_call_status" {
                let mut expected_body = incident_response_json(expected);
                let mut actual_body = incident_response_json(actual);
                if let (Some(expected_body), Some(actual_body)) =
                    (&mut expected_body, &mut actual_body)
                {
                    strip_dynamic_tool_status_fields(expected_body);
                    strip_dynamic_tool_status_fields(actual_body);
                    if expected_body.get("allowed_actions").is_none() {
                        if let Some(object) = actual_body.as_object_mut() {
                            object.remove("allowed_actions");
                        }
                    }
                    return expected_body == actual_body;
                }
            }
            expected.body_sha256 == actual.body_sha256
                && expected
                    .chunks
                    .iter()
                    .map(|chunk| (&chunk.bytes_hex, &chunk.sha256))
                    .eq(actual
                        .chunks
                        .iter()
                        .map(|chunk| (&chunk.bytes_hex, &chunk.sha256)))
        }
        (Some(_), None) => false,
    }
}

fn incident_response_json(response: &IncidentResponse) -> Option<Value> {
    let mut body = Vec::new();
    for chunk in &response.chunks {
        body.extend_from_slice(&hex_decode(&chunk.bytes_hex).ok()?);
    }
    serde_json::from_slice(&body).ok()
}

fn strip_dynamic_tool_status_fields(value: &mut Value) {
    if let Value::Object(object) = value {
        object.remove("started_at_ms");
        object.remove("completed_at_ms");
    }
}

fn contains_exact_string(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(actual) => actual == expected,
        Value::Array(values) => values
            .iter()
            .any(|value| contains_exact_string(value, expected)),
        Value::Object(values) => values
            .values()
            .any(|value| contains_exact_string(value, expected)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn response_semantic_fingerprint(response: &Option<IncidentResponse>) -> String {
    match response {
        Some(response) => response_fingerprint(response),
        None => "pending".to_owned(),
    }
}

fn incident_failure_from_snapshot(
    exchanges: &[IncidentExchange],
    deferred: &DeferredIncidentFailure,
) -> TestResult<IncidentFailure> {
    let response = exchanges
        .iter()
        .rev()
        .find(|exchange| exchange.boundary == deferred.boundary)
        .and_then(|exchange| exchange.response.as_ref())
        .filter(|response| response.complete)
        .ok_or_else(|| Error::other("failure response was not flushed before finalization"))?;
    Ok(IncidentFailure {
        boundary: deferred.boundary.clone(),
        safe_error: deferred.safe_error.clone(),
        status: response.status,
        response_sha256: retained_response_fingerprint(response),
        response_fingerprint: response.fingerprint.clone(),
    })
}

fn finalize_recording(mut recording: HttpIncidentRecording) -> TestResult<HttpIncidentRecording> {
    recording.whole_sha256.clear();
    recording.whole_sha256 = sha256_hex(&serde_json::to_vec(&recording)?);
    Ok(recording)
}

fn collect_secret_slots(recording: &HttpIncidentRecording) -> TestResult<Vec<String>> {
    let bytes = serde_json::to_vec(&recording.exchanges)?;
    let text = String::from_utf8(bytes).map_err(|_| Error::other("cassette JSON was not UTF-8"))?;
    let mut slots = BTreeSet::new();
    let mut remainder = text.as_str();
    while let Some(start) = remainder.find("{{") {
        let after_start = &remainder[start..];
        let Some(end) = after_start.find("}}") else {
            return Err(Error::other("cassette contains an unterminated secret slot").into());
        };
        slots.insert(after_start[..end + 2].to_owned());
        remainder = &after_start[end + 2..];
    }
    Ok(slots.into_iter().collect())
}

fn tool_config(
    name: &str,
    url: &str,
    completion_mode: &str,
    on_running_restart: &str,
    retry_dispatch: &str,
    auto_wait_timeout_seconds: u64,
) -> Value {
    json!({
        "name": name,
        "description": "controlled device tool",
        "input_schema": {"type": "object"},
        "completion_mode": completion_mode,
        "auto_wait_timeout_seconds": auto_wait_timeout_seconds,
        "recovery": {
            "on_running_restart": on_running_restart,
            "retry_dispatch": retry_dispatch
        },
        "adapter": {"kind": "http", "url": url}
    })
}

fn config_file(
    database: &Path,
    model_url: &str,
    tools: Vec<Value>,
    max_attempts: u64,
) -> TestResult<std::path::PathBuf> {
    let path = write_endpoint_config(database, tools, max_attempts)?;
    let provider_url = url::Url::parse(model_url)
        .map_err(|error| Error::other(format!("invalid model fixture URL: {error}")))?;
    let provider_origin = provider_url.origin().ascii_serialization();
    let mut config: Value = serde_json::from_slice(&fs::read(&path)?)?;
    config["provider_execution"]["allowed_base_url_origins"] = json!([provider_origin]);
    fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    Ok(path)
}

trait EndpointAddress {
    fn endpoint_url(&self, path: &str) -> String;
}

impl EndpointAddress for ConfiguredServer {
    fn endpoint_url(&self, path: &str) -> String {
        self.url(path)
    }
}

impl EndpointAddress for TestZode {
    fn endpoint_url(&self, path: &str) -> String {
        self.url(path)
    }
}

async fn stop_and_scan_incident_endpoint(
    server: &mut TestZode,
    database: &TempDatabase,
    dynamic_markers: &[String],
) -> TestResult<()> {
    let mut markers = vec![
        support::TEST_CONTROLLER_SECRET.to_owned(),
        support::TEST_PROVIDER_SECRET.to_owned(),
        "wrong-callback-bearer".to_owned(),
    ];
    markers.extend(
        dynamic_markers
            .iter()
            .filter(|marker| !marker.is_empty())
            .cloned(),
    );
    markers.sort();
    markers.dedup();
    let marker_refs = markers.iter().map(String::as_str).collect::<Vec<_>>();
    server.stop(&marker_refs).await?;
    for marker in &markers {
        if support::sqlite_contains_secret(database.path(), marker).await? {
            return Err(Error::other("stopped Endpoint SQLite retained a secret marker").into());
        }
    }
    let root = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("temporary database omitted its root"))?;
    scan_incident_secret_tree(root, database.path(), &markers)
}

fn scan_incident_secret_tree(root: &Path, database: &Path, markers: &[String]) -> TestResult<()> {
    let database_wal = format!("{}-wal", database.display());
    let database_shm = format!("{}-shm", database.display());
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let path_text = path.to_string_lossy();
            if path == database || path_text == database_wal || path_text == database_shm {
                continue;
            }
            let bytes = fs::read(&path)?;
            for marker in markers.iter().filter(|marker| !marker.is_empty()) {
                if !bytes
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes())
                {
                    continue;
                }
                let controller_store = path.file_name().and_then(|name| name.to_str())
                    == Some("controller.secret")
                    || path.components().any(|component| {
                        component
                            .as_os_str()
                            .to_string_lossy()
                            .contains(".controller-auth")
                    });
                let controller_file = controller_store && marker == support::TEST_CONTROLLER_SECRET;
                let credential_file = path.strip_prefix(root.join("credentials")).is_ok()
                    && marker == support::TEST_PROVIDER_SECRET;
                if !controller_file && !credential_file {
                    return Err(Error::other(format!(
                        "test secret marker escaped its designated secret file into {}",
                        path.display()
                    ))
                    .into());
                }
            }
        }
    }
    Ok(())
}

async fn create_session<S: EndpointAddress>(
    client: &Client,
    server: &S,
    provider_url: &str,
    idempotency_key: &str,
    tools: &[&str],
) -> TestResult<String> {
    install_test_replica(
        client,
        &server.endpoint_url(""),
        &format!("install-{idempotency_key}"),
    )
    .await?;
    let callback_base_url = format!("{}/v1/callbacks", server.endpoint_url(""));
    create_session_without_replica_at_callback(
        client,
        server,
        provider_url,
        idempotency_key,
        tools,
        &callback_base_url,
    )
    .await
}

async fn create_session_without_replica<S: EndpointAddress>(
    client: &Client,
    server: &S,
    provider_url: &str,
    idempotency_key: &str,
    tools: &[&str],
) -> TestResult<String> {
    let callback_base_url = format!("{}/v1/callbacks", server.endpoint_url(""));
    create_session_without_replica_at_callback(
        client,
        server,
        provider_url,
        idempotency_key,
        tools,
        &callback_base_url,
    )
    .await
}

async fn create_session_at_callback<S: EndpointAddress>(
    client: &Client,
    server: &S,
    provider_url: &str,
    idempotency_key: &str,
    tools: &[&str],
    callback_base_url: &str,
) -> TestResult<String> {
    install_test_replica(
        client,
        &server.endpoint_url(""),
        &format!("install-{idempotency_key}"),
    )
    .await?;
    create_session_without_replica_at_callback(
        client,
        server,
        provider_url,
        idempotency_key,
        tools,
        callback_base_url,
    )
    .await
}

async fn create_session_without_replica_at_callback<S: EndpointAddress>(
    client: &Client,
    server: &S,
    provider_url: &str,
    idempotency_key: &str,
    tools: &[&str],
    callback_base_url: &str,
) -> TestResult<String> {
    let response = authenticated(client.post(server.endpoint_url("/v1/sessions")))
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
            "tools": tools,
            "callback_base_url": callback_base_url
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

async fn post_message<S: EndpointAddress>(
    client: &Client,
    server: &S,
    id: &str,
    key: &str,
    content: &str,
) -> TestResult<Value> {
    let response =
        authenticated(client.post(server.endpoint_url(&format!("/v1/sessions/{id}/messages"))))
            .header("Idempotency-Key", key)
            .json(&json!({"content": content}))
            .send_with_timeout()
            .await?;
    let status = response.status();
    let body = response_json(response).await?;
    if status != StatusCode::ACCEPTED {
        return Err(Error::other(format!(
            "message admission did not return 202: {status} {body}"
        ))
        .into());
    }
    Ok(body)
}

async fn read_session<S: EndpointAddress>(
    client: &Client,
    server: &S,
    id: &str,
) -> TestResult<Value> {
    let response = authenticated(client.get(server.endpoint_url(&format!("/v1/sessions/{id}"))))
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_json(response).await?;
    if status != StatusCode::OK {
        return Err(Error::other(format!("session read failed: {status} {body}")).into());
    }
    Ok(body)
}

struct SseFrames {
    stream: futures_util::stream::BoxStream<'static, Result<Bytes, reqwest::Error>>,
    buffer: Vec<u8>,
}

#[derive(Debug)]
struct SseFrame {
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
        loop {
            if let Some(end) = self.buffer.windows(2).position(|window| window == b"\n\n") {
                let frame = self.buffer.drain(..end + 2).collect::<Vec<_>>();
                if let Some(frame) = parse_sse_frame(&frame)? {
                    return Ok(frame);
                }
            }
            let chunk = timeout(Duration::from_secs(10), self.stream.next())
                .await
                .map_err(|_| Error::new(ErrorKind::TimedOut, "Endpoint SSE frame timed out"))?
                .ok_or_else(|| {
                    Error::new(ErrorKind::UnexpectedEof, "Endpoint SSE ended early")
                })??;
            self.buffer.extend_from_slice(&chunk);
        }
    }
}

fn parse_sse_frame(frame: &[u8]) -> TestResult<Option<SseFrame>> {
    let text = std::str::from_utf8(frame)?;
    let mut event = None;
    let mut data = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("event: ") {
            event = Some(value.to_owned());
        } else if let Some(value) = line.strip_prefix("data: ") {
            data = Some(serde_json::from_str(value)?);
        }
    }
    Ok(match (event, data) {
        (Some(event), Some(data)) => Some(SseFrame { event, data }),
        _ => None,
    })
}

async fn replay_events_through_version<S: EndpointAddress>(
    client: &Client,
    server: &S,
    session_id: &str,
    through_version: u64,
) -> TestResult<Vec<SseFrame>> {
    let response = authenticated(client.get(server.endpoint_url("/v1/events")))
        .header("Last-Event-ID", "0")
        .send_with_timeout()
        .await?;
    if response.status() != StatusCode::OK {
        let status = response.status();
        let body = response_text(response).await?;
        return Err(Error::other(format!(
            "session event replay failed before version {through_version}: {status} {body}"
        ))
        .into());
    }
    let mut frames = SseFrames::new(response);
    let mut replay = Vec::new();
    for _ in 0..512 {
        let frame = frames.next().await?;
        if frame.data["session_id"].as_str() != Some(session_id) {
            continue;
        }
        let version = frame.data["version"]
            .as_u64()
            .ok_or_else(|| Error::other("durable SSE event omitted its session version"))?;
        if version > through_version {
            return Err(Error::other(format!(
                "session event replay skipped target version {through_version} and reached {version}"
            ))
            .into());
        }
        replay.push(frame);
        if version == through_version {
            return Ok(replay);
        }
    }
    Err(Error::other(format!(
        "session event replay did not reach version {through_version} within 512 events"
    ))
    .into())
}

async fn read_tool_call(
    client: &Client,
    incident: &IncidentRecorder,
    public_proxy: &IncidentProxy,
    session_id: &str,
    tool_call_id: &str,
    fallback: &Value,
) -> TestResult<Value> {
    if incident.has_deferred_failure() {
        return Ok(fallback.clone());
    }
    let path = incident.public_path(
        "public.tool_call_status",
        format!("/v1/sessions/{session_id}/tool-calls/{tool_call_id}"),
        session_id,
    )?;
    let url = if incident.request_count("public.tool_call_status") == 0 {
        format!("{}{}", public_proxy.base_url(), path)
    } else {
        public_proxy.upstream_url(&path)
    };
    let response = authenticated(client.get(url)).send_with_timeout().await?;
    let status = response.status();
    let body_text = response_text(response).await?;
    if status != StatusCode::OK {
        let safe_error = format!(
            "tool-call status route returned {status} for {tool_call_id} after its fixture barrier"
        );
        if status == StatusCode::NOT_FOUND {
            incident.defer_failure("public.tool_call_status", &safe_error);
            return Ok(fallback.clone());
        }
        return Err(Error::other(format!(
            "tool-call GET for {tool_call_id} returned {status} after its fixture barrier: {body_text}"
        ))
        .into());
    }
    let body: Value = serde_json::from_str(&body_text)?;
    assert_eq!(body["schema"], "zode.tool-call.v1");
    assert_eq!(body["session_id"], session_id);
    assert_eq!(body["tool_call_id"], tool_call_id);
    Ok(body)
}

async fn wait_for_tool_status(
    client: &Client,
    incident: &IncidentRecorder,
    public_proxy: &IncidentProxy,
    session_id: &str,
    tool_call_id: &str,
    expected_status: &str,
    fallback: Value,
) -> TestResult<Value> {
    timeout(Duration::from_secs(10), async {
        loop {
            let record = read_tool_call(
                client,
                incident,
                public_proxy,
                session_id,
                tool_call_id,
                &fallback,
            )
            .await?;
            let actual = record["status"]
                .as_str()
                .ok_or_else(|| Error::other("tool-call GET omitted status"))?;
            if actual == expected_status {
                return Ok(record);
            }
            if !matches!(actual, "planned" | "running") {
                return Err(Error::other(format!(
                    "tool call {tool_call_id} reached {actual} while waiting for {expected_status}"
                ))
                .into());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::TimedOut,
            format!("tool call {tool_call_id} did not reach {expected_status}"),
        )
    })?
}

fn tool_status_fallback(
    session_id: &str,
    tool_call_id: &str,
    tool_name: &str,
    completion_mode: &str,
    status: &str,
    result: Value,
    error: Value,
) -> Value {
    json!({
        "schema": "zode.tool-call.v1",
        "session_id": session_id,
        "tool_call_id": tool_call_id,
        "tool_name": tool_name,
        "completion_mode": completion_mode,
        "status": status,
        "result": result,
        "error": error
    })
}

async fn wait_for_wait_state<S: EndpointAddress>(
    client: &Client,
    server: &S,
    session_id: &str,
    expected_reason: &str,
    expected_timeout: u64,
) -> TestResult<Value> {
    timeout(Duration::from_secs(5), async {
        loop {
            let state = read_session(client, server, session_id).await?;
            let wait = &state["wait"];
            if wait["reason"].as_str() == Some(expected_reason)
                && wait["timeout_seconds"].as_u64() == Some(expected_timeout)
            {
                return Ok(state);
            }
            if wait.is_object() && !wait["reason"].is_null() {
                return Err(Error::other(format!(
                    "session {session_id} exposed an unexpected wait state: {wait}"
                ))
                .into());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        Error::other(format!(
        "session {session_id} did not durably expose wait {expected_reason:?} before the deadline"
    ))
    })?
}

fn assert_provider_tool_contract(request: &Value, ordinary_tool_names: &[&str]) -> TestResult<()> {
    let tools = request["tools"]
        .as_array()
        .ok_or_else(|| Error::other("provider request omitted structured tools"))?;
    let mut names = Vec::with_capacity(tools.len());
    for tool in tools {
        assert_eq!(tool["type"], "function", "provider tool was not a function");
        let function = tool["function"]
            .as_object()
            .ok_or_else(|| Error::other("provider function tool omitted function object"))?;
        let name = function["name"]
            .as_str()
            .ok_or_else(|| Error::other("provider function tool omitted name"))?;
        names.push(name.to_owned());
    }
    let expected_names = ordinary_tool_names
        .iter()
        .copied()
        .chain(std::iter::once("wait_for"))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(
        names, expected_names,
        "provider wire did not preserve the exact selected tool order followed by wait_for"
    );
    assert_eq!(
        names
            .iter()
            .filter(|name| name.as_str() == "wait_for")
            .count(),
        1,
        "provider wire did not expose exactly one wait_for definition"
    );
    let wait_tool = tools
        .iter()
        .find(|tool| tool["function"]["name"] == "wait_for")
        .ok_or_else(|| Error::other("provider wire omitted wait_for definition"))?;
    let wait_parameters = &wait_tool["function"]["parameters"];
    assert_eq!(wait_parameters["type"], "object");
    assert_eq!(wait_parameters["properties"]["reason"]["type"], "string");
    assert_eq!(
        wait_parameters["properties"]["timeout_seconds"]["type"],
        "integer"
    );
    assert_eq!(
        wait_parameters["properties"]["timeout_seconds"]["minimum"],
        json!(1)
    );
    assert_eq!(
        wait_parameters["properties"]["timeout_seconds"]["maximum"],
        json!(600)
    );
    assert_eq!(wait_parameters["additionalProperties"], json!(false));
    assert_eq!(
        wait_parameters["required"],
        json!(["reason"]),
        "wait_for reason must be required and timeout_seconds optional"
    );

    for ordinary_tool_name in ordinary_tool_names {
        assert_eq!(
            names
                .iter()
                .filter(|name| name.as_str() == *ordinary_tool_name)
                .count(),
            1,
            "provider wire did not expose the selected ordinary tool"
        );
        let ordinary_tool = tools
            .iter()
            .find(|tool| tool["function"]["name"] == *ordinary_tool_name)
            .ok_or_else(|| Error::other("provider wire omitted selected ordinary tool"))?;
        assert_eq!(
            ordinary_tool["function"]["parameters"],
            json!({"type": "object"}),
            "ordinary tool schema was not preserved on the provider wire"
        );
    }
    Ok(())
}

async fn complete_callback(
    client: &Client,
    callback_url: &str,
    bearer: &str,
    content: &str,
) -> TestResult<(StatusCode, String)> {
    let response = client
        .post(callback_url)
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({
            "status": "completed",
            "result": {"content": content}
        }))
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_text(response).await?;
    Ok((status, body))
}

async fn complete_callback_json(
    client: &Client,
    callback_url: &str,
    bearer: &str,
    body: &str,
) -> TestResult<(StatusCode, String)> {
    let response = client
        .post(callback_url)
        .header("Authorization", format!("Bearer {bearer}"))
        .header("Content-Type", "application/json")
        .body(body.to_owned())
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_text(response).await?;
    Ok((status, body))
}

fn captured_callback_from_incident(
    incident: &IncidentRecorder,
    boundary: &str,
) -> TestResult<(String, String)> {
    fn find_callback_url(value: &Value) -> Option<String> {
        match value {
            Value::Object(object) => {
                if let Some(url) = object.get("callback_url").and_then(Value::as_str) {
                    return Some(url.to_owned());
                }
                object.values().find_map(find_callback_url)
            }
            Value::Array(values) => values.iter().find_map(find_callback_url),
            _ => None,
        }
    }

    let invocation = incident.request_json(boundary, 0)?;
    let callback_url = find_callback_url(&invocation).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            "external callback invocation omitted callback_url",
        )
    })?;
    if !callback_url.contains("/v1/callbacks/") {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "external callback URL did not identify the public callback route",
        )
        .into());
    }
    let bearer = incident
        .request_headers(boundary, 0)?
        .into_iter()
        .find(|header| header.name == "authorization")
        .and_then(|header| header.value.strip_prefix("Bearer ").map(str::to_owned));
    let bearer = bearer.ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            "external callback invocation omitted its bearer",
        )
    })?;
    Ok((callback_url, bearer))
}

fn captured_callback(tool: &ToolFixture) -> TestResult<(String, String)> {
    fn find_callback_url(value: &Value) -> Option<String> {
        match value {
            Value::Object(object) => {
                if let Some(url) = object.get("callback_url").and_then(Value::as_str) {
                    return Some(url.to_owned());
                }
                object.values().find_map(find_callback_url)
            }
            Value::Array(values) => values.iter().find_map(find_callback_url),
            _ => None,
        }
    }

    let invocation =
        tool.invocations().into_iter().next().ok_or_else(|| {
            Error::new(ErrorKind::NotFound, "external callback invocation missing")
        })?;
    let callback_url = find_callback_url(&invocation).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            "external callback invocation omitted callback_url",
        )
    })?;
    if !callback_url.contains("/v1/callbacks/") {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "external callback URL did not identify the public callback route",
        )
        .into());
    }
    let bearer = tool.invocation_headers().iter().find_map(|headers| {
        headers
            .get("authorization")
            .and_then(Value::as_str)
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::to_owned)
    });
    let bearer = bearer.ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            "external callback invocation omitted its bearer",
        )
    })?;
    Ok((callback_url, bearer))
}

fn callback_id(callback_url: &str) -> TestResult<String> {
    let id = callback_url
        .split("/v1/callbacks/")
        .nth(1)
        .and_then(|value| value.split(['?', '#']).next())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "callback URL has no callback id"))?;
    Ok(id.to_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_mixed_tool_batch_is_concurrent_ordered_and_waits_once() -> TestResult<()> {
    const E2E: &str = "e2e_mixed_tool_batch_is_concurrent_ordered_and_waits_once";
    let incident = IncidentRecorder::new(
        E2E,
        "retain the first public tool-status failure and the complete mixed provider/tool exchange",
    )?;
    let database = TempDatabase::new("async-mixed")?;
    let release_slow = Arc::new(Notify::new());
    let first_round = ModelScript::tool_calls(vec![
        ToolCallScript::new("fast-call", "fast_tool", r#"{"value":"fast"}"#),
        ToolCallScript::new("slow-call", "slow_tool", r#"{"value":"slow"}"#),
        ToolCallScript::new("failed-call", "failed_tool", r#"{"value":"failed"}"#),
    ]);
    let scripts = if incident.is_replay() {
        vec![ModelScript::final_text("mixed batch final")]
    } else {
        vec![first_round, ModelScript::final_text("mixed batch final")]
    };
    let mut model = ModelFixture::start(scripts).await?;
    let mut provider_proxy = incident
        .proxy("provider.model", model.provider_url())
        .await?;
    let mut fast = ToolFixture::start(vec![ToolScript::Response(json!({
        "status": "completed",
        "result": {"content": "fast result"}
    }))])
    .await?;
    let mut slow = ToolFixture::start(vec![ToolScript::Hold {
        release: release_slow.clone(),
        response: json!({"status": "completed", "result": {"content": "slow result"}}),
    }])
    .await?;
    let mut failed = ToolFixture::start(vec![ToolScript::Status(503)]).await?;
    let ordered_tools = Arc::new(OrderedArrival::default());
    let mut fast_proxy = incident
        .ordered_proxy(
            "tool.fast",
            fast.adapter_url(),
            ordered_tools.clone(),
            0,
            false,
        )
        .await?;
    let mut slow_proxy = incident
        .ordered_proxy(
            "tool.slow",
            slow.adapter_url(),
            ordered_tools.clone(),
            1,
            true,
        )
        .await?;
    let mut failed_proxy = incident
        .ordered_proxy("tool.failed", failed.adapter_url(), ordered_tools, 2, false)
        .await?;
    let tools = vec![
        tool_config(
            "fast_tool",
            &fast_proxy.base_url(),
            "response",
            "unknown_outcome",
            "never",
            20,
        ),
        tool_config(
            "slow_tool",
            &slow_proxy.base_url(),
            "response",
            "unknown_outcome",
            "never",
            7,
        ),
        tool_config(
            "failed_tool",
            &failed_proxy.base_url(),
            "response",
            "unknown_outcome",
            "never",
            20,
        ),
    ];
    let config = config_file(&database, &provider_proxy.base_url(), tools, 1)?;
    let mut server = TestZode::start(
        &database,
        &config,
        &[
            support::TEST_CONTROLLER_SECRET,
            support::TEST_PROVIDER_SECRET,
        ],
    )
    .await?;
    let mut public_proxy = incident
        .proxy("public.tool_call_status", server.url(""))
        .await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &provider_proxy.base_url(),
        "create-mixed",
        &["fast_tool", "slow_tool", "failed_tool"],
    )
    .await?;
    post_message(
        &client,
        &server,
        &session_id,
        "mixed-message",
        "run the mixed batch",
    )
    .await?;
    incident.wait_for_requests("provider.model", 1).await?;
    let first_request = incident.request_json("provider.model", 0)?;
    assert_provider_tool_contract(&first_request, &["fast_tool", "slow_tool", "failed_tool"])?;
    incident.wait_for_requests("tool.fast", 1).await?;
    incident.wait_for_requests("tool.slow", 1).await?;
    incident.wait_for_requests("tool.failed", 1).await?;
    incident.wait_for_completions("tool.fast", 1).await?;
    incident.wait_for_completions("tool.failed", 1).await?;

    let fast_record = wait_for_tool_status(
        &client,
        &incident,
        &public_proxy,
        &session_id,
        "fast-call",
        "completed",
        tool_status_fallback(
            &session_id,
            "fast-call",
            "fast_tool",
            "response",
            "completed",
            json!({"content": "fast result"}),
            Value::Null,
        ),
    )
    .await?;
    assert_eq!(fast_record["tool_name"], "fast_tool");
    assert_eq!(fast_record["completion_mode"], "response");
    assert_eq!(fast_record["result"], json!({"content": "fast result"}));
    assert!(fast_record["error"].is_null());
    let failed_record = wait_for_tool_status(
        &client,
        &incident,
        &public_proxy,
        &session_id,
        "failed-call",
        "failed",
        tool_status_fallback(
            &session_id,
            "failed-call",
            "failed_tool",
            "response",
            "failed",
            Value::Null,
            json!({
                "class": "tool_execution_failed",
                "message": "tool execution failed"
            }),
        ),
    )
    .await?;
    assert_eq!(failed_record["tool_name"], "failed_tool");
    assert_eq!(failed_record["completion_mode"], "response");
    assert!(failed_record["result"].is_null());
    assert_eq!(
        failed_record["error"],
        json!({
            "class": "tool_execution_failed",
            "message": "tool execution failed"
        })
    );
    let slow_record = wait_for_tool_status(
        &client,
        &incident,
        &public_proxy,
        &session_id,
        "slow-call",
        "running",
        tool_status_fallback(
            &session_id,
            "slow-call",
            "slow_tool",
            "response",
            "running",
            Value::Null,
            Value::Null,
        ),
    )
    .await?;
    assert_eq!(slow_record["tool_name"], "slow_tool");
    assert_eq!(slow_record["completion_mode"], "response");
    assert!(slow_record["result"].is_null());
    assert!(slow_record["error"].is_null());

    if incident.has_deferred_failure() {
        release_slow.notify_waiters();
        slow_proxy.release_replay();
        incident.wait_for_completions("tool.slow", 1).await?;
        incident.wait_for_completions("provider.model", 2).await?;
        if incident.is_replay() {
            assert_eq!(model.request_count(), 0);
            assert_eq!(fast.invocation_count(), 0);
            assert_eq!(slow.invocation_count(), 0);
            assert_eq!(failed.invocation_count(), 0);
        }
        stop_and_scan_incident_endpoint(&mut server, &database, &[]).await?;
        let result = incident.finish();
        public_proxy.stop().await?;
        provider_proxy.stop().await?;
        fast_proxy.stop().await?;
        slow_proxy.stop().await?;
        failed_proxy.stop().await?;
        model.stop().await?;
        fast.stop().await?;
        slow.stop().await?;
        failed.stop().await?;
        return result;
    }

    let before_release = timeout(Duration::from_secs(10), async {
        loop {
            let state = read_session(&client, &server, &session_id).await?;
            let transcript = state["transcript"]
                .as_array()
                .ok_or_else(|| Error::other("mixed batch GET omitted transcript"))?;
            let results = transcript
                .iter()
                .filter(|message| {
                    matches!(
                        message["tool_call_id"].as_str(),
                        Some("fast-call" | "slow-call" | "failed-call")
                    )
                })
                .collect::<Vec<_>>();
            if results.len() == 3 {
                if state["wait"]["source"] != "auto_tool_batch"
                    || state["wait"]["tool_call_ids"] != json!(["slow-call"])
                    || state["wait"]["timeout_seconds"] != 7
                {
                    return Err(Error::other(format!(
                        "mixed batch committed tool results without its one exact auto wait: {}",
                        state["wait"]
                    ))
                    .into());
                }
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::TimedOut,
            "mixed batch did not commit foreground results",
        )
    })??;
    let transcript = before_release["transcript"]
        .as_array()
        .ok_or_else(|| Error::other("mixed batch GET omitted transcript"))?;
    let results = transcript
        .iter()
        .filter(|message| {
            matches!(
                message["tool_call_id"].as_str(),
                Some("fast-call" | "slow-call" | "failed-call")
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .map(|message| message["tool_call_id"].as_str())
            .collect::<Vec<_>>(),
        vec![Some("fast-call"), Some("slow-call"), Some("failed-call")]
    );
    assert_eq!(results[0]["content"], "fast result");
    assert!(results[1]["content"]
        .as_str()
        .is_some_and(|content| content.contains("async_running")));
    assert_eq!(results[2]["content"], "tool execution failed");
    let before_events = replay_events_through_version(
        &client,
        &server,
        &session_id,
        before_release["version"]
            .as_u64()
            .ok_or_else(|| Error::other("mixed batch GET omitted version"))?,
    )
    .await?;
    let wait_events = before_events
        .iter()
        .filter(|frame| frame.event == "wait_set")
        .collect::<Vec<_>>();
    assert_eq!(wait_events.len(), 1);
    assert_eq!(
        wait_events[0].data["data"]["wait"]["source"],
        "auto_tool_batch"
    );
    assert_eq!(
        wait_events[0].data["data"]["wait"]["tool_call_ids"],
        json!(["slow-call"])
    );
    release_slow.notify_waiters();
    slow_proxy.release_replay();
    incident.wait_for_completions("tool.slow", 1).await?;
    let slow_completed = wait_for_tool_status(
        &client,
        &incident,
        &public_proxy,
        &session_id,
        "slow-call",
        "completed",
        tool_status_fallback(
            &session_id,
            "slow-call",
            "slow_tool",
            "response",
            "completed",
            json!({"content": "slow result"}),
            Value::Null,
        ),
    )
    .await?;
    assert_eq!(slow_completed["result"], json!({"content": "slow result"}));
    assert!(slow_completed["error"].is_null());
    incident.wait_for_requests("provider.model", 2).await?;
    let after_release = timeout(Duration::from_secs(5), async {
        loop {
            let state = read_session(&client, &server, &session_id).await?;
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
            "mixed final activation barrier timed out",
        )
    })??;
    let after_events = replay_events_through_version(
        &client,
        &server,
        &session_id,
        after_release["version"]
            .as_u64()
            .ok_or_else(|| Error::other("mixed batch final GET omitted version"))?,
    )
    .await?;
    assert_eq!(
        after_events
            .iter()
            .filter(|frame| frame.event == "wait_set")
            .count(),
        1,
        "mixed batch created more than one WaitSet"
    );
    assert_eq!(incident.request_count("tool.fast"), 1);
    assert_eq!(incident.request_count("tool.slow"), 1);
    assert_eq!(incident.request_count("tool.failed"), 1);
    stop_and_scan_incident_endpoint(&mut server, &database, &[]).await?;
    let result = incident.finish();
    public_proxy.stop().await?;
    provider_proxy.stop().await?;
    fast_proxy.stop().await?;
    slow_proxy.stop().await?;
    failed_proxy.stop().await?;
    model.stop().await?;
    fast.stop().await?;
    slow.stop().await?;
    failed.stop().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_explicit_wait_last_wins_without_skipping_ordinary_tool() -> TestResult<()> {
    let database = TempDatabase::new("async-explicit-wait")?;
    let mut model = ModelFixture::start(vec![ModelScript::tool_calls(vec![
        ToolCallScript::new(
            "wait-first",
            "wait_for",
            r#"{"reason":"first wait","timeout_seconds":10}"#,
        ),
        ToolCallScript::new("ordinary-call", "ordinary_tool", r#"{"value":"ordinary"}"#),
        ToolCallScript::new(
            "wait-last",
            "wait_for",
            r#"{"reason":"last wait","timeout_seconds":20}"#,
        ),
    ])])
    .await?;
    let mut ordinary = ToolFixture::start(vec![ToolScript::Response(json!({
        "status": "completed",
        "result": {"content": "ordinary completed"}
    }))])
    .await?;
    let tools = vec![tool_config(
        "ordinary_tool",
        &ordinary.adapter_url(),
        "response",
        "unknown_outcome",
        "never",
        20,
    )];
    let config = config_file(&database, &model.provider_url(), tools, 1)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        "create-explicit-wait",
        &["ordinary_tool"],
    )
    .await?;
    post_message(
        &client,
        &server,
        &session_id,
        "explicit-wait-message",
        "run ordinary work and wait",
    )
    .await?;
    model.wait_for_requests(1).await?;
    let first_request = model
        .request(0)
        .ok_or_else(|| Error::other("explicit wait provider request missing"))?;
    assert_provider_tool_contract(&first_request, &["ordinary_tool"])?;
    ordinary.wait_for_invocations(1).await?;
    let state = wait_for_wait_state(&client, &server, &session_id, "last wait", 20).await?;
    assert_eq!(state["wait"]["reason"], "last wait");
    assert_eq!(state["wait"]["timeout_seconds"], 20);
    assert_eq!(state["wait"]["source"], "wait_for");
    assert_eq!(ordinary.invocation_count(), 1);
    let transcript = state["transcript"]
        .as_array()
        .ok_or_else(|| Error::other("explicit wait GET omitted transcript"))?;
    let ordinary_results = transcript
        .iter()
        .filter(|message| message["tool_call_id"] == "ordinary-call")
        .collect::<Vec<_>>();
    assert_eq!(ordinary_results.len(), 1);
    assert_eq!(ordinary_results[0]["role"], "tool");
    assert_eq!(ordinary_results[0]["content"], "ordinary completed");
    server.stop().await?;
    model.stop().await?;
    ordinary.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_explicit_wait_defaults_to_sixty_seconds_and_survives_restart() -> TestResult<()> {
    let database = TempDatabase::new("async-wait-default-restart")?;
    let mut model = ModelFixture::start(vec![ModelScript::tool_call(
        "wait-default",
        "wait_for",
        r#"{"reason":"default wait"}"#,
    )])
    .await?;
    let config = config_file(&database, &model.provider_url(), Vec::new(), 1)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        "create-wait-default-restart",
        &[],
    )
    .await?;
    post_message(
        &client,
        &server,
        &session_id,
        "wait-default-message",
        "start default wait",
    )
    .await?;
    model.wait_for_requests(1).await?;
    let first_request = model
        .request(0)
        .ok_or_else(|| Error::other("default wait provider request missing"))?;
    assert_provider_tool_contract(&first_request, &[])?;
    let before_restart =
        wait_for_wait_state(&client, &server, &session_id, "default wait", 60).await?;
    assert_eq!(before_restart["wait"]["reason"], "default wait");
    assert_eq!(before_restart["wait"]["timeout_seconds"], 60);
    assert_eq!(before_restart["wait"]["source"], "wait_for");

    server.stop().await?;
    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let after_restart = read_session(&client, &restarted, &session_id).await?;
    assert_eq!(after_restart["wait"]["reason"], "default wait");
    assert_eq!(after_restart["wait"]["timeout_seconds"], 60);
    assert_eq!(after_restart["wait"]["source"], "wait_for");
    assert_eq!(model.request_count(), 1);
    restarted.stop().await?;
    model.stop().await?;
    Ok(())
}

async fn invalid_wait_case(seconds: u64, label: &str) -> TestResult<()> {
    let database = TempDatabase::new(label)?;
    let mut model = ModelFixture::start(vec![ModelScript::tool_call(
        "invalid-wait-call",
        "wait_for",
        format!(r#"{{"reason":"bad","timeout_seconds":{seconds}}}"#),
    )])
    .await?;
    let mut server = ConfiguredServer::start(
        &database,
        &config_file(&database, &model.provider_url(), Vec::new(), 1)?,
    )
    .await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        &format!("create-{label}"),
        &[],
    )
    .await?;
    post_message(
        &client,
        &server,
        &session_id,
        "invalid-wait-message",
        "bad wait",
    )
    .await?;
    model.wait_for_requests(1).await?;
    let body = timeout(Duration::from_secs(5), async {
        loop {
            let response =
                authenticated(client.get(server.url(&format!("/v1/sessions/{session_id}"))))
                    .send_with_timeout()
                    .await?;
            let status = response.status();
            let body = response_text(response).await?;
            if status != StatusCode::OK {
                return Err(Error::other(format!(
                    "invalid wait session projection failed: {status} {body}"
                ))
                .into());
            }
            if body.contains("invalid_request") || body.contains("422") {
                return Ok::<String, Box<dyn std::error::Error + Send + Sync>>(body);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::TimedOut,
            "invalid wait outcome projection timed out",
        )
    })??;
    assert!(body.contains("invalid_request") || body.contains("422"));
    server.stop().await?;
    model.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_explicit_wait_zero_is_rejected() -> TestResult<()> {
    invalid_wait_case(0, "async-wait-zero").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_explicit_wait_above_maximum_is_rejected() -> TestResult<()> {
    invalid_wait_case(601, "async-wait-high").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_explicit_wait_legacy_high_value_is_rejected() -> TestResult<()> {
    invalid_wait_case(1800, "async-wait-legacy-high").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_external_completion_first_wins_and_wakes_one_next_activation() -> TestResult<()> {
    const E2E: &str = "e2e_external_completion_first_wins_and_wakes_one_next_activation";
    let incident = IncidentRecorder::new_with_fixture(
        E2E,
        "retain the first public tool-status failure and the authenticated callback race exchange",
        "e2e_external_completion_first_wins_and_wakes_one_next_activation.v2",
    )?;
    let database = TempDatabase::new("async-first-wins")?;
    let first_round =
        ModelScript::tool_call("callback-call", "callback_tool", r#"{"value":"remote"}"#);
    let scripts = if incident.is_replay() {
        vec![ModelScript::final_text("callback resumed")]
    } else {
        vec![first_round, ModelScript::final_text("callback resumed")]
    };
    let mut model = ModelFixture::start(scripts).await?;
    let mut provider_proxy = incident
        .proxy("provider.model", model.provider_url())
        .await?;
    let release_callback_adapter = Arc::new(Notify::new());
    let mut callback = ToolFixture::start(vec![ToolScript::Hold {
        release: release_callback_adapter.clone(),
        response: json!({"status": "completed", "result": {"content": "unused"}}),
    }])
    .await?;
    let mut callback_proxy = incident
        .held_proxy("tool.external_callback", callback.adapter_url())
        .await?;
    let config = config_file(
        &database,
        &provider_proxy.base_url(),
        vec![tool_config(
            "callback_tool",
            &callback_proxy.base_url(),
            "external_callback",
            "await_callback",
            "never",
            20,
        )],
        1,
    )?;
    let mut server = TestZode::start(
        &database,
        &config,
        &[
            support::TEST_CONTROLLER_SECRET,
            support::TEST_PROVIDER_SECRET,
        ],
    )
    .await?;
    let mut public_proxy = incident
        .proxy("public.tool_call_status", server.url(""))
        .await?;
    let mut callback_public_proxy = incident
        .arrival_barrier_proxy("public.callback", server.url(""), 1, 2)
        .await?;
    let client = support::http_client()?;
    let callback_base_url = format!("{}/v1/callbacks", callback_public_proxy.base_url());
    let session_id = create_session_at_callback(
        &client,
        &server,
        &provider_proxy.base_url(),
        "create-first-wins",
        &["callback_tool"],
        &callback_base_url,
    )
    .await?;
    post_message(
        &client,
        &server,
        &session_id,
        "first-wins-message",
        "start callback",
    )
    .await?;
    incident.wait_for_requests("provider.model", 1).await?;
    let first_request = incident.request_json("provider.model", 0)?;
    assert_provider_tool_contract(&first_request, &["callback_tool"])?;
    incident
        .wait_for_requests("tool.external_callback", 1)
        .await?;
    let running = wait_for_tool_status(
        &client,
        &incident,
        &public_proxy,
        &session_id,
        "callback-call",
        "running",
        tool_status_fallback(
            &session_id,
            "callback-call",
            "callback_tool",
            "external_callback",
            "running",
            Value::Null,
            Value::Null,
        ),
    )
    .await?;
    assert_eq!(running["tool_name"], "callback_tool");
    assert_eq!(running["completion_mode"], "external_callback");
    assert!(running["result"].is_null());
    assert!(running["error"].is_null());

    if incident.has_deferred_failure() {
        release_callback_adapter.notify_waiters();
        callback_proxy.release_replay();
        incident
            .wait_for_completions("tool.external_callback", 1)
            .await?;
        incident.wait_for_completions("provider.model", 2).await?;
        if incident.is_replay() {
            assert_eq!(model.request_count(), 0);
            assert_eq!(callback.invocation_count(), 0);
        }
        stop_and_scan_incident_endpoint(&mut server, &database, &[]).await?;
        let result = incident.finish();
        public_proxy.stop().await?;
        callback_public_proxy.stop().await?;
        provider_proxy.stop().await?;
        callback_proxy.stop().await?;
        model.stop().await?;
        callback.stop().await?;
        return result;
    }

    let (callback_url, bearer) =
        captured_callback_from_incident(&incident, "tool.external_callback")?;
    let stable_callback_id = callback_id(&callback_url)?;
    assert!(!stable_callback_id.is_empty());
    incident.register_slot("wrong-callback-bearer", "{{WRONG_CALLBACK_BEARER}}");
    let (wrong_status, wrong_body) = complete_callback(
        &client,
        &callback_url,
        "wrong-callback-bearer",
        "must not win",
    )
    .await?;
    assert_eq!(
        wrong_status,
        StatusCode::NOT_FOUND,
        "wrong callback bearer did not use safe not-found: {wrong_body}"
    );
    let after_wrong = read_tool_call(
        &client,
        &incident,
        &public_proxy,
        &session_id,
        "callback-call",
        &tool_status_fallback(
            &session_id,
            "callback-call",
            "callback_tool",
            "external_callback",
            "running",
            Value::Null,
            Value::Null,
        ),
    )
    .await?;
    assert_eq!(after_wrong["status"], "running");

    let first_client = client.clone();
    let first_url = callback_url.clone();
    let first_bearer = bearer.clone();
    let first = tokio::spawn(async move {
        complete_callback(&first_client, &first_url, &first_bearer, "candidate-a").await
    });
    incident.wait_for_requests("public.callback", 2).await?;
    let second_client = client.clone();
    let second_url = callback_url.clone();
    let second_bearer = bearer.clone();
    let second = tokio::spawn(async move {
        complete_callback(&second_client, &second_url, &second_bearer, "candidate-b").await
    });
    incident.wait_for_requests("public.callback", 3).await?;
    let first = first.await??;
    let second = second.await??;
    let outcomes = [first.0, second.0];
    assert_eq!(
        outcomes.iter().filter(|status| status.is_success()).count(),
        1,
        "callback race did not admit exactly one completion: {first:?} {second:?}"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|status| **status == StatusCode::CONFLICT)
            .count(),
        1,
        "callback race did not reject exactly one completion: {first:?} {second:?}"
    );
    let winner = if first.0.is_success() {
        "candidate-a"
    } else {
        "candidate-b"
    };
    let loser = if winner == "candidate-a" {
        "candidate-b"
    } else {
        "candidate-a"
    };
    let completed = wait_for_tool_status(
        &client,
        &incident,
        &public_proxy,
        &session_id,
        "callback-call",
        "completed",
        tool_status_fallback(
            &session_id,
            "callback-call",
            "callback_tool",
            "external_callback",
            "completed",
            json!({"content": winner}),
            Value::Null,
        ),
    )
    .await?;
    assert_eq!(completed["result"], json!({"content": winner}));
    assert!(completed["error"].is_null());
    incident.wait_for_requests("provider.model", 2).await?;
    let state = timeout(Duration::from_secs(10), async {
        loop {
            let state = read_session(&client, &server, &session_id).await?;
            let assistant_committed = state["transcript"].as_array().is_some_and(|messages| {
                messages.iter().any(|message| {
                    message["role"] == "assistant" && message["content"] == "callback resumed"
                })
            });
            // The provider barrier only proves request admission.  Wait for
            // the public idle projection so ActivationFinished is durable
            // before sealing the terminal stream version.
            if assistant_committed
                && state["status"] == "idle"
                && state["active_activation"].is_null()
            {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::TimedOut,
            "callback did not wake one next activation",
        )
    })??;
    let terminal_version = state["version"]
        .as_u64()
        .ok_or_else(|| Error::other("callback GET omitted version"))?;
    let events =
        replay_events_through_version(&client, &server, &session_id, terminal_version).await?;
    assert_eq!(
        events
            .iter()
            .filter(|frame| {
                frame.event == "async_tool_call_completed"
                    && frame.data["data"]["tool_call_id"] == "callback-call"
            })
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|frame| {
                frame.event == "delivery_queued"
                    && frame.data["data"]["source_tool_call_id"] == "callback-call"
            })
            .count(),
        1
    );
    let sealed_requests = model.seal_request_phase();
    assert_eq!(incident.request_count("provider.model"), 2);
    let after_loser = read_tool_call(
        &client,
        &incident,
        &public_proxy,
        &session_id,
        "callback-call",
        &tool_status_fallback(
            &session_id,
            "callback-call",
            "callback_tool",
            "external_callback",
            "completed",
            json!({"content": winner}),
            Value::Null,
        ),
    )
    .await?;
    assert_eq!(after_loser["status"], "completed");
    assert_eq!(after_loser["result"], json!({"content": winner}));
    assert!(after_loser["error"].is_null());
    let unchanged = read_session(&client, &server, &session_id).await?;
    assert_eq!(unchanged["version"], terminal_version);
    assert!(!unchanged.to_string().contains(loser));
    assert_eq!(model.request_count(), sealed_requests);
    assert_eq!(model.request_phase_violations(), 0);
    assert_eq!(incident.request_count("tool.external_callback"), 1);
    assert_eq!(incident.request_count("public.callback"), 3);
    let unauthorized_status = client
        .get(format!(
            "{}/v1/sessions/{session_id}/tool-calls/callback-call",
            public_proxy.base_url()
        ))
        .send_with_timeout()
        .await?;
    let unauthorized_code = unauthorized_status.status();
    let unauthorized_body = response_text(unauthorized_status).await?;
    assert_eq!(
        unauthorized_code,
        StatusCode::UNAUTHORIZED,
        "{unauthorized_body}"
    );
    if !incident.is_replay() {
        incident.defer_failure(
            "public.tool_call_status",
            "missing controller bearer was safely rejected after the callback race",
        );
    }
    stop_and_scan_incident_endpoint(&mut server, &database, std::slice::from_ref(&bearer)).await?;
    let result = incident.finish();
    public_proxy.stop().await?;
    callback_public_proxy.stop().await?;
    provider_proxy.stop().await?;
    callback_proxy.stop().await?;
    model.stop().await?;
    callback.stop().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_auto_wait_timeout_does_not_cancel_running_tool() -> TestResult<()> {
    const E2E: &str = "e2e_auto_wait_timeout_does_not_cancel_running_tool";
    let incident = IncidentRecorder::new(
        E2E,
        "retain the first public tool-status failure and the complete timeout provider/tool exchange",
    )?;
    let database = TempDatabase::new("async-auto-timeout")?;
    let release = Arc::new(Notify::new());
    let first_round = ModelScript::tool_call("timeout-call", "timeout_tool", r#"{"value":"slow"}"#);
    let scripts = if incident.is_replay() {
        vec![ModelScript::final_text("timeout wake observed")]
    } else {
        vec![
            first_round,
            ModelScript::final_text("timeout wake observed"),
        ]
    };
    let mut model = ModelFixture::start(scripts).await?;
    let mut provider_proxy = incident
        .proxy("provider.model", model.provider_url())
        .await?;
    let mut tool = ToolFixture::start(vec![ToolScript::Hold {
        release: release.clone(),
        response: json!({"status": "completed", "result": {"content": "late result"}}),
    }])
    .await?;
    let mut tool_proxy = incident
        .held_proxy("tool.timeout", tool.adapter_url())
        .await?;
    let config = config_file(
        &database,
        &provider_proxy.base_url(),
        vec![tool_config(
            "timeout_tool",
            &tool_proxy.base_url(),
            "response",
            "unknown_outcome",
            "never",
            1,
        )],
        1,
    )?;
    let mut server = TestZode::start(
        &database,
        &config,
        &[
            support::TEST_CONTROLLER_SECRET,
            support::TEST_PROVIDER_SECRET,
        ],
    )
    .await?;
    let mut public_proxy = incident
        .proxy("public.tool_call_status", server.url(""))
        .await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &provider_proxy.base_url(),
        "create-timeout",
        &["timeout_tool"],
    )
    .await?;
    post_message(
        &client,
        &server,
        &session_id,
        "timeout-message",
        "run slowly",
    )
    .await?;
    incident.wait_for_requests("provider.model", 1).await?;
    let first_request = incident.request_json("provider.model", 0)?;
    assert_provider_tool_contract(&first_request, &["timeout_tool"])?;
    incident.wait_for_requests("tool.timeout", 1).await?;
    let running = wait_for_tool_status(
        &client,
        &incident,
        &public_proxy,
        &session_id,
        "timeout-call",
        "running",
        tool_status_fallback(
            &session_id,
            "timeout-call",
            "timeout_tool",
            "response",
            "running",
            Value::Null,
            Value::Null,
        ),
    )
    .await?;
    assert_eq!(running["tool_name"], "timeout_tool");
    assert_eq!(running["completion_mode"], "response");
    assert!(running["result"].is_null());
    assert!(running["error"].is_null());

    if incident.has_deferred_failure() {
        release.notify_waiters();
        tool_proxy.release_replay();
        incident.wait_for_completions("tool.timeout", 1).await?;
        incident.wait_for_completions("provider.model", 2).await?;
        if incident.is_replay() {
            assert_eq!(model.request_count(), 0);
            assert_eq!(tool.invocation_count(), 0);
        }
        stop_and_scan_incident_endpoint(&mut server, &database, &[]).await?;
        let result = incident.finish();
        public_proxy.stop().await?;
        provider_proxy.stop().await?;
        tool_proxy.stop().await?;
        model.stop().await?;
        tool.stop().await?;
        return result;
    }

    let waiting = timeout(Duration::from_secs(10), async {
        loop {
            let state = read_session(&client, &server, &session_id).await?;
            if state["wait"]["source"] == "auto_tool_batch"
                && state["wait"]["tool_call_ids"] == json!(["timeout-call"])
                && state["wait"]["timeout_seconds"] == 1
            {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            if state["wait"].is_object() && !state["wait"].is_null() {
                return Err(Error::other(format!(
                    "timeout tool exposed the wrong auto wait: {}",
                    state["wait"]
                ))
                .into());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::TimedOut,
            "timeout tool never exposed its auto wait",
        )
    })??;
    let wait_id = waiting["wait"]["wait_id"]
        .as_str()
        .ok_or_else(|| Error::other("auto wait omitted wait_id"))?
        .to_owned();

    // Timer expiry must not turn a still-running tool into a second model
    // round.  The activation may finish its parked wait, but the terminal
    // delivery is the only wake that can make a follow-up eligible.
    let before_release = timeout(Duration::from_secs(10), async {
        loop {
            let state = read_session(&client, &server, &session_id).await?;
            let tool_running = state["tool_calls"].as_array().is_some_and(|calls| {
                calls.iter().any(|call| {
                    call["tool_call_id"] == "timeout-call" && call["status"] == "running"
                })
            });
            let followup_started = state["transcript"].as_array().is_some_and(|messages| {
                messages.iter().any(|message| {
                    message["role"] == "assistant" && message["content"] == "timeout wake observed"
                })
            });
            if tool_running
                && state["wait"].is_null()
                && state["active_activation"].is_null()
                && !followup_started
            {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::TimedOut,
            "timeout did not park while its tool remained running",
        )
    })??;
    assert_eq!(incident.request_count("provider.model"), 1);
    let still_running = wait_for_tool_status(
        &client,
        &incident,
        &public_proxy,
        &session_id,
        "timeout-call",
        "running",
        tool_status_fallback(
            &session_id,
            "timeout-call",
            "timeout_tool",
            "response",
            "running",
            Value::Null,
            Value::Null,
        ),
    )
    .await?;
    assert!(still_running["result"].is_null());
    assert!(still_running["error"].is_null());
    let events = replay_events_through_version(
        &client,
        &server,
        &session_id,
        before_release["version"]
            .as_u64()
            .ok_or_else(|| Error::other("timeout GET omitted version"))?,
    )
    .await?;
    let set_index = events
        .iter()
        .position(|frame| {
            frame.event == "wait_set"
                && frame.data["data"]["wait"]["wait_id"] == wait_id
                && frame.data["data"]["wait"]["tool_call_ids"] == json!(["timeout-call"])
        })
        .ok_or_else(|| Error::other("SSE omitted the exact timeout WaitSet"))?;
    let expired_index = events
        .iter()
        .position(|frame| frame.event == "wait_expired" && frame.data["data"]["wait_id"] == wait_id)
        .ok_or_else(|| Error::other("SSE omitted the exact WaitExpired"))?;
    assert!(
        set_index < expired_index,
        "WaitExpired preceded its WaitSet"
    );
    assert!(!events.iter().any(|frame| {
        frame.event == "async_tool_call_cancelled"
            && frame.data["data"]["tool_call_id"] == "timeout-call"
    }));
    assert_eq!(incident.request_count("tool.timeout"), 1);
    release.notify_waiters();
    tool_proxy.release_replay();
    incident.wait_for_completions("tool.timeout", 1).await?;
    let completed = wait_for_tool_status(
        &client,
        &incident,
        &public_proxy,
        &session_id,
        "timeout-call",
        "completed",
        tool_status_fallback(
            &session_id,
            "timeout-call",
            "timeout_tool",
            "response",
            "completed",
            json!({"content": "late result"}),
            Value::Null,
        ),
    )
    .await?;
    assert_eq!(completed["result"], json!({"content": "late result"}));
    assert!(completed["error"].is_null());
    incident.wait_for_requests("provider.model", 2).await?;
    let after_release = timeout(Duration::from_secs(10), async {
        loop {
            let state = read_session(&client, &server, &session_id).await?;
            if state["wait"].is_null()
                && state["transcript"].as_array().is_some_and(|messages| {
                    messages.iter().any(|message| {
                        message["role"] == "assistant"
                            && message["content"] == "timeout wake observed"
                    })
                })
            {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::TimedOut,
            "timeout did not finish its terminal wake activation",
        )
    })??;
    let after_events = replay_events_through_version(
        &client,
        &server,
        &session_id,
        after_release["version"]
            .as_u64()
            .ok_or_else(|| Error::other("timeout final GET omitted version"))?,
    )
    .await?;
    assert!(after_events.iter().any(|frame| {
        frame.event == "wait_expired" && frame.data["data"]["wait_id"] == wait_id
    }));
    assert_eq!(incident.request_count("tool.timeout"), 1);
    assert_eq!(incident.completed_count("tool.timeout"), 1);
    stop_and_scan_incident_endpoint(&mut server, &database, &[]).await?;
    let result = incident.finish();
    public_proxy.stop().await?;
    provider_proxy.stop().await?;
    tool_proxy.stop().await?;
    model.stop().await?;
    tool.stop().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_bounded_background_tool_output_reaches_durable_terminal() -> TestResult<()> {
    let database = TempDatabase::new("async-bounded-background-output")?;
    let bounded_content = "bounded-background-output\n".repeat(1_600);
    assert!(bounded_content.len() < 64 * 1024);
    assert!(
        serde_json::to_vec(&json!({
            "content": bounded_content,
            "result": {"content": bounded_content},
        }))?
        .len()
            > 64 * 1024,
        "fixture must cross the historical duplicated-delivery bound"
    );
    let release = Arc::new(Notify::new());
    let mut model = ModelFixture::start(vec![
        ModelScript::tool_call(
            "bounded-background-call",
            "bounded_background_tool",
            r#"{"value":"bounded"}"#,
        ),
        ModelScript::final_text("bounded background result observed"),
    ])
    .await?;
    let mut tool = ToolFixture::start(vec![ToolScript::Hold {
        release: release.clone(),
        response: json!({
            "status": "completed",
            "result": {"content": bounded_content}
        }),
    }])
    .await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        vec![tool_config(
            "bounded_background_tool",
            &tool.adapter_url(),
            "response",
            "unknown_outcome",
            "never",
            20,
        )],
        1,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        "create-bounded-background-output",
        &["bounded_background_tool"],
    )
    .await?;
    post_message(
        &client,
        &server,
        &session_id,
        "bounded-background-output-message",
        "return the bounded background result",
    )
    .await?;
    model.wait_for_requests(1).await?;
    tool.wait_for_invocations(1).await?;
    timeout(Duration::from_secs(10), async {
        loop {
            let state = read_session(&client, &server, &session_id).await?;
            if state["tool_calls"].as_array().is_some_and(|calls| {
                calls.iter().any(|call| {
                    call["tool_call_id"] == "bounded-background-call" && call["status"] == "running"
                })
            }) {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "bounded tool never became running"))??;
    release.notify_waiters();
    tool.wait_for_completions(1).await?;
    model.wait_for_requests(2).await?;
    let state = timeout(Duration::from_secs(10), async {
        loop {
            let state = read_session(&client, &server, &session_id).await?;
            let completed = state["tool_calls"].as_array().is_some_and(|calls| {
                calls.iter().any(|call| {
                    call["tool_call_id"] == "bounded-background-call"
                        && call["status"] == "completed"
                        && call["result"]["content"] == bounded_content
                })
            });
            let final_message = state["transcript"].as_array().is_some_and(|messages| {
                messages.iter().any(|message| {
                    message["role"] == "assistant"
                        && message["content"] == "bounded background result observed"
                })
            });
            if completed && final_message {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::TimedOut,
            "bounded background result did not reach durable terminal state",
        )
    })??;
    assert_eq!(model.request_count(), 2);
    assert!(model
        .request(1)
        .is_some_and(|request| contains_exact_string(&request["messages"], &bounded_content)));
    assert_eq!(
        state["tool_calls"].as_array().map(|calls| {
            calls
                .iter()
                .filter(|call| call["tool_call_id"] == "bounded-background-call")
                .count()
        }),
        Some(1)
    );
    server.stop().await?;
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_two_session_waits_do_not_cross() -> TestResult<()> {
    let database = TempDatabase::new("async-isolation")?;
    let mut model = ModelFixture::start(vec![
        ModelScript::tool_call(
            "wait-one",
            "wait_for",
            r#"{"reason":"session one","timeout_seconds":10}"#,
        ),
        ModelScript::tool_call(
            "wait-two",
            "wait_for",
            r#"{"reason":"session two","timeout_seconds":20}"#,
        ),
    ])
    .await?;
    let mut tools = ToolFixture::start(Vec::new()).await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        vec![tool_config(
            "ordinary_tool",
            &tools.adapter_url(),
            "response",
            "unknown_outcome",
            "never",
            20,
        )],
        1,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    install_test_replica(&client, &server.url(""), "install-isolation").await?;
    let first_session_id = create_session_without_replica(
        &client,
        &server,
        &model.provider_url(),
        "create-isolation-one",
        &[],
    )
    .await?;
    let second_session_id = create_session_without_replica(
        &client,
        &server,
        &model.provider_url(),
        "create-isolation-two",
        &[],
    )
    .await?;
    post_message(
        &client,
        &server,
        &first_session_id,
        "isolation-one-message",
        "one",
    )
    .await?;
    model.wait_for_requests(1).await?;
    post_message(
        &client,
        &server,
        &second_session_id,
        "isolation-two-message",
        "two",
    )
    .await?;
    model.wait_for_requests(2).await?;
    assert_eq!(
        model.request_count(),
        2,
        "session isolation made an extra provider request"
    );
    let one = wait_for_wait_state(&client, &server, &first_session_id, "session one", 10).await?;
    let two = wait_for_wait_state(&client, &server, &second_session_id, "session two", 20).await?;
    assert_eq!(one["wait"]["reason"], "session one");
    assert_eq!(one["wait"]["timeout_seconds"], 10);
    assert_eq!(two["wait"]["reason"], "session two");
    assert_eq!(two["wait"]["timeout_seconds"], 20);
    assert!(!one.to_string().contains("session two"));
    assert!(!two.to_string().contains("session one"));
    server.stop().await?;
    model.stop().await?;
    tools.stop().await?;
    Ok(())
}

async fn restart_tool_case(
    label: &str,
    expected_status: &str,
    cancel_status: Option<StatusCode>,
) -> TestResult<()> {
    let database = TempDatabase::new(label)?;
    let mut model = ModelFixture::start(vec![ModelScript::tool_call(
        "restart-call",
        "restart_tool",
        r#"{"value":"restart"}"#,
    )])
    .await?;
    let mut tool = ToolFixture::start(vec![ToolScript::Hold {
        release: Arc::new(Notify::new()),
        response: json!({"status": "completed", "result": {"content": "not reached"}}),
    }])
    .await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        vec![tool_config(
            "restart_tool",
            &tool.adapter_url(),
            "response",
            "unknown_outcome",
            "never",
            20,
        )],
        1,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        &format!("create-{label}"),
        &["restart_tool"],
    )
    .await?;
    post_message(
        &client,
        &server,
        &session_id,
        "restart-message",
        "run before restart",
    )
    .await?;
    tool.wait_for_invocations(1).await?;
    let running = read_session(&client, &server, &session_id).await?;
    let running_tool = running["tool_calls"]
        .as_array()
        .and_then(|calls| {
            calls
                .iter()
                .find(|call| call["tool_call_id"] == "restart-call")
        })
        .ok_or_else(|| Error::other("running tool projection was absent"))?;
    assert_eq!(running_tool["status"], "running");
    assert_eq!(running_tool["allowed_actions"], json!(["cancel"]));
    server.stop().await?;
    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let state = read_session(&client, &restarted, &session_id).await?;
    assert!(state.to_string().contains(expected_status));
    let restarted_tool = state["tool_calls"]
        .as_array()
        .and_then(|calls| {
            calls
                .iter()
                .find(|call| call["tool_call_id"] == "restart-call")
        })
        .ok_or_else(|| Error::other("restarted tool projection was absent"))?;
    assert_eq!(restarted_tool["allowed_actions"], json!([]));
    if let Some(expected) = cancel_status {
        let response = authenticated(client.post(restarted.url(&format!(
            "/v1/sessions/{session_id}/tool-calls/restart-call/cancel"
        ))))
        .header("Idempotency-Key", "restart-cancel")
        .json(&json!({"reason": "inspect recovery"}))
        .send_with_timeout()
        .await?;
        assert_eq!(response.status(), expected);
    }
    restarted.stop().await?;
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_http_response_tool_rejects_runtime_restarted_recovery() -> TestResult<()> {
    let database = TempDatabase::new("invalid-response-recovery")?;
    let mut tool = ToolFixture::start(Vec::new()).await?;
    let config = config_file(
        &database,
        "http://127.0.0.1:1/v1",
        vec![tool_config(
            "response_tool",
            &tool.adapter_url(),
            "response",
            "runtime_restarted",
            "never",
            20,
        )],
        1,
    )?;
    let result = ConfiguredServer::start(&database, &config).await;
    match result {
        Err(error) => {
            let message = error.to_string();
            assert!(
                !message.contains("did not become ready"),
                "invalid HTTP recovery config was treated as readiness timeout: {message}"
            );
            assert!(
                message.contains("non-zero"),
                "invalid HTTP recovery config did not actively exit non-zero: {message}"
            );
        }
        Ok(mut server) => {
            server.stop().await?;
            return Err(Error::other(
                "Endpoint accepted an HTTP response tool with runtime_restarted recovery",
            )
            .into());
        }
    }
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_restart_remote_response_becomes_unknown_and_cancel_cannot_rewrite_it() -> TestResult<()>
{
    restart_tool_case(
        "restart-remote-response",
        "unknown_outcome",
        Some(StatusCode::CONFLICT),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_restart_unknown_response_rejects_unsupported_mark_failed() -> TestResult<()> {
    let database = TempDatabase::new("restart-no-false-failure")?;
    let mut model = ModelFixture::start(vec![ModelScript::tool_call(
        "unknown-call",
        "unknown_tool",
        r#"{"value":"unknown"}"#,
    )])
    .await?;
    let mut tool = ToolFixture::start(vec![ToolScript::Hold {
        release: Arc::new(Notify::new()),
        response: json!({"status": "completed", "result": {"content": "not reached"}}),
    }])
    .await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        vec![tool_config(
            "unknown_tool",
            &tool.adapter_url(),
            "response",
            "unknown_outcome",
            "never",
            20,
        )],
        1,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        "create-unknown-mark-failed",
        &["unknown_tool"],
    )
    .await?;
    post_message(
        &client,
        &server,
        &session_id,
        "unknown-message",
        "run remote work",
    )
    .await?;
    tool.wait_for_invocations(1).await?;
    server.stop().await?;
    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let response = authenticated(client.post(restarted.url(&format!(
        "/v1/sessions/{session_id}/tool-calls/unknown-call/reconcile"
    ))))
    .header("Idempotency-Key", "unsupported-mark-failed")
    .json(&json!({"action": "mark_failed"}))
    .send_with_timeout()
    .await?;
    let status = response.status();
    let body = response_text(response).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let state = read_session(&client, &restarted, &session_id).await?;
    assert!(state.to_string().contains("unknown_outcome"));
    restarted.stop().await?;
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_external_callback_tool_stays_running_and_completes_after_restart() -> TestResult<()> {
    let database = TempDatabase::new("restart-external-callback")?;
    let mut model = ModelFixture::start(vec![
        ModelScript::tool_call("external-call", "external_tool", r#"{"value":"callback"}"#),
        ModelScript::final_text("external callback final"),
    ])
    .await?;
    let mut tool = ToolFixture::start(vec![ToolScript::Hold {
        release: Arc::new(Notify::new()),
        response: json!({"status": "completed", "result": {"content": "ignored"}}),
    }])
    .await?;
    let config = config_file(
        &database,
        &model.provider_url(),
        vec![tool_config(
            "external_tool",
            &tool.adapter_url(),
            "external_callback",
            "await_callback",
            "never",
            20,
        )],
        1,
    )?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &model.provider_url(),
        "create-external-restart",
        &["external_tool"],
    )
    .await?;
    post_message(
        &client,
        &server,
        &session_id,
        "external-message",
        "wait for callback",
    )
    .await?;
    tool.wait_for_invocations(1).await?;
    let (callback_url, bearer) = captured_callback(&tool)?;
    let callback_id = callback_id(&callback_url)?;
    server.stop().await?;
    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let state = read_session(&client, &restarted, &session_id).await?;
    assert!(state.to_string().contains("running"));
    let restarted_callback_url = restarted.url(&format!("/v1/callbacks/{callback_id}"));
    let (status, body) = complete_callback(
        &client,
        &restarted_callback_url,
        &bearer,
        "callback completed",
    )
    .await?;
    assert!(
        status.is_success(),
        "callback completion failed: {status} {body}"
    );
    model.wait_for_requests(2).await?;
    // The provider fixture's request barrier fires when the second request
    // is admitted, before the response stream has been reduced into the
    // durable assistant message.  Wait on that public projection rather than
    // racing a point-in-time GET against the runtime task.
    let final_state = timeout(Duration::from_secs(5), async {
        loop {
            let state = read_session(&client, &restarted, &session_id).await?;
            if state.to_string().contains("external callback final") {
                return Ok::<Value, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::TimedOut,
            "callback assistant projection timed out",
        )
    })??;
    assert!(final_state.to_string().contains("external callback final"));
    restarted.stop().await?;
    model.stop().await?;
    tool.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_cancel_one_tool_does_not_cancel_siblings() -> TestResult<()> {
    const E2E: &str = "e2e_cancel_one_tool_does_not_cancel_siblings";
    let incident = IncidentRecorder::new_with_fixture(
        E2E,
        "retain the first public cancellation failure and both concurrent tool exchanges",
        "e2e_cancel_one_tool_does_not_cancel_siblings.v3",
    )?;
    let database = TempDatabase::new("async-cancel-sibling")?;
    let release_cancelled = Arc::new(Notify::new());
    let release_sibling = Arc::new(Notify::new());
    let first_round = ModelScript::tool_calls(vec![
        ToolCallScript::new("cancel-call", "cancel_tool", r#"{"value":"cancel"}"#),
        ToolCallScript::new("sibling-call", "sibling_tool", r#"{"value":"sibling"}"#),
    ]);
    let scripts = if incident.is_replay() {
        vec![ModelScript::final_text("cancel sibling final")]
    } else {
        vec![first_round, ModelScript::final_text("cancel sibling final")]
    };
    let mut model = ModelFixture::start(scripts).await?;
    let mut provider_proxy = incident
        .proxy("provider.model", model.provider_url())
        .await?;
    let mut cancelled = ToolFixture::start(vec![ToolScript::Hold {
        release: release_cancelled.clone(),
        response: json!({
            "status": "completed",
            "result": {"content": "cancelled tool eventually returned"}
        }),
    }])
    .await?;
    let mut sibling = ToolFixture::start(vec![ToolScript::Hold {
        release: release_sibling.clone(),
        response: json!({
            "status": "completed",
            "result": {"content": "sibling completed"}
        }),
    }])
    .await?;
    let ordered_tools = Arc::new(OrderedArrival::default());
    let mut cancelled_proxy = incident
        .ordered_proxy(
            "tool.cancel",
            cancelled.adapter_url(),
            ordered_tools.clone(),
            0,
            false,
        )
        .await?;
    let mut sibling_proxy = incident
        .ordered_proxy(
            "tool.sibling",
            sibling.adapter_url(),
            ordered_tools,
            1,
            true,
        )
        .await?;
    let config = config_file(
        &database,
        &provider_proxy.base_url(),
        vec![
            tool_config(
                "cancel_tool",
                &cancelled_proxy.base_url(),
                "response",
                "unknown_outcome",
                "never",
                20,
            ),
            tool_config(
                "sibling_tool",
                &sibling_proxy.base_url(),
                "response",
                "unknown_outcome",
                "never",
                20,
            ),
        ],
        1,
    )?;
    let mut server = TestZode::start(
        &database,
        &config,
        &[
            support::TEST_CONTROLLER_SECRET,
            support::TEST_PROVIDER_SECRET,
        ],
    )
    .await?;
    let mut public_cancel_proxy = incident
        .proxy("public.tool_call_cancel", server.url(""))
        .await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &provider_proxy.base_url(),
        "create-cancel-sibling",
        &["cancel_tool", "sibling_tool"],
    )
    .await?;
    incident.register_slot(&session_id, "{{SESSION_ID}}");
    post_message(
        &client,
        &server,
        &session_id,
        "cancel-sibling-message",
        "cancel one tool but keep its sibling",
    )
    .await?;
    incident.wait_for_requests("provider.model", 1).await?;
    let first_request = incident.request_json("provider.model", 0)?;
    assert_provider_tool_contract(&first_request, &["cancel_tool", "sibling_tool"])?;
    incident.wait_for_requests("tool.cancel", 1).await?;
    incident.wait_for_requests("tool.sibling", 1).await?;

    let cancel_response = authenticated(client.post(format!(
        "{}/v1/sessions/{session_id}/tool-calls/cancel-call/cancel",
        public_cancel_proxy.base_url()
    )))
    .header("Idempotency-Key", "cancel-one-call")
    .json(&json!({"reason": "cancel only this call"}))
    .send_with_timeout()
    .await?;
    let cancel_status = cancel_response.status();
    let cancel_body = response_text(cancel_response).await?;
    if !cancel_status.is_success() {
        let safe_error = format!(
            "tool cancellation route returned {cancel_status} before sibling isolation could be observed"
        );
        incident.defer_failure("public.tool_call_cancel", &safe_error);
        release_cancelled.notify_waiters();
        release_sibling.notify_waiters();
        cancelled_proxy.release_replay();
        sibling_proxy.release_replay();
        let _ = incident.wait_for_completions("tool.cancel", 1).await;
        incident.wait_for_completions("tool.sibling", 1).await?;
        let _ = incident.wait_for_completions("provider.model", 2).await;
        stop_and_scan_incident_endpoint(&mut server, &database, &[]).await?;
        let result = incident.finish();
        public_cancel_proxy.stop().await?;
        provider_proxy.stop().await?;
        cancelled_proxy.stop().await?;
        sibling_proxy.stop().await?;
        model.stop().await?;
        cancelled.stop().await?;
        sibling.stop().await?;
        return result;
    }
    let cancelled_record: Value = serde_json::from_str(&cancel_body)?;
    assert_eq!(cancelled_record["status"], "cancelled", "{cancel_body}");
    assert_eq!(cancelled_record["allowed_actions"], json!([]));

    let mut public_status_proxy = incident
        .proxy("public.tool_call_status", server.url(""))
        .await?;
    let sibling_record = wait_for_tool_status(
        &client,
        &incident,
        &public_status_proxy,
        &session_id,
        "sibling-call",
        "running",
        tool_status_fallback(
            &session_id,
            "sibling-call",
            "sibling_tool",
            "response",
            "running",
            Value::Null,
            Value::Null,
        ),
    )
    .await?;
    assert_eq!(sibling_record["status"], "running");
    assert_eq!(sibling_record["allowed_actions"], json!(["cancel"]));
    if !incident.is_replay() {
        assert_eq!(cancelled.invocation_count(), 1);
        assert_eq!(sibling.invocation_count(), 1);
    }

    release_sibling.notify_waiters();
    release_cancelled.notify_waiters();
    cancelled_proxy.release_replay();
    sibling_proxy.release_replay();
    incident.wait_for_completions("tool.sibling", 1).await?;
    incident.wait_for_requests("provider.model", 2).await?;
    incident.wait_for_completions("provider.model", 2).await?;
    let final_state = timeout(Duration::from_secs(5), async {
        loop {
            let state = read_session(&client, &server, &session_id).await?;
            if state.to_string().contains("cancel sibling final") {
                return Ok::<Value, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::TimedOut,
            "cancel-sibling final assistant projection timed out",
        )
    })??;
    let sibling_completed = wait_for_tool_status(
        &client,
        &incident,
        &public_status_proxy,
        &session_id,
        "sibling-call",
        "completed",
        tool_status_fallback(
            &session_id,
            "sibling-call",
            "sibling_tool",
            "response",
            "completed",
            json!({"content": "sibling completed"}),
            Value::Null,
        ),
    )
    .await?;
    assert_eq!(
        sibling_completed["result"],
        json!({"content": "sibling completed"})
    );
    assert_eq!(sibling_completed["allowed_actions"], json!([]));
    assert_eq!(incident.request_count("tool.cancel"), 1);
    assert_eq!(incident.request_count("tool.sibling"), 1);
    let events = replay_events_through_version(
        &client,
        &server,
        &session_id,
        final_state["version"]
            .as_u64()
            .ok_or_else(|| Error::other("cancel sibling GET omitted version"))?,
    )
    .await?;
    assert_eq!(
        events
            .iter()
            .filter(|frame| {
                frame.event == "async_tool_call_cancelled"
                    && frame.data["data"]["tool_call_id"] == "cancel-call"
            })
            .count(),
        1
    );
    assert!(!events.iter().any(|frame| {
        frame.event == "async_tool_call_cancelled"
            && frame.data["data"]["tool_call_id"] == "sibling-call"
    }));
    let unauthorized_response = client
        .post(format!(
            "{}/v1/sessions/{session_id}/tool-calls/cancel-call/cancel",
            public_cancel_proxy.base_url()
        ))
        .json(&json!({"reason": "unauthorized probe"}))
        .send_with_timeout()
        .await?;
    let unauthorized_status = unauthorized_response.status();
    let unauthorized_body = response_text(unauthorized_response).await?;
    assert_eq!(
        unauthorized_status,
        StatusCode::UNAUTHORIZED,
        "{unauthorized_body}"
    );
    if !incident.is_replay() {
        incident.defer_failure(
            "public.tool_call_cancel",
            "missing controller bearer was safely rejected after sibling cancellation",
        );
    }
    stop_and_scan_incident_endpoint(&mut server, &database, &[]).await?;
    let result = incident.finish();
    public_status_proxy.stop().await?;
    public_cancel_proxy.stop().await?;
    provider_proxy.stop().await?;
    cancelled_proxy.stop().await?;
    sibling_proxy.stop().await?;
    model.stop().await?;
    cancelled.stop().await?;
    sibling.stop().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_callback_payload_idempotency_is_canonical() -> TestResult<()> {
    const E2E: &str = "e2e_callback_payload_idempotency_is_canonical";
    let incident = IncidentRecorder::new_with_fixture(
        E2E,
        "retain the first public tool-status failure and canonical callback duplicate exchange",
        "e2e_callback_payload_idempotency_is_canonical.v2",
    )?;
    let database = TempDatabase::new("async-callback-canonical")?;
    let first_round = ModelScript::tool_call(
        "canonical-callback-call",
        "canonical_callback_tool",
        r#"{"value":"canonical"}"#,
    );
    let scripts = if incident.is_replay() {
        vec![ModelScript::final_text("canonical callback final")]
    } else {
        vec![
            first_round,
            ModelScript::final_text("canonical callback final"),
        ]
    };
    let mut model = ModelFixture::start(scripts).await?;
    let mut provider_proxy = incident
        .proxy("provider.model", model.provider_url())
        .await?;
    let release_adapter = Arc::new(Notify::new());
    let mut callback_tool = ToolFixture::start(vec![ToolScript::Hold {
        release: release_adapter.clone(),
        response: json!({
            "status": "completed",
            "result": {"content": "adapter acknowledgement"}
        }),
    }])
    .await?;
    let mut callback_proxy = incident
        .held_proxy("tool.canonical_callback", callback_tool.adapter_url())
        .await?;
    let config = config_file(
        &database,
        &provider_proxy.base_url(),
        vec![tool_config(
            "canonical_callback_tool",
            &callback_proxy.base_url(),
            "external_callback",
            "await_callback",
            "never",
            20,
        )],
        1,
    )?;
    let mut server = TestZode::start(
        &database,
        &config,
        &[
            support::TEST_CONTROLLER_SECRET,
            support::TEST_PROVIDER_SECRET,
        ],
    )
    .await?;
    let mut public_status_proxy = incident
        .proxy("public.tool_call_status", server.url(""))
        .await?;
    let mut public_callback_proxy = incident.proxy("public.callback", server.url("")).await?;
    let client = support::http_client()?;
    let callback_base_url = format!("{}/v1/callbacks", public_callback_proxy.base_url());
    let session_id = create_session_at_callback(
        &client,
        &server,
        &provider_proxy.base_url(),
        "create-callback-canonical",
        &["canonical_callback_tool"],
        &callback_base_url,
    )
    .await?;
    post_message(
        &client,
        &server,
        &session_id,
        "callback-canonical-message",
        "canonical callback payload",
    )
    .await?;
    incident.wait_for_requests("provider.model", 1).await?;
    let first_request = incident.request_json("provider.model", 0)?;
    assert_provider_tool_contract(&first_request, &["canonical_callback_tool"])?;
    incident
        .wait_for_requests("tool.canonical_callback", 1)
        .await?;
    let running = wait_for_tool_status(
        &client,
        &incident,
        &public_status_proxy,
        &session_id,
        "canonical-callback-call",
        "running",
        tool_status_fallback(
            &session_id,
            "canonical-callback-call",
            "canonical_callback_tool",
            "external_callback",
            "running",
            Value::Null,
            Value::Null,
        ),
    )
    .await?;
    assert_eq!(running["status"], "running");
    assert_eq!(running["allowed_actions"], json!(["cancel"]));

    let (callback_url, bearer) =
        captured_callback_from_incident(&incident, "tool.canonical_callback")?;
    incident.register_slot(&bearer, "{{CALLBACK_BEARER}}");
    let first_body = r#"{"status":"completed","result":{"content":"canonical winner"}}"#;
    let duplicate_body = r#"{"result":{"content":"canonical winner"},"status":"completed"}"#;
    let late_body = r#"{"status":"completed","result":{"content":"late replacement"}}"#;
    let (first_status, first_response) =
        complete_callback_json(&client, &callback_url, &bearer, first_body).await?;
    assert!(
        first_status.is_success(),
        "first callback failed: {first_response}"
    );
    incident.wait_for_completions("provider.model", 2).await?;
    let (duplicate_status, duplicate_response) =
        complete_callback_json(&client, &callback_url, &bearer, duplicate_body).await?;
    if !duplicate_status.is_success() {
        let safe_error = format!(
            "canonical duplicate callback was rejected: {duplicate_status} {duplicate_response}"
        );
        incident.defer_failure("public.callback", &safe_error);
    } else {
        assert_eq!(duplicate_response, first_response);
    }
    let completed = wait_for_tool_status(
        &client,
        &incident,
        &public_status_proxy,
        &session_id,
        "canonical-callback-call",
        "completed",
        tool_status_fallback(
            &session_id,
            "canonical-callback-call",
            "canonical_callback_tool",
            "external_callback",
            "completed",
            json!({"content": "canonical winner"}),
            Value::Null,
        ),
    )
    .await?;
    assert_eq!(completed["result"], json!({"content": "canonical winner"}));
    assert_eq!(completed["allowed_actions"], json!([]));
    let terminal_state = timeout(Duration::from_secs(10), async {
        loop {
            let state = read_session(&client, &server, &session_id).await?;
            if state["status"] == "idle" && state["active_activation"].is_null() {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        Error::new(
            ErrorKind::TimedOut,
            "canonical callback terminal barrier timed out",
        )
    })??;
    let terminal_version = terminal_state["version"]
        .as_u64()
        .ok_or_else(|| Error::other("canonical callback GET omitted version"))?;
    let (late_status, late_response) =
        complete_callback_json(&client, &callback_url, &bearer, late_body).await?;
    assert_eq!(late_status, StatusCode::CONFLICT, "{late_response}");
    let after_late = read_session(&client, &server, &session_id).await?;
    assert_eq!(after_late["version"], terminal_version);
    let events =
        replay_events_through_version(&client, &server, &session_id, terminal_version).await?;
    assert_eq!(
        events
            .iter()
            .filter(|frame| {
                frame.event == "async_tool_call_completed"
                    && frame.data["data"]["tool_call_id"] == "canonical-callback-call"
            })
            .count(),
        1
    );
    release_adapter.notify_waiters();
    callback_proxy.release_replay();
    let _ = incident
        .wait_for_completions("tool.canonical_callback", 1)
        .await;
    stop_and_scan_incident_endpoint(&mut server, &database, &[bearer]).await?;
    let result = incident.finish();
    public_callback_proxy.stop().await?;
    public_status_proxy.stop().await?;
    provider_proxy.stop().await?;
    callback_proxy.stop().await?;
    model.stop().await?;
    callback_tool.stop().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_oversized_tool_output_uses_secret_safe_blob_reference() -> TestResult<()> {
    const E2E: &str = "e2e_oversized_tool_output_uses_secret_safe_blob_reference";
    let incident = IncidentRecorder::new_with_fixture(
        E2E,
        "retain the first public tool-status failure and oversized tool output exchange",
        "e2e_oversized_tool_output_uses_secret_safe_blob_reference.v2",
    )?;
    let database = TempDatabase::new("async-oversized-blob")?;
    let oversized_content = "oversized-output-".repeat(5_000);
    assert!(oversized_content.len() > 65_536);
    let mut model = ModelFixture::start(if incident.is_replay() {
        vec![ModelScript::final_text("oversized blob final")]
    } else {
        vec![
            ModelScript::tool_call("oversized-call", "oversized_tool", r#"{"value":"large"}"#),
            ModelScript::final_text("oversized blob final"),
        ]
    })
    .await?;
    let mut provider_proxy = incident
        .proxy("provider.model", model.provider_url())
        .await?;
    let mut tool = ToolFixture::start(vec![ToolScript::Response(json!({
        "status": "completed",
        "result": {"content": oversized_content}
    }))])
    .await?;
    let mut tool_proxy = incident.proxy("tool.oversized", tool.adapter_url()).await?;
    let config = config_file(
        &database,
        &provider_proxy.base_url(),
        vec![tool_config(
            "oversized_tool",
            &tool_proxy.base_url(),
            "response",
            "unknown_outcome",
            "never",
            20,
        )],
        1,
    )?;
    let mut server = TestZode::start(
        &database,
        &config,
        &[
            support::TEST_CONTROLLER_SECRET,
            support::TEST_PROVIDER_SECRET,
        ],
    )
    .await?;
    let mut public_proxy = incident
        .proxy("public.tool_call_status", server.url(""))
        .await?;
    let client = support::http_client()?;
    let session_id = create_session(
        &client,
        &server,
        &provider_proxy.base_url(),
        "create-oversized-blob",
        &["oversized_tool"],
    )
    .await?;
    post_message(
        &client,
        &server,
        &session_id,
        "oversized-blob-message",
        "return a large result",
    )
    .await?;
    incident.wait_for_requests("provider.model", 1).await?;
    let first_request = incident.request_json("provider.model", 0)?;
    assert_provider_tool_contract(&first_request, &["oversized_tool"])?;
    incident.wait_for_requests("tool.oversized", 1).await?;
    incident.wait_for_completions("tool.oversized", 1).await?;
    let record = wait_for_tool_status(
        &client,
        &incident,
        &public_proxy,
        &session_id,
        "oversized-call",
        "completed",
        tool_status_fallback(
            &session_id,
            "oversized-call",
            "oversized_tool",
            "response",
            "completed",
            Value::Null,
            Value::Null,
        ),
    )
    .await?;
    if incident.has_deferred_failure() {
        stop_and_scan_incident_endpoint(&mut server, &database, &[]).await?;
        let result = incident.finish();
        public_proxy.stop().await?;
        provider_proxy.stop().await?;
        tool_proxy.stop().await?;
        model.stop().await?;
        tool.stop().await?;
        return result;
    }
    assert_eq!(record["status"], "completed");
    let blob = record["result"]["blob"]
        .as_object()
        .ok_or_else(|| Error::other("oversized tool result was not a blob reference"))?;
    assert!(blob["id"].as_str().is_some());
    assert!(blob["bytes"].as_u64().is_some_and(|bytes| bytes > 65_536));
    assert!(record["result"]["content"].is_null());
    assert!(!record.to_string().contains(support::TEST_PROVIDER_SECRET));
    let state = read_session(&client, &server, &session_id).await?;
    assert!(!state.to_string().contains(&oversized_content));
    assert!(!state.to_string().contains(support::TEST_PROVIDER_SECRET));
    let blobs = database
        .path()
        .parent()
        .ok_or_else(|| Error::other("oversized blob database omitted its root"))?
        .join("blobs");
    let blob_files = fs::read_dir(&blobs)?.collect::<Result<Vec<_>, _>>()?;
    assert!(
        !blob_files.is_empty(),
        "oversized output did not create a blob file"
    );
    let unauthorized_response = client
        .get(format!(
            "{}/v1/sessions/{session_id}/tool-calls/oversized-call",
            public_proxy.base_url()
        ))
        .send_with_timeout()
        .await?;
    let unauthorized_status = unauthorized_response.status();
    let unauthorized_body = response_text(unauthorized_response).await?;
    assert_eq!(
        unauthorized_status,
        StatusCode::UNAUTHORIZED,
        "{unauthorized_body}"
    );
    if !incident.is_replay() {
        incident.defer_failure(
            "public.tool_call_status",
            "missing controller bearer was safely rejected after oversized result inspection",
        );
    }
    stop_and_scan_incident_endpoint(&mut server, &database, &[]).await?;
    let result = incident.finish();
    public_proxy.stop().await?;
    provider_proxy.stop().await?;
    tool_proxy.stop().await?;
    model.stop().await?;
    tool.stop().await?;
    result
}

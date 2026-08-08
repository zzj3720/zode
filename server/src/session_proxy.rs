use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, Response, StatusCode},
};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    access::ActorContext,
    store::{
        AuthProfileRecord, AuthReplicaRecord, ControlStore, EndpointRecord,
        ProviderDescriptorRecord, StoreError,
    },
};

const MAX_ENDPOINT_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_TOOLS: usize = 128;

#[derive(Debug, Error)]
pub(crate) enum SessionProxyError {
    #[error("session request is invalid")]
    Invalid,
    #[error("session request is too large")]
    PayloadTooLarge,
    #[error("session resource was not found")]
    NotFound,
    #[error("session command conflicts with an existing command")]
    Conflict,
    #[error("Endpoint is unavailable")]
    EndpointUnavailable,
    #[error("credential replica is unavailable")]
    AuthReplicaUnavailable,
    #[error("session proxy failed")]
    Internal,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateSessionRequest {
    #[serde(default)]
    model: Option<ModelSelectionRequest>,
    #[serde(default)]
    tools: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModelSelectionRequest {
    provider: String,
    model: String,
    provider_execution: ProviderExecution,
    #[serde(default, rename = "auth_authority_id")]
    _auth_authority_id: Option<String>,
    auth_profile_id: String,
    minimum_auth_revision: u64,
}

type CreateModelSelection = ModelSelectionRequest;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderExecution {
    schema: String,
    revision: u64,
    kind: String,
    base_url: String,
    #[serde(default)]
    options: BTreeMap<String, Value>,
}

pub(crate) struct ProxyJson {
    pub(crate) status: StatusCode,
    pub(crate) body: Value,
}

struct EndpointTarget {
    record: EndpointRecord,
    authorization: HeaderValue,
}

struct CreatePolicy {
    forwarded: Value,
}

enum EndpointJson {
    Public(ProxyJson),
    ReceiptMiss,
}

struct JsonRequest<'a> {
    idempotency_key: Option<&'a str>,
    body: Option<&'a Value>,
    replay_only: bool,
}

pub(crate) struct SessionProxy {
    store: Arc<ControlStore>,
    client: reqwest::Client,
    callback_origin: String,
    create_policy: Mutex<()>,
}

impl SessionProxy {
    pub(crate) fn new(store: Arc<ControlStore>, callback_origin: String) -> Result<Self, ()> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ())?;
        Ok(Self {
            store,
            client,
            callback_origin,
            create_policy: Mutex::new(()),
        })
    }

    pub(crate) async fn create_session(
        &self,
        actor: &ActorContext,
        endpoint_id: &str,
        idempotency_key: &str,
        request: CreateSessionRequest,
    ) -> Result<ProxyJson, SessionProxyError> {
        validate_idempotency_key(idempotency_key)?;
        let target = self.endpoint_target(endpoint_id).await?;
        let provisional = self.create_body(endpoint_id, &request)?;
        match self
            .send_json(
                &target,
                actor,
                reqwest::Method::POST,
                "/v1/sessions",
                JsonRequest {
                    idempotency_key: Some(idempotency_key),
                    body: Some(&provisional),
                    replay_only: true,
                },
            )
            .await?
        {
            EndpointJson::Public(response) => return Ok(response),
            EndpointJson::ReceiptMiss => {}
        }

        let _policy = self.create_policy.lock().await;
        let policy = self
            .validate_create_policy(&target.record, endpoint_id, &request)
            .await?;
        match self
            .send_json(
                &target,
                actor,
                reqwest::Method::POST,
                "/v1/sessions",
                JsonRequest {
                    idempotency_key: Some(idempotency_key),
                    body: Some(&policy.forwarded),
                    replay_only: false,
                },
            )
            .await?
        {
            EndpointJson::Public(response) => Ok(response),
            EndpointJson::ReceiptMiss => Err(SessionProxyError::Internal),
        }
    }

    pub(crate) async fn list_sessions(
        &self,
        actor: &ActorContext,
        endpoint_id: &str,
        limit: Option<u64>,
        cursor: Option<&str>,
    ) -> Result<ProxyJson, SessionProxyError> {
        let target = self.endpoint_target(endpoint_id).await?;
        let mut url = url::Url::parse(&format!("{}/v1/sessions", target.record.base_url))
            .map_err(|_| SessionProxyError::Internal)?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(limit) = limit {
                query.append_pair("limit", &limit.to_string());
            }
            if let Some(cursor) = cursor {
                if cursor.is_empty()
                    || cursor.len() > 4 * 1024
                    || cursor.chars().any(char::is_control)
                {
                    return Err(SessionProxyError::Invalid);
                }
                query.append_pair("cursor", cursor);
            }
        }
        self.send_json_url(
            &target,
            actor,
            reqwest::Method::GET,
            url,
            JsonRequest {
                idempotency_key: None,
                body: None,
                replay_only: false,
            },
        )
        .await
        .and_then(public_only)
    }

    pub(crate) async fn get_session(
        &self,
        actor: &ActorContext,
        endpoint_id: &str,
        session_id: &str,
    ) -> Result<ProxyJson, SessionProxyError> {
        validate_path_identifier(session_id)?;
        let target = self.endpoint_target(endpoint_id).await?;
        self.send_json(
            &target,
            actor,
            reqwest::Method::GET,
            &format!("/v1/sessions/{session_id}"),
            JsonRequest {
                idempotency_key: None,
                body: None,
                replay_only: false,
            },
        )
        .await
        .and_then(public_only)
    }

    pub(crate) async fn append_message(
        &self,
        actor: &ActorContext,
        endpoint_id: &str,
        session_id: &str,
        idempotency_key: &str,
        body: Value,
    ) -> Result<ProxyJson, SessionProxyError> {
        validate_path_identifier(session_id)?;
        validate_idempotency_key(idempotency_key)?;
        let target = self.endpoint_target(endpoint_id).await?;
        let path = format!("/v1/sessions/{session_id}/messages");
        match self
            .send_json(
                &target,
                actor,
                reqwest::Method::POST,
                &path,
                JsonRequest {
                    idempotency_key: Some(idempotency_key),
                    body: Some(&body),
                    replay_only: true,
                },
            )
            .await?
        {
            EndpointJson::Public(response) => return Ok(response),
            EndpointJson::ReceiptMiss => {}
        }
        self.send_json(
            &target,
            actor,
            reqwest::Method::POST,
            &path,
            JsonRequest {
                idempotency_key: Some(idempotency_key),
                body: Some(&body),
                replay_only: false,
            },
        )
        .await
        .and_then(public_only)
    }

    pub(crate) async fn select_model(
        &self,
        actor: &ActorContext,
        endpoint_id: &str,
        session_id: &str,
        idempotency_key: &str,
        request: ModelSelectionRequest,
    ) -> Result<ProxyJson, SessionProxyError> {
        validate_path_identifier(session_id)?;
        validate_idempotency_key(idempotency_key)?;
        let target = self.endpoint_target(endpoint_id).await?;
        let body = self.model_body(&request);
        let path = format!("/v1/sessions/{session_id}/model");
        match self
            .send_json(
                &target,
                actor,
                reqwest::Method::PUT,
                &path,
                JsonRequest {
                    idempotency_key: Some(idempotency_key),
                    body: Some(&body),
                    replay_only: true,
                },
            )
            .await?
        {
            EndpointJson::Public(response) => return Ok(response),
            EndpointJson::ReceiptMiss => {}
        }

        let policy = self
            .validate_create_policy(
                &target.record,
                endpoint_id,
                &CreateSessionRequest {
                    model: Some(request),
                    tools: Vec::new(),
                },
            )
            .await?;
        let model = policy
            .forwarded
            .get("model")
            .cloned()
            .ok_or(SessionProxyError::Internal)?;
        match self
            .send_json(
                &target,
                actor,
                reqwest::Method::PUT,
                &path,
                JsonRequest {
                    idempotency_key: Some(idempotency_key),
                    body: Some(&model),
                    replay_only: false,
                },
            )
            .await?
        {
            EndpointJson::Public(response) => Ok(response),
            EndpointJson::ReceiptMiss => Err(SessionProxyError::Internal),
        }
    }

    pub(crate) async fn stream_events(
        &self,
        actor: &ActorContext,
        endpoint_id: &str,
        session_id: &str,
        last_event_id: Option<&str>,
    ) -> Result<Response<Body>, SessionProxyError> {
        validate_path_identifier(session_id)?;
        if last_event_id.is_some_and(|value| {
            value.is_empty()
                || value.len() > 128
                || !value.as_bytes().iter().all(u8::is_ascii_digit)
        }) {
            return Err(SessionProxyError::Invalid);
        }
        let target = self.endpoint_target(endpoint_id).await?;
        let mut request = self.authorized_request(
            &target,
            actor,
            reqwest::Method::GET,
            &format!("/v1/sessions/{session_id}/events"),
        )?;
        if let Some(last_event_id) = last_event_id {
            request = request.header("last-event-id", last_event_id);
        }
        let response = tokio::time::timeout_at(actor.assertion_expiry_deadline(), request.send())
            .await
            .map_err(|_| SessionProxyError::EndpointUnavailable)?
            .map_err(|_| SessionProxyError::EndpointUnavailable)?;
        if !response.status().is_success() {
            return Err(map_endpoint_error(response).await);
        }
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
        {
            return Err(SessionProxyError::EndpointUnavailable);
        }
        let source = Box::pin(response.bytes_stream());
        let expiry = actor.assertion_expiry_deadline();
        let stream = futures_util::stream::unfold(
            (source, expiry),
            |(mut source, expiry)| async move {
                tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(expiry) => None,
                    item = source.next() => item.map(|chunk| {
                        let result = chunk.map_err(|_| std::io::Error::other("Endpoint event stream closed"));
                        (result, (source, expiry))
                    }),
                }
            },
        );
        let mut public = Response::new(Body::from_stream(stream));
        *public.status_mut() = StatusCode::OK;
        public.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        public
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        Ok(public)
    }

    pub(crate) async fn forward_callback(
        &self,
        endpoint_id: &str,
        callback_id: &str,
        headers: &HeaderMap,
        body: Vec<u8>,
    ) -> Result<ProxyJson, SessionProxyError> {
        validate_callback_id(callback_id)?;
        let authorization = callback_authorization(headers)?;
        let content_type = optional_header(headers, header::CONTENT_TYPE)?;
        let record = self.endpoint_record(endpoint_id).await?;
        let url = url::Url::parse(&format!("{}/v1/callbacks/{callback_id}", record.base_url))
            .map_err(|_| SessionProxyError::Internal)?;
        let mut request = self
            .client
            .post(url)
            .header(header::AUTHORIZATION, authorization)
            .body(body)
            .timeout(Duration::from_secs(10));
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, content_type);
        }
        let response = request
            .send()
            .await
            .map_err(|_| SessionProxyError::EndpointUnavailable)?;
        let status = response.status();
        let body = read_bounded_json(response).await?;
        if status.is_success() {
            return Ok(ProxyJson { status, body });
        }
        let code = body
            .get("error")
            .and_then(Value::as_object)
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str);
        Err(map_status(status, code))
    }

    async fn validate_create_policy(
        &self,
        endpoint: &EndpointRecord,
        endpoint_id: &str,
        request: &CreateSessionRequest,
    ) -> Result<CreatePolicy, SessionProxyError> {
        if request.tools.len() > MAX_TOOLS
            || request
                .tools
                .iter()
                .any(|tool| !valid_identifier(tool) || !endpoint.tools.contains(tool))
        {
            return Err(SessionProxyError::Invalid);
        }
        let Some(model) = request.model.as_ref() else {
            return Ok(CreatePolicy {
                forwarded: self.create_body(endpoint_id, request)?,
            });
        };
        if !valid_identifier(&model.provider)
            || !valid_identifier(&model.model)
            || !valid_identifier(&model.auth_profile_id)
            || model.minimum_auth_revision == 0
            || model.provider_execution.schema != "zode.provider-execution.v1"
        {
            return Err(SessionProxyError::Invalid);
        }
        let store = Arc::clone(&self.store);
        let provider = model.provider.clone();
        let profile_id = model.auth_profile_id.clone();
        let revision = model.provider_execution.revision;
        let endpoint_id_owned = endpoint_id.to_owned();
        let (descriptor, profile, replicas) = tokio::task::spawn_blocking(move || {
            let descriptor = store
                .get_provider_descriptor_revision(&provider, revision)?
                .ok_or(StoreError::Integrity)?;
            let profile = store
                .get_auth_profile(&profile_id)?
                .ok_or(StoreError::Integrity)?;
            let replicas = store.list_auth_replicas(&profile_id)?;
            if !replicas
                .iter()
                .any(|replica| replica.endpoint_id == endpoint_id_owned)
            {
                return Err(StoreError::Integrity);
            }
            Ok::<_, StoreError>((descriptor, profile, replicas))
        })
        .await
        .map_err(|_| SessionProxyError::Internal)?
        .map_err(|_| SessionProxyError::Invalid)?;
        validate_descriptor(model, &descriptor)?;
        validate_profile(model, endpoint_id, &profile, &replicas)?;
        if !endpoint.provider_adapter_kinds.contains(&descriptor.kind) {
            return Err(SessionProxyError::Invalid);
        }
        Ok(CreatePolicy {
            forwarded: self.create_body(endpoint_id, request)?,
        })
    }

    fn create_body(
        &self,
        endpoint_id: &str,
        request: &CreateSessionRequest,
    ) -> Result<Value, SessionProxyError> {
        let model = request.model.as_ref().map(|model| self.model_body(model));
        Ok(json!({
            "model": model,
            "tools": request.tools,
            "callback_base_url": format!(
                "{}/v1/endpoints/{endpoint_id}/callbacks",
                self.callback_origin
            ),
        }))
    }

    fn model_body(&self, model: &ModelSelectionRequest) -> Value {
        json!({
            "provider": model.provider,
            "provider_execution": {
                "schema": model.provider_execution.schema,
                "revision": model.provider_execution.revision,
                "kind": model.provider_execution.kind,
                "base_url": model.provider_execution.base_url,
                "options": model.provider_execution.options,
            },
            "model": model.model,
            "auth_authority_id": self.store.authority_id(),
            "auth_profile_id": model.auth_profile_id,
            "minimum_auth_revision": model.minimum_auth_revision,
        })
    }

    async fn endpoint_target(
        &self,
        endpoint_id: &str,
    ) -> Result<EndpointTarget, SessionProxyError> {
        validate_path_identifier(endpoint_id)?;
        let store = Arc::clone(&self.store);
        let endpoint_id = endpoint_id.to_owned();
        let (record, mut secret) = tokio::task::spawn_blocking(move || {
            let record = store
                .get_endpoint(&endpoint_id)?
                .ok_or(StoreError::Integrity)?;
            let secret = store
                .load_endpoint_secret(&record.secret_ref)?
                .ok_or(StoreError::Integrity)?;
            Ok::<_, StoreError>((record, secret))
        })
        .await
        .map_err(|_| SessionProxyError::Internal)?
        .map_err(|_| SessionProxyError::NotFound)?;
        let authorization = {
            let secret_text =
                std::str::from_utf8(&secret).map_err(|_| SessionProxyError::Internal)?;
            HeaderValue::from_str(&format!("Bearer {secret_text}"))
                .map_err(|_| SessionProxyError::Internal)?
        };
        secret_bytes_clear(&mut secret);
        Ok(EndpointTarget {
            record,
            authorization,
        })
    }

    async fn endpoint_record(
        &self,
        endpoint_id: &str,
    ) -> Result<EndpointRecord, SessionProxyError> {
        validate_path_identifier(endpoint_id)?;
        let store = Arc::clone(&self.store);
        let endpoint_id = endpoint_id.to_owned();
        tokio::task::spawn_blocking(move || store.get_endpoint(&endpoint_id))
            .await
            .map_err(|_| SessionProxyError::Internal)?
            .map_err(|_| SessionProxyError::Internal)?
            .ok_or(SessionProxyError::NotFound)
    }

    fn authorized_request(
        &self,
        target: &EndpointTarget,
        actor: &ActorContext,
        method: reqwest::Method,
        path: &str,
    ) -> Result<reqwest::RequestBuilder, SessionProxyError> {
        let url = url::Url::parse(&format!("{}{}", target.record.base_url, path))
            .map_err(|_| SessionProxyError::Internal)?;
        Ok(self
            .client
            .request(method, url)
            .header(header::AUTHORIZATION, target.authorization.clone())
            .header("zode-subject", actor.endpoint_subject()))
    }

    async fn send_json(
        &self,
        target: &EndpointTarget,
        actor: &ActorContext,
        method: reqwest::Method,
        path: &str,
        details: JsonRequest<'_>,
    ) -> Result<EndpointJson, SessionProxyError> {
        let url = url::Url::parse(&format!("{}{}", target.record.base_url, path))
            .map_err(|_| SessionProxyError::Internal)?;
        self.send_json_url(target, actor, method, url, details)
            .await
    }

    async fn send_json_url(
        &self,
        target: &EndpointTarget,
        actor: &ActorContext,
        method: reqwest::Method,
        url: url::Url,
        details: JsonRequest<'_>,
    ) -> Result<EndpointJson, SessionProxyError> {
        let mut request = self
            .client
            .request(method, url)
            .header(header::AUTHORIZATION, target.authorization.clone())
            .header("zode-subject", actor.endpoint_subject())
            .timeout(Duration::from_secs(10));
        if let Some(idempotency_key) = details.idempotency_key {
            request = request.header("idempotency-key", idempotency_key);
        }
        if details.replay_only {
            request = request.header("zode-idempotency-mode", "replay-only");
        }
        if let Some(body) = details.body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| SessionProxyError::EndpointUnavailable)?;
        let status = response.status();
        let body = read_bounded_json(response).await?;
        if status.is_success() {
            return Ok(EndpointJson::Public(ProxyJson { status, body }));
        }
        let code = body
            .get("error")
            .and_then(Value::as_object)
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str);
        if details.replay_only
            && status == StatusCode::NOT_FOUND
            && code == Some("idempotency_receipt_not_found")
        {
            return Ok(EndpointJson::ReceiptMiss);
        }
        Err(map_status(status, code))
    }
}

fn validate_descriptor(
    model: &CreateModelSelection,
    descriptor: &ProviderDescriptorRecord,
) -> Result<(), SessionProxyError> {
    let models: Vec<String> =
        serde_json::from_str(&descriptor.models_json).map_err(|_| SessionProxyError::Internal)?;
    let options: BTreeMap<String, Value> =
        serde_json::from_str(&descriptor.options_json).map_err(|_| SessionProxyError::Internal)?;
    if descriptor.provider != model.provider
        || descriptor.revision != model.provider_execution.revision
        || descriptor.kind != model.provider_execution.kind
        || descriptor.base_url != model.provider_execution.base_url
        || options != model.provider_execution.options
        || !models.contains(&model.model)
    {
        return Err(SessionProxyError::Invalid);
    }
    Ok(())
}

fn validate_profile(
    model: &CreateModelSelection,
    endpoint_id: &str,
    profile: &AuthProfileRecord,
    replicas: &[AuthReplicaRecord],
) -> Result<(), SessionProxyError> {
    if profile.deleted_at_ms.is_some() {
        return Err(SessionProxyError::AuthReplicaUnavailable);
    }
    if profile.profile_id != model.auth_profile_id
        || profile.provider != model.provider
        || profile.kind != "api_key"
        || profile.revision < model.minimum_auth_revision
    {
        return Err(SessionProxyError::Invalid);
    }
    let endpoint_ids: Vec<String> = serde_json::from_str(&profile.endpoint_ids_json)
        .map_err(|_| SessionProxyError::Internal)?;
    if profile.sharing_mode != "selected" || !endpoint_ids.iter().any(|id| id == endpoint_id) {
        return Err(SessionProxyError::AuthReplicaUnavailable);
    }
    let replica = replicas
        .iter()
        .find(|replica| replica.endpoint_id == endpoint_id)
        .ok_or(SessionProxyError::AuthReplicaUnavailable)?;
    if replica.status != "ready"
        || replica.revision < model.minimum_auth_revision
        || replica.observed_revision.unwrap_or(0) < model.minimum_auth_revision
    {
        return Err(SessionProxyError::AuthReplicaUnavailable);
    }
    Ok(())
}

async fn read_bounded_json(response: reqwest::Response) -> Result<Value, SessionProxyError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ENDPOINT_RESPONSE_BYTES as u64)
    {
        return Err(SessionProxyError::EndpointUnavailable);
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| SessionProxyError::EndpointUnavailable)?;
        if bytes.len().saturating_add(chunk.len()) > MAX_ENDPOINT_RESPONSE_BYTES {
            return Err(SessionProxyError::EndpointUnavailable);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| SessionProxyError::EndpointUnavailable)
}

async fn map_endpoint_error(response: reqwest::Response) -> SessionProxyError {
    let status = response.status();
    match read_bounded_json(response).await {
        Ok(body) => {
            let code = body
                .get("error")
                .and_then(Value::as_object)
                .and_then(|error| error.get("code"))
                .and_then(Value::as_str);
            map_status(status, code)
        }
        Err(error) => error,
    }
}

fn map_status(status: StatusCode, code: Option<&str>) -> SessionProxyError {
    match status {
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => SessionProxyError::Invalid,
        StatusCode::PAYLOAD_TOO_LARGE => SessionProxyError::PayloadTooLarge,
        StatusCode::NOT_FOUND => SessionProxyError::NotFound,
        StatusCode::CONFLICT => SessionProxyError::Conflict,
        StatusCode::SERVICE_UNAVAILABLE if code == Some("auth_replica_unavailable") => {
            SessionProxyError::AuthReplicaUnavailable
        }
        StatusCode::SERVICE_UNAVAILABLE | StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT => {
            SessionProxyError::EndpointUnavailable
        }
        _ => SessionProxyError::Internal,
    }
}

fn public_only(outcome: EndpointJson) -> Result<ProxyJson, SessionProxyError> {
    match outcome {
        EndpointJson::Public(response) => Ok(response),
        EndpointJson::ReceiptMiss => Err(SessionProxyError::Internal),
    }
}

fn validate_idempotency_key(value: &str) -> Result<(), SessionProxyError> {
    if value.is_empty()
        || value.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(SessionProxyError::Invalid);
    }
    Ok(())
}

fn validate_path_identifier(value: &str) -> Result<(), SessionProxyError> {
    if !valid_identifier(value) {
        return Err(SessionProxyError::Invalid);
    }
    Ok(())
}

fn validate_callback_id(value: &str) -> Result<(), SessionProxyError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        })
    {
        return Err(SessionProxyError::Invalid);
    }
    Ok(())
}

fn callback_authorization(headers: &HeaderMap) -> Result<HeaderValue, SessionProxyError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(SessionProxyError::NotFound)?;
    if values.next().is_some() {
        return Err(SessionProxyError::NotFound);
    }
    Ok(value.clone())
}

fn optional_header(
    headers: &HeaderMap,
    name: header::HeaderName,
) -> Result<Option<HeaderValue>, SessionProxyError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(SessionProxyError::Invalid);
    }
    Ok(Some(value.clone()))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn secret_bytes_clear(bytes: &mut [u8]) {
    bytes.fill(0);
}

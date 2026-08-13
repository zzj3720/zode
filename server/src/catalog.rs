use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::Mutex;
use url::{Host, Url};
use zode_protocol::{negotiate_endpoint_protocol, EndpointCapabilities, EndpointIdentity};

use crate::{
    access::ActorContext,
    store::{
        hex, BeginEndpointCreate, ControlStore, EndpointCreateCompletion, EndpointCreateOperation,
        EndpointRecord, StoreError,
    },
};

const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_LABEL_BYTES: usize = 256;
const MAX_BASE_URL_BYTES: usize = 2 * 1024;
const MAX_CONTROL_SECRET_BYTES: usize = 64 * 1024;
const MAX_ENDPOINT_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub(crate) enum CatalogError {
    #[error("invalid Endpoint request")]
    Invalid,
    #[error("Endpoint was not found")]
    NotFound,
    #[error("Endpoint request is too large")]
    PayloadTooLarge,
    #[error("Endpoint command conflicts with an existing operation")]
    Conflict,
    #[error("Endpoint is unavailable")]
    EndpointUnavailable,
    #[error("Endpoint catalog failed")]
    Internal,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateEndpointRequest {
    label: String,
    base_url: String,
    #[serde(default)]
    control_auth: Option<ControlAuth>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlAuth {
    kind: String,
    secret: String,
}

pub(crate) struct EndpointProbe {
    pub(crate) identity: EndpointIdentity,
    pub(crate) capabilities: EndpointCapabilities,
}

pub(crate) struct Catalog {
    store: Arc<ControlStore>,
    client: reqwest::Client,
    creates: Mutex<()>,
}

impl Catalog {
    pub(crate) fn new(store: Arc<ControlStore>) -> Result<Self, ()> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ())?;
        Ok(Self {
            store,
            client,
            creates: Mutex::new(()),
        })
    }

    pub(crate) async fn create_endpoint(
        &self,
        actor: &ActorContext,
        idempotency_key: &str,
        mut request: CreateEndpointRequest,
    ) -> Result<Value, CatalogError> {
        if !validate_text(idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES)
            || !validate_text(&request.label, MAX_LABEL_BYTES)
        {
            return Err(CatalogError::Invalid);
        }
        request.base_url = normalize_endpoint_url(&request.base_url)?;
        let control_secret = request
            .control_auth
            .as_ref()
            .map(|auth| auth.secret.as_str())
            .unwrap_or("")
            .to_owned();
        if let Some(auth) = request.control_auth.as_ref() {
            if auth.kind != "bearer"
                || auth.secret.len() > MAX_CONTROL_SECRET_BYTES
                || auth.secret.as_bytes().iter().any(u8::is_ascii_whitespace)
            {
                return Err(if auth.secret.len() > MAX_CONTROL_SECRET_BYTES {
                    CatalogError::PayloadTooLarge
                } else {
                    CatalogError::Invalid
                });
            }
        }

        let keys = self.store.keys();
        let actor_key = *actor.actor_key();
        let command_key = keys.digest(
            b"endpoint-create-command-v1",
            &[&actor_key, idempotency_key.as_bytes()],
        );
        let request_fingerprint =
            request_fingerprint(&keys, &request.label, &request.base_url, &control_secret);
        let secret_ref = hex(&keys.digest(
            b"endpoint-control-secret-ref-v1",
            &[&actor_key, &command_key],
        ));
        let candidate = EndpointCreateOperation {
            actor_key,
            command_key,
            request_fingerprint,
            label: request.label,
            base_url: request.base_url,
            secret_ref,
            created_at_ms: unix_millis()?,
        };

        let _create = self.creates.lock().await;
        let store = Arc::clone(&self.store);
        let begin = tokio::task::spawn_blocking(move || store.begin_endpoint_create(candidate))
            .await
            .map_err(|_| CatalogError::Internal)?
            .map_err(map_store_error)?;
        let (operation, replay) = match begin {
            BeginEndpointCreate::Pending(operation) => (operation, None),
            BeginEndpointCreate::Complete(operation, record) => (operation, Some(record)),
        };
        verify_operation(&keys, &operation, &control_secret, replay.as_deref())?;
        if let Some(record) = replay {
            return Ok(public_endpoint(&record));
        }

        let store = Arc::clone(&self.store);
        let secret_ref = operation.secret_ref.clone();
        let mut secret = control_secret.into_bytes();
        tokio::task::spawn_blocking(move || {
            let result = store.stage_endpoint_secret(&secret_ref, &secret);
            secret.fill(0);
            result
        })
        .await
        .map_err(|_| CatalogError::Internal)?
        .map_err(map_store_error)?;

        let probe = self.probe_endpoint(&operation.base_url).await?;
        let store = Arc::clone(&self.store);
        let operation = Arc::new(operation);
        let completion = Arc::clone(&operation);
        let probe = EndpointCreateCompletion {
            endpoint_id: probe.identity.endpoint_id,
            controller_authority_id: probe.identity.authority_id,
            controller_credential_revision: probe.identity.revision,
            protocol_version: probe.identity.protocol_version,
            provider_adapter_kinds: probe.capabilities.provider_adapter_kinds,
            tools: probe
                .capabilities
                .tools
                .into_iter()
                .map(|tool| tool.name)
                .collect(),
        };
        let record =
            tokio::task::spawn_blocking(move || store.complete_endpoint_create(&completion, probe))
                .await
                .map_err(|_| CatalogError::Internal)?
                .map_err(map_store_error)?;
        Ok(public_endpoint(&record))
    }

    pub(crate) async fn list_endpoints(&self) -> Result<Value, CatalogError> {
        let store = Arc::clone(&self.store);
        let records = tokio::task::spawn_blocking(move || store.list_endpoints())
            .await
            .map_err(|_| CatalogError::Internal)?
            .map_err(map_store_error)?;
        Ok(json!({
            "schema": "zode.endpoints.v1",
            "items": records.iter().map(public_endpoint).collect::<Vec<_>>()
        }))
    }

    pub(crate) async fn get_endpoint(
        &self,
        endpoint_id: &str,
    ) -> Result<Option<Value>, CatalogError> {
        if !validate_text(endpoint_id, 256) {
            return Err(CatalogError::Invalid);
        }
        let store = Arc::clone(&self.store);
        let endpoint_id = endpoint_id.to_owned();
        let record = tokio::task::spawn_blocking(move || store.get_endpoint(&endpoint_id))
            .await
            .map_err(|_| CatalogError::Internal)?
            .map_err(map_store_error)?;
        Ok(record.as_ref().map(public_endpoint))
    }

    pub(crate) async fn probe_endpoint_by_id(
        &self,
        endpoint_id: &str,
    ) -> Result<Value, CatalogError> {
        if !validate_text(endpoint_id, 256) {
            return Err(CatalogError::Invalid);
        }
        let store = Arc::clone(&self.store);
        let endpoint_id_owned = endpoint_id.to_owned();
        let record = tokio::task::spawn_blocking(move || {
            store
                .get_endpoint(&endpoint_id_owned)
                .map_err(map_store_error)?
                .ok_or(CatalogError::NotFound)
        })
        .await
        .map_err(|_| CatalogError::Internal)??;
        let probe = self.probe_endpoint(&record.base_url).await?;
        if probe.identity.endpoint_id != record.endpoint_id
            || probe.identity.protocol_version != record.protocol_version
        {
            return Err(CatalogError::EndpointUnavailable);
        }
        Ok(public_endpoint_observation(
            &record,
            "online",
            unix_millis()?,
        ))
    }

    pub(crate) async fn probe_local_endpoint(
        &self,
        base_url: &str,
        secret: &str,
    ) -> Result<EndpointProbe, CatalogError> {
        let _ = secret;
        self.probe_endpoint(base_url).await
    }

    pub(crate) async fn install_auth_replica(
        &self,
        endpoint_id: &str,
        profile_id: &str,
        operation_id: &str,
        body: Value,
    ) -> Result<Value, CatalogError> {
        if !validate_text(endpoint_id, 256)
            || !validate_text(profile_id, 256)
            || !validate_text(operation_id, MAX_IDEMPOTENCY_KEY_BYTES)
        {
            return Err(CatalogError::Invalid);
        }
        let store = Arc::clone(&self.store);
        let endpoint_id = endpoint_id.to_owned();
        let endpoint = tokio::task::spawn_blocking(move || {
            store
                .get_endpoint(&endpoint_id)?
                .ok_or(StoreError::Integrity)
        })
        .await
        .map_err(|_| CatalogError::Internal)?
        .map_err(map_store_error)?;
        let response = self
            .client
            .put(format!(
                "{}/v1/auth-replicas/{profile_id}",
                endpoint.base_url
            ))
            .header("idempotency-key", operation_id)
            .json(&body)
            .send()
            .await
            .map_err(|_| CatalogError::EndpointUnavailable)?;
        if !response.status().is_success() {
            return Err(CatalogError::EndpointUnavailable);
        }
        read_json_response(response).await
    }

    async fn probe_endpoint(&self, base_url: &str) -> Result<EndpointProbe, CatalogError> {
        let identity: EndpointIdentity = self.probe_json(base_url, "/v1/identity").await?;
        let capabilities: EndpointCapabilities =
            self.probe_json(base_url, "/v1/capabilities").await?;
        negotiate_endpoint_protocol(&identity, &capabilities)
            .map_err(|_| CatalogError::EndpointUnavailable)?;
        Ok(EndpointProbe {
            identity,
            capabilities,
        })
    }

    async fn probe_json<T: serde::de::DeserializeOwned>(
        &self,
        base_url: &str,
        path: &str,
    ) -> Result<T, CatalogError> {
        let response = self
            .client
            .get(format!("{base_url}{path}"))
            .send()
            .await
            .map_err(|_| CatalogError::EndpointUnavailable)?;
        if !response.status().is_success() {
            return Err(CatalogError::EndpointUnavailable);
        }
        read_typed_json_response(response).await
    }
}

async fn read_json_response(response: reqwest::Response) -> Result<Value, CatalogError> {
    read_typed_json_response(response).await
}

async fn read_typed_json_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, CatalogError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ENDPOINT_RESPONSE_BYTES as u64)
    {
        return Err(CatalogError::EndpointUnavailable);
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| CatalogError::EndpointUnavailable)?;
        if bytes.len().saturating_add(chunk.len()) > MAX_ENDPOINT_RESPONSE_BYTES {
            return Err(CatalogError::EndpointUnavailable);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| CatalogError::EndpointUnavailable)
}

fn request_fingerprint(
    keys: &crate::store::KeyMaterial,
    label: &str,
    base_url: &str,
    secret: &str,
) -> [u8; 32] {
    keys.digest(
        b"endpoint-create-request-v1",
        &[
            label.as_bytes(),
            base_url.as_bytes(),
            b"bearer",
            secret.as_bytes(),
        ],
    )
}

fn verify_operation(
    keys: &crate::store::KeyMaterial,
    operation: &EndpointCreateOperation,
    secret: &str,
    record: Option<&EndpointRecord>,
) -> Result<(), CatalogError> {
    let expected = request_fingerprint(keys, &operation.label, &operation.base_url, secret);
    if !bool::from(operation.request_fingerprint.ct_eq(&expected)) {
        return Err(CatalogError::Internal);
    }
    if let Some(record) = record {
        if record.label != operation.label
            || record.base_url != operation.base_url
            || record.secret_ref != operation.secret_ref
        {
            return Err(CatalogError::Internal);
        }
    }
    Ok(())
}

fn public_endpoint(record: &EndpointRecord) -> Value {
    public_endpoint_observation(record, "online", record.created_at_ms)
}

fn public_endpoint_observation(
    record: &EndpointRecord,
    status: &str,
    observed_at_ms: i64,
) -> Value {
    json!({
        "schema": "zode.endpoint.v1",
        "endpoint_id": record.endpoint_id,
        "label": record.label,
        "kind": record.kind,
        "status": status,
        "disabled": false,
        "controller_authority_id": record.controller_authority_id,
        "controller_credential_revision": record.controller_credential_revision,
        "capabilities": {
            "providers": record.provider_adapter_kinds,
            "tools": record.tools,
            "protocol_version": record.protocol_version,
        },
        "last_observed_at_ms": observed_at_ms,
        "auth_replica_summary": {
            "ready": 0,
            "pending": 0,
            "stale": 0,
        }
    })
}

fn normalize_endpoint_url(value: &str) -> Result<String, CatalogError> {
    if !validate_text(value, MAX_BASE_URL_BYTES) {
        return Err(CatalogError::Invalid);
    }
    let url = Url::parse(value).map_err(|_| CatalogError::Invalid)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(CatalogError::Invalid);
    }
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&url) => {}
        _ => return Err(CatalogError::Invalid),
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn validate_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn unix_millis() -> Result<i64, CatalogError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CatalogError::Internal)?
        .as_millis();
    i64::try_from(millis).map_err(|_| CatalogError::Internal)
}

fn map_store_error(error: StoreError) -> CatalogError {
    match error {
        StoreError::Conflict => CatalogError::Conflict,
        _ => CatalogError::Internal,
    }
}

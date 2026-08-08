use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{to_bytes, Body},
    extract::{rejection::QueryRejection, Path, Query, Request, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use zode_protocol::{
    encode_json_bounded, CapabilityTool as WireCapabilityTool, EndpointCapabilities,
    EndpointHealth, AUTH_REPLICA_CREDENTIAL_SCHEMA_V1, EXTERNAL_CALLBACK_CAPABILITY,
    MAX_CAPABILITIES_BODY_BYTES, MAX_HEALTH_BODY_BYTES, PROVIDER_HTTP_CAPABILITY,
    TOOL_HTTP_CAPABILITY, WAIT_FOR_TOOL,
};

use crate::{
    control::{
        ControlAuthError, ControlRotationError, ControlState, ControllerAuthRotationRequest,
        MAX_ROTATION_REQUEST_BYTES,
    },
    domain::{
        ActiveWait, AsyncToolCallRecord, CompletionMode, DeliveryKind, DurablePayload, EventDraft,
        EventRecord, ProviderExecutionSelection, QueuedDelivery, SessionEvent,
        SessionModelSelection, SessionOwner, SessionSelection, SessionState, ToolCall,
        TranscriptMessage, MAX_ERROR_MESSAGE_BYTES, MAX_IDENTIFIER_BYTES,
    },
    provider::{
        ProviderExecutionPolicy, ReplicaError, ReplicaInstallRequest, ReplicaMutation,
        ReplicaStore, ReplicaTombstoneRequest, MAX_REPLICA_REQUEST_BYTES,
    },
    runtime::{CallbackCompletion, Runtime, RuntimeCommandError},
    storage::{
        EventStore, RehydrateError, SessionCreate, SessionCreateCommand, SessionListCursor,
        StoreError, MAX_SESSION_LIST_LIMIT,
    },
};

const PUBLIC_SCHEMA: &str = "zode.event.v1";
const READ_GLOBAL_BATCH_SIZE: usize = 256;
const MAX_SESSION_REQUEST_BYTES: usize = 256 * 1024;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 1_024;

#[derive(Clone)]
pub struct AppState {
    store: Arc<dyn EventStore>,
    control: Arc<ControlState>,
    replicas: Arc<ReplicaStore>,
    runtime: Arc<Runtime>,
    provider_policy: ProviderExecutionPolicy,
    health_body: Arc<Vec<u8>>,
    capabilities_body: Arc<Vec<u8>>,
}

impl AppState {
    pub fn new(
        store: Arc<dyn EventStore>,
        control: Arc<ControlState>,
        replicas: Arc<ReplicaStore>,
        runtime: Arc<Runtime>,
        provider_policy: ProviderExecutionPolicy,
        health_body: Vec<u8>,
        capabilities_body: Vec<u8>,
    ) -> Self {
        Self {
            store,
            control,
            replicas,
            runtime,
            provider_policy,
            health_body: Arc::new(health_body),
            capabilities_body: Arc::new(capabilities_body),
        }
    }
}

pub type CapabilityTool = WireCapabilityTool;

pub fn build_health_body(endpoint_id: &str) -> Result<Vec<u8>, String> {
    let body = EndpointHealth::ready(endpoint_id.to_owned());
    body.validate()
        .map_err(|_| "health projection is incompatible".to_owned())?;
    encode_json_bounded(&body, MAX_HEALTH_BODY_BYTES)
        .map_err(|_| "health projection could not be encoded".to_owned())
}

pub fn build_capabilities_body(
    endpoint_id: &str,
    provider_adapter_kinds: Vec<String>,
    tools: Vec<CapabilityTool>,
) -> Result<Vec<u8>, String> {
    build_capabilities_body_with_callback(endpoint_id, provider_adapter_kinds, tools, false)
}

/// Build the bounded capability projection from the effective composition.
/// External-callback tools are advertised only when their public route and
/// durable runtime lifecycle are ready; dormant configuration is hidden.
pub fn build_capabilities_body_with_callback(
    endpoint_id: &str,
    mut provider_adapter_kinds: Vec<String>,
    mut tools: Vec<CapabilityTool>,
    callback_lifecycle_enabled: bool,
) -> Result<Vec<u8>, String> {
    if !callback_lifecycle_enabled {
        tools.retain(|tool| tool.completion_mode != EXTERNAL_CALLBACK_CAPABILITY);
    }
    provider_adapter_kinds.sort_unstable();
    tools.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    let mut outbound_capabilities = Vec::new();
    if !provider_adapter_kinds.is_empty() {
        outbound_capabilities.push(PROVIDER_HTTP_CAPABILITY.to_owned());
    }
    if !tools.is_empty() {
        outbound_capabilities.push(TOOL_HTTP_CAPABILITY.to_owned());
    }
    if callback_lifecycle_enabled
        && tools
            .iter()
            .any(|tool| tool.completion_mode == EXTERNAL_CALLBACK_CAPABILITY)
    {
        outbound_capabilities.push(EXTERNAL_CALLBACK_CAPABILITY.to_owned());
    }
    let body = EndpointCapabilities::v1(
        endpoint_id.to_owned(),
        provider_adapter_kinds,
        vec![AUTH_REPLICA_CREDENTIAL_SCHEMA_V1.to_owned()],
        outbound_capabilities,
        vec![WAIT_FOR_TOOL.to_owned()],
        tools,
    );
    body.validate()
        .map_err(|_| "capability projection is incompatible".to_owned())?;
    encode_json_bounded(&body, MAX_CAPABILITIES_BODY_BYTES)
        .map_err(|_| "capability projection could not be encoded".to_owned())
}

#[derive(Clone, Debug, Serialize)]
struct PublicEvent {
    schema: &'static str,
    id: String,
    session_id: String,
    version: u64,
    kind: String,
    data: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionListQuery {
    #[serde(default)]
    limit: Option<u64>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSessionBody {
    #[serde(default)]
    model: Option<CreateModelSelection>,
    #[serde(default)]
    tools: Vec<String>,
    #[serde(default)]
    callback_base_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateModelSelection {
    provider: String,
    provider_execution: CreateProviderExecutionSelection,
    model: String,
    auth_authority_id: String,
    auth_profile_id: String,
    #[serde(default = "default_auth_revision", alias = "minimum_auth_revision")]
    auth_revision: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateProviderExecutionSelection {
    schema: String,
    revision: u64,
    kind: String,
    base_url: String,
    #[serde(default)]
    options: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageRequest {
    content: String,
    #[serde(default)]
    message_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalCallbackRequest {
    status: ExternalCallbackStatus,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<ExternalCallbackError>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExternalCallbackStatus {
    Completed,
    Failed,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalCallbackError {
    class: String,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolCancelRequest {
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolReconcileRequest {
    action: String,
}

struct ModelDeliverySpec {
    command_id: String,
    event_id: String,
    delivery_id: String,
    dedupe_key: String,
    message_id: String,
    content: String,
    created_at_ms: i64,
}

#[derive(Debug, Serialize)]
struct CanonicalCreateRequest<'a> {
    schema: &'static str,
    path: &'static str,
    selection: &'a SessionSelection,
}

#[derive(Debug, Serialize)]
struct CommandResponse {
    schema: &'static str,
    session_id: String,
    accepted: bool,
    version: u64,
}

#[derive(Debug)]
enum ServiceError {
    NotFound,
    IdempotencyReceiptNotFound,
    Conflict(String),
    AuthReplicaUnavailable,
    Malformed,
    Invalid(String),
    PayloadTooLarge,
    Backend,
}

impl ServiceError {
    fn store(error: StoreError) -> Self {
        match error {
            StoreError::OptimisticConcurrency { .. }
            | StoreError::CommandIdempotencyConflict { .. }
            | StoreError::EventIdempotencyConflict { .. }
            | StoreError::DuplicateEventIdInBatch { .. } => {
                Self::Conflict("request conflicts with an existing command".into())
            }
            StoreError::SessionNotFound => Self::NotFound,
            StoreError::InvalidSessionListLimit => {
                Self::Invalid("invalid session list limit".into())
            }
            StoreError::InvalidSessionListCursor => Self::Malformed,
            StoreError::EmptyField { .. } | StoreError::Domain(_) => {
                Self::Invalid("invalid request".into())
            }
            _ => Self::Backend,
        }
    }

    fn rehydrate(error: RehydrateError) -> Self {
        match error {
            RehydrateError::Store(StoreError::SessionNotFound) => Self::NotFound,
            _ => Self::Backend,
        }
    }

    fn read_store(error: StoreError) -> Self {
        match error {
            StoreError::SessionNotFound => Self::NotFound,
            _ => Self::Backend,
        }
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    retryable: bool,
}

impl ApiError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "invalid_request",
            message: message.into(),
            retryable: false,
        }
    }

    fn malformed() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "malformed_request",
            message: "malformed request".into(),
            retryable: false,
        }
    }

    fn payload_too_large() -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "payload_too_large",
            message: "request payload is too large".into(),
            retryable: false,
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "conflict",
            message: message.into(),
            retryable: false,
        }
    }

    fn replica_not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "auth_replica_not_found",
            message: "credential replica was not found".into(),
            retryable: false,
        }
    }

    fn tool_not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "tool_call_not_found",
            message: "tool call was not found".into(),
            retryable: false,
        }
    }

    fn callback_not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "callback_not_found",
            message: "callback was not found".into(),
            retryable: false,
        }
    }

    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "internal server error".into(),
            retryable: false,
        }
    }

    fn from_service(error: ServiceError) -> Self {
        match error {
            ServiceError::NotFound => Self {
                status: StatusCode::NOT_FOUND,
                code: "session_not_found",
                message: "session was not found".into(),
                retryable: false,
            },
            ServiceError::IdempotencyReceiptNotFound => Self {
                status: StatusCode::NOT_FOUND,
                code: "idempotency_receipt_not_found",
                message: "idempotency receipt was not found".into(),
                retryable: false,
            },
            ServiceError::Conflict(message) => Self {
                status: StatusCode::CONFLICT,
                code: "conflict",
                message,
                retryable: false,
            },
            ServiceError::AuthReplicaUnavailable => Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "auth_replica_unavailable",
                message: "credential replica is unavailable".into(),
                retryable: true,
            },
            ServiceError::Malformed => Self::malformed(),
            ServiceError::Invalid(message) => Self::invalid(message),
            ServiceError::PayloadTooLarge => Self::payload_too_large(),
            ServiceError::Backend => Self::internal(),
        }
    }

    fn from_control(error: ControlAuthError) -> Self {
        match error {
            ControlAuthError::Unauthenticated => Self {
                status: StatusCode::UNAUTHORIZED,
                code: "unauthenticated",
                message: "authentication required".into(),
                retryable: false,
            },
            ControlAuthError::Malformed => Self::malformed(),
            ControlAuthError::PayloadTooLarge => Self::payload_too_large(),
        }
    }

    fn from_rotation(error: ControlRotationError) -> Self {
        match error {
            ControlRotationError::Invalid => Self::invalid("invalid controller auth rotation"),
            ControlRotationError::PayloadTooLarge => Self::payload_too_large(),
            ControlRotationError::Conflict => Self::conflict("controller auth operation conflicts"),
            ControlRotationError::Internal => Self::internal(),
        }
    }

    fn from_replica(error: ReplicaError) -> Self {
        match error {
            ReplicaError::Invalid => Self::invalid("invalid credential replica request"),
            ReplicaError::Conflict => Self::conflict("credential replica operation conflicts"),
            ReplicaError::NotFound => Self::replica_not_found(),
            ReplicaError::Storage(_)
            | ReplicaError::Record(_)
            | ReplicaError::Unavailable
            | ReplicaError::Disabled
            | ReplicaError::SecretUnavailable => Self::internal(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": {
                    "code": self.code,
                    "message": self.message,
                    "retryable": self.retryable,
                }
            })),
        )
            .into_response()
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/identity", get(identity))
        .route("/v1/health", get(health))
        .route("/v1/capabilities", get(capabilities))
        .route("/v1/controller-auth", put(rotate_controller_auth))
        .route("/v1/auth-replicas", get(list_auth_replicas))
        .route(
            "/v1/auth-replicas/{profile}",
            get(read_auth_replica).put(install_auth_replica),
        )
        .route("/v1/sessions", get(list_sessions).post(create_session))
        .route("/v1/sessions/{id}", get(get_session))
        .route("/v1/sessions/{id}/messages", post(append_message))
        .route("/v1/sessions/{id}/model", put(select_model))
        .route(
            "/v1/sessions/{id}/tool-calls/{tool_call_id}",
            get(read_tool_call),
        )
        .route(
            "/v1/sessions/{id}/tool-calls/{tool_call_id}/cancel",
            post(cancel_tool_call),
        )
        .route(
            "/v1/sessions/{id}/tool-calls/{tool_call_id}/reconcile",
            post(reconcile_tool_call),
        )
        .route(
            "/v1/callbacks/{callback_id}",
            post(complete_external_callback),
        )
        .route("/v1/sessions/{id}/events", get(stream_events))
        .with_state(state)
}

async fn health(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    state
        .control
        .authenticate_controller(&headers)
        .map_err(ApiError::from_control)?;
    Ok(pre_serialized_json(state.health_body.as_ref()))
}

async fn capabilities(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    state
        .control
        .authenticate_controller(&headers)
        .map_err(ApiError::from_control)?;
    Ok(pre_serialized_json(state.capabilities_body.as_ref()))
}

fn pre_serialized_json(body: &[u8]) -> Response {
    let mut response = Response::new(Body::from(body.to_owned()));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

async fn list_auth_replicas(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let context = state
        .control
        .authenticate_controller(&headers)
        .map_err(ApiError::from_control)?;
    let replicas = state.replicas.clone();
    let authority_id = context.authority_id().to_owned();
    let metadata = tokio::task::spawn_blocking(move || replicas.list_metadata(&authority_id))
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(ApiError::from_replica)?;
    Ok(Json(json!({
        "schema": "zode.auth-replica-list.v1",
        "items": metadata.into_iter().map(public_replica_metadata).collect::<Vec<_>>(),
    })))
}

fn public_replica_metadata(metadata: crate::provider::ReplicaMetadata) -> Value {
    json!({
        "schema": "zode.auth-replica.v1",
        "authority_id": metadata.authority_id,
        "auth_profile_id": metadata.profile_id,
        "provider": metadata.provider,
        "revision": metadata.revision,
        "expires_at_ms": metadata.expires_at_ms,
        "status": metadata.status,
    })
}

async fn read_auth_replica(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let context = state
        .control
        .authenticate_controller(&headers)
        .map_err(ApiError::from_control)?;
    let replicas = state.replicas.clone();
    let authority_id = context.authority_id().to_owned();
    let metadata =
        tokio::task::spawn_blocking(move || replicas.read_metadata(&authority_id, &profile_id))
            .await
            .map_err(|_| ApiError::internal())?
            .map_err(ApiError::from_replica)?;
    Ok(Json(public_replica_metadata(metadata)))
}

async fn install_auth_replica(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, ApiError> {
    let context = state
        .control
        .authenticate_controller(&headers)
        .map_err(ApiError::from_control)?;
    let idempotency_key = required_idempotency_key(&headers).map_err(ApiError::from_service)?;
    require_json_content_type(&headers)?;
    let body = to_bytes(request.into_body(), MAX_REPLICA_REQUEST_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let value: Value = serde_json::from_slice(&body).map_err(|_| ApiError::malformed())?;
    let schema = value
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::invalid("credential replica schema is required"))?;
    let mutation = match schema {
        "zode.auth-replica.install.v1" => ReplicaMutation::Install(
            serde_json::from_value::<ReplicaInstallRequest>(value)
                .map_err(|_| ApiError::invalid("invalid credential replica request"))?,
        ),
        "zode.auth-replica.tombstone.v1" => ReplicaMutation::Tombstone(
            serde_json::from_value::<ReplicaTombstoneRequest>(value)
                .map_err(|_| ApiError::invalid("invalid credential replica request"))?,
        ),
        _ => return Err(ApiError::invalid("unsupported credential replica schema")),
    };
    let mutation_authority = match &mutation {
        ReplicaMutation::Install(replica) => &replica.authority_id,
        ReplicaMutation::Tombstone(replica) => &replica.authority_id,
    };
    if mutation_authority != context.authority_id() {
        return Err(ApiError::invalid(
            "credential replica authority does not match",
        ));
    }
    let replicas = state.replicas.clone();
    let authority_id = context.authority_id().to_owned();
    let profile_for_store = profile_id.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        replicas.apply(
            &profile_for_store,
            &authority_id,
            &idempotency_key,
            mutation,
        )
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(ApiError::from_replica)?;
    let metadata = outcome.metadata;
    let body = public_replica_metadata(metadata);
    let mut response = Json(body).into_response();
    *response.status_mut() =
        StatusCode::from_u16(outcome.status).map_err(|_| ApiError::internal())?;
    Ok(response)
}

async fn identity(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<zode_protocol::EndpointIdentity>, ApiError> {
    let context = state
        .control
        .authenticate_controller(&headers)
        .map_err(ApiError::from_control)?;
    Ok(Json(zode_protocol::EndpointIdentity::v1(
        state.control.endpoint_id(),
        context.authority_id(),
        context.revision(),
    )))
}

async fn rotate_controller_auth(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, ApiError> {
    let controller = state
        .control
        .authenticate_controller(request.headers())
        .map_err(ApiError::from_control)?;
    let idempotency_key = rotation_idempotency_key(request.headers())?;
    require_json_content_type(request.headers())?;
    let body = to_bytes(request.into_body(), MAX_ROTATION_REQUEST_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let rotation: ControllerAuthRotationRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::malformed())?;
    let control = state.control.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        control.rotate(&controller, &idempotency_key, &rotation)
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(ApiError::from_rotation)?;

    let mut response = Response::new(Body::from(outcome.body));
    *response.status_mut() =
        StatusCode::from_u16(outcome.status).map_err(|_| ApiError::internal())?;
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    Ok(response)
}

async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<(StatusCode, Json<CommandResponse>), ApiError> {
    let context = state
        .control
        .authenticate(&headers)
        .map_err(ApiError::from_control)?;
    require_json_content_type(&headers)?;
    let body = to_bytes(request.into_body(), MAX_SESSION_REQUEST_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let body: Value = serde_json::from_slice(&body).map_err(|_| ApiError::malformed())?;
    let selection = validate_create_body(body)?;
    let idempotency_key = required_idempotency_key(&headers).map_err(ApiError::from_service)?;
    let replay_only = replay_only_mode(&headers).map_err(ApiError::from_service)?;
    let owner = SessionOwner::new(context.authority_id(), context.subject());
    let semantic_request = CanonicalCreateRequest {
        schema: "zode.session-create.v1",
        path: "/v1/sessions",
        selection: &selection,
    };
    let command = SessionCreateCommand::new(&owner, &idempotency_key, &semantic_request)
        .map_err(ServiceError::store)
        .map_err(ApiError::from_service)?;
    let store = state.store.clone();
    let replicas = state.replicas.clone();
    let provider_policy = state.provider_policy.clone();
    let runtime = state.runtime.clone();
    let operation = run_blocking(move || {
        let replay = store
            .lookup_session_create(&owner, &command)
            .map_err(ServiceError::store)?;
        if replay_only {
            return replay.ok_or(ServiceError::IdempotencyReceiptNotFound);
        }
        if let Some(replay) = replay {
            return Ok(replay);
        }
        runtime
            .validate_tool_selection(&selection.tools)
            .map_err(|_| ServiceError::Invalid("invalid tool selection".into()))?;
        if let Some(model) = selection.model.as_ref() {
            provider_policy
                .validate(&model.provider_execution)
                .map_err(|_| ServiceError::Invalid("invalid provider execution".into()))?;
            replicas
                .resolve(
                    &model.auth_authority_id,
                    &model.auth_profile_id,
                    &model.provider,
                    model.auth_revision,
                )
                .map_err(|error| match error {
                    ReplicaError::Disabled | ReplicaError::SecretUnavailable => {
                        ServiceError::AuthReplicaUnavailable
                    }
                    ReplicaError::Invalid => {
                        ServiceError::Invalid("invalid credential replica selection".into())
                    }
                    _ => ServiceError::Backend,
                })?;
        }
        store
            .create_session(&SessionCreate {
                owner,
                command,
                created_at_ms: current_time_ms(),
                selection,
            })
            .map_err(ServiceError::store)
    })
    .await
    .map_err(ApiError::from_service)?;

    state
        .runtime
        .observe_commit(&operation.append, &operation.state)
        .await;
    Ok((
        StatusCode::CREATED,
        Json(CommandResponse {
            schema: "zode.command.v1",
            session_id: operation.state.session_id.clone(),
            accepted: true,
            version: operation.append.stream_version,
        }),
    ))
}

async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<SessionListQuery>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let context = state
        .control
        .authenticate(&headers)
        .map_err(ApiError::from_control)?;
    let Query(query) = query.map_err(|_| ApiError::malformed())?;
    let limit = query.limit.unwrap_or(50);
    if !(1..=MAX_SESSION_LIST_LIMIT as u64).contains(&limit) {
        return Err(ApiError::invalid(format!(
            "limit must be between 1 and {MAX_SESSION_LIST_LIMIT}"
        )));
    }
    let owner = SessionOwner::new(context.authority_id(), context.subject());
    let cursor = query
        .cursor
        .as_deref()
        .map(SessionListCursor::decode)
        .transpose()
        .map_err(|_| ApiError::malformed())?;
    if cursor
        .as_ref()
        .is_some_and(|cursor| cursor.owner() != &owner)
    {
        return Err(ApiError::malformed());
    }
    let store = state.store.clone();
    let page =
        run_blocking(move || list_owned_sessions(&*store, &owner, cursor.as_ref(), limit as usize))
            .await
            .map_err(ApiError::from_service)?;
    Ok(Json(json!({
        "schema": "zode.session-list.v1",
        "items": page.items,
        "next_cursor": page.next_cursor,
    })))
}

async fn get_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let context = state
        .control
        .authenticate(&headers)
        .map_err(ApiError::from_control)?;
    let store = state.store.clone();
    let id = session_id.clone();
    let owner = SessionOwner::new(context.authority_id(), context.subject());
    let session = run_blocking(move || existing_owned_session(&*store, &id, &owner))
        .await
        .map_err(ApiError::from_service)?;
    Ok(Json(session_view(session)))
}

async fn append_message(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    request: Request,
) -> Result<(StatusCode, Json<CommandResponse>), ApiError> {
    let context = state
        .control
        .authenticate(&headers)
        .map_err(ApiError::from_control)?;
    let idempotency_key = required_idempotency_key(&headers).map_err(ApiError::from_service)?;
    let replay_only = replay_only_mode(&headers).map_err(ApiError::from_service)?;
    require_json_content_type(&headers)?;
    let body = to_bytes(request.into_body(), MAX_SESSION_REQUEST_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let request: MessageRequest =
        serde_json::from_slice(&body).map_err(|error| match error.classify() {
            serde_json::error::Category::Data => ApiError::invalid("invalid message request"),
            _ => ApiError::malformed(),
        })?;
    let owner = SessionOwner::new(context.authority_id(), context.subject());
    let owner_digest = owner_digest(&owner.authority_id, &owner.subject);
    let command_id = format!(
        "message-{}",
        semantic_digest(
            "session.message.key",
            &format!("{owner_digest}:{session_id}"),
            &idempotency_key,
        )
    );
    let message_id = request.message_id.unwrap_or_else(|| {
        format!(
            "message-{}",
            semantic_digest(
                "session.message.id",
                &format!("{owner_digest}:{session_id}"),
                &idempotency_key,
            )
        )
    });
    let event_id = format!(
        "message-appended-{}",
        semantic_digest("session.message.event", &command_id, &message_id)
    );
    let delivery_id = format!(
        "delivery-{}",
        semantic_digest("session.message.delivery", &command_id, &message_id)
    );
    let delivery_event_id = format!(
        "delivery-queued-{}",
        semantic_digest("session.message.delivery-event", &command_id, &message_id)
    );
    let delivery_dedupe_key = format!("delivery:{command_id}");
    let created_at_ms = current_time_ms();
    let store = state.store.clone();
    let id = session_id.clone();
    let key = idempotency_key.clone();
    let runtime_owner = owner.clone();
    let operation = run_blocking(move || {
        let expected_message = TranscriptMessage {
            message_id: message_id.clone(),
            role: crate::domain::TranscriptRole::User,
            content: request.content.clone(),
            tool_call_id: None,
            tool_calls: Vec::<ToolCall>::new(),
            dedupe_key: Some(key.clone()),
            source_queue_id: None,
        };
        let requested_delivery = DurablePayload::inline(json!({
            "message_id": &message_id,
            "content": &request.content,
        }))
        .ok()
        .map(|payload| QueuedDelivery {
            queue_id: 0,
            delivery_id: delivery_id.clone(),
            kind: DeliveryKind::UserInput,
            payload,
            dedupe_key: delivery_dedupe_key.clone(),
            wake: true,
            created_at_ms: Some(created_at_ms),
            source_tool_call_id: None,
            materialized_message_id: None,
        });
        if let Some(replay) = replay_message_command(
            &*store,
            &owner,
            &id,
            &command_id,
            &expected_message,
            requested_delivery.as_ref(),
        )? {
            return Ok(replay);
        }
        if replay_only {
            return Err(ServiceError::IdempotencyReceiptNotFound);
        }
        let current = store
            .rehydrate_owned(&owner, &id)
            .map_err(ServiceError::rehydrate)?;
        if current.selection.model.is_some() {
            return enqueue_model_delivery(
                &*store,
                &owner,
                &id,
                current,
                ModelDeliverySpec {
                    command_id: command_id.clone(),
                    event_id: delivery_event_id,
                    delivery_id,
                    dedupe_key: delivery_dedupe_key,
                    message_id: message_id.clone(),
                    content: request.content.clone(),
                    created_at_ms,
                },
            );
        }
        let event = SessionEvent::MessageAppended {
            message: expected_message,
            wake_wait: true,
        };
        let append = store
            .append_owned(
                &owner,
                &id,
                current.stream_version,
                &command_id,
                &[EventDraft::new(event_id, event)],
            )
            .map_err(ServiceError::store)?;
        let state = store
            .rehydrate_owned(&owner, &id)
            .map_err(ServiceError::rehydrate)?;
        Ok((append, state))
    })
    .await
    .map_err(ApiError::from_service)?;

    state
        .runtime
        .observe_commit(&operation.0, &operation.1)
        .await;
    if !operation.0.replayed {
        state.runtime.wake(runtime_owner, session_id.clone());
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(CommandResponse {
            schema: "zode.command.v1",
            session_id,
            accepted: true,
            version: operation.0.stream_version,
        }),
    ))
}

async fn select_model(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    request: Request,
) -> Result<(StatusCode, Json<CommandResponse>), ApiError> {
    let context = state
        .control
        .authenticate(&headers)
        .map_err(ApiError::from_control)?;
    let idempotency_key = required_idempotency_key(&headers).map_err(ApiError::from_service)?;
    let replay_only = replay_only_mode(&headers).map_err(ApiError::from_service)?;
    require_json_content_type(&headers)?;
    let body = to_bytes(request.into_body(), MAX_SESSION_REQUEST_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let body: Value = serde_json::from_slice(&body).map_err(|_| ApiError::malformed())?;
    let model = parse_model_selection(body)?;
    let owner = SessionOwner::new(context.authority_id(), context.subject());
    let command_id = session_command_id("model", &owner, &session_id, &idempotency_key);
    let event_id = format!("model-selection-changed:{command_id}");
    let store = state.store.clone();
    let replicas = state.replicas.clone();
    let provider_policy = state.provider_policy.clone();
    let runtime_owner = owner.clone();
    let id = session_id.clone();
    let expected_model = model.clone();
    let operation = run_blocking(move || {
        let replay =
            lookup_session_command(&*store, &owner, &id, &command_id, |event| match event {
                SessionEvent::ModelSelectionChanged { selection } => {
                    selection.model.as_ref() == Some(&expected_model)
                }
                _ => false,
            })?;
        if let Some(replay) = replay {
            return Ok(replay);
        }
        if replay_only {
            return Err(ServiceError::IdempotencyReceiptNotFound);
        }
        // Resolve ownership/existence before provider policy or replica state
        // so a cross-owner or missing session cannot probe credential status.
        let current = store
            .rehydrate_owned(&owner, &id)
            .map_err(ServiceError::rehydrate)?;
        provider_policy
            .validate(&model.provider_execution)
            .map_err(|_| ServiceError::Invalid("invalid provider execution".into()))?;
        replicas
            .resolve(
                &model.auth_authority_id,
                &model.auth_profile_id,
                &model.provider,
                model.auth_revision,
            )
            .map_err(|error| match error {
                ReplicaError::Disabled
                | ReplicaError::SecretUnavailable
                | ReplicaError::Unavailable => ServiceError::AuthReplicaUnavailable,
                ReplicaError::Invalid => {
                    ServiceError::Invalid("invalid credential replica selection".into())
                }
                _ => ServiceError::Backend,
            })?;
        let mut selection = current.selection;
        selection.model = Some(model);
        let append = store
            .append_owned(
                &owner,
                &id,
                current.stream_version,
                &command_id,
                &[EventDraft::new(
                    event_id,
                    SessionEvent::ModelSelectionChanged { selection },
                )],
            )
            .map_err(ServiceError::store)?;
        let state = store
            .rehydrate_owned(&owner, &id)
            .map_err(ServiceError::rehydrate)?;
        Ok((append, state))
    })
    .await
    .map_err(ApiError::from_service)?;

    state
        .runtime
        .observe_commit(&operation.0, &operation.1)
        .await;
    if !operation.0.replayed {
        state.runtime.wake(runtime_owner, session_id.clone());
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(CommandResponse {
            schema: "zode.command.v1",
            session_id,
            accepted: true,
            version: operation.0.stream_version,
        }),
    ))
}

async fn read_tool_call(
    State(state): State<AppState>,
    Path((session_id, tool_call_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let context = state
        .control
        .authenticate(&headers)
        .map_err(ApiError::from_control)?;
    if session_id.is_empty() || tool_call_id.is_empty() {
        return Err(ApiError::tool_not_found());
    }
    let owner = SessionOwner::new(context.authority_id(), context.subject());
    let record = state
        .runtime
        .read_tool_call(owner, session_id.clone(), tool_call_id)
        .await
        .map_err(api_error_from_runtime_tool)?
        .ok_or_else(ApiError::tool_not_found)?;
    Ok(Json(public_tool_status(session_id, record)))
}

async fn cancel_tool_call(
    State(state): State<AppState>,
    Path((session_id, tool_call_id)): Path<(String, String)>,
    headers: HeaderMap,
    request: Request,
) -> Result<Json<Value>, ApiError> {
    let context = state
        .control
        .authenticate(&headers)
        .map_err(ApiError::from_control)?;
    let idempotency_key = required_idempotency_key(&headers).map_err(ApiError::from_service)?;
    require_json_content_type(&headers)?;
    let body = to_bytes(request.into_body(), MAX_SESSION_REQUEST_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let request: ToolCancelRequest = serde_json::from_slice(&body).map_err(|error| match error
        .classify()
    {
        serde_json::error::Category::Data => ApiError::invalid("invalid tool cancellation request"),
        _ => ApiError::malformed(),
    })?;
    if request.reason.is_empty() {
        return Err(ApiError::invalid("cancellation reason is required"));
    }
    if request.reason.len() > MAX_ERROR_MESSAGE_BYTES {
        return Err(ApiError::payload_too_large());
    }
    let owner = SessionOwner::new(context.authority_id(), context.subject());
    let command_id = session_command_id("tool-cancel", &owner, &session_id, &idempotency_key);
    let record = state
        .runtime
        .cancel_tool_call(
            owner,
            session_id.clone(),
            tool_call_id,
            request.reason,
            command_id,
        )
        .await
        .map_err(api_error_from_runtime_tool)?;
    Ok(Json(public_tool_status(session_id, record)))
}

async fn reconcile_tool_call(
    State(state): State<AppState>,
    Path((session_id, tool_call_id)): Path<(String, String)>,
    headers: HeaderMap,
    request: Request,
) -> Result<Json<Value>, ApiError> {
    let context = state
        .control
        .authenticate(&headers)
        .map_err(ApiError::from_control)?;
    let idempotency_key = required_idempotency_key(&headers).map_err(ApiError::from_service)?;
    require_json_content_type(&headers)?;
    let body = to_bytes(request.into_body(), MAX_SESSION_REQUEST_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let request: ToolReconcileRequest =
        serde_json::from_slice(&body).map_err(|error| match error.classify() {
            serde_json::error::Category::Data => {
                ApiError::invalid("invalid tool reconciliation request")
            }
            _ => ApiError::malformed(),
        })?;
    if request.action != "retry_dispatch" {
        return Err(ApiError::invalid("unsupported reconciliation action"));
    }
    let owner = SessionOwner::new(context.authority_id(), context.subject());
    let command_id = session_command_id("tool-reconcile", &owner, &session_id, &idempotency_key);
    let record = state
        .runtime
        .reconcile_tool_call(
            owner,
            session_id.clone(),
            tool_call_id,
            request.action,
            command_id,
        )
        .await
        .map_err(api_error_from_runtime_tool)?;
    Ok(Json(public_tool_status(session_id, record)))
}

async fn complete_external_callback(
    State(state): State<AppState>,
    Path(callback_id): Path<String>,
    headers: HeaderMap,
    request: Request,
) -> Result<Json<Value>, ApiError> {
    let Some(bearer) = callback_bearer(&headers) else {
        return Err(ApiError::callback_not_found());
    };
    if callback_id.is_empty() || callback_id.len() > 256 {
        return Err(ApiError::callback_not_found());
    }
    require_json_content_type(&headers)?;
    let body = to_bytes(request.into_body(), MAX_SESSION_REQUEST_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let value: Value = serde_json::from_slice(&body).map_err(|error| match error.classify() {
        serde_json::error::Category::Data => ApiError::invalid("invalid callback request"),
        _ => ApiError::malformed(),
    })?;
    let request: ExternalCallbackRequest = serde_json::from_value(value.clone())
        .map_err(|_| ApiError::invalid("invalid callback request"))?;
    match request.status {
        ExternalCallbackStatus::Completed => {
            if request.result.is_none() || request.error.is_some() {
                return Err(ApiError::invalid("invalid callback completion"));
            }
        }
        ExternalCallbackStatus::Failed => {
            let Some(error) = request.error.as_ref() else {
                return Err(ApiError::invalid("invalid callback failure"));
            };
            if request.result.is_some()
                || error.class.trim().is_empty()
                || error.message.trim().is_empty()
            {
                return Err(ApiError::invalid("invalid callback failure"));
            }
            if error.class.len() > MAX_IDENTIFIER_BYTES
                || error.message.len() > MAX_ERROR_MESSAGE_BYTES
            {
                return Err(ApiError::payload_too_large());
            }
        }
    }
    let completion = state
        .runtime
        .complete_external_callback(callback_id, bearer, value)
        .await
        .map_err(api_error_from_runtime_callback)?;
    let body = match completion {
        CallbackCompletion::Admitted(body) | CallbackCompletion::Replayed(body) => body,
    };
    Ok(Json(body))
}

fn callback_bearer(headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = value.to_str().ok()?.trim();
    let (scheme, token) = value.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty() && !token.chars().any(char::is_whitespace)).then(|| token.to_owned())
}

fn api_error_from_runtime_tool(error: RuntimeCommandError) -> ApiError {
    match error {
        RuntimeCommandError::NotFound => ApiError::tool_not_found(),
        RuntimeCommandError::Conflict => {
            ApiError::conflict("tool call conflicts with its current state")
        }
        RuntimeCommandError::Invalid(_) => ApiError::invalid("invalid tool call request"),
        RuntimeCommandError::Backend => ApiError::internal(),
    }
}

fn api_error_from_runtime_callback(error: RuntimeCommandError) -> ApiError {
    match error {
        RuntimeCommandError::NotFound => ApiError::callback_not_found(),
        RuntimeCommandError::Conflict => {
            ApiError::conflict("callback conflicts with its terminal result")
        }
        RuntimeCommandError::Invalid(_) => ApiError::invalid("invalid callback request"),
        RuntimeCommandError::Backend => ApiError::internal(),
    }
}

fn enqueue_model_delivery(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    mut current: SessionState,
    spec: ModelDeliverySpec,
) -> Result<(crate::storage::AppendResult, SessionState), ServiceError> {
    let payload = DurablePayload::inline(json!({
        "message_id": &spec.message_id,
        "content": &spec.content,
    }))
    .map_err(service_error_from_domain)?;

    for _ in 0..16 {
        let queue_id = current
            .delivery_ack
            .checked_add(current.delivery_queue.len() as u64 + 1)
            .ok_or_else(|| ServiceError::Invalid("delivery queue is full".into()))?;
        let delivery = QueuedDelivery {
            queue_id,
            delivery_id: spec.delivery_id.clone(),
            kind: DeliveryKind::UserInput,
            payload: payload.clone(),
            dedupe_key: spec.dedupe_key.clone(),
            wake: true,
            created_at_ms: Some(spec.created_at_ms),
            source_tool_call_id: None,
            materialized_message_id: None,
        };
        let event = SessionEvent::DeliveryQueued {
            delivery: delivery.clone(),
        };
        match store.append_owned(
            owner,
            session_id,
            current.stream_version,
            &spec.command_id,
            &[EventDraft::new(spec.event_id.clone(), event)],
        ) {
            Ok(append) => {
                let state = store
                    .rehydrate_owned(owner, session_id)
                    .map_err(ServiceError::rehydrate)?;
                return Ok((append, state));
            }
            Err(StoreError::OptimisticConcurrency { .. }) => {
                current = store
                    .rehydrate_owned(owner, session_id)
                    .map_err(ServiceError::rehydrate)?;
            }
            Err(StoreError::CommandIdempotencyConflict { .. }) => {
                if let Some(replay) =
                    replay_queued_delivery(store, owner, session_id, &spec.command_id, &delivery)?
                {
                    return Ok(replay);
                }
                return Err(ServiceError::Conflict(
                    "request conflicts with an existing command".into(),
                ));
            }
            Err(error) => return Err(ServiceError::store(error)),
        }
    }

    Err(ServiceError::Conflict(
        "request could not be admitted concurrently".into(),
    ))
}

fn replay_queued_delivery(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    command_id: &str,
    requested: &QueuedDelivery,
) -> Result<Option<(crate::storage::AppendResult, SessionState)>, ServiceError> {
    let records = store
        .read_stream_owned(owner, session_id, 0)
        .map_err(ServiceError::read_store)?;
    let events = records
        .into_iter()
        .filter(|record| record.command_id == command_id)
        .collect::<Vec<_>>();
    let Some(first) = events.first() else {
        return Ok(None);
    };
    if events.len() != 1 {
        return Err(ServiceError::Conflict(
            "request conflicts with an existing command".into(),
        ));
    }
    let SessionEvent::DeliveryQueued { delivery } = &first.event else {
        return Err(ServiceError::Conflict(
            "request conflicts with an existing command".into(),
        ));
    };
    if !same_delivery_request(delivery, requested) {
        return Err(ServiceError::Conflict(
            "request conflicts with an existing command".into(),
        ));
    }
    let state = store
        .rehydrate_owned(owner, session_id)
        .map_err(ServiceError::rehydrate)?;
    let stream_version = events
        .last()
        .map(|record| record.stream_version)
        .unwrap_or(state.stream_version);
    Ok(Some((
        crate::storage::AppendResult {
            stream_id: session_id.to_owned(),
            command_id: command_id.to_owned(),
            events,
            stream_version,
            replayed: true,
        },
        state,
    )))
}

fn same_delivery_request(left: &QueuedDelivery, right: &QueuedDelivery) -> bool {
    left.delivery_id == right.delivery_id
        && left.kind == right.kind
        && left.payload == right.payload
        && left.dedupe_key == right.dedupe_key
        && left.wake == right.wake
        && left.source_tool_call_id == right.source_tool_call_id
}

/// Look up an already admitted message command before inspecting current
/// session state. The same key and semantic request returns the original
/// append; a different request conflicts without appending a new event.
fn replay_message_command(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    command_id: &str,
    expected_message: &TranscriptMessage,
    requested_delivery: Option<&QueuedDelivery>,
) -> Result<Option<(crate::storage::AppendResult, SessionState)>, ServiceError> {
    let records = match store.read_stream_owned(owner, session_id, 0) {
        Ok(records) => records,
        Err(StoreError::SessionNotFound) => return Ok(None),
        Err(error) => return Err(ServiceError::read_store(error)),
    };
    let events = records
        .into_iter()
        .filter(|record| record.command_id == command_id)
        .collect::<Vec<_>>();
    let Some(first) = events.first() else {
        return Ok(None);
    };
    if events.len() != 1 {
        return Err(ServiceError::Conflict(
            "request conflicts with an existing command".into(),
        ));
    }
    let matches = match &first.event {
        SessionEvent::MessageAppended { message, .. } => message == expected_message,
        SessionEvent::DeliveryQueued { delivery } => {
            requested_delivery.is_some_and(|requested| same_delivery_request(delivery, requested))
        }
        _ => false,
    };
    if !matches {
        return Err(ServiceError::Conflict(
            "request conflicts with an existing command".into(),
        ));
    }
    let state = store
        .rehydrate_owned(owner, session_id)
        .map_err(ServiceError::rehydrate)?;
    let stream_version = events
        .last()
        .map(|record| record.stream_version)
        .unwrap_or(state.stream_version);
    Ok(Some((
        crate::storage::AppendResult {
            stream_id: session_id.to_owned(),
            command_id: command_id.to_owned(),
            events,
            stream_version,
            replayed: true,
        },
        state,
    )))
}

fn service_error_from_domain(error: crate::domain::DomainError) -> ServiceError {
    match error {
        crate::domain::DomainError::DurablePayloadTooLarge { .. }
        | crate::domain::DomainError::TextTooLarge { .. } => ServiceError::PayloadTooLarge,
        _ => ServiceError::Invalid("invalid message request".into()),
    }
}

async fn stream_events(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let context = state
        .control
        .authenticate(&headers)
        .map_err(ApiError::from_control)?;
    let after = parse_last_event_id(&headers).map_err(ApiError::from_service)?;
    let owner = SessionOwner::new(context.authority_id(), context.subject());
    let receiver = state.runtime.publisher().subscribe();
    let store = state.store.clone();
    let id = session_id.clone();
    let replay_owner = owner.clone();
    let replay = run_blocking(move || read_events_after(&*store, &id, &replay_owner, after))
        .await
        .map_err(ApiError::from_service)?;

    let stream = async_stream::stream! {
        yield Ok::<SseEvent, Infallible>(SseEvent::default().comment("stream-open"));
        let mut last_position = after.unwrap_or(0);
        for record in replay {
            if record.global_position > last_position {
                last_position = record.global_position;
                if let Some(public) = public_event(&record) {
                    yield Ok::<SseEvent, Infallible>(sse_event(public));
                }
            }
        }

        let mut receiver = receiver;
        loop {
            match receiver.recv().await {
                Ok(event) if event.stream_id == session_id
                    && event.global_position > last_position => {
                    // Publication is a notification, not the ordering authority. A
                    // concurrent commit may publish a later event before an earlier
                    // commit's observer runs, so recover the complete durable tail
                    // before yielding anything from this notification.
                    let store = state.store.clone();
                    let id = session_id.clone();
                    let owner = owner.clone();
                    match run_blocking(move || {
                        read_session_events_after(&*store, &owner, &id, last_position)
                    })
                    .await
                    {
                        Ok(records) => for record in records {
                            if record.global_position > last_position {
                                last_position = record.global_position;
                                if let Some(public) = public_event(&record) {
                                    yield Ok::<SseEvent, Infallible>(sse_event(public));
                                }
                            }
                        },
                        Err(_) => {
                            yield Ok::<SseEvent, Infallible>(SseEvent::default()
                                .event("error")
                                .data(sse_internal_error_data()));
                            break;
                        }
                    }
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let store = state.store.clone();
                    let id = session_id.clone();
                    let owner = owner.clone();
                    match run_blocking(move || {
                        read_session_events_after(&*store, &owner, &id, last_position)
                    })
                    .await
                    {
                        Ok(records) => for record in records {
                            if record.global_position > last_position {
                                last_position = record.global_position;
                                if let Some(public) = public_event(&record) {
                                    yield Ok::<SseEvent, Infallible>(sse_event(public));
                                }
                            }
                        },
                        Err(_) => {
                            yield Ok::<SseEvent, Infallible>(SseEvent::default()
                                .event("error")
                                .data(sse_internal_error_data()));
                            break;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

fn validate_create_body(body: Value) -> Result<SessionSelection, ApiError> {
    let Value::Object(object) = &body else {
        return Err(ApiError::invalid("session create body must be an object"));
    };
    if object.contains_key("session_id") {
        return Err(ApiError::invalid("session_id is generated by the endpoint"));
    }
    let parsed: CreateSessionBody = serde_json::from_value(body.clone())
        .map_err(|_| ApiError::invalid("invalid session selection"))?;
    let model = parsed.model.map(model_selection_from_request);
    let selection = SessionSelection {
        model,
        tools: parsed.tools,
        callback_base_url: parsed.callback_base_url,
    };
    Ok(selection)
}

fn parse_model_selection(body: Value) -> Result<SessionModelSelection, ApiError> {
    serde_json::from_value::<CreateModelSelection>(body)
        .map(model_selection_from_request)
        .map_err(|_| ApiError::invalid("invalid model selection"))
}

fn model_selection_from_request(model: CreateModelSelection) -> SessionModelSelection {
    SessionModelSelection {
        provider: model.provider,
        provider_execution: ProviderExecutionSelection {
            schema: model.provider_execution.schema,
            revision: model.provider_execution.revision,
            kind: model.provider_execution.kind,
            base_url: model.provider_execution.base_url,
            options: model.provider_execution.options,
        },
        model: model.model,
        auth_authority_id: model.auth_authority_id,
        auth_profile_id: model.auth_profile_id,
        auth_revision: model.auth_revision,
    }
}

fn session_command_id(kind: &str, owner: &SessionOwner, session_id: &str, key: &str) -> String {
    semantic_digest(
        &format!("session.{kind}.command"),
        &format!(
            "{}:{}:{}",
            owner_digest(&owner.authority_id, &owner.subject),
            session_id,
            key
        ),
        key,
    )
}

fn lookup_session_command<F>(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    command_id: &str,
    matches_request: F,
) -> Result<Option<(crate::storage::AppendResult, SessionState)>, ServiceError>
where
    F: Fn(&SessionEvent) -> bool,
{
    let records = match store.read_stream_owned(owner, session_id, 0) {
        Ok(records) => records,
        Err(StoreError::SessionNotFound) => return Ok(None),
        Err(error) => return Err(ServiceError::read_store(error)),
    };
    let events = records
        .into_iter()
        .filter(|record| record.command_id == command_id)
        .collect::<Vec<_>>();
    let Some(first) = events.first() else {
        return Ok(None);
    };
    if events.len() != 1 || !matches_request(&first.event) {
        return Err(ServiceError::Conflict(
            "request conflicts with an existing command".into(),
        ));
    }
    let state = store
        .rehydrate_owned(owner, session_id)
        .map_err(ServiceError::rehydrate)?;
    Ok(Some((
        crate::storage::AppendResult {
            stream_id: session_id.to_owned(),
            command_id: command_id.to_owned(),
            stream_version: events
                .last()
                .map(|event| event.stream_version)
                .unwrap_or(state.stream_version),
            events,
            replayed: true,
        },
        state,
    )))
}

fn default_auth_revision() -> u64 {
    1
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

fn existing_owned_session(
    store: &dyn EventStore,
    session_id: &str,
    owner: &SessionOwner,
) -> Result<SessionState, ServiceError> {
    store
        .rehydrate_owned(owner, session_id)
        .map_err(ServiceError::rehydrate)
}

struct PublicSessionListPage {
    items: Vec<Value>,
    next_cursor: Option<String>,
}

fn list_owned_sessions(
    store: &dyn EventStore,
    owner: &SessionOwner,
    cursor: Option<&SessionListCursor>,
    limit: usize,
) -> Result<PublicSessionListPage, ServiceError> {
    store
        .list_sessions_page(owner, cursor, limit)
        .map(|page| {
            let next_cursor = page
                .next_cursor
                .map(|cursor| cursor.encode())
                .transpose()
                .map_err(ServiceError::store)?;
            let items = page
                .items
                .into_iter()
                .map(|item| {
                    json!({
                        "session_id": item.session_id,
                        "version": item.version,
                        "status": item.status,
                        "created_at_ms": item.created_at_ms,
                        "model": item.selection.model.map(public_model),
                    })
                })
                .collect();
            Ok(PublicSessionListPage { items, next_cursor })
        })
        .map_err(ServiceError::store)?
}

fn read_events_after(
    store: &dyn EventStore,
    session_id: &str,
    owner: &SessionOwner,
    after: Option<u64>,
) -> Result<Vec<EventRecord>, ServiceError> {
    after.map_or_else(
        || {
            store
                .read_stream_owned(owner, session_id, 0)
                .map_err(ServiceError::read_store)
        },
        |position| read_session_events_after(store, owner, session_id, position),
    )
}

fn read_session_events_after(
    store: &dyn EventStore,
    owner: &SessionOwner,
    session_id: &str,
    mut after_position: u64,
) -> Result<Vec<EventRecord>, ServiceError> {
    let mut matching = Vec::new();
    loop {
        let batch = store
            .read_session_events(owner, session_id, after_position, READ_GLOBAL_BATCH_SIZE)
            .map_err(ServiceError::read_store)?;
        let full_batch = batch.len() == READ_GLOBAL_BATCH_SIZE;
        if let Some(last) = batch.last() {
            after_position = last.global_position;
        }
        matching.extend(
            batch
                .into_iter()
                .filter(|event| event.stream_id == session_id),
        );
        if !full_batch {
            return Ok(matching);
        }
    }
}

async fn run_blocking<T, F>(operation: F) -> Result<T, ServiceError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ServiceError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| ServiceError::Backend)?
}

fn parse_last_event_id(headers: &HeaderMap) -> Result<Option<u64>, ServiceError> {
    let mut values = headers.get_all("last-event-id").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ServiceError::Malformed);
    }
    value
        .to_str()
        .map_err(|_| ServiceError::Malformed)?
        .parse::<u64>()
        .map(Some)
        .map_err(|_| ServiceError::Malformed)
}

fn require_json_content_type(headers: &HeaderMap) -> Result<(), ApiError> {
    let mut values = headers.get_all(axum::http::header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return Err(ApiError::invalid("content type must be application/json"));
    };
    if values.next().is_some() {
        return Err(ApiError::malformed());
    }
    let value = value
        .to_str()
        .map_err(|_| ApiError::invalid("content type must be application/json"))?;
    let media_type = value.split(';').next().map(str::trim).unwrap_or_default();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Err(ApiError::invalid("content type must be application/json"));
    }
    Ok(())
}

fn optional_idempotency_key(headers: &HeaderMap) -> Result<Option<String>, ServiceError> {
    let mut values = headers.get_all("idempotency-key").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ServiceError::Invalid("duplicate Idempotency-Key".into()));
    }
    if value.as_bytes().len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(ServiceError::PayloadTooLarge);
    }
    let value = value
        .to_str()
        .map_err(|error| ServiceError::Invalid(format!("invalid Idempotency-Key: {error}")))?;
    if value.is_empty() {
        return Err(ServiceError::Invalid(
            "Idempotency-Key must not be empty".into(),
        ));
    }
    Ok(Some(value.to_owned()))
}

fn replay_only_mode(headers: &HeaderMap) -> Result<bool, ServiceError> {
    let mut values = headers.get_all("zode-idempotency-mode").iter();
    let Some(value) = values.next() else {
        return Ok(false);
    };
    if values.next().is_some() {
        return Err(ServiceError::Malformed);
    }
    let value = value.to_str().map_err(|_| ServiceError::Malformed)?;
    match value {
        "replay-only" => Ok(true),
        _ => Err(ServiceError::Invalid("unsupported idempotency mode".into())),
    }
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<String, ServiceError> {
    optional_idempotency_key(headers)?
        .ok_or_else(|| ServiceError::Invalid("Idempotency-Key header is required".into()))
}

fn rotation_idempotency_key(headers: &HeaderMap) -> Result<String, ApiError> {
    let mut values = headers.get_all("idempotency-key").iter();
    let Some(value) = values.next() else {
        return Err(ApiError::malformed());
    };
    if values.next().is_some() {
        return Err(ApiError::malformed());
    }
    if value.as_bytes().len() > 1_024 {
        return Err(ApiError::payload_too_large());
    }
    let value = std::str::from_utf8(value.as_bytes()).map_err(|_| ApiError::malformed())?;
    if value.is_empty() {
        return Err(ApiError::malformed());
    }
    Ok(value.to_owned())
}

fn owner_digest(authority_id: &str, subject: &str) -> String {
    digest_fields("zode.session-owner.v1", &[authority_id, subject])
}

fn semantic_digest(kind: &str, scope: &str, value: &str) -> String {
    digest_fields(kind, &[scope, value])
}

fn digest_fields(kind: &str, fields: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(kind.as_bytes());
    digest.update([0]);
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    format!("sha256:v1:{:x}", digest.finalize())
}

fn session_view(state: SessionState) -> Value {
    let model = state.selection.model.map(public_model);
    let active_activation = state.active_activation.map(|activation| {
        json!({
            "activation_id": activation.activation_id,
            "selection_version": activation.selection_version,
            "minimum_auth_revision": activation.minimum_auth_revision,
            "started_at_ms": activation.started_at_ms,
            "rounds_started": activation.rounds_started,
            "model": activation.selection.model.map(public_model),
            "tools": activation.selection.tools,
        })
    });
    let active_model_round = state.active_model_round.map(|round| {
        json!({
            "activation_id": round.activation_id,
            "round_id": round.round_id,
            "delivery_through_queue_id": round.delivery_through_queue_id,
            "request": round.request.map(|request| json!({
                "request_id": request.request_id,
                "maximum_attempts": request.maximum_attempts,
                "minimum_auth_revision": request.minimum_auth_revision,
            })),
            "attempt": round.attempt.map(|attempt| json!({
                "attempt_id": attempt.attempt_id,
                "attempt_number": attempt.attempt_number,
                "auth_revision": attempt.auth_revision,
                "outcome": attempt.outcome,
            })),
            "retry": round.retry.map(|retry| json!({
                "failed_attempt_number": retry.failed_attempt_number,
                "next_attempt_number": retry.next_attempt_number,
                "delay_ms": retry.delay_ms,
                "maximum_attempts": retry.maximum_attempts,
                "error_class": retry.error_class,
            })),
        })
    });
    let last_model_attempts_exhausted = state.last_model_attempts_exhausted.map(|fact| {
        json!({
            "activation_id": fact.activation_id,
            "round_id": fact.round_id,
            "attempt_number": fact.attempt_number,
            "maximum_attempts": fact.maximum_attempts,
            "finished_at_ms": fact.finished_at_ms,
            "reason": "model_attempts_exhausted",
        })
    });
    let pending = state
        .delivery_queue
        .into_iter()
        .map(|delivery| {
            json!({
                "queue_id": delivery.queue_id,
                "delivery_id": delivery.delivery_id,
                "kind": serializable(&delivery.kind),
                "wake": delivery.wake,
                "source_tool_call_id": delivery.source_tool_call_id,
                "materialized_message_id": delivery.materialized_message_id,
            })
        })
        .collect::<Vec<_>>();
    let tools = state
        .async_tool_calls
        .into_values()
        .map(public_tool)
        .collect::<Vec<_>>();
    json!({
        "schema": "zode.session.v1",
        "session_id": state.session_id,
        "version": state.stream_version,
        "status": state.status,
        "model": model,
        "transcript": state.transcript.into_iter().map(public_message).collect::<Vec<_>>(),
        "delivery": { "acknowledged_through": state.delivery_ack, "pending": pending },
        "wait": state.active_wait.map(public_wait),
        "tool_calls": tools,
        "active_activation": active_activation,
        "active_model_round": active_model_round,
        "last_model_attempts_exhausted": last_model_attempts_exhausted,
    })
}

fn public_model(model: SessionModelSelection) -> Value {
    json!({
        "provider": model.provider,
        "provider_execution_schema": model.provider_execution.schema,
        "provider_execution_revision": model.provider_execution.revision,
        "provider_execution_kind": model.provider_execution.kind,
        "provider_execution_base_url": model.provider_execution.base_url,
        "provider_execution_options": model.provider_execution.options,
        "model": model.model,
        "auth_authority_id": model.auth_authority_id,
        "auth_profile_id": model.auth_profile_id,
        "auth_revision": model.auth_revision,
    })
}

fn public_message(message: TranscriptMessage) -> Value {
    json!({
        "message_id": message.message_id,
        "role": message.role,
        "content": message.content,
        "tool_call_id": message.tool_call_id,
        "tool_calls": message.tool_calls.into_iter().map(|call| json!({
            "tool_call_id": call.tool_call_id,
            "tool_name": call.tool_name,
        })).collect::<Vec<_>>(),
    })
}

fn public_wait(wait: ActiveWait) -> Value {
    json!({
        "wait_id": wait.wait_id,
        "reason": wait.reason,
        "timeout_seconds": wait.timeout_seconds,
        "deadline_ms": wait.deadline_ms,
        "source": wait.source,
        "tool_call_ids": wait.tool_call_ids,
    })
}

fn public_tool(record: AsyncToolCallRecord) -> Value {
    let status = record.status.clone();
    let reconciliation = public_reconciliation(&status);
    json!({
        "tool_call_id": record.tool_call_id,
        "tool_name": record.tool_name,
        "status": status,
        "started_at_ms": record.started_at_ms,
        "auto_wait_seconds": record.auto_wait_seconds,
        "completion_mode": public_completion_mode(&record.completion_mode),
        "result": record.result.map(public_payload),
        "error": record.error.map(public_tool_error),
        "cancel_reason": record.cancel_reason,
        "completed_at_ms": record.completed_at_ms,
        "reconciliation": reconciliation,
    })
}

fn public_completion_mode(mode: &CompletionMode) -> &'static str {
    match mode {
        CompletionMode::ProcessLocal => "response",
        CompletionMode::ExternalCallback => EXTERNAL_CALLBACK_CAPABILITY,
    }
}

fn public_tool_status(session_id: String, record: AsyncToolCallRecord) -> Value {
    let mut body = public_tool(record);
    if let Value::Object(object) = &mut body {
        object.insert("schema".into(), Value::String("zode.tool-call.v1".into()));
        object.insert("session_id".into(), Value::String(session_id));
    }
    body
}

fn public_payload(payload: DurablePayload) -> Value {
    match payload {
        DurablePayload::Inline(value) => value.value().clone(),
        DurablePayload::BlobRef(blob) => json!({
            "blob": {
                "id": blob.blob_id,
                "media_type": blob.media_type,
                "bytes": blob.byte_len,
            }
        }),
        DurablePayload::Redacted(_) => json!({ "redacted": true }),
    }
}

fn public_reconciliation(status: &crate::domain::AsyncToolStatus) -> Value {
    if matches!(status, crate::domain::AsyncToolStatus::UnknownOutcome) {
        json!({ "reason": "unknown_outcome" })
    } else {
        Value::Null
    }
}

fn public_tool_error(error: crate::domain::ToolError) -> Value {
    let (class, message) = match error.class.as_str() {
        "tool_execution_failed" => ("tool_execution_failed", "tool execution failed"),
        "tool_unavailable" => ("tool_unavailable", "tool unavailable"),
        "tool_cancelled" => ("tool_cancelled", "tool call cancelled"),
        _ => ("tool_failed", "tool call failed"),
    };
    json!({ "class": class, "message": message })
}

fn public_event(record: &EventRecord) -> Option<PublicEvent> {
    // Durable storage contains private coordination facts (prepared request
    // envelopes, attempt claims, dedupe/index details).  They remain in the
    // stream for replay but never become public SSE frames.
    let kind = match &record.event {
        SessionEvent::ModelRequestPrepared { .. }
        | SessionEvent::ModelAttemptStarted { .. }
        | SessionEvent::ModelRequestCompleted { .. }
        | SessionEvent::WaitTimerScheduled { .. }
        | SessionEvent::AsyncToolCallCallbackPlanned { .. }
        | SessionEvent::DedupeRecorded { .. } => return None,
        SessionEvent::MessageAppended { message, .. }
            if message.role == crate::domain::TranscriptRole::Assistant
                && message.tool_calls.is_empty() =>
        {
            "assistant_message_committed"
        }
        SessionEvent::ModelAttemptsExhausted { .. } => "model_attempts_exhausted",
        SessionEvent::ModelStepRetryScheduled { .. } => "model_step_retrying",
        SessionEvent::AsyncToolCallCallbackCompleted { .. } => "async_tool_call_completed",
        SessionEvent::AsyncToolCallCallbackFailed { .. } => "async_tool_call_failed",
        SessionEvent::SessionCreated { .. }
        | SessionEvent::ModelSelectionChanged { .. }
        | SessionEvent::StatusChanged { .. }
        | SessionEvent::DeliveryQueued { .. }
        | SessionEvent::DeliveryAcknowledged { .. }
        | SessionEvent::DeliveryMaterialized { .. }
        | SessionEvent::MessageAppended { .. }
        | SessionEvent::ActivationStarted { .. }
        | SessionEvent::ModelRoundStarted { .. }
        | SessionEvent::ModelAttemptFailedFact { .. }
        | SessionEvent::ModelAttemptInterrupted { .. }
        | SessionEvent::ActivationFinished { .. }
        | SessionEvent::ModelAttemptFailed { .. }
        | SessionEvent::WaitSet { .. }
        | SessionEvent::WaitCleared { .. }
        | SessionEvent::WaitExpired { .. }
        | SessionEvent::AsyncToolCallStarted { .. }
        | SessionEvent::AsyncToolCallRunning { .. }
        | SessionEvent::AsyncToolCallUnknownOutcome { .. }
        | SessionEvent::AsyncToolCallRuntimeRestarted { .. }
        | SessionEvent::AsyncToolCallProgress { .. }
        | SessionEvent::AsyncToolCallCompleted { .. }
        | SessionEvent::AsyncToolCallFailed { .. }
        | SessionEvent::AsyncToolCallCancelled { .. } => record.event.kind(),
    };
    Some(PublicEvent {
        schema: PUBLIC_SCHEMA,
        id: record.global_position.to_string(),
        session_id: record.stream_id.clone(),
        version: record.stream_version,
        kind: kind.to_owned(),
        data: public_event_data(&record.event),
    })
}

fn public_event_data(event: &SessionEvent) -> Value {
    match event {
        SessionEvent::SessionCreated { session_id, .. } => json!({ "session_id": session_id }),
        SessionEvent::ModelSelectionChanged { selection } => json!({
            "model": selection.model.clone().map(public_model),
            "tools": selection.tools,
        }),
        SessionEvent::StatusChanged { status } => json!({ "status": serializable(status) }),
        SessionEvent::DeliveryQueued { delivery } => json!({
            "queue_id": delivery.queue_id,
            "delivery_id": delivery.delivery_id,
            "kind": serializable(&delivery.kind),
            "wake": delivery.wake,
            "source_tool_call_id": delivery.source_tool_call_id,
        }),
        SessionEvent::DeliveryAcknowledged { through_queue_id } => {
            json!({ "through_queue_id": through_queue_id })
        }
        SessionEvent::DeliveryMaterialized { queue_id, message } => json!({
            "queue_id": queue_id,
            "message": public_message(message.clone()),
        }),
        SessionEvent::MessageAppended { message, wake_wait } => json!({
            "message": public_message(message.clone()),
            "wake_wait": wake_wait,
        }),
        SessionEvent::ActivationStarted {
            activation_id,
            selection,
            selection_version,
            minimum_auth_revision,
            started_at_ms,
        } => json!({
            "activation_id": activation_id,
            "selection_version": selection_version,
            "minimum_auth_revision": minimum_auth_revision,
            "started_at_ms": started_at_ms,
            "model": selection.model.clone().map(public_model),
            "tools": selection.tools,
        }),
        SessionEvent::ModelRoundStarted {
            activation_id,
            round_id,
            delivery_through_queue_id,
            started_at_ms,
        } => json!({
            "activation_id": activation_id,
            "round_id": round_id,
            "delivery_through_queue_id": delivery_through_queue_id,
            "started_at_ms": started_at_ms,
        }),
        SessionEvent::ModelAttemptFailedFact {
            activation_id,
            round_id,
            attempt_number,
            error_class,
            retryable,
            ..
        } => json!({
            "activation_id": activation_id,
            "round_id": round_id,
            "attempt_number": attempt_number,
            "error": { "class": error_class, "retryable": retryable },
        }),
        SessionEvent::ModelAttemptInterrupted {
            activation_id,
            round_id,
            attempt_number,
            ..
        } => json!({
            "activation_id": activation_id,
            "round_id": round_id,
            "attempt_number": attempt_number,
            "reason": "model_attempt_interrupted",
        }),
        SessionEvent::ModelAttemptsExhausted { fact } => json!({
            "activation_id": fact.activation_id,
            "round_id": fact.round_id,
            "attempt_number": fact.attempt_number,
            "maximum_attempts": fact.maximum_attempts,
            "reason": "model_attempts_exhausted",
            "finished_at_ms": fact.finished_at_ms,
        }),
        SessionEvent::ModelStepRetryScheduled { schedule } => json!({
            "activation_id": schedule.activation_id,
            "round_id": schedule.round_id,
            "failed_attempt_number": schedule.failed_attempt_number,
            "next_attempt_number": schedule.next_attempt_number,
            "delay_ms": schedule.delay_ms,
            "maximum_attempts": schedule.maximum_attempts,
            "error_class": schedule.error_class,
        }),
        SessionEvent::ActivationFinished {
            activation_id,
            outcome,
            finished_at_ms,
        } => json!({
            "activation_id": activation_id,
            "outcome": serializable(outcome),
            "finished_at_ms": finished_at_ms,
        }),
        SessionEvent::ModelAttemptFailed { failure } => json!({
            "trigger_message_id": failure.trigger_message_id,
            "error": serializable(&failure.error),
        }),
        SessionEvent::WaitSet { wait } => json!({ "wait": public_wait(wait.clone()) }),
        SessionEvent::WaitCleared { wait_id } | SessionEvent::WaitExpired { wait_id } => {
            json!({ "wait_id": wait_id })
        }
        SessionEvent::AsyncToolCallStarted { record } => json!({
            "tool_call_id": record.tool_call_id,
            "tool_name": record.tool_name,
            "status": serializable(&record.status),
            "completion_mode": public_completion_mode(&record.completion_mode),
            "auto_wait_seconds": record.auto_wait_seconds,
        }),
        SessionEvent::AsyncToolCallRunning { tool_call_id } => json!({
            "tool_call_id": tool_call_id,
            "status": "running",
        }),
        SessionEvent::AsyncToolCallUnknownOutcome { tool_call_id, .. } => json!({
            "tool_call_id": tool_call_id,
            "status": "unknown_outcome",
        }),
        SessionEvent::AsyncToolCallRuntimeRestarted {
            tool_call_id,
            completed_at_ms,
            ..
        } => json!({
            "tool_call_id": tool_call_id,
            "completed_at_ms": completed_at_ms,
            "status": "runtime_restarted",
        }),
        SessionEvent::AsyncToolCallCallbackCompleted {
            tool_call_id,
            completed_at_ms,
            ..
        } => json!({
            "tool_call_id": tool_call_id,
            "completed_at_ms": completed_at_ms,
            "status": "completed",
        }),
        SessionEvent::AsyncToolCallCallbackFailed {
            tool_call_id,
            completed_at_ms,
            ..
        } => json!({
            "tool_call_id": tool_call_id,
            "completed_at_ms": completed_at_ms,
            "status": "failed",
        }),
        SessionEvent::AsyncToolCallProgress { tool_call_id, .. } => {
            json!({ "tool_call_id": tool_call_id })
        }
        SessionEvent::AsyncToolCallCompleted {
            tool_call_id,
            completed_at_ms,
            ..
        } => json!({
            "tool_call_id": tool_call_id,
            "completed_at_ms": completed_at_ms,
            "status": "completed",
        }),
        SessionEvent::AsyncToolCallFailed {
            tool_call_id,
            error,
            completed_at_ms,
        } => json!({
            "tool_call_id": tool_call_id,
            "completed_at_ms": completed_at_ms,
            "status": "failed",
            "error": public_tool_error(error.clone()),
        }),
        SessionEvent::AsyncToolCallCancelled {
            tool_call_id,
            reason,
            completed_at_ms,
        } => json!({
            "tool_call_id": tool_call_id,
            "completed_at_ms": completed_at_ms,
            "status": "cancelled",
            "reason": reason,
        }),
        // Private events are filtered by `public_event` before this mapping
        // is used. Keep an explicit neutral fallback so a future durable fact
        // cannot accidentally expose its serialized payload.
        _ => Value::Null,
    }
}

fn serializable<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

fn sse_event(public: PublicEvent) -> SseEvent {
    let id = public.id.clone();
    let kind = public.kind.clone();
    let data = serde_json::to_string(&public).unwrap_or_else(|_| sse_internal_error_data());
    SseEvent::default().id(id).event(kind).data(data)
}

fn sse_internal_error_data() -> String {
    json!({
        "schema": PUBLIC_SCHEMA,
        "error": {
            "code": "internal_error",
            "message": "internal server error",
            "retryable": false,
        },
    })
    .to_string()
}

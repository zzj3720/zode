use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    convert::Infallible,
    sync::Arc,
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
use tokio::sync::broadcast;
use zode_protocol::{
    encode_json_bounded, CapabilityTool as WireCapabilityTool, EndpointCapabilities,
    EndpointHealth, AUTH_REPLICA_CREDENTIAL_SCHEMA_ANTHROPIC_V1, AUTH_REPLICA_CREDENTIAL_SCHEMA_V1,
    EXTERNAL_CALLBACK_CAPABILITY, MAX_CAPABILITIES_BODY_BYTES, MAX_HEALTH_BODY_BYTES,
    PROVIDER_HTTP_CAPABILITY, TOOL_HTTP_CAPABILITY, WAIT_FOR_TOOL,
};

use crate::{
    control::{ControlAuthError, ControlRotationError, ControlState},
    domain::{
        ActiveWait, AsyncToolCallRecord, CompletionMode, DurablePayload, EventRecord, ModelLimits,
        ProviderExecutionSelection, SessionEvent, SessionModelSelection, SessionOwner,
        SessionSelection, SessionState, TranscriptMessage, MAX_ERROR_MESSAGE_BYTES,
        MAX_IDENTIFIER_BYTES,
    },
    runtime::{
        session_command_id, CallbackCompletion, ReplicaInstallRequest, ReplicaMetadata,
        ReplicaPortError, ReplicaTombstoneRequest, Runtime, RuntimeCommandError,
        RuntimeStreamEvent, SessionListCursor, SessionListPage, TransientModelEvent,
        MAX_REPLICA_REQUEST_BYTES, MAX_SESSION_LIST_LIMIT,
    },
};

const PUBLIC_SCHEMA: &str = "zode.event.v1";
const READ_GLOBAL_BATCH_SIZE: usize = 256;
const MAX_SESSION_REQUEST_BYTES: usize = 256 * 1024;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 1_024;
const SHARED_SESSION_AUTHORITY: &str = "local";
const SHARED_SESSION_SUBJECT: &str = "shared";

fn shared_session_owner() -> SessionOwner {
    SessionOwner::new(SHARED_SESSION_AUTHORITY, SHARED_SESSION_SUBJECT)
}

#[derive(Clone)]
pub struct AppState {
    control: Arc<ControlState>,
    runtime: Arc<Runtime>,
    health_body: Arc<Vec<u8>>,
    capabilities_body: Arc<Vec<u8>>,
}

impl AppState {
    pub fn new(
        control: Arc<ControlState>,
        runtime: Arc<Runtime>,
        health_body: Vec<u8>,
        capabilities_body: Vec<u8>,
    ) -> Self {
        Self {
            control,
            runtime,
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
    let mut credential_schemas = Vec::new();
    if provider_adapter_kinds
        .iter()
        .any(|kind| kind == "openai_compatible")
    {
        credential_schemas.push(AUTH_REPLICA_CREDENTIAL_SCHEMA_V1.to_owned());
    }
    if provider_adapter_kinds
        .iter()
        .any(|kind| kind == "anthropic")
    {
        credential_schemas.push(AUTH_REPLICA_CREDENTIAL_SCHEMA_ANTHROPIC_V1.to_owned());
    }
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
        credential_schemas,
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
    #[serde(default)]
    limits: Option<CreateModelLimits>,
    auth_authority_id: String,
    auth_profile_id: String,
    #[serde(default = "default_auth_revision", alias = "minimum_auth_revision")]
    auth_revision: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateModelLimits {
    context_window_tokens: u64,
    max_output_tokens: u32,
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
    AuthReplicaUnavailable,
    Malformed,
    Invalid(String),
    PayloadTooLarge,
    Backend,
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

    fn from_replica(error: ReplicaPortError) -> Self {
        match error {
            ReplicaPortError::Invalid => Self::invalid("invalid credential replica request"),
            ReplicaPortError::Conflict => Self::conflict("credential replica operation conflicts"),
            ReplicaPortError::NotFound => Self::replica_not_found(),
            ReplicaPortError::Unavailable
            | ReplicaPortError::Disabled
            | ReplicaPortError::SecretUnavailable
            | ReplicaPortError::Backend => Self::internal(),
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
        .route("/v1/events", get(stream_endpoint_events))
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> Result<Response, ApiError> {
    Ok(pre_serialized_json(state.health_body.as_ref()))
}

async fn capabilities(State(state): State<AppState>) -> Result<Response, ApiError> {
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

async fn list_auth_replicas(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let metadata = state
        .runtime
        .list_replicas(String::new())
        .await
        .map_err(ApiError::from_replica)?;
    Ok(Json(json!({
        "schema": "zode.auth-replica-list.v1",
        "items": metadata.into_iter().map(public_replica_metadata).collect::<Vec<_>>(),
    })))
}

fn public_replica_metadata(metadata: ReplicaMetadata) -> Value {
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
) -> Result<Json<Value>, ApiError> {
    let metadata = state
        .runtime
        .list_replicas(String::new())
        .await
        .map_err(ApiError::from_replica)?;
    let metadata = metadata
        .into_iter()
        .find(|item| item.profile_id == profile_id)
        .ok_or_else(|| ApiError::from_replica(ReplicaPortError::NotFound))?;
    Ok(Json(public_replica_metadata(metadata)))
}

async fn install_auth_replica(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, ApiError> {
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
    let outcome = match schema {
        "zode.auth-replica.install.v1" => {
            let request = serde_json::from_value::<ReplicaInstallRequest>(value)
                .map_err(|_| ApiError::invalid("invalid credential replica request"))?;
            let authority_id = request.authority_id.clone();
            state
                .runtime
                .install_replica(profile_id, authority_id, idempotency_key, request)
                .await
        }
        "zode.auth-replica.tombstone.v1" => {
            let request = serde_json::from_value::<ReplicaTombstoneRequest>(value)
                .map_err(|_| ApiError::invalid("invalid credential replica request"))?;
            let authority_id = request.authority_id.clone();
            state
                .runtime
                .tombstone_replica(profile_id, authority_id, idempotency_key, request)
                .await
        }
        _ => return Err(ApiError::invalid("unsupported credential replica schema")),
    }
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
) -> Result<Json<zode_protocol::EndpointIdentity>, ApiError> {
    Ok(Json(zode_protocol::EndpointIdentity::v1(
        state.control.endpoint_id(),
        SHARED_SESSION_AUTHORITY,
        1,
    )))
}

async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<(StatusCode, Json<CommandResponse>), ApiError> {
    require_json_content_type(&headers)?;
    let body = to_bytes(request.into_body(), MAX_SESSION_REQUEST_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let body: Value = serde_json::from_slice(&body).map_err(|_| ApiError::malformed())?;
    let selection = validate_create_body(body)?;
    let idempotency_key = required_idempotency_key(&headers).map_err(ApiError::from_service)?;
    let replay_only = replay_only_mode(&headers).map_err(ApiError::from_service)?;
    let owner = shared_session_owner();
    let operation = state
        .runtime
        .create_session(owner, idempotency_key, selection, replay_only)
        .await
        .map_err(api_error_from_runtime_session)?;
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
    query: Result<Query<SessionListQuery>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::malformed())?;
    let limit = query.limit.unwrap_or(50);
    if !(1..=MAX_SESSION_LIST_LIMIT as u64).contains(&limit) {
        return Err(ApiError::invalid(format!(
            "limit must be between 1 and {MAX_SESSION_LIST_LIMIT}"
        )));
    }
    let owner = shared_session_owner();
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
    let page = state
        .runtime
        .list_sessions(owner, cursor, limit as usize)
        .await
        .map_err(api_error_from_runtime_session)?;
    Ok(Json(
        public_session_list(page).map_err(ApiError::from_service)?,
    ))
}

async fn get_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let owner = shared_session_owner();
    let session = state
        .runtime
        .get_session(owner, session_id)
        .await
        .map_err(api_error_from_runtime_session)?;
    Ok(Json(session_view(session)))
}

async fn append_message(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    request: Request,
) -> Result<(StatusCode, Json<CommandResponse>), ApiError> {

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
    let owner = shared_session_owner();
    let (append, _) = state
        .runtime
        .append_message(
            owner,
            session_id.clone(),
            idempotency_key,
            request.content,
            request.message_id,
            replay_only,
        )
        .await
        .map_err(api_error_from_runtime_session)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CommandResponse {
            schema: "zode.command.v1",
            session_id,
            accepted: true,
            version: append.stream_version,
        }),
    ))
}

async fn select_model(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    request: Request,
) -> Result<(StatusCode, Json<CommandResponse>), ApiError> {

    let idempotency_key = required_idempotency_key(&headers).map_err(ApiError::from_service)?;
    let replay_only = replay_only_mode(&headers).map_err(ApiError::from_service)?;
    require_json_content_type(&headers)?;
    let body = to_bytes(request.into_body(), MAX_SESSION_REQUEST_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let body: Value = serde_json::from_slice(&body).map_err(|_| ApiError::malformed())?;
    let model = parse_model_selection(body)?;
    let owner = shared_session_owner();
    let (append, _) = state
        .runtime
        .select_model(
            owner,
            session_id.clone(),
            idempotency_key,
            model,
            replay_only,
        )
        .await
        .map_err(api_error_from_runtime_session)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CommandResponse {
            schema: "zode.command.v1",
            session_id,
            accepted: true,
            version: append.stream_version,
        }),
    ))
}

async fn read_tool_call(
    State(state): State<AppState>,
    Path((session_id, tool_call_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {

    if session_id.is_empty() || tool_call_id.is_empty() {
        return Err(ApiError::tool_not_found());
    }
    let owner = shared_session_owner();
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
    let owner = shared_session_owner();
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
    let owner = shared_session_owner();
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

fn api_error_from_runtime_session(error: RuntimeCommandError) -> ApiError {
    match error {
        RuntimeCommandError::NotFound => ApiError::from_service(ServiceError::NotFound),
        RuntimeCommandError::IdempotencyReceiptNotFound => {
            ApiError::from_service(ServiceError::IdempotencyReceiptNotFound)
        }
        RuntimeCommandError::Conflict => {
            ApiError::conflict("request conflicts with an existing command")
        }
        RuntimeCommandError::Invalid("payload_too_large") => ApiError::payload_too_large(),
        RuntimeCommandError::Invalid(message) => ApiError::invalid(message),
        RuntimeCommandError::AuthReplicaUnavailable => {
            ApiError::from_service(ServiceError::AuthReplicaUnavailable)
        }
        RuntimeCommandError::Backend => ApiError::internal(),
    }
}

fn api_error_from_runtime_tool(error: RuntimeCommandError) -> ApiError {
    match error {
        RuntimeCommandError::NotFound => ApiError::tool_not_found(),
        RuntimeCommandError::Conflict => {
            ApiError::conflict("tool call conflicts with its current state")
        }
        RuntimeCommandError::Invalid(_) => ApiError::invalid("invalid tool call request"),
        RuntimeCommandError::Backend
        | RuntimeCommandError::IdempotencyReceiptNotFound
        | RuntimeCommandError::AuthReplicaUnavailable => ApiError::internal(),
    }
}

fn api_error_from_runtime_callback(error: RuntimeCommandError) -> ApiError {
    match error {
        RuntimeCommandError::NotFound => ApiError::callback_not_found(),
        RuntimeCommandError::Conflict => {
            ApiError::conflict("callback conflicts with its terminal result")
        }
        RuntimeCommandError::Invalid(_) => ApiError::invalid("invalid callback request"),
        RuntimeCommandError::Backend
        | RuntimeCommandError::IdempotencyReceiptNotFound
        | RuntimeCommandError::AuthReplicaUnavailable => ApiError::internal(),
    }
}

async fn stream_endpoint_events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {

    let after = parse_last_event_id(&headers).map_err(ApiError::from_service)?;
    let owner = shared_session_owner();
    let (subscription, initial_records) = state
        .runtime
        .subscribe_owned(owner.clone(), after.unwrap_or(0), READ_GLOBAL_BATCH_SIZE)
        .await
        .map_err(api_error_from_runtime_session)?;
    let initial_batch_was_full = initial_records.len() == READ_GLOBAL_BATCH_SIZE;
    let initial_catch_up_pending = !initial_records.is_empty();

    let stream = async_stream::stream! {
        yield Ok::<SseEvent, Infallible>(SseEvent::default().comment("stream-open"));
        let mut last_position = after.unwrap_or(0);
        let mut owned_sessions = BTreeSet::new();
        let mut receiver = subscription.receiver;
        let mut skip_through_sequence = subscription.fence.sequence;
        let mut catch_up_through = subscription.fence.durable_position;
        let mut catch_up_pending = initial_catch_up_pending;
        let mut retry_barriers = subscription.fence.retry_barriers;
        retry_barriers.retain(|_, position| *position > last_position);
        let mut blocked_transient = None::<TransientModelEvent>;
        let mut prefer_live = true;
        let mut catch_up_batch = VecDeque::from(initial_records);
        let mut catch_up_batch_was_full = initial_batch_was_full;

        'stream: loop {
            if let Some(event) = blocked_transient.take() {
                if retry_barriers
                    .get(&event.session_id)
                    .is_some_and(|position| *position > last_position)
                {
                    blocked_transient = Some(event);
                } else {
                    retry_barriers.remove(&event.session_id);
                    prefer_live = false;
                    yield Ok::<SseEvent, Infallible>(transient_model_event(event));
                    continue;
                }
            }

            let live = if catch_up_pending && blocked_transient.is_none() && prefer_live {
                match receiver.try_recv() {
                    Ok(message) => Some(Ok(message)),
                    Err(broadcast::error::TryRecvError::Empty) => None,
                    Err(broadcast::error::TryRecvError::Lagged(skipped)) => {
                        Some(Err(broadcast::error::RecvError::Lagged(skipped)))
                    }
                    Err(broadcast::error::TryRecvError::Closed) => {
                        Some(Err(broadcast::error::RecvError::Closed))
                    }
                }
            } else if !catch_up_pending && blocked_transient.is_none() {
                Some(receiver.recv().await)
            } else {
                None
            };

            if let Some(live) = live {
                match live {
                    Ok(message) if message.sequence <= skip_through_sequence => continue,
                    Ok(message) => match message.event {
                        RuntimeStreamEvent::Transient(event) => {
                            if !owned_sessions.contains(&event.session_id) {
                                match state
                                    .runtime
                                    .session_is_owned(owner.clone(), event.session_id.clone())
                                    .await
                                {
                                    Ok(true) => {
                                        owned_sessions.insert(event.session_id.clone());
                                    }
                                    Ok(false) => continue,
                                    Err(_) => {
                                        yield Ok::<SseEvent, Infallible>(SseEvent::default()
                                            .event("error")
                                            .data(sse_internal_error_data()));
                                        break 'stream;
                                    }
                                }
                            }
                            if retry_barriers
                                .get(&event.session_id)
                                .is_some_and(|position| *position > last_position)
                            {
                                blocked_transient = Some(event);
                                prefer_live = false;
                            } else {
                                prefer_live = false;
                                yield Ok::<SseEvent, Infallible>(transient_model_event(event));
                                continue;
                            }
                        }
                        RuntimeStreamEvent::Durable(event) => {
                            if event.global_position <= last_position {
                                continue;
                            }
                            catch_up_through = catch_up_through.max(event.global_position);
                            catch_up_pending = true;
                            if durable_fences_following_transient(&event) {
                                retry_barriers
                                    .insert(event.stream_id.clone(), event.global_position);
                            }
                        }
                    },
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        match state
                            .runtime
                            .subscribe_owned(
                                owner.clone(),
                                last_position,
                                READ_GLOBAL_BATCH_SIZE,
                            )
                            .await
                        {
                            Ok((next, records)) => {
                                receiver = next.receiver;
                                skip_through_sequence = next.fence.sequence;
                                catch_up_through =
                                    catch_up_through.max(next.fence.durable_position);
                                retry_barriers = next.fence.retry_barriers;
                                retry_barriers.retain(|_, position| *position > last_position);
                                blocked_transient = None;
                                if records.is_empty() {
                                    catch_up_batch.clear();
                                    catch_up_batch_was_full = false;
                                    catch_up_pending = false;
                                    prefer_live = true;
                                } else {
                                    catch_up_batch_was_full =
                                        records.len() == READ_GLOBAL_BATCH_SIZE;
                                    catch_up_batch = records.into();
                                    catch_up_pending = true;
                                    prefer_live = false;
                                }
                            }
                            Err(_) => {
                                yield Ok::<SseEvent, Infallible>(SseEvent::default()
                                    .event("error")
                                    .data(sse_internal_error_data()));
                                break 'stream;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break 'stream,
                }
            }

            if !catch_up_pending {
                continue;
            }

            if catch_up_batch.is_empty() {
                match state
                    .runtime
                    .read_owned_events(owner.clone(), last_position, READ_GLOBAL_BATCH_SIZE)
                    .await
                {
                    Ok(records) if records.is_empty() => {
                        catch_up_pending = false;
                        prefer_live = true;
                        continue;
                    }
                    Ok(records) => {
                        catch_up_batch_was_full = records.len() == READ_GLOBAL_BATCH_SIZE;
                        catch_up_batch = records.into();
                    }
                    Err(_) => {
                        yield Ok::<SseEvent, Infallible>(SseEvent::default()
                            .event("error")
                            .data(sse_internal_error_data()));
                        break 'stream;
                    }
                }
            }

            while let Some(record) = catch_up_batch.pop_front() {
                if record.global_position > catch_up_through {
                    catch_up_batch.clear();
                    catch_up_pending = false;
                    prefer_live = true;
                    break;
                }
                if record.global_position <= last_position {
                    continue;
                }
                last_position = record.global_position;
                owned_sessions.insert(record.stream_id.clone());
                retry_barriers.retain(|_, position| *position > last_position);
                let reached_fence = last_position == catch_up_through;
                let exhausted_short_batch =
                    catch_up_batch.is_empty() && !catch_up_batch_was_full;
                if reached_fence || exhausted_short_batch {
                    catch_up_batch.clear();
                    catch_up_pending = false;
                }
                prefer_live = true;
                if let Some(public) = public_event(&record) {
                    yield Ok::<SseEvent, Infallible>(sse_event(public));
                    tokio::task::yield_now().await;
                    break;
                }
                if !catch_up_pending {
                    break;
                }
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
        limits: model.limits.map(|limits| ModelLimits {
            context_window_tokens: limits.context_window_tokens,
            max_output_tokens: limits.max_output_tokens,
        }),
        auth_authority_id: model.auth_authority_id,
        auth_profile_id: model.auth_profile_id,
        auth_revision: model.auth_revision,
    }
}

fn default_auth_revision() -> u64 {
    1
}

fn public_session_list(page: SessionListPage) -> Result<Value, ServiceError> {
    let next_cursor = page
        .next_cursor
        .map(|cursor| cursor.encode())
        .transpose()
        .map_err(|_| ServiceError::Backend)?;
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
        .collect::<Vec<_>>();
    Ok(json!({
        "schema": "zode.session-list.v1",
        "items": items,
        "next_cursor": next_cursor,
    }))
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

fn session_view(state: SessionState) -> Value {
    let model = state.selection.model.map(public_model);
    let active_activation = state.active_activation.map(|activation| {
        json!({
            "activation_id": activation.activation_id,
            "selection_version": activation.selection_version,
            "minimum_auth_revision": activation.minimum_auth_revision,
            "started_at_ms": activation.started_at_ms,
            "model": activation.selection.model.map(public_model),
            "tools": activation.selection.tools,
        })
    });
    let active_model_round = state.active_model_round.map(|round| {
        json!({
            "activation_id": round.activation_id,
            "round_id": round.round_id,
            "purpose": round.purpose,
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
    let context_handoff = state.latest_context_handoff.map(|handoff| {
        json!({
            "handoff_id": handoff.handoff_id,
            "previous_handoff_id": handoff.previous_handoff_id,
            "generation": handoff.next_generation,
            "covered_through_message_id": handoff.covered_through_message_id,
            "source_tokens": handoff.source_tokens,
            "document_tokens": handoff.document_tokens,
            "token_accounting_version": handoff.token_accounting_version,
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
        "context_handoff": context_handoff,
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
        "limits": model.limits,
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
    let allowed_actions = public_tool_actions(&record);
    let reconciliation = public_reconciliation(&record);
    json!({
        "tool_call_id": record.tool_call_id,
        "tool_name": record.tool_name,
        "status": record.status,
        "started_at_ms": record.started_at_ms,
        "auto_wait_seconds": record.auto_wait_seconds,
        "completion_mode": public_completion_mode(&record.completion_mode),
        "allowed_actions": allowed_actions,
        "result": record.result.map(public_payload),
        "error": record.error.map(public_tool_error),
        "cancel_reason": record.cancel_reason,
        "completed_at_ms": record.completed_at_ms,
        "reconciliation": reconciliation,
    })
}

fn public_tool_actions(record: &AsyncToolCallRecord) -> Vec<&'static str> {
    match record.status {
        crate::domain::AsyncToolStatus::Planned | crate::domain::AsyncToolStatus::Running => {
            vec!["cancel"]
        }
        crate::domain::AsyncToolStatus::UnknownOutcome if record.retry_dispatch_deduplicated => {
            vec!["retry_dispatch"]
        }
        _ => Vec::new(),
    }
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

fn public_reconciliation(record: &AsyncToolCallRecord) -> Value {
    if matches!(
        record.status,
        crate::domain::AsyncToolStatus::UnknownOutcome
    ) {
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

fn durable_fences_following_transient(record: &EventRecord) -> bool {
    matches!(&record.event, SessionEvent::ModelStepRetryScheduled { .. })
}

fn public_event(record: &EventRecord) -> Option<PublicEvent> {
    // Durable storage contains private lifecycle claims and dedupe/index
    // details. They remain in the stream for replay but never become public
    // SSE frames. Provider request content is never persisted here.
    let kind = match &record.event {
        SessionEvent::ModelRequestPrepared { .. }
        | SessionEvent::ModelRequestDeclared { .. }
        | SessionEvent::ContextHandoffPlanned { .. }
        | SessionEvent::ModelAttemptStarted { .. }
        | SessionEvent::ModelRequestAbandoned { .. }
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
        SessionEvent::ContextHandoffCreated { .. } => "context_handoff_created",
        SessionEvent::ContextHandoffFailed { .. } => "context_handoff_failed",
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

fn transient_model_event(event: TransientModelEvent) -> SseEvent {
    SseEvent::default().event("assistant_message_delta").data(
        json!({
            "schema": "zode.transient-event.v1",
            "session_id": event.session_id,
            "activation_id": event.activation_id,
            "round_id": event.round_id,
            "text": event.text,
        })
        .to_string(),
    )
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
            purpose,
            delivery_through_queue_id,
            started_at_ms,
        } => json!({
            "activation_id": activation_id,
            "round_id": round_id,
            "purpose": purpose,
            "delivery_through_queue_id": delivery_through_queue_id,
            "started_at_ms": started_at_ms,
        }),
        SessionEvent::ContextHandoffCreated { handoff } => json!({
            "handoff_id": handoff.handoff_id,
            "previous_handoff_id": handoff.previous_handoff_id,
            "generation": handoff.next_generation,
            "covered_through_message_id": handoff.covered_through_message_id,
            "source_tokens": handoff.source_tokens,
            "document_tokens": handoff.document_tokens,
            "token_accounting_version": handoff.token_accounting_version,
        }),
        SessionEvent::ContextHandoffFailed {
            plan_id,
            error,
            finished_at_ms,
        } => json!({
            "plan_id": plan_id,
            "error": serializable(error),
            "finished_at_ms": finished_at_ms,
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

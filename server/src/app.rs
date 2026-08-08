use std::sync::Arc;

use axum::{
    body::to_bytes,
    extract::{Extension, OriginalUri, Path, Query, Request, State},
    http::{header, uri::Authority, HeaderMap, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde_json::{json, Value};

use serde::Deserialize;

use crate::{
    access::{require_access, AccessVerifier, ActorContext},
    catalog::{Catalog, CatalogError, CreateEndpointRequest},
    config::Deployment,
    provider_authority::{
        CreateAuthProfileRequest, ProviderAuthority, ProviderError, PutProviderDescriptorRequest,
        SetDefaultAuthProfileRequest,
    },
    session_proxy::{CreateSessionRequest, ProxyJson, SessionProxy, SessionProxyError},
    ui_assets::UiAssets,
};

const MAX_ENDPOINT_CREATE_BODY_BYTES: usize = 128 * 1024;
const MAX_PROVIDER_DESCRIPTOR_BODY_BYTES: usize = 128 * 1024;
const MAX_PROFILE_BODY_BYTES: usize = 128 * 1024;
const MAX_SESSION_BODY_BYTES: usize = 1024 * 1024;
const MAX_CALLBACK_BODY_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
struct AppState {
    catalog: Arc<Catalog>,
    providers: Arc<ProviderAuthority>,
    sessions: Arc<SessionProxy>,
    ui_assets: Option<Arc<UiAssets>>,
    deployment: Deployment,
    local_endpoint_id: Option<String>,
}

#[derive(Clone)]
struct SurfaceState {
    management: SurfaceAuthority,
    callback: SurfaceAuthority,
}

#[derive(Clone)]
struct SurfaceAuthority {
    authority: Authority,
    default_port: u16,
}

pub(crate) struct RouterConfig {
    pub(crate) management_authority: String,
    pub(crate) management_default_port: u16,
    pub(crate) callback_authority: String,
    pub(crate) callback_default_port: u16,
    pub(crate) deployment: Deployment,
    pub(crate) local_endpoint_id: Option<String>,
}

pub(crate) fn router(
    access: Arc<AccessVerifier>,
    catalog: Arc<Catalog>,
    providers: Arc<ProviderAuthority>,
    sessions: Arc<SessionProxy>,
    ui_assets: Option<Arc<UiAssets>>,
    config: RouterConfig,
) -> Router {
    let state = AppState {
        catalog,
        providers,
        sessions,
        ui_assets,
        deployment: config.deployment,
        local_endpoint_id: config.local_endpoint_id,
    };
    let surface = SurfaceState {
        management: SurfaceAuthority {
            authority: config
                .management_authority
                .parse()
                .expect("validated config has a management authority"),
            default_port: config.management_default_port,
        },
        callback: SurfaceAuthority {
            authority: config
                .callback_authority
                .parse()
                .expect("validated config has a callback authority"),
            default_port: config.callback_default_port,
        },
    };
    let management = Router::new()
        .route("/v1/system", get(system))
        .route("/v1/endpoints", get(list_endpoints).post(create_endpoint))
        .route("/v1/endpoints/{endpoint_id}", get(get_endpoint))
        .route("/v1/endpoints/{endpoint_id}/probe", post(probe_endpoint))
        .route("/v1/providers", get(list_providers))
        .route("/v1/providers/{provider}", put(put_provider_descriptor))
        .route(
            "/v1/providers/{provider}/auth-profiles",
            get(list_auth_profiles).post(create_auth_profile),
        )
        .route(
            "/v1/providers/{provider}/auth-profiles/{profile_id}",
            delete(delete_auth_profile),
        )
        .route(
            "/v1/providers/{provider}/default-auth-profile",
            put(set_default_auth_profile),
        )
        .route(
            "/v1/auth-profiles/{profile_id}/replicas",
            get(list_auth_profile_replicas),
        )
        .route(
            "/v1/endpoints/{endpoint_id}/sessions",
            get(list_sessions).post(create_session),
        )
        .route(
            "/v1/endpoints/{endpoint_id}/sessions/{session_id}",
            get(get_session),
        )
        .route(
            "/v1/endpoints/{endpoint_id}/sessions/{session_id}/messages",
            post(append_message),
        )
        .route(
            "/v1/endpoints/{endpoint_id}/sessions/{session_id}/events",
            get(stream_session_events),
        )
        .fallback(management_fallback)
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(access, require_access));
    let callback = Router::new()
        .route(
            "/v1/endpoints/{endpoint_id}/callbacks/{callback_id}",
            post(forward_callback),
        )
        .with_state(state);
    management
        .merge(callback)
        .layer(middleware::from_fn_with_state(surface, enforce_surface))
}

async fn enforce_surface(
    State(state): State<SurfaceState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(authorities) = request_authorities(&request) else {
        return safe_not_found();
    };
    let callback_path = is_callback_path(request.uri().path());
    if authorities_match_surface(&authorities, &state.callback) {
        if request.method() == Method::POST && callback_path {
            return next.run(request).await;
        }
        return safe_not_found();
    }
    if authorities_match_surface(&authorities, &state.management) {
        if callback_path {
            return safe_not_found();
        }
        return next.run(request).await;
    }
    safe_not_found()
}

struct RequestAuthorities {
    uri: Option<Authority>,
    host: Option<Authority>,
}

fn request_authorities(request: &Request) -> Option<RequestAuthorities> {
    let uri = request.uri().authority().cloned();
    if uri.as_ref().is_some_and(has_userinfo) {
        return None;
    }
    let mut hosts = request.headers().get_all(header::HOST).iter();
    let host = match hosts.next() {
        Some(value) => {
            let authority = value.to_str().ok()?.parse::<Authority>().ok()?;
            if has_userinfo(&authority) {
                return None;
            }
            Some(authority)
        }
        None => None,
    };
    if hosts.next().is_some() {
        return None;
    }
    if uri.is_none() && host.is_none() {
        return None;
    }
    Some(RequestAuthorities { uri, host })
}

fn has_userinfo(authority: &Authority) -> bool {
    authority.as_str().contains('@')
}

fn authorities_match_surface(authorities: &RequestAuthorities, surface: &SurfaceAuthority) -> bool {
    authorities
        .uri
        .as_ref()
        .is_none_or(|authority| authority_matches_surface(authority, surface))
        && authorities
            .host
            .as_ref()
            .is_none_or(|authority| authority_matches_surface(authority, surface))
}

fn authority_matches_surface(authority: &Authority, surface: &SurfaceAuthority) -> bool {
    authority
        .host()
        .eq_ignore_ascii_case(surface.authority.host())
        && authority.port_u16().unwrap_or(surface.default_port)
            == surface.authority.port_u16().unwrap_or(surface.default_port)
}

fn is_callback_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/v1/endpoints/") else {
        return false;
    };
    let Some((endpoint_id, callback_id)) = rest.split_once("/callbacks/") else {
        return false;
    };
    !endpoint_id.is_empty()
        && !endpoint_id.contains('/')
        && !callback_id.is_empty()
        && !callback_id.contains('/')
}

fn safe_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "error": {
                "code": "not_found",
                "message": "resource was not found",
                "retryable": false
            }
        })),
    )
        .into_response()
}

async fn management_fallback(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if uri.path() == "/v1" || uri.path().starts_with("/v1/") {
        return route_not_found();
    }
    state
        .ui_assets
        .as_ref()
        .map(|assets| assets.response(&method, uri.path(), &headers))
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response())
}

fn route_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "error": {
                "code": "route_not_found",
                "message": "public route was not found",
                "retryable": false
            }
        })),
    )
        .into_response()
}

async fn system(State(state): State<AppState>) -> Response {
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "schema": "zode.system.v1",
            "deployment": state.deployment.as_str(),
            "local_endpoint_id": state.local_endpoint_id,
            "ingress": {
                "management_auth": "cloudflare_access",
                "callback_origin": "separate"
            },
            "features": {
                "remote_endpoints": true,
                "provider_auth": true
            }
        })),
    )
        .into_response()
}

async fn forward_callback(
    State(state): State<AppState>,
    Path((endpoint_id, callback_id)): Path<(String, String)>,
    request: Request,
) -> Result<Response, ApiError> {
    let headers = request.headers().clone();
    let body = to_bytes(request.into_body(), MAX_CALLBACK_BODY_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    state
        .sessions
        .forward_callback(&endpoint_id, &callback_id, &headers, body.to_vec())
        .await
        .map(callback_proxy_json_response)
        .map_err(ApiError::from_session_proxy)
}

async fn list_providers(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    state
        .providers
        .list()
        .await
        .map(Json)
        .map_err(ApiError::from_provider)
}

async fn put_provider_descriptor(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Extension(actor): Extension<ActorContext>,
    request: Request,
) -> Result<Json<Value>, ApiError> {
    let idempotency_key = one_header(request.headers(), "idempotency-key")?;
    let body = to_bytes(request.into_body(), MAX_PROVIDER_DESCRIPTOR_BODY_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let request: PutProviderDescriptorRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::invalid())?;
    state
        .providers
        .put_descriptor(&actor, &idempotency_key, &provider, request)
        .await
        .map(Json)
        .map_err(ApiError::from_provider)
}

async fn list_auth_profiles(
    State(state): State<AppState>,
    Path(provider): Path<String>,
) -> Result<Json<Value>, ApiError> {
    state
        .providers
        .list_profiles(&provider)
        .await
        .map(Json)
        .map_err(ApiError::from_provider)
}

async fn create_auth_profile(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Extension(actor): Extension<ActorContext>,
    request: Request,
) -> Result<Response, ApiError> {
    let idempotency_key = one_header(request.headers(), "idempotency-key")?;
    let body = to_bytes(request.into_body(), MAX_PROFILE_BODY_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let request: CreateAuthProfileRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::invalid())?;
    let profile = state
        .providers
        .create_profile(&actor, &idempotency_key, &provider, request)
        .await
        .map_err(ApiError::from_provider)?;
    Ok((StatusCode::CREATED, Json(profile)).into_response())
}

async fn set_default_auth_profile(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Extension(actor): Extension<ActorContext>,
    request: Request,
) -> Result<Json<Value>, ApiError> {
    let idempotency_key = one_header(request.headers(), "idempotency-key")?;
    let body = to_bytes(request.into_body(), MAX_PROFILE_BODY_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let request: SetDefaultAuthProfileRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::invalid())?;
    state
        .providers
        .set_default_profile(&actor, &idempotency_key, &provider, request)
        .await
        .map(Json)
        .map_err(ApiError::from_provider)
}

async fn delete_auth_profile(
    State(state): State<AppState>,
    Path((provider, profile_id)): Path<(String, String)>,
    Extension(actor): Extension<ActorContext>,
    request: Request,
) -> Result<Json<Value>, ApiError> {
    let idempotency_key = one_header(request.headers(), "idempotency-key")?;
    state
        .providers
        .delete_profile(&actor, &idempotency_key, &provider, &profile_id)
        .await
        .map(Json)
        .map_err(ApiError::from_provider)
}

async fn list_auth_profile_replicas(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    state
        .providers
        .list_replicas(&profile_id)
        .await
        .map(Json)
        .map_err(ApiError::from_provider)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionListQuery {
    limit: Option<u64>,
    cursor: Option<String>,
}

async fn create_session(
    State(state): State<AppState>,
    Path(endpoint_id): Path<String>,
    Extension(actor): Extension<ActorContext>,
    request: Request,
) -> Result<Response, ApiError> {
    let idempotency_key = one_header(request.headers(), "idempotency-key")?;
    let body = to_bytes(request.into_body(), MAX_SESSION_BODY_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let request: CreateSessionRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::invalid())?;
    state
        .sessions
        .create_session(&actor, &endpoint_id, &idempotency_key, request)
        .await
        .map(proxy_json_response)
        .map_err(ApiError::from_session_proxy)
}

async fn list_sessions(
    State(state): State<AppState>,
    Path(endpoint_id): Path<String>,
    Extension(actor): Extension<ActorContext>,
    Query(query): Query<SessionListQuery>,
) -> Result<Response, ApiError> {
    state
        .sessions
        .list_sessions(&actor, &endpoint_id, query.limit, query.cursor.as_deref())
        .await
        .map(proxy_json_response)
        .map_err(ApiError::from_session_proxy)
}

async fn get_session(
    State(state): State<AppState>,
    Path((endpoint_id, session_id)): Path<(String, String)>,
    Extension(actor): Extension<ActorContext>,
) -> Result<Response, ApiError> {
    state
        .sessions
        .get_session(&actor, &endpoint_id, &session_id)
        .await
        .map(proxy_json_response)
        .map_err(ApiError::from_session_proxy)
}

async fn append_message(
    State(state): State<AppState>,
    Path((endpoint_id, session_id)): Path<(String, String)>,
    Extension(actor): Extension<ActorContext>,
    request: Request,
) -> Result<Response, ApiError> {
    let idempotency_key = one_header(request.headers(), "idempotency-key")?;
    let body = to_bytes(request.into_body(), MAX_SESSION_BODY_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let body = serde_json::from_slice(&body).map_err(|_| ApiError::invalid())?;
    state
        .sessions
        .append_message(&actor, &endpoint_id, &session_id, &idempotency_key, body)
        .await
        .map(proxy_json_response)
        .map_err(ApiError::from_session_proxy)
}

async fn stream_session_events(
    State(state): State<AppState>,
    Path((endpoint_id, session_id)): Path<(String, String)>,
    Extension(actor): Extension<ActorContext>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let last_event_id = optional_one_header(&headers, "last-event-id")?;
    state
        .sessions
        .stream_events(&actor, &endpoint_id, &session_id, last_event_id.as_deref())
        .await
        .map_err(ApiError::from_session_proxy)
}

fn proxy_json_response(outcome: ProxyJson) -> Response {
    (outcome.status, Json(outcome.body)).into_response()
}

fn callback_proxy_json_response(outcome: ProxyJson) -> Response {
    (
        outcome.status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(outcome.body),
    )
        .into_response()
}

async fn create_endpoint(
    State(state): State<AppState>,
    Extension(actor): Extension<ActorContext>,
    request: Request,
) -> Result<Response, ApiError> {
    let idempotency_key = one_header(request.headers(), "idempotency-key")?;
    let body = to_bytes(request.into_body(), MAX_ENDPOINT_CREATE_BODY_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large())?;
    let request: CreateEndpointRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::invalid())?;
    let endpoint = state
        .catalog
        .create_endpoint(&actor, &idempotency_key, request)
        .await
        .map_err(ApiError::from_catalog)?;
    Ok((StatusCode::CREATED, Json(endpoint)).into_response())
}

async fn list_endpoints(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    state
        .catalog
        .list_endpoints()
        .await
        .map(Json)
        .map_err(ApiError::from_catalog)
}

async fn get_endpoint(
    State(state): State<AppState>,
    Path(endpoint_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    state
        .catalog
        .get_endpoint(&endpoint_id)
        .await
        .map_err(ApiError::from_catalog)?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}

async fn probe_endpoint(
    State(state): State<AppState>,
    Path(endpoint_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    state
        .catalog
        .probe_endpoint_by_id(&endpoint_id)
        .await
        .map(Json)
        .map_err(ApiError::from_catalog)
}

fn one_header(headers: &HeaderMap, name: &'static str) -> Result<String, ApiError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or_else(ApiError::invalid)?;
    if values.next().is_some() {
        return Err(ApiError::invalid());
    }
    std::str::from_utf8(value.as_bytes())
        .map(str::to_owned)
        .map_err(|_| ApiError::invalid())
}

fn optional_one_header(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<Option<String>, ApiError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ApiError::invalid());
    }
    std::str::from_utf8(value.as_bytes())
        .map(|value| Some(value.to_owned()))
        .map_err(|_| ApiError::invalid())
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    retryable: bool,
}

impl ApiError {
    fn invalid() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: "request is invalid",
            retryable: false,
        }
    }

    fn payload_too_large() -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "payload_too_large",
            message: "request is too large",
            retryable: false,
        }
    }

    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: "resource was not found",
            retryable: false,
        }
    }

    fn from_catalog(error: CatalogError) -> Self {
        match error {
            CatalogError::Invalid => Self::invalid(),
            CatalogError::NotFound => Self::not_found(),
            CatalogError::PayloadTooLarge => Self::payload_too_large(),
            CatalogError::Conflict => Self {
                status: StatusCode::CONFLICT,
                code: "operation_conflict",
                message: "management operation conflicts",
                retryable: false,
            },
            CatalogError::EndpointUnavailable => Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "endpoint_unavailable",
                message: "Endpoint is unavailable",
                retryable: true,
            },
            CatalogError::Internal => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "internal_error",
                message: "request could not be completed",
                retryable: false,
            },
        }
    }

    fn from_provider(error: ProviderError) -> Self {
        match error {
            ProviderError::Invalid => Self::invalid(),
            ProviderError::NotFound => Self::not_found(),
            ProviderError::PayloadTooLarge => Self::payload_too_large(),
            ProviderError::Conflict => Self {
                status: StatusCode::CONFLICT,
                code: "operation_conflict",
                message: "management operation conflicts",
                retryable: false,
            },
            ProviderError::Internal => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "internal_error",
                message: "request could not be completed",
                retryable: false,
            },
        }
    }

    fn from_session_proxy(error: SessionProxyError) -> Self {
        match error {
            SessionProxyError::Invalid => Self::invalid(),
            SessionProxyError::PayloadTooLarge => Self::payload_too_large(),
            SessionProxyError::NotFound => Self::not_found(),
            SessionProxyError::Conflict => Self {
                status: StatusCode::CONFLICT,
                code: "conflict",
                message: "session command conflicts",
                retryable: false,
            },
            SessionProxyError::EndpointUnavailable => Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "endpoint_unavailable",
                message: "Endpoint is unavailable",
                retryable: true,
            },
            SessionProxyError::AuthReplicaUnavailable => Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "auth_replica_unavailable",
                message: "credential replica is unavailable",
                retryable: true,
            },
            SessionProxyError::Internal => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "internal_error",
                message: "request could not be completed",
                retryable: false,
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({
                "error": {
                    "code": self.code,
                    "message": self.message,
                    "retryable": self.retryable
                }
            })),
        )
            .into_response()
    }
}

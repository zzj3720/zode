use std::sync::Arc;

use axum::{
    body::to_bytes,
    extract::{Extension, Path, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};

use crate::{
    access::{require_access, AccessVerifier, ActorContext},
    catalog::{Catalog, CatalogError, CreateEndpointRequest},
    ui_assets::UiAssets,
};

const MAX_ENDPOINT_CREATE_BODY_BYTES: usize = 128 * 1024;

#[derive(Clone)]
struct AppState {
    catalog: Arc<Catalog>,
    ui_assets: Option<Arc<UiAssets>>,
}

pub(crate) fn router(
    access: Arc<AccessVerifier>,
    catalog: Arc<Catalog>,
    ui_assets: Option<Arc<UiAssets>>,
) -> Router {
    let ui_enabled = ui_assets.is_some();
    let state = AppState { catalog, ui_assets };
    let mut routes = Router::new()
        .route("/v1/system", get(system))
        .route("/v1/endpoints", get(list_endpoints).post(create_endpoint))
        .route("/v1/endpoints/{endpoint_id}", get(get_endpoint))
        .route("/v1/providers", get(list_providers));
    if ui_enabled {
        routes = routes.route("/", get(ui_root));
    }
    routes
        .fallback(StatusCode::NOT_FOUND)
        .with_state(state)
        .layer(middleware::from_fn_with_state(access, require_access))
}

async fn ui_root(State(state): State<AppState>) -> Response {
    state
        .ui_assets
        .as_ref()
        .expect("UI root route requires preloaded assets")
        .root_response()
}

async fn system() -> Json<Value> {
    Json(json!({
        "schema": "zode.system.v1",
        "deployment": "server_only",
        "local_endpoint_id": null,
        "ingress": {
            "management_auth": "cloudflare_access",
            "callback_origin": "separate"
        },
        "features": {
            "remote_endpoints": true,
            "provider_auth": true
        }
    }))
}

async fn list_providers() -> Json<Value> {
    Json(json!({
        "schema": "zode.providers.v1",
        "providers": []
    }))
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

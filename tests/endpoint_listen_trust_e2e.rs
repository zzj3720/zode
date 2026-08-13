//! Red anchors for listen-scope trust: Endpoint protocol has no controller
//! auth, and every caller sees every session.

#[path = "support/http_sse.rs"]
mod http_sse_support;
pub(crate) mod support;

use http_sse_support::*;
use reqwest::StatusCode;
use serde_json::{json, Value};
use support::{http_client, require_ulid, response_text, HttpRequestExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_endpoint_protocol_has_no_controller_auth(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("listen-trust-no-auth")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;

    let create = client
        .post(server.url("/v1/sessions"))
        .header("Idempotency-Key", "listen-trust-create")
        .header("Content-Type", "application/json")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    let create_status = create.status();
    let create_body_text = response_text(create).await?;
    assert_eq!(
        create_status,
        StatusCode::CREATED,
        "unauthenticated create must be admitted: {create_body_text}"
    );
    let create_body: Value = serde_json::from_str(&create_body_text)?;
    let session_id = require_ulid(&create_body)?;

    let get = client
        .get(server.url(&format!("/v1/sessions/{session_id}")))
        .send_with_timeout()
        .await?;
    assert_eq!(
        get.status(),
        StatusCode::OK,
        "unauthenticated get must succeed: {}",
        response_text(get).await?
    );

    let list = client
        .get(server.url("/v1/sessions?limit=100"))
        .send_with_timeout()
        .await?;
    let list_status = list.status();
    let list_body = response_text(list).await?;
    assert_eq!(
        list_status,
        StatusCode::OK,
        "unauthenticated list must succeed: {list_body}"
    );
    assert!(
        list_body.contains(&session_id),
        "unauthenticated list omitted the created session: {list_body}"
    );

    let events = client
        .get(server.url("/v1/events"))
        .header("Last-Event-ID", "0")
        .send_with_timeout()
        .await?;
    assert_eq!(
        events.status(),
        StatusCode::OK,
        "unauthenticated SSE must succeed: {}",
        response_text(events).await?
    );

    let identity = client
        .get(server.url("/v1/identity"))
        .send_with_timeout()
        .await?;
    assert_eq!(identity.status(), StatusCode::OK);

    server.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_endpoint_sessions_are_shared_across_callers(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("listen-trust-shared-sessions")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;

    let first = client
        .post(server.url("/v1/sessions"))
        .header("Idempotency-Key", "shared-create-a")
        .header("Content-Type", "application/json")
        .header("Zode-Subject", "caller-a")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    let first_status = first.status();
    let first_text = response_text(first).await?;
    assert_eq!(
        first_status,
        StatusCode::CREATED,
        "first caller create must succeed without a controller bearer: {first_text}"
    );
    let first_body: Value = serde_json::from_str(&first_text)?;
    let session_id = require_ulid(&first_body)?;

    let list = client
        .get(server.url("/v1/sessions?limit=100"))
        .header("Zode-Subject", "caller-b")
        .send_with_timeout()
        .await?;
    let list_status = list.status();
    let list_body = response_text(list).await?;
    assert_eq!(
        list_status,
        StatusCode::OK,
        "second caller list must succeed: {list_body}"
    );
    assert!(
        list_body.contains(&session_id),
        "second caller must see the first caller's session: {list_body}"
    );

    let get = client
        .get(server.url(&format!("/v1/sessions/{session_id}")))
        .header("Zode-Subject", "caller-b")
        .send_with_timeout()
        .await?;
    assert_eq!(
        get.status(),
        StatusCode::OK,
        "second caller must read the first caller's session: {}",
        response_text(get).await?
    );

    server.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_two_actor_sessions_are_shared_on_one_endpoint(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("listen-trust-two-actor")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;

    let create = client
        .post(server.url("/v1/sessions"))
        .header("Idempotency-Key", "two-actor-create")
        .header("Content-Type", "application/json")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    let create_status = create.status();
    let create_text = response_text(create).await?;
    assert_eq!(
        create_status,
        StatusCode::CREATED,
        "actor A create must succeed: {create_text}"
    );
    let session_id = require_ulid(&serde_json::from_str(&create_text)?)?;

    let list = client
        .get(server.url("/v1/sessions?limit=100"))
        .send_with_timeout()
        .await?;
    let list_status = list.status();
    let list_body = response_text(list).await?;
    assert_eq!(
        list_status,
        StatusCode::OK,
        "actor B list must succeed: {list_body}"
    );
    assert!(
        list_body.contains(&session_id),
        "actor B must see actor A's session: {list_body}"
    );

    server.stop().await?;
    Ok(())
}

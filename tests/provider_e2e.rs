#![allow(dead_code)]

mod support;

use std::{
    fs,
    io::{Error as IoError, ErrorKind},
    path::{Path, PathBuf},
};

use reqwest::StatusCode;
use serde_json::{json, Value};
use support::{
    authenticated, install_test_replica, response_text, write_endpoint_config, ConfiguredServer,
    HttpRequestExt, ModelFixture, ModelHold, ModelScript, TempDatabase, TestResult,
};

const PROFILE_A: &str = "profile-provider-a";
const PROFILE_B: &str = "profile-provider-b";
const SECRET_A: &str = "provider-profile-a-secret";
const SECRET_B: &str = "provider-profile-b-secret";
const EXPIRED_SECRET: &str = "provider-expired-secret";

async fn install_replica(
    client: &reqwest::Client,
    server: &ConfiguredServer,
    profile: &str,
    key: &str,
    revision: u64,
    secret: &str,
    expires_at_ms: Option<i64>,
) -> TestResult<()> {
    let response = authenticated(client.put(server.url(&format!("/v1/auth-replicas/{profile}"))))
        .header("Idempotency-Key", key)
        .json(&json!({
            "schema": "zode.auth-replica.install.v1",
            "authority_id": "controller-e2e",
            "provider": "fixture-provider",
            "kind": "api_key",
            "revision": revision,
            "credential_schema": "openai-compatible.api-key.v1",
            "expires_at_ms": expires_at_ms,
            "secret": {
                "encoding": "application/zode-secret-envelope",
                "payload": secret
            }
        }))
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_text(response).await?;
    if !status.is_success() {
        return Err(
            IoError::other(format!("replica {profile} install failed: {status} {body}")).into(),
        );
    }
    if body.contains(secret) {
        return Err(
            IoError::other(format!("replica {profile} install response exposed secret")).into(),
        );
    }
    Ok(())
}

fn config_with_origins(database: &TempDatabase, origins: &[String]) -> TestResult<PathBuf> {
    let path = write_endpoint_config(database.path(), Vec::new(), 1)?;
    let mut config: Value = serde_json::from_slice(&fs::read(&path)?)?;
    config["provider_execution"]["allowed_base_url_origins"] = json!(origins);
    fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    Ok(path)
}

fn model_body(base_url: &str) -> Value {
    model_body_for_profile(base_url, "profile-e2e", 1)
}

fn model_body_for_profile(base_url: &str, profile: &str, minimum_revision: u64) -> Value {
    json!({
        "model": {
            "provider": "fixture-provider",
            "provider_execution": {
                "schema": "zode.provider-execution.v1",
                "revision": 1,
                "kind": "openai_compatible",
                "base_url": base_url
            },
            "model": "fixture-model",
            "auth_authority_id": "controller-e2e",
            "auth_profile_id": profile,
            "minimum_auth_revision": minimum_revision
        }
    })
}

async fn create_model(
    client: &reqwest::Client,
    server: &ConfiguredServer,
    key: &str,
    body: &Value,
) -> TestResult<(StatusCode, String)> {
    let response = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", key)
        .json(body)
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_text(response).await?;
    Ok((status, body))
}

async fn post_message(
    client: &reqwest::Client,
    server: &ConfiguredServer,
    session_id: &str,
) -> TestResult<StatusCode> {
    let response =
        authenticated(client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))))
            .header("Idempotency-Key", "provider-origin-port-message")
            .json(&json!({"content": "provider origin port check"}))
            .send_with_timeout()
            .await?;
    Ok(response.status())
}

/// A host-only allowlist entry is the origin on the default port, not a
/// wildcard for every same-host listener. Before the provider fix this case
/// is admitted and the real fixture receives a model request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_provider_origin_default_port_rejects_arbitrary_explicit_port() -> TestResult<()> {
    let database = TempDatabase::new("provider-origin-port-reject")?;
    let mut provider = ModelFixture::start(vec![ModelScript::final_text("unexpected")]).await?;
    let config = config_with_origins(&database, &["http://127.0.0.1".to_owned()])?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    install_test_replica(
        &client,
        &server.url(""),
        "provider-origin-port-reject-replica",
    )
    .await?;

    let (status, body) = create_model(
        &client,
        &server,
        "provider-origin-port-reject",
        &model_body(&provider.provider_url()),
    )
    .await?;
    if status == StatusCode::CREATED {
        let session_id = serde_json::from_str::<Value>(&body)?["session_id"]
            .as_str()
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "create omitted session_id"))?
            .to_owned();
        let _ = post_message(&client, &server, &session_id).await?;
        provider.wait_for_requests(1).await?;
    }

    server.stop().await?;
    provider.stop().await?;
    if status != StatusCode::UNPROCESSABLE_ENTITY {
        return Err(IoError::other(format!(
            "host-only origin wildcarded explicit provider port: {status} {body}"
        ))
        .into());
    }
    Ok(())
}

/// An explicit port remains usable when the descriptor's provider origin is
/// exactly the configured origin; this guards against over-tightening while
/// fixing the wildcard case above.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_provider_origin_explicit_port_allows_exact_fixture() -> TestResult<()> {
    let database = TempDatabase::new("provider-origin-port-allow")?;
    let mut provider = ModelFixture::start(vec![ModelScript::final_text("exact origin")]).await?;
    let config = config_with_origins(&database, &[provider.origin()])?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    install_test_replica(
        &client,
        &server.url(""),
        "provider-origin-port-allow-replica",
    )
    .await?;

    let (status, body) = create_model(
        &client,
        &server,
        "provider-origin-port-allow",
        &model_body(&provider.provider_url()),
    )
    .await?;
    if status != StatusCode::CREATED {
        server.stop().await?;
        provider.stop().await?;
        return Err(IoError::other(format!(
            "exact provider origin was rejected: {status} {body}"
        ))
        .into());
    }
    let session_id = serde_json::from_str::<Value>(&body)?["session_id"]
        .as_str()
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "create omitted session_id"))?
        .to_owned();
    let message_status = post_message(&client, &server, &session_id).await?;
    if message_status != StatusCode::ACCEPTED {
        server.stop().await?;
        provider.stop().await?;
        return Err(IoError::other(format!(
            "exact provider origin message was rejected: {message_status}"
        ))
        .into());
    }
    provider.wait_for_requests(1).await?;
    server.stop().await?;
    provider.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_two_profiles_one_provider_resolve_exact_replica() -> TestResult<()> {
    let database = TempDatabase::new("provider-two-profiles")?;
    let mut provider = ModelFixture::start(vec![
        ModelScript::final_text("profile A response"),
        ModelScript::final_text("profile B response"),
    ])
    .await?;
    let config = config_with_origins(&database, &[provider.origin()])?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    install_replica(
        &client,
        &server,
        PROFILE_A,
        "provider-two-profiles-a",
        1,
        SECRET_A,
        None,
    )
    .await?;
    install_replica(
        &client,
        &server,
        PROFILE_B,
        "provider-two-profiles-b",
        1,
        SECRET_B,
        None,
    )
    .await?;

    for (index, (profile, expected_secret)) in [(PROFILE_A, SECRET_A), (PROFILE_B, SECRET_B)]
        .into_iter()
        .enumerate()
    {
        let (status, body) = create_model(
            &client,
            &server,
            &format!("provider-two-profiles-create-{index}"),
            &model_body_for_profile(&provider.provider_url(), profile, 1),
        )
        .await?;
        if status != StatusCode::CREATED {
            server.stop().await?;
            provider.stop().await?;
            return Err(IoError::other(format!(
                "profile {profile} create failed: {status} {body}"
            ))
            .into());
        }
        let session_id = serde_json::from_str::<Value>(&body)?["session_id"]
            .as_str()
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "create omitted session_id"))?
            .to_owned();
        let message_status = post_message(&client, &server, &session_id).await?;
        if message_status != StatusCode::ACCEPTED {
            server.stop().await?;
            provider.stop().await?;
            return Err(IoError::other(format!(
                "profile {profile} message failed: {message_status}"
            ))
            .into());
        }
        provider.wait_for_requests(index + 1).await?;
        let authorization = provider
            .request_headers(index)
            .and_then(|headers| headers["authorization"].as_str().map(str::to_owned))
            .ok_or_else(|| IoError::other("provider request omitted authorization"))?;
        if authorization != format!("Bearer {expected_secret}") {
            server.stop().await?;
            provider.stop().await?;
            return Err(IoError::other(format!(
                "profile {profile} resolved the wrong credential: {authorization}"
            ))
            .into());
        }
    }

    server.stop().await?;
    provider.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_bad_replica_never_falls_back_to_environment() -> TestResult<()> {
    let database = TempDatabase::new("provider-no-environment-fallback")?;
    let mut provider = ModelFixture::start(vec![ModelScript::final_text("must not run")]).await?;
    let config = config_with_origins(&database, &[provider.origin()])?;
    let mut server = ConfiguredServer::start_with_readiness_timeout_and_env(
        &database,
        &config,
        std::time::Duration::from_secs(10),
        &[(
            "OPENAI_API_KEY",
            Path::new("environment-secret-must-not-be-used"),
        )],
    )
    .await?;
    let client = support::http_client()?;
    install_replica(
        &client,
        &server,
        PROFILE_A,
        "provider-no-environment-fallback",
        1,
        EXPIRED_SECRET,
        Some(0),
    )
    .await?;
    let (status, body) = create_model(
        &client,
        &server,
        "provider-no-environment-fallback-create",
        &model_body_for_profile(&provider.provider_url(), PROFILE_A, 1),
    )
    .await?;
    if status != StatusCode::SERVICE_UNAVAILABLE {
        server.stop().await?;
        provider.stop().await?;
        return Err(IoError::other(format!(
            "expired replica fell back to environment credential: {status} {body}"
        ))
        .into());
    }
    if provider.request_count() != 0 {
        server.stop().await?;
        provider.stop().await?;
        return Err(IoError::other("bad replica reached provider despite unavailable auth").into());
    }
    server.stop().await?;
    provider.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_replica_rotation_keeps_inflight_and_updates_next_request() -> TestResult<()> {
    let database = TempDatabase::new("provider-rotation-inflight")?;
    let hold = ModelHold::new();
    let mut provider = ModelFixture::start(vec![
        ModelScript::stream_hold(hold.clone()),
        ModelScript::final_text("rotated response"),
    ])
    .await?;
    let config = config_with_origins(&database, &[provider.origin()])?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    install_replica(
        &client,
        &server,
        PROFILE_A,
        "provider-rotation-inflight-v1",
        1,
        SECRET_A,
        None,
    )
    .await?;
    let (status, body) = create_model(
        &client,
        &server,
        "provider-rotation-inflight-create",
        &model_body_for_profile(&provider.provider_url(), PROFILE_A, 1),
    )
    .await?;
    if status != StatusCode::CREATED {
        server.stop().await?;
        provider.stop().await?;
        return Err(
            IoError::other(format!("rotation session create failed: {status} {body}")).into(),
        );
    }
    let session_id = serde_json::from_str::<Value>(&body)?["session_id"]
        .as_str()
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "create omitted session_id"))?
        .to_owned();
    let first_message_status = post_message(&client, &server, &session_id).await?;
    if first_message_status != StatusCode::ACCEPTED {
        server.stop().await?;
        provider.stop().await?;
        return Err(IoError::other(format!(
            "first rotation message failed: {first_message_status}"
        ))
        .into());
    }
    provider.wait_for_requests(1).await?;
    hold.wait_entered().await?;
    install_replica(
        &client,
        &server,
        PROFILE_A,
        "provider-rotation-inflight-v2",
        2,
        SECRET_B,
        None,
    )
    .await?;
    let second_message =
        authenticated(client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))))
            .header(
                "Idempotency-Key",
                "provider-rotation-inflight-second-message",
            )
            .json(&json!({"content": "queue next request during rotation"}))
            .send_with_timeout()
            .await?;
    if second_message.status() != StatusCode::ACCEPTED {
        server.stop().await?;
        provider.stop().await?;
        return Err(IoError::other(format!(
            "second rotation message failed: {}",
            second_message.status()
        ))
        .into());
    }
    hold.release();
    provider.wait_for_requests(2).await?;
    let first_authorization = provider
        .request_headers(0)
        .and_then(|headers| headers["authorization"].as_str().map(str::to_owned))
        .ok_or_else(|| IoError::other("first in-flight request omitted authorization"))?;
    let second_authorization = provider
        .request_headers(1)
        .and_then(|headers| headers["authorization"].as_str().map(str::to_owned))
        .ok_or_else(|| IoError::other("next request omitted authorization"))?;
    if first_authorization != format!("Bearer {SECRET_A}")
        || second_authorization != format!("Bearer {SECRET_B}")
    {
        server.stop().await?;
        provider.stop().await?;
        return Err(IoError::other(format!(
            "rotation revision leaked across request boundary: first={first_authorization}, second={second_authorization}"
        ))
        .into());
    }
    server.stop().await?;
    provider.stop().await?;
    Ok(())
}

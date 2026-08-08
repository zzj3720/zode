#![allow(dead_code)]

mod support;

use std::{
    fs,
    io::{Error as IoError, ErrorKind},
    path::{Path, PathBuf},
    time::Duration,
};

use bytes::Bytes;
use futures_util::{stream::BoxStream, StreamExt};
use reqwest::StatusCode;
use serde_json::{json, Value};
use support::{
    assert_response_headers_secret_free, authenticated, install_test_replica, response_text,
    sqlite_contains_secret, write_endpoint_config, ConfiguredServer, HttpRequestExt, ModelFixture,
    ModelHold, ModelScript, TempDatabase, TestResult, TestZode, TEST_CONTROLLER_SECRET,
};

const PROFILE_A: &str = "profile-provider-a";
const PROFILE_B: &str = "profile-provider-b";
const SECRET_A: &str = "provider-profile-a-secret";
const SECRET_B: &str = "provider-profile-b-secret";
const SECRET_C: &str = "provider-profile-c-secret";
const EXPIRED_SECRET: &str = "provider-expired-secret";

struct ReplicaInstall<'a> {
    profile: &'a str,
    key: &'a str,
    revision: u64,
    secret: &'a str,
    expires_at_ms: Option<i64>,
}

async fn install_replica(
    client: &reqwest::Client,
    server: &ConfiguredServer,
    profile: &str,
    key: &str,
    revision: u64,
    secret: &str,
    expires_at_ms: Option<i64>,
) -> TestResult<()> {
    let forbidden = [secret, TEST_CONTROLLER_SECRET];
    install_replica_at(
        client,
        &server.url(""),
        ReplicaInstall {
            profile,
            key,
            revision,
            secret,
            expires_at_ms,
        },
        &forbidden,
    )
    .await
}

async fn install_replica_at(
    client: &reqwest::Client,
    base_url: &str,
    install: ReplicaInstall<'_>,
    forbidden: &[&str],
) -> TestResult<()> {
    let response =
        authenticated(client.put(format!("{base_url}/v1/auth-replicas/{}", install.profile)))
            .header("Idempotency-Key", install.key)
            .json(&json!({
                "schema": "zode.auth-replica.install.v1",
                "authority_id": "controller-e2e",
                "provider": "fixture-provider",
                "kind": "api_key",
                "revision": install.revision,
                "credential_schema": "openai-compatible.api-key.v1",
                "expires_at_ms": install.expires_at_ms,
                "secret": {
                    "encoding": "application/zode-secret-envelope",
                    "payload": install.secret
                }
            }))
            .send_with_timeout()
            .await?;
    let status = response.status();
    assert_response_headers_secret_free(&response, forbidden);
    let body = response_text(response).await?;
    assert_secret_free(&body, forbidden)?;
    if !status.is_success() {
        return Err(IoError::other(format!(
            "replica {} install failed: {status} {body}",
            install.profile
        ))
        .into());
    }
    Ok(())
}

struct ProfileRound<'a> {
    provider_url: &'a str,
    profile: &'a str,
    minimum_revision: u64,
    create_key: &'a str,
    message_key: &'a str,
    message: &'a str,
    marker: &'a str,
}

async fn tombstone_replica_at(
    client: &reqwest::Client,
    base_url: &str,
    profile: &str,
    key: &str,
    revision: u64,
) -> TestResult<(StatusCode, String)> {
    let response = authenticated(client.put(format!("{base_url}/v1/auth-replicas/{profile}")))
        .header("Idempotency-Key", key)
        .json(&json!({
            "schema": "zode.auth-replica.tombstone.v1",
            "authority_id": "controller-e2e",
            "provider": "fixture-provider",
            "revision": revision
        }))
        .send_with_timeout()
        .await?;
    assert_response_headers_secret_free(&response, &[TEST_CONTROLLER_SECRET]);
    let status = response.status();
    let body = response_text(response).await?;
    assert_secret_free(&body, &[TEST_CONTROLLER_SECRET])?;
    Ok((status, body))
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
    create_model_at(client, &server.url(""), key, body).await
}

async fn create_model_at(
    client: &reqwest::Client,
    base_url: &str,
    key: &str,
    body: &Value,
) -> TestResult<(StatusCode, String)> {
    let response = authenticated(client.post(format!("{base_url}/v1/sessions")))
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
    post_message_at(
        client,
        &server.url(""),
        session_id,
        "provider-origin-port-message",
        "provider origin port check",
    )
    .await
}

async fn post_message_at(
    client: &reqwest::Client,
    base_url: &str,
    session_id: &str,
    idempotency_key: &str,
    content: &str,
) -> TestResult<StatusCode> {
    let response =
        authenticated(client.post(format!("{base_url}/v1/sessions/{session_id}/messages")))
            .header("Idempotency-Key", idempotency_key)
            .json(&json!({"content": content}))
            .send_with_timeout()
            .await?;
    Ok(response.status())
}

fn assert_secret_free(body: &str, forbidden: &[&str]) -> TestResult<()> {
    if forbidden
        .iter()
        .filter(|marker| !marker.is_empty())
        .any(|marker| body.contains(marker))
    {
        return Err(IoError::other("provider profile secret reached a public body").into());
    }
    Ok(())
}

async fn read_session_at(
    client: &reqwest::Client,
    base_url: &str,
    session_id: &str,
    forbidden: &[&str],
) -> TestResult<(StatusCode, String)> {
    let response = authenticated(client.get(format!("{base_url}/v1/sessions/{session_id}")))
        .send_with_timeout()
        .await?;
    assert_response_headers_secret_free(&response, forbidden);
    let status = response.status();
    let body = response_text(response).await?;
    assert_secret_free(&body, forbidden)?;
    Ok((status, body))
}

struct ProfileSse {
    stream: BoxStream<'static, Result<Bytes, reqwest::Error>>,
    buffer: Vec<u8>,
    forbidden: Vec<String>,
}

async fn open_profile_events(
    client: &reqwest::Client,
    base_url: &str,
    session_id: &str,
    forbidden: &[&str],
) -> TestResult<ProfileSse> {
    let response = authenticated(client.get(format!("{base_url}/v1/sessions/{session_id}/events")))
        .send_with_timeout()
        .await?;
    assert_response_headers_secret_free(&response, forbidden);
    if response.status() != StatusCode::OK {
        let status = response.status();
        let body = response_text(response).await?;
        assert_secret_free(&body, forbidden)?;
        return Err(IoError::other(format!("profile SSE returned HTTP {status}")).into());
    }
    Ok(ProfileSse {
        stream: response.bytes_stream().boxed(),
        buffer: Vec::new(),
        forbidden: forbidden.iter().map(|value| (*value).to_owned()).collect(),
    })
}

impl ProfileSse {
    async fn next(&mut self) -> TestResult<(String, Value)> {
        loop {
            if let Some(end) = self.buffer.windows(2).position(|window| window == b"\n\n") {
                let frame = self.buffer.drain(..end + 2).collect::<Vec<_>>();
                for marker in self.forbidden.iter().filter(|marker| !marker.is_empty()) {
                    if frame
                        .windows(marker.len())
                        .any(|window| window == marker.as_bytes())
                    {
                        return Err(IoError::other("provider profile secret reached SSE").into());
                    }
                }
                let text = std::str::from_utf8(&frame)?;
                let mut event = None;
                let mut data = None;
                for line in text.lines() {
                    if let Some(value) = line.strip_prefix("event: ") {
                        event = Some(value.to_owned());
                    } else if let Some(value) = line.strip_prefix("data: ") {
                        data = Some(serde_json::from_str(value)?);
                    }
                }
                if let (Some(event), Some(data)) = (event, data) {
                    return Ok((event, data));
                }
            }
            let chunk = tokio::time::timeout(Duration::from_secs(30), self.stream.next())
                .await
                .map_err(|_| IoError::new(ErrorKind::TimedOut, "profile SSE frame timed out"))?
                .ok_or_else(|| {
                    IoError::new(ErrorKind::UnexpectedEof, "profile SSE ended early")
                })??;
            self.buffer.extend_from_slice(&chunk);
        }
    }
}

async fn wait_profile_assistant(
    events: &mut ProfileSse,
    session_id: &str,
    marker: &str,
) -> TestResult<()> {
    loop {
        let (event, data) = events.next().await?;
        if event == "assistant_message_committed" || data["kind"] == "assistant_message_committed" {
            if data["session_id"] != session_id || !data.to_string().contains(marker) {
                return Err(IoError::other("profile assistant event was invalid").into());
            }
            return Ok(());
        }
    }
}

fn session_id_from_create(body: &str) -> TestResult<String> {
    serde_json::from_str::<Value>(body)?["session_id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            IoError::new(ErrorKind::InvalidData, "profile create omitted session_id").into()
        })
}

fn assert_selected_profile(body: &str, profile: &str, revision: u64) -> TestResult<()> {
    let body: Value = serde_json::from_str(body)?;
    if body["model"]["auth_profile_id"] != profile || body["model"]["auth_revision"] != revision {
        return Err(IoError::other(format!(
            "session selected unexpected profile/revision: {}",
            body["model"]
        ))
        .into());
    }
    Ok(())
}

fn assert_replica_unavailable(status: StatusCode, body: &str) -> TestResult<()> {
    if status != StatusCode::SERVICE_UNAVAILABLE {
        return Err(IoError::other(format!(
            "wrong profile was not rejected as auth_replica_unavailable: {status} {body}"
        ))
        .into());
    }
    let body: Value = serde_json::from_str(body)?;
    if body["error"]["code"] != "auth_replica_unavailable" {
        return Err(IoError::other(format!(
            "wrong profile returned the wrong safe error: {body}"
        ))
        .into());
    }
    Ok(())
}

fn assert_provider_authorization(
    provider: &ModelFixture,
    request_index: usize,
    secret: &str,
) -> TestResult<()> {
    let authorization = provider
        .request_headers(request_index)
        .and_then(|headers| headers["authorization"].as_str().map(str::to_owned))
        .ok_or_else(|| IoError::other("provider request omitted authorization"))?;
    if authorization != format!("Bearer {secret}") {
        return Err(IoError::other(format!(
            "provider resolved the wrong profile secret: request {request_index}"
        ))
        .into());
    }
    Ok(())
}

async fn run_profile_round(
    client: &reqwest::Client,
    endpoint: &TestZode,
    round: ProfileRound<'_>,
    forbidden: &[&str],
) -> TestResult<String> {
    let (status, body) = create_model_at(
        client,
        &endpoint.url(""),
        round.create_key,
        &model_body_for_profile(round.provider_url, round.profile, round.minimum_revision),
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "profile create failed: {body}");
    assert_secret_free(&body, forbidden)?;
    let session_id = session_id_from_create(&body)?;
    let mut events = open_profile_events(client, &endpoint.url(""), &session_id, forbidden).await?;
    let message_status = post_message_at(
        client,
        &endpoint.url(""),
        &session_id,
        round.message_key,
        round.message,
    )
    .await?;
    assert_eq!(
        message_status,
        StatusCode::ACCEPTED,
        "profile message rejected"
    );
    wait_profile_assistant(&mut events, &session_id, round.marker).await?;
    let (read_status, read_body) =
        read_session_at(client, &endpoint.url(""), &session_id, forbidden).await?;
    assert_eq!(read_status, StatusCode::OK, "profile session read failed");
    assert_selected_profile(&read_body, round.profile, round.minimum_revision.max(1))?;
    Ok(session_id)
}

async fn read_replica_at(
    client: &reqwest::Client,
    base_url: &str,
    profile: &str,
    forbidden: &[&str],
) -> TestResult<(StatusCode, String)> {
    let response = authenticated(client.get(format!("{base_url}/v1/auth-replicas/{profile}")))
        .send_with_timeout()
        .await?;
    assert_response_headers_secret_free(&response, forbidden);
    let status = response.status();
    let body = response_text(response).await?;
    assert_secret_free(&body, forbidden)?;
    Ok((status, body))
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_multiple_profiles_selection_isolated_across_replace_tombstone_restart(
) -> TestResult<()> {
    let database = TempDatabase::new("provider-profile-lifecycle")?;
    let forbidden = [SECRET_A, SECRET_B, SECRET_C, TEST_CONTROLLER_SECRET];
    let mut provider = ModelFixture::start(vec![
        ModelScript::final_text("profile A revision 1"),
        ModelScript::final_text("profile A revision 2"),
        ModelScript::final_text("profile B before tombstone"),
        ModelScript::final_text("profile B after tombstone"),
        ModelScript::final_text("profile B after restart"),
    ])
    .await?;
    let config = config_with_origins(&database, &[provider.origin()])?;
    let mut endpoint = TestZode::start(database.path(), &config, &forbidden).await?;
    let client = support::http_client()?;

    let scenario = async {
        let base_url = endpoint.url("");
        install_replica_at(
            &client,
            &base_url,
            ReplicaInstall {
                profile: PROFILE_A,
                key: "profile-lifecycle-a-rev1",
                revision: 1,
                secret: SECRET_A,
                expires_at_ms: None,
            },
            &forbidden,
        )
        .await?;
        install_replica_at(
            &client,
            &base_url,
            ReplicaInstall {
                profile: PROFILE_B,
                key: "profile-lifecycle-b-rev1",
                revision: 1,
                secret: SECRET_B,
                expires_at_ms: None,
            },
            &forbidden,
        )
        .await?;

        let _profile_a_rev1 = run_profile_round(
            &client,
            &endpoint,
            ProfileRound {
                provider_url: &provider.provider_url(),
                profile: PROFILE_A,
                minimum_revision: 1,
                create_key: "profile-lifecycle-a-session-1",
                message_key: "profile-lifecycle-a-message-1",
                message: "select profile A revision 1",
                marker: "profile A revision 1",
            },
            &forbidden,
        )
        .await?;
        provider.wait_for_requests(1).await?;
        assert_provider_authorization(&provider, 0, SECRET_A)?;

        let (missing_status, missing_body) = create_model_at(
            &client,
            &base_url,
            "profile-lifecycle-missing-profile",
            &model_body_for_profile(&provider.provider_url(), "profile-missing", 1),
        )
        .await?;
        assert_secret_free(&missing_body, &forbidden)?;
        assert_replica_unavailable(missing_status, &missing_body)?;
        assert_eq!(provider.request_count(), 1);

        install_replica_at(
            &client,
            &base_url,
            ReplicaInstall {
                profile: PROFILE_A,
                key: "profile-lifecycle-a-rev2",
                revision: 2,
                secret: SECRET_C,
                expires_at_ms: None,
            },
            &forbidden,
        )
        .await?;
        let _profile_a_rev2 = run_profile_round(
            &client,
            &endpoint,
            ProfileRound {
                provider_url: &provider.provider_url(),
                profile: PROFILE_A,
                minimum_revision: 2,
                create_key: "profile-lifecycle-a-session-2",
                message_key: "profile-lifecycle-a-message-2",
                message: "select profile A revision 2",
                marker: "profile A revision 2",
            },
            &forbidden,
        )
        .await?;
        provider.wait_for_requests(2).await?;
        assert_provider_authorization(&provider, 1, SECRET_C)?;

        let _profile_b_before_tombstone = run_profile_round(
            &client,
            &endpoint,
            ProfileRound {
                provider_url: &provider.provider_url(),
                profile: PROFILE_B,
                minimum_revision: 1,
                create_key: "profile-lifecycle-b-session-1",
                message_key: "profile-lifecycle-b-message-1",
                message: "select profile B before tombstone",
                marker: "profile B before tombstone",
            },
            &forbidden,
        )
        .await?;
        provider.wait_for_requests(3).await?;
        assert_provider_authorization(&provider, 2, SECRET_B)?;

        let (tombstone_status, tombstone_body) = tombstone_replica_at(
            &client,
            &base_url,
            PROFILE_A,
            "profile-lifecycle-a-tombstone",
            3,
        )
        .await?;
        assert!(
            tombstone_status.is_success(),
            "profile A tombstone failed: {tombstone_status} {tombstone_body}"
        );
        let tombstone: Value = serde_json::from_str(&tombstone_body)?;
        assert_eq!(tombstone["status"], "tombstoned");
        assert_eq!(tombstone["revision"], 3);

        let (tombstoned_status, tombstoned_body) = create_model_at(
            &client,
            &base_url,
            "profile-lifecycle-a-after-tombstone",
            &model_body_for_profile(&provider.provider_url(), PROFILE_A, 1),
        )
        .await?;
        assert_secret_free(&tombstoned_body, &forbidden)?;
        assert_replica_unavailable(tombstoned_status, &tombstoned_body)?;
        assert_eq!(provider.request_count(), 3);

        let _profile_b_after_tombstone = run_profile_round(
            &client,
            &endpoint,
            ProfileRound {
                provider_url: &provider.provider_url(),
                profile: PROFILE_B,
                minimum_revision: 1,
                create_key: "profile-lifecycle-b-session-2",
                message_key: "profile-lifecycle-b-message-2",
                message: "select profile B after tombstone",
                marker: "profile B after tombstone",
            },
            &forbidden,
        )
        .await?;
        provider.wait_for_requests(4).await?;
        assert_provider_authorization(&provider, 3, SECRET_B)?;

        endpoint.stop(&forbidden).await?;
        for secret in [SECRET_A, SECRET_B, SECRET_C] {
            assert!(!sqlite_contains_secret(database.path(), secret).await?);
        }
        endpoint = TestZode::start(database.path(), &config, &forbidden).await?;
        let restarted_base_url = endpoint.url("");
        let (a_status, a_body) =
            read_replica_at(&client, &restarted_base_url, PROFILE_A, &forbidden).await?;
        assert_eq!(a_status, StatusCode::OK, "tombstoned profile GET failed");
        let a_metadata: Value = serde_json::from_str(&a_body)?;
        assert_eq!(a_metadata["status"], "tombstoned");
        assert_eq!(a_metadata["revision"], 3);
        let (b_status, b_body) =
            read_replica_at(&client, &restarted_base_url, PROFILE_B, &forbidden).await?;
        assert_eq!(b_status, StatusCode::OK, "ready profile GET failed");
        let b_metadata: Value = serde_json::from_str(&b_body)?;
        assert_eq!(b_metadata["status"], "ready");
        assert_eq!(b_metadata["revision"], 1);

        let _profile_b_after_restart = run_profile_round(
            &client,
            &endpoint,
            ProfileRound {
                provider_url: &provider.provider_url(),
                profile: PROFILE_B,
                minimum_revision: 1,
                create_key: "profile-lifecycle-b-session-3",
                message_key: "profile-lifecycle-b-message-3",
                message: "select profile B after restart",
                marker: "profile B after restart",
            },
            &forbidden,
        )
        .await?;
        provider.wait_for_requests(5).await?;
        assert_provider_authorization(&provider, 4, SECRET_B)?;

        let (post_restart_status, post_restart_body) = create_model_at(
            &client,
            &restarted_base_url,
            "profile-lifecycle-a-after-restart",
            &model_body_for_profile(&provider.provider_url(), PROFILE_A, 1),
        )
        .await?;
        assert_secret_free(&post_restart_body, &forbidden)?;
        assert_replica_unavailable(post_restart_status, &post_restart_body)?;
        assert_eq!(provider.request_count(), 5);
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    let endpoint_stop = endpoint.stop(&forbidden).await;
    let provider_stop = provider.stop().await;
    scenario?;
    endpoint_stop?;
    provider_stop?;
    for secret in [SECRET_A, SECRET_B, SECRET_C] {
        assert!(!sqlite_contains_secret(database.path(), secret).await?);
    }
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

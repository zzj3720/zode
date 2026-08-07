mod support;

use std::{
    fs,
    io::Error,
    path::{Path, PathBuf},
    time::Duration,
};

use serde_json::{json, Value};
use support::{
    new_llm_live_recording_run_dir, new_llm_recording_run_dir, run_provider_roundtrip_and_restart,
    scan_llm_recording_tree, sqlite_contains_secret, write_endpoint_config, LlmHttpProxy,
    LlmHttpRecording, LlmHttpRecordingMetadata, ProviderRoundtripSpec, TempDatabase, TestResult,
    TEST_CONTROLLER_SECRET,
};
use tokio::time::timeout;

const PROVIDER: &str = "opencode-go";
const PROVIDER_UPSTREAM_ORIGIN: &str = "https://opencode.ai";
const MODEL: &str = "deepseek-v4-flash";
const PROFILE: &str = "opencode-live-provider-e2e";
const SUBJECT: &str = "live-provider-subject";
const FIRST_PROMPT: &str = "Reply with exactly ZODE_LIVE_OK.";
const RESTART_PROMPT: &str = "Reply with exactly ZODE_LIVE_RESTART_OK.";
const OFFLINE_REPLAY_SECRET: &str = "offline-live-recording-provider-key";
const RECORDING_PATH: &str =
    "tests/fixtures/provider_recordings/opencode_go_deepseek_v4_flash.v2.json";
const LIVE_PROVIDER_TIMEOUT: Duration = Duration::from_secs(120);

fn live_config(database: &Path) -> TestResult<PathBuf> {
    let path = write_endpoint_config(database, Vec::new(), 1)?;
    let mut config: Value = serde_json::from_slice(&fs::read(&path)?)?;
    config["provider_execution"]["adapter_kinds"] = json!(["openai_compatible"]);
    config["provider_execution"]["allowed_base_url_origins"] = json!(["http://127.0.0.1"]);
    fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    Ok(path)
}

fn merge_live_errors(
    primary: TestResult<()>,
    cleanup_errors: Vec<String>,
    secret: &str,
) -> TestResult<()> {
    let cleanup = cleanup_errors
        .into_iter()
        .map(|error| error.replace(secret, "[redacted]"))
        .collect::<Vec<_>>();
    match (primary, cleanup.is_empty()) {
        (Ok(()), true) => Ok(()),
        (Ok(()), false) => Err(Error::other(format!(
            "live provider cleanup failed: {}",
            cleanup.join("; ")
        ))
        .into()),
        (Err(error), true) => {
            Err(Error::other(error.to_string().replace(secret, "[redacted]")).into())
        }
        (Err(error), false) => Err(Error::other(format!(
            "live provider failed: {}; cleanup failed: {}",
            error.to_string().replace(secret, "[redacted]"),
            cleanup.join("; ")
        ))
        .into()),
    }
}

async fn run_live_provider(api_key: String) -> TestResult<()> {
    let quarantine = new_llm_recording_run_dir()?;
    let recording_id = quarantine
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::other("live recording run id was invalid"))?
        .to_owned();
    let database = TempDatabase::new("live-provider")?;
    let config = live_config(database.path())?;
    let mut recorder = LlmHttpProxy::record(
        PROVIDER_UPSTREAM_ORIGIN,
        PROVIDER,
        MODEL,
        &quarantine,
        LlmHttpRecordingMetadata {
            recording_id: recording_id.clone(),
            purpose: "live_provider_roundtrip_and_restart".to_owned(),
            owner: "e2e_live_opencode_provider_roundtrip_and_restart".to_owned(),
            boundary: "endpoint_aimux_provider_http".to_owned(),
            secret_slots: vec!["SLOT_PROVIDER_AUTHORIZATION_HEADER".to_owned()],
        },
    )
    .await?;
    let primary = run_provider_roundtrip_and_restart(ProviderRoundtripSpec {
        database: database.path().to_owned(),
        config,
        provider_base_url: recorder.base_url("/zen/go/v1"),
        provider: PROVIDER.to_owned(),
        model: MODEL.to_owned(),
        profile: PROFILE.to_owned(),
        subject: SUBJECT.to_owned(),
        provider_secret: api_key.clone(),
        first_prompt: FIRST_PROMPT.to_owned(),
        first_marker: "ZODE_LIVE_OK".to_owned(),
        restart_prompt: RESTART_PROMPT.to_owned(),
        restart_marker: "ZODE_LIVE_RESTART_OK".to_owned(),
        idempotency_prefix: "live-provider".to_owned(),
        forbidden: vec![api_key.clone(), TEST_CONTROLLER_SECRET.to_owned()],
        child_environment: Vec::new(),
    })
    .await;

    let mut cleanup_errors = Vec::new();
    if let Err(error) = recorder.stop().await {
        cleanup_errors.push(format!("recording proxy stop failed: {error}"));
    }
    if let Some(error) = recorder.flush_error() {
        cleanup_errors.push(format!("recording flush failed: {error}"));
    }
    if let Err(error) = scan_llm_recording_tree(&quarantine, &[&api_key, TEST_CONTROLLER_SECRET]) {
        cleanup_errors.push(error.to_string());
    }
    match sqlite_contains_secret(database.path(), &api_key).await {
        Ok(true) => cleanup_errors.push("provider credential reached runtime SQLite".to_owned()),
        Ok(false) => {}
        Err(error) => cleanup_errors.push(error.to_string()),
    }
    match sqlite_contains_secret(database.path(), TEST_CONTROLLER_SECRET).await {
        Ok(true) => cleanup_errors.push("controller credential reached runtime SQLite".to_owned()),
        Ok(false) => {}
        Err(error) => cleanup_errors.push(error.to_string()),
    }

    let recording = match recorder.recording() {
        Ok(recording) => Some(recording),
        Err(error) => {
            cleanup_errors.push(format!("recording finalization failed: {error}"));
            None
        }
    };
    if let Some(recording) = recording {
        if let Err(error) = recording.write_atomic(
            &quarantine.join("recording.json"),
            &[&api_key, TEST_CONTROLLER_SECRET],
        ) {
            cleanup_errors.push(format!("quarantine envelope flush failed: {error}"));
        }
        if primary.is_ok() && cleanup_errors.is_empty() {
            if recording.requests.len() != 2 {
                cleanup_errors.push(format!(
                    "successful live run recorded {} exchanges, expected exactly two",
                    recording.requests.len()
                ));
            } else {
                match new_llm_live_recording_run_dir(&recording_id) {
                    Ok(live_directory) => {
                        if let Err(error) = recording.write_atomic(
                            &live_directory.join("recording.json"),
                            &[&api_key, TEST_CONTROLLER_SECRET],
                        ) {
                            cleanup_errors.push(format!("live envelope flush failed: {error}"));
                        }
                    }
                    Err(error) => {
                        cleanup_errors.push(format!("live run allocation failed: {error}"))
                    }
                }
            }
        }
        if primary.is_ok()
            && cleanup_errors.is_empty()
            && std::env::var("ZODE_PROMOTE_LLM_RECORDING").as_deref() == Ok("1")
        {
            let tracked = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(RECORDING_PATH);
            if let Err(error) =
                recording.write_atomic(&tracked, &[&api_key, TEST_CONTROLLER_SECRET])
            {
                cleanup_errors.push(format!("explicit cassette promotion failed: {error}"));
            }
        }
        eprintln!(
            "live provider recording finalized: run_id={} exchanges={}",
            recording_id,
            recording.requests.len()
        );
    }
    if let Err(error) = scan_llm_recording_tree(&quarantine, &[&api_key, TEST_CONTROLLER_SECRET]) {
        cleanup_errors.push(error.to_string());
    }
    merge_live_errors(primary, cleanup_errors, &api_key)
}

fn assert_retained_live_recording_exactly_two_exchanges() -> TestResult<()> {
    let retained =
        LlmHttpRecording::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(RECORDING_PATH))?;
    if retained.requests.len() != 2 {
        return Err(Error::other(format!(
            "retained live recording had {} exchanges, expected exactly two",
            retained.requests.len()
        ))
        .into());
    }
    Ok(())
}

async fn replay_retained_live_recording(recording: LlmHttpRecording) -> TestResult<()> {
    let mut replay = LlmHttpProxy::replay(recording, false).await?;
    let database = TempDatabase::new("live-recording-exact-count")?;
    let config = live_config(database.path())?;
    let primary = run_provider_roundtrip_and_restart(ProviderRoundtripSpec {
        database: database.path().to_owned(),
        config,
        provider_base_url: replay.base_url("/zen/go/v1"),
        provider: PROVIDER.to_owned(),
        model: MODEL.to_owned(),
        profile: PROFILE.to_owned(),
        subject: SUBJECT.to_owned(),
        provider_secret: OFFLINE_REPLAY_SECRET.to_owned(),
        first_prompt: FIRST_PROMPT.to_owned(),
        first_marker: "ZODE_LIVE_OK".to_owned(),
        restart_prompt: RESTART_PROMPT.to_owned(),
        restart_marker: "ZODE_LIVE_RESTART_OK".to_owned(),
        idempotency_prefix: "live-recording-exact-count".to_owned(),
        forbidden: vec![
            OFFLINE_REPLAY_SECRET.to_owned(),
            TEST_CONTROLLER_SECRET.to_owned(),
        ],
        child_environment: Vec::new(),
    })
    .await;
    let mut cleanup_errors = Vec::new();
    if !replay.replay_exhausted() || replay.observed_requests().len() != 2 {
        cleanup_errors
            .push("retained live replay did not consume exactly two exchanges".to_owned());
    }
    if let Err(error) = replay.stop().await {
        cleanup_errors.push(format!("retained live replay proxy stop failed: {error}"));
    }
    match sqlite_contains_secret(database.path(), OFFLINE_REPLAY_SECRET).await {
        Ok(true) => {
            cleanup_errors.push("offline replay credential reached runtime SQLite".to_owned())
        }
        Ok(false) => {}
        Err(error) => cleanup_errors.push(error.to_string()),
    }
    match sqlite_contains_secret(database.path(), TEST_CONTROLLER_SECRET).await {
        Ok(true) => cleanup_errors.push("controller credential reached runtime SQLite".to_owned()),
        Ok(false) => {}
        Err(error) => cleanup_errors.push(error.to_string()),
    }
    merge_live_errors(primary, cleanup_errors, OFFLINE_REPLAY_SECRET)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_live_opencode_provider_records_exactly_two_exchanges() -> TestResult<()> {
    assert_retained_live_recording_exactly_two_exchanges()?;
    let recording =
        LlmHttpRecording::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(RECORDING_PATH))?;
    replay_retained_live_recording(recording).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_live_opencode_provider_roundtrip_and_restart() -> TestResult<()> {
    assert_retained_live_recording_exactly_two_exchanges()?;
    if std::env::var("ZODE_RUN_LIVE_PROVIDER_E2E").as_deref() != Ok("1") {
        eprintln!(
            "live provider E2E not run; set ZODE_RUN_LIVE_PROVIDER_E2E=1 for manual real-network acceptance"
        );
        return Ok(());
    }
    let api_key = std::env::var("OPENCODE_API_KEY").map_err(|_| {
        Error::other(
            "ZODE_RUN_LIVE_PROVIDER_E2E=1 requires OPENCODE_API_KEY in the test environment",
        )
    })?;
    if api_key.is_empty() {
        return Err(Error::other("OPENCODE_API_KEY must not be empty").into());
    }
    timeout(LIVE_PROVIDER_TIMEOUT, run_live_provider(api_key))
        .await
        .map_err(|_| Error::other("live provider E2E exceeded its 120 second deadline"))?
}

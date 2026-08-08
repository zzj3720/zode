mod support;

use std::{
    fs,
    io::{Error, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
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
const LIVE_REPLAY_BENCHMARK_SCHEMA: &str = "zode.llm-http-replay-benchmark.v1";
const LIVE_REPLAY_BENCHMARK_REPETITIONS: usize = 3;

fn live_config(database: &Path, provider_origin: &str) -> TestResult<PathBuf> {
    let path = write_endpoint_config(database, Vec::new(), 1)?;
    let mut config: Value = serde_json::from_slice(&fs::read(&path)?)?;
    config["provider_execution"]["adapter_kinds"] = json!(["openai_compatible"]);
    config["provider_execution"]["allowed_base_url_origins"] = json!([provider_origin]);
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
    let config = live_config(database.path(), &recorder.base_url(""))?;
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
        let mut live_directory = None;
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
                    Ok(directory) => {
                        if let Err(error) = recording.promote_immutable(
                            &directory.join("recording.json"),
                            &[&api_key, TEST_CONTROLLER_SECRET],
                        ) {
                            cleanup_errors.push(format!("live envelope flush failed: {error}"));
                        } else {
                            live_directory = Some(directory);
                        }
                    }
                    Err(error) => {
                        cleanup_errors.push(format!("live run allocation failed: {error}"))
                    }
                }
            }
        }
        if primary.is_ok() && cleanup_errors.is_empty() {
            if let Some(directory) = live_directory.as_deref() {
                let promoted = LlmHttpRecording::load(&directory.join("recording.json"));
                match promoted {
                    Ok(promoted) => {
                        if let Err(error) =
                            benchmark_live_replay(&promoted, &api_key, directory).await
                        {
                            cleanup_errors.push(format!("live replay benchmark failed: {error}"));
                        }
                    }
                    Err(error) => cleanup_errors.push(format!(
                        "promoted live recording reload failed before benchmark: {error}"
                    )),
                }
            } else {
                cleanup_errors.push("live replay benchmark had no recording directory".to_owned());
            }
        }
        if primary.is_ok()
            && cleanup_errors.is_empty()
            && std::env::var("ZODE_PROMOTE_LLM_RECORDING").as_deref() == Ok("1")
        {
            let tracked = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(RECORDING_PATH);
            if let Err(error) =
                recording.promote_immutable(&tracked, &[&api_key, TEST_CONTROLLER_SECRET])
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

async fn replay_recording_roundtrip(
    recording: LlmHttpRecording,
    captured_timing: bool,
    provider_secret: &str,
    idempotency_prefix: &str,
) -> TestResult<Duration> {
    let mut replay = LlmHttpProxy::replay_with_authorization(
        recording,
        captured_timing,
        Some(provider_secret.to_owned()),
    )
    .await?;
    let database = TempDatabase::new("live-recording-exact-count")?;
    let config = live_config(database.path(), &replay.base_url(""))?;
    let started = Instant::now();
    let primary = run_provider_roundtrip_and_restart(ProviderRoundtripSpec {
        database: database.path().to_owned(),
        config,
        provider_base_url: replay.base_url("/zen/go/v1"),
        provider: PROVIDER.to_owned(),
        model: MODEL.to_owned(),
        profile: PROFILE.to_owned(),
        subject: SUBJECT.to_owned(),
        provider_secret: provider_secret.to_owned(),
        first_prompt: FIRST_PROMPT.to_owned(),
        first_marker: "ZODE_LIVE_OK".to_owned(),
        restart_prompt: RESTART_PROMPT.to_owned(),
        restart_marker: "ZODE_LIVE_RESTART_OK".to_owned(),
        idempotency_prefix: idempotency_prefix.to_owned(),
        forbidden: vec![
            provider_secret.to_owned(),
            TEST_CONTROLLER_SECRET.to_owned(),
        ],
        child_environment: Vec::new(),
    })
    .await;
    let elapsed = started.elapsed();
    let mut cleanup_errors = Vec::new();
    if !replay.replay_exhausted() || replay.observed_requests().len() != 2 {
        cleanup_errors.push("live replay did not consume exactly two exchanges".to_owned());
    }
    if let Err(error) = replay.stop().await {
        cleanup_errors.push(format!("live replay proxy stop failed: {error}"));
    }
    match sqlite_contains_secret(database.path(), provider_secret).await {
        Ok(true) => cleanup_errors.push("replay credential reached runtime SQLite".to_owned()),
        Ok(false) => {}
        Err(error) => cleanup_errors.push(error.to_string()),
    }
    match sqlite_contains_secret(database.path(), TEST_CONTROLLER_SECRET).await {
        Ok(true) => cleanup_errors.push("controller credential reached runtime SQLite".to_owned()),
        Ok(false) => {}
        Err(error) => cleanup_errors.push(error.to_string()),
    }
    merge_live_errors(primary, cleanup_errors, provider_secret)?;
    Ok(elapsed)
}

async fn replay_retained_live_recording(recording: LlmHttpRecording) -> TestResult<()> {
    replay_recording_roundtrip(
        recording,
        false,
        OFFLINE_REPLAY_SECRET,
        "live-recording-exact-count",
    )
    .await
    .map(|_| ())
}

fn write_live_replay_benchmark(
    directory: &Path,
    recording: &LlmHttpRecording,
    immediate_ms: &[u128],
    captured_ms: &[u128],
    forbidden: &[&str],
) -> TestResult<()> {
    let path = directory.join("replay-benchmark.v1.json");
    let response_chunks = recording
        .requests
        .iter()
        .map(|exchange| exchange.response.chunks.len())
        .sum::<usize>();
    let value = json!({
        "schema": LIVE_REPLAY_BENCHMARK_SCHEMA,
        "recording_id": recording.recording_id,
        "owner": recording.owner,
        "provider": recording.provider,
        "model": recording.model,
        "measurement": "endpoint_roundtrip_and_restart",
        "exchanges": recording.requests.len(),
        "response_chunks": response_chunks,
        "repetitions": LIVE_REPLAY_BENCHMARK_REPETITIONS,
        "immediate_elapsed_ms": immediate_ms,
        "captured_elapsed_ms": captured_ms,
    });
    let bytes = serde_json::to_vec_pretty(&value)?;
    if forbidden
        .iter()
        .filter(|marker| !marker.is_empty())
        .any(|marker| {
            bytes
                .windows(marker.len())
                .any(|candidate| candidate == marker.as_bytes())
        })
    {
        return Err(Error::other("live replay benchmark contained credential material").into());
    }
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

async fn benchmark_live_replay(
    recording: &LlmHttpRecording,
    provider_secret: &str,
    live_directory: &Path,
) -> TestResult<()> {
    let mut immediate_ms = Vec::with_capacity(LIVE_REPLAY_BENCHMARK_REPETITIONS);
    let mut captured_ms = Vec::with_capacity(LIVE_REPLAY_BENCHMARK_REPETITIONS);
    for repetition in 0..LIVE_REPLAY_BENCHMARK_REPETITIONS {
        immediate_ms.push(
            replay_recording_roundtrip(
                recording.clone(),
                false,
                provider_secret,
                &format!("live-replay-benchmark-immediate-{repetition}"),
            )
            .await?
            .as_millis(),
        );
        captured_ms.push(
            replay_recording_roundtrip(
                recording.clone(),
                true,
                provider_secret,
                &format!("live-replay-benchmark-captured-{repetition}"),
            )
            .await?
            .as_millis(),
        );
    }
    write_live_replay_benchmark(
        live_directory,
        recording,
        &immediate_ms,
        &captured_ms,
        &[provider_secret, TEST_CONTROLLER_SECRET],
    )?;
    eprintln!(
        "live provider replay benchmark: run_id={} exchanges={} immediate_ms={:?} captured_ms={:?}",
        recording.recording_id,
        recording.requests.len(),
        immediate_ms,
        captured_ms,
    );
    Ok(())
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

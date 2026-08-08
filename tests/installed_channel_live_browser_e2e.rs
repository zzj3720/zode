mod support;

use std::{
    env, fs,
    fs::OpenOptions,
    io::{Error, Write},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use support::{
    new_llm_recording_run_dir, scan_llm_recording_tree, LlmHttpProxy, LlmHttpRecording,
    LlmHttpResponseOutcome, TestResult,
};
use tokio::{process::Command, time::timeout};

const E2E: &str = "e2e_installed_channel_live_browser_provider_roundtrip";
const PROVIDER: &str = "zode-installed-live-test";
const MODEL: &str = "deepseek-v4-flash";
const UPSTREAM_ORIGIN: &str = "https://opencode.ai";
const EXPECTED_PROMPT: &str = "Reply with exactly ZODE_E2_LIVE_OK.";
const EXPECTED_REPLY: &str = "ZODE_E2_LIVE_OK";

struct Secret(Vec<u8>);

impl Secret {
    fn text(&self) -> TestResult<&str> {
        Ok(std::str::from_utf8(&self.0)?)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn output_contains_secret(bytes: &[u8], secret: &str) -> bool {
    !secret.is_empty()
        && bytes
            .windows(secret.len())
            .any(|window| window == secret.as_bytes())
}

fn bounded_output(stdout: &[u8], stderr: &[u8]) -> String {
    const LIMIT: usize = 16 * 1024;
    let mut result = Vec::with_capacity(LIMIT);
    for bytes in [stdout, stderr] {
        let remaining = LIMIT.saturating_sub(result.len());
        result.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
        if result.len() == LIMIT {
            break;
        }
    }
    String::from_utf8_lossy(&result).into_owned()
}

fn scrub_provider_environment(command: &mut Command) {
    for variable in [
        "ZODE_RELEASE_LIVE_PROVIDER_BASE_URL",
        "ZODE_RELEASE_LIVE_PROVIDER_API_KEY",
        "ZODE_E2E_LIVE_PROVIDER_API_KEY",
        "OPENCODE_GO_API_KEY",
        "DEEPSEEK_API_KEY",
        "ZODE_RELEASE_PROVIDER_API_KEY",
        "ZODE_RELEASE_TEST_BLOCK_SECOND_ASSISTANT_EVENTS",
        "OPENCODE_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "MISTRAL_API_KEY",
        "TOGETHER_API_KEY",
        "XAI_API_KEY",
        "GROQ_API_KEY",
        "COHERE_API_KEY",
    ] {
        command.env_remove(variable);
    }
}

async fn run_persistent_state_guard(
    repository: &PathBuf,
    channel_root: &PathBuf,
) -> TestResult<()> {
    let lock_path = channel_root.join(".installed-channel-live-smoke.lock");
    let mut lock = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .map_err(|error| {
            Error::other(format!(
                "persistent state guard could not reserve channel: {error}"
            ))
        })?;
    write!(
        lock,
        "{{\"schema\":\"zode.installed-channel-live-smoke-lock.v1\",\"pid\":{},\"run_id\":\"persistent-state-guard\",\"started_at_unix_ms\":{}}}\n",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_millis())
            .unwrap_or_default(),
    )?;
    drop(lock);
    let result = async {
        let local_channel = repository.join("release/local-channel.cjs");
        let guard = repository.join("tests/release_e2e/installed_channel_persistent_state_e2e.cjs");
        let mut start = Command::new("node");
        start
            .current_dir(repository)
            .args([
                local_channel.as_os_str(),
                "start".as_ref(),
                "--channel-root".as_ref(),
                channel_root.as_os_str(),
            ])
            .env("ZODE_RELEASE_LOCAL_CHANNEL_ROOT", channel_root);
        scrub_provider_environment(&mut start);
        let start_output = timeout(Duration::from_secs(60), start.output())
            .await
            .map_err(|_| Error::other("persistent state guard channel start timed out"))??;
        if !start_output.status.success() {
            return Err(Error::other(format!(
                "persistent state guard channel start failed: {}",
                bounded_output(&start_output.stdout, &start_output.stderr)
            ))
            .into());
        }

        let mut guard_command = Command::new("node");
        guard_command
            .current_dir(repository)
            .arg(guard)
            .env("ZODE_RELEASE_LOCAL_CHANNEL_ROOT", channel_root)
            .env("ZODE_RELEASE_TEST_PROVIDER_IDS", PROVIDER);
        if let Ok(url) = env::var("ZODE_RELEASE_CHANNEL_URL") {
            guard_command.env("ZODE_RELEASE_CHANNEL_URL", url);
        }
        scrub_provider_environment(&mut guard_command);
        let guard_output = timeout(Duration::from_secs(90), guard_command.output())
            .await
            .map_err(|_| Error::other("persistent state guard timed out"))??;

        let mut stop = Command::new("node");
        stop.current_dir(repository)
            .args([
                local_channel.as_os_str(),
                "stop".as_ref(),
                "--channel-root".as_ref(),
                channel_root.as_os_str(),
            ])
            .env("ZODE_RELEASE_LOCAL_CHANNEL_ROOT", channel_root);
        scrub_provider_environment(&mut stop);
        let stop_output = timeout(Duration::from_secs(60), stop.output())
            .await
            .map_err(|_| Error::other("persistent state guard channel stop timed out"))??;
        if !stop_output.status.success() {
            return Err(Error::other(format!(
                "persistent state guard channel stop failed: {}",
                bounded_output(&stop_output.stdout, &stop_output.stderr)
            ))
            .into());
        }
        if !guard_output.status.success() {
            return Err(Error::other(format!(
                "persistent state guard failed: {}",
                bounded_output(&guard_output.stdout, &guard_output.stderr)
            ))
            .into());
        }
        Ok(())
    }
    .await;
    let _ = fs::remove_file(&lock_path);
    result
}

fn decode_hex(value: &str) -> TestResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::other("recorded provider chunk had invalid hex").into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or_else(|| Error::other("invalid chunk hex"))?;
            let low = hex_nibble(pair[1]).ok_or_else(|| Error::other("invalid chunk hex"))?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn recorded_assistant_text(exchange: &support::LlmHttpRecordingExchange) -> TestResult<String> {
    let mut bytes = Vec::new();
    for chunk in &exchange.response.chunks {
        bytes.extend(decode_hex(&chunk.bytes_hex)?);
    }
    let stream = std::str::from_utf8(&bytes)?;
    let mut text = String::new();
    for line in stream.lines() {
        let Some(data) = line.strip_prefix("data:").map(str::trim) else {
            continue;
        };
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let chunk: Value = serde_json::from_str(data)?;
        if let Some(content) = chunk["choices"][0]["delta"]["content"].as_str() {
            text.push_str(content);
        }
    }
    Ok(text)
}

fn recorded_reply_matches(value: &str) -> bool {
    let value = value.trim();
    value == EXPECTED_REPLY
        || [".", "!", "?"]
            .iter()
            .any(|suffix| value.strip_suffix(suffix) == Some(EXPECTED_REPLY))
}

fn assert_recording(
    recording: &LlmHttpRecording,
    secret: &str,
    expected_exchanges: usize,
) -> TestResult<()> {
    if recording.requests.len() != expected_exchanges {
        return Err(Error::other(format!(
            "installed live browser recorded {} provider exchanges, expected {}",
            recording.requests.len(),
            expected_exchanges,
        ))
        .into());
    }
    for exchange in &recording.requests {
        let request: Value = serde_json::from_str(
            exchange
                .request
                .canonical_json
                .as_deref()
                .ok_or_else(|| Error::other("live provider request omitted canonical JSON"))?,
        )?;
        let prompt_present = request["messages"].as_array().is_some_and(|messages| {
            messages
                .iter()
                .any(|message| message["role"] == "user" && message["content"] == EXPECTED_PROMPT)
        });
        let response_text = recorded_assistant_text(exchange)?;
        if exchange.request.method != "POST"
            || exchange.request.path != "/zen/go/v1/chat/completions"
            || request["model"] != MODEL
            || !prompt_present
            || exchange.response.status != Some(200)
            || !recorded_reply_matches(&response_text)
            || exchange.response.chunks.len() < 2
            || !matches!(
                &exchange.response.outcome,
                LlmHttpResponseOutcome::Complete { done_seen: true }
            )
        {
            return Err(Error::other(
                "installed live browser recording did not prove model, prompt, stream chunks, and terminal reply",
            )
            .into());
        }
    }
    let serialized = serde_json::to_vec(recording)?;
    if recording.secret_slots.is_empty()
        || serialized
            .windows(secret.len())
            .any(|window| window == secret.as_bytes())
    {
        return Err(
            Error::other("installed live browser recording retained the provider secret").into(),
        );
    }
    Ok(())
}

async fn run_live(artifact: PathBuf, secret: Secret, persistent: bool) -> TestResult<()> {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let quarantine = new_llm_recording_run_dir()?;
    let recording_id = quarantine
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| Error::other("live recording id was invalid"))?
        .to_owned();
    let mut recorder = LlmHttpProxy::record_with_attempt_plan_and_authorization(
        UPSTREAM_ORIGIN,
        PROVIDER,
        MODEL,
        &quarantine,
        support::LlmHttpRecordingMetadata {
            recording_id: recording_id.clone(),
            purpose: "installed_channel_live_browser_provider_roundtrip".to_owned(),
            owner: E2E.to_owned(),
            boundary: "endpoint_aimux_provider_http".to_owned(),
            secret_slots: vec!["SLOT_PROVIDER_AUTHORIZATION_HEADER".to_owned()],
        },
        None,
        true,
    )
    .await?;

    let recorder_base_url = recorder.base_url("/zen/go/v1");
    let script = repository.join("tests/release_e2e/installed_channel_browser_smoke_e2e.cjs");
    let (channel_root, cleanup_channel_root) = if persistent {
        if let Ok(existing) = env::var("ZODE_RELEASE_LOCAL_CHANNEL_ROOT") {
            let root = PathBuf::from(existing);
            fs::create_dir_all(&root)?;
            (Some(root), false)
        } else {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or_default();
            let root = env::temp_dir().join(format!(
                "zode-local-channel-live-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&root)?;
            (Some(root), true)
        }
    } else {
        (None, false)
    };
    let mut command = Command::new("node");
    command
        .current_dir(&repository)
        .arg(script)
        .env("ZODE_RELEASE_CHANNEL_ARTIFACT", &artifact)
        .kill_on_drop(true);
    if let Some(root) = &channel_root {
        command.env("ZODE_RELEASE_LOCAL_CHANNEL_ROOT", root);
    }
    for variable in [
        "OPENCODE_GO_API_KEY",
        "DEEPSEEK_API_KEY",
        "OPENCODE_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "MISTRAL_API_KEY",
        "TOGETHER_API_KEY",
        "XAI_API_KEY",
        "GROQ_API_KEY",
        "COHERE_API_KEY",
    ] {
        command.env_remove(variable);
    }
    command
        .env("ZODE_RELEASE_LIVE_PROVIDER_BASE_URL", &recorder_base_url)
        .env("ZODE_RELEASE_LIVE_PROVIDER_API_KEY", secret.text()?);
    let mut cleanup_errors = Vec::new();
    let browser_failure = match timeout(Duration::from_secs(300), command.output()).await {
        Err(_) => Some("installed live browser E2E exceeded its 300 second deadline".to_owned()),
        Ok(Err(error)) => Some(format!(
            "installed live browser smoke could not start: {error}"
        )),
        Ok(Ok(browser_result)) => {
            if output_contains_secret(&browser_result.stdout, secret.text()?)
                || output_contains_secret(&browser_result.stderr, secret.text()?)
            {
                Some("installed browser child output exposed provider credential".to_owned())
            } else if !browser_result.status.success() {
                Some(format!(
                    "installed live browser smoke failed: {}",
                    bounded_output(&browser_result.stdout, &browser_result.stderr)
                ))
            } else {
                None
            }
        }
    };
    if let Some(error) = browser_failure {
        cleanup_errors.push(error);
    }
    if persistent {
        if let Some(root) = channel_root.as_ref() {
            if let Err(error) = run_persistent_state_guard(&repository, root).await {
                cleanup_errors.push(error.to_string());
            }
        }
    }
    if let Err(error) = recorder.stop().await {
        cleanup_errors.push(format!("provider recorder stop failed: {error}"));
    }
    if let Some(error) = recorder.flush_error() {
        cleanup_errors.push(format!("provider recorder flush failed: {error}"));
    }
    if let Err(error) = scan_llm_recording_tree(&quarantine, &[secret.text()?]) {
        cleanup_errors.push(error.to_string());
    }
    match recorder.recording() {
        Ok(recording) => {
            let expected_exchanges = if persistent { 2 } else { 1 };
            if let Err(error) = assert_recording(&recording, secret.text()?, expected_exchanges) {
                cleanup_errors.push(error.to_string());
            }
            if let Err(error) =
                recording.write_atomic(&quarantine.join("recording.json"), &[secret.text()?])
            {
                cleanup_errors.push(format!("provider recording durable flush failed: {error}"));
            }
        }
        Err(error) => {
            cleanup_errors.push(format!("provider recording finalization failed: {error}"))
        }
    }
    if let Err(error) = scan_llm_recording_tree(&quarantine, &[secret.text()?]) {
        cleanup_errors.push(error.to_string());
    }
    let result = if cleanup_errors.is_empty() {
        println!(
            "installed live browser PASS recording_id={} artifact_revision={} provider_exchanges={}",
            recording_id,
            artifact
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("unknown"),
            if persistent { 2 } else { 1 },
        );
        Ok(())
    } else {
        Err(Error::other(format!(
            "installed live browser evidence gate failed: {}",
            cleanup_errors.join("; ")
        ))
        .into())
    };

    if cleanup_channel_root {
        if let Some(root) = channel_root {
            let _ = fs::remove_dir_all(root);
        }
    }
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_installed_channel_live_browser_provider_roundtrip() -> TestResult<()> {
    if env::var("ZODE_RUN_INSTALLED_CHANNEL_LIVE_BROWSER_E2E").as_deref() != Ok("1") {
        eprintln!(
            "installed live browser E2E not run; set ZODE_RUN_INSTALLED_CHANNEL_LIVE_BROWSER_E2E=1"
        );
        return Ok(());
    }
    let artifact = PathBuf::from(env::var("ZODE_RELEASE_CHANNEL_ARTIFACT").map_err(|_| {
        Error::other("installed live browser E2E requires ZODE_RELEASE_CHANNEL_ARTIFACT")
    })?);
    if !artifact.is_dir() {
        return Err(Error::other("installed live browser artifact directory is missing").into());
    }
    let secret = Secret(
        env::var("OPENCODE_GO_API_KEY")
            .map_err(|_| Error::other("installed live browser E2E requires OPENCODE_GO_API_KEY"))?
            .into_bytes(),
    );
    if secret.0.is_empty() {
        return Err(Error::other("OPENCODE_GO_API_KEY must not be empty").into());
    }
    let persistent =
        env::var("ZODE_RUN_INSTALLED_CHANNEL_PERSISTENT_LIVE_BROWSER_E2E").as_deref() == Ok("1");
    timeout(
        Duration::from_secs(360),
        run_live(artifact, secret, persistent),
    )
    .await
    .map_err(|_| Error::other("installed live browser E2E exceeded its 360 second deadline"))?
}

mod support;

use std::{env, io::Error, path::PathBuf, time::Duration};

use serde_json::Value;
use support::{
    new_llm_live_recording_run_dir, new_llm_recording_run_dir, scan_llm_recording_tree,
    LlmHttpProxy, LlmHttpRecording, LlmHttpRecordingMetadata, LlmHttpResponseOutcome, TestResult,
};
use tokio::{process::Command, time::timeout};

const E2E: &str = "e2e_live_management_browser_all_in_one_roundtrip";
const PROVIDER: &str = "opencode-go";
const PROVIDER_UPSTREAM_ORIGIN: &str = "https://opencode.ai";
const MODEL: &str = "deepseek-v4-flash";
const LIVE_TIMEOUT: Duration = Duration::from_secs(180);

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

async fn run_live_browser(secret: Secret) -> TestResult<()> {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let server_binary = repository.join("server/target/debug/zode-server");
    if !server_binary.is_file() {
        return Err(Error::other(
            "live browser E2E requires a built server/target/debug/zode-server",
        )
        .into());
    }

    let quarantine = new_llm_recording_run_dir()?;
    let recording_id = quarantine
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::other("live browser recording id was invalid"))?
        .to_owned();
    let mut recorder = LlmHttpProxy::record(
        PROVIDER_UPSTREAM_ORIGIN,
        PROVIDER,
        MODEL,
        &quarantine,
        LlmHttpRecordingMetadata {
            recording_id: recording_id.clone(),
            purpose: "management_browser_all_in_one_roundtrip".to_owned(),
            owner: E2E.to_owned(),
            boundary: "endpoint_aimux_provider_http".to_owned(),
            secret_slots: vec!["SLOT_PROVIDER_AUTHORIZATION_HEADER".to_owned()],
        },
    )
    .await?;

    let mut command = Command::new("vp");
    command
        .current_dir(repository.join("web/e2e"))
        .args([
            "run",
            "test",
            "--project=chromium",
            "--grep=e2e_all_in_one_first_run_uses_normal_server_api_and_local_endpoint",
        ])
        .env(
            "ZODE_E2E_LIVE_PROVIDER_BASE_URL",
            recorder.base_url("/zen/go/v1"),
        )
        .env("ZODE_E2E_LIVE_PROVIDER_API_KEY", secret.text()?)
        .env("ZODE_ENDPOINT_BIN", env!("CARGO_BIN_EXE_zode"))
        .env("ZODE_SERVER_BIN", &server_binary);
    for variable in [
        "OPENCODE_GO_API_KEY",
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

    let browser_result = match command.output().await {
        Ok(output) => {
            let output_is_safe = assert_output_secret_free(&output.stdout, secret.text()?)
                .and_then(|()| assert_output_secret_free(&output.stderr, secret.text()?));
            if let Err(error) = output_is_safe {
                Err(error)
            } else if output.status.success() {
                Ok(())
            } else {
                Err(Error::other(format!(
                    "live browser E2E failed (status={}): {}",
                    output.status,
                    bounded_output(&output.stdout, &output.stderr)
                ))
                .into())
            }
        }
        Err(error) => Err(error.into()),
    };

    let mut cleanup_errors = Vec::new();
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
            if let Err(error) = assert_recording(&recording) {
                cleanup_errors.push(error.to_string());
            }
            if let Err(error) =
                recording.write_atomic(&quarantine.join("recording.json"), &[secret.text()?])
            {
                cleanup_errors.push(format!("quarantine envelope flush failed: {error}"));
            }
            if browser_result.is_ok() && cleanup_errors.is_empty() {
                match new_llm_live_recording_run_dir(&recording_id) {
                    Ok(live_directory) => {
                        if let Err(error) = recording.promote_immutable(
                            &live_directory.join("recording.json"),
                            &[secret.text()?],
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
        Err(error) => cleanup_errors.push(format!("recording finalization failed: {error}")),
    }
    if let Err(error) = scan_llm_recording_tree(&quarantine, &[secret.text()?]) {
        cleanup_errors.push(error.to_string());
    }

    eprintln!(
        "live management browser recording finalized: quarantine={}",
        quarantine.display()
    );
    merge_results(browser_result, cleanup_errors)
}

fn assert_recording(recording: &LlmHttpRecording) -> TestResult<()> {
    if recording.requests.len() != 1 {
        return Err(Error::other(format!(
            "live browser recorded {} provider exchanges, expected exactly one",
            recording.requests.len()
        ))
        .into());
    }
    let exchange = &recording.requests[0];
    let request: Value = serde_json::from_str(
        exchange
            .request
            .canonical_json
            .as_deref()
            .ok_or_else(|| Error::other("live provider request omitted canonical JSON"))?,
    )?;
    let prompt_observed = request["messages"].as_array().is_some_and(|messages| {
        messages.iter().any(|message| {
            message["role"] == "user" && message["content"] == "Reply with exactly ZODE_E2_LIVE_OK."
        })
    });
    let response_text = recorded_assistant_text(exchange)?;
    let terminal_is_recordable = matches!(
        &exchange.response.outcome,
        LlmHttpResponseOutcome::Complete { done_seen: true }
            | LlmHttpResponseOutcome::ClientDisconnect
    );
    if exchange.request.method != "POST"
        || exchange.request.path != "/zen/go/v1/chat/completions"
        || request["model"] != MODEL
        || !prompt_observed
        || exchange.response.status != Some(200)
        || response_text != "ZODE_E2_LIVE_OK"
        || !terminal_is_recordable
    {
        return Err(Error::other(
            "live browser provider recording did not bind the expected model, prompt, and complete stream",
        )
        .into());
    }
    Ok(())
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

fn decode_hex(value: &str) -> TestResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::other("recorded provider chunk had invalid hex").into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])
                .ok_or_else(|| Error::other("recorded provider chunk had invalid hex"))?;
            let low = hex_nibble(pair[1])
                .ok_or_else(|| Error::other("recorded provider chunk had invalid hex"))?;
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

fn merge_results(primary: TestResult<()>, cleanup_errors: Vec<String>) -> TestResult<()> {
    match (primary, cleanup_errors.is_empty()) {
        (Ok(()), true) => Ok(()),
        (Ok(()), false) => Err(Error::other(format!(
            "live browser evidence gate failed: {}",
            cleanup_errors.join("; ")
        ))
        .into()),
        (Err(error), true) => Err(error),
        (Err(error), false) => Err(Error::other(format!(
            "{error}; evidence cleanup failed: {}",
            cleanup_errors.join("; ")
        ))
        .into()),
    }
}

fn assert_output_secret_free(bytes: &[u8], secret: &str) -> TestResult<()> {
    if contains(bytes, secret.as_bytes()) {
        return Err(Error::other("live browser child output exposed provider credential").into());
    }
    Ok(())
}

fn contains(bytes: &[u8], marker: &[u8]) -> bool {
    !marker.is_empty() && bytes.windows(marker.len()).any(|window| window == marker)
}

fn bounded_output(stdout: &[u8], stderr: &[u8]) -> String {
    const MAX_OUTPUT: usize = 16 * 1024;
    let mut output = Vec::with_capacity(stdout.len().saturating_add(stderr.len()).min(MAX_OUTPUT));
    for bytes in [stdout, stderr] {
        let remaining = MAX_OUTPUT.saturating_sub(output.len());
        output.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
        if output.len() == MAX_OUTPUT {
            break;
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_live_management_browser_all_in_one_roundtrip() -> TestResult<()> {
    if env::var("ZODE_RUN_LIVE_MANAGEMENT_BROWSER_E2E").as_deref() != Ok("1") {
        eprintln!(
            "live management browser E2E not run; set ZODE_RUN_LIVE_MANAGEMENT_BROWSER_E2E=1"
        );
        return Ok(());
    }
    let secret = Secret(
        env::var("OPENCODE_GO_API_KEY")
            .map_err(|_| Error::other("live management browser E2E requires OPENCODE_GO_API_KEY"))?
            .into_bytes(),
    );
    if secret.0.is_empty() {
        return Err(Error::other("OPENCODE_GO_API_KEY must not be empty").into());
    }
    timeout(LIVE_TIMEOUT, run_live_browser(secret))
        .await
        .map_err(|_| Error::other("live management browser E2E exceeded its 180 second deadline"))?
}

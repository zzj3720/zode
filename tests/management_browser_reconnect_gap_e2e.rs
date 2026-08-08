//! Real-browser recovery replay for the approved reconnect/child-reap evidence gap.

#[cfg(unix)]
#[path = "support/process_capture.rs"]
mod process_capture;

#[cfg(unix)]
mod unix_management_browser_reconnect_gap {
    use std::{
        env, fs,
        io::{Error, ErrorKind},
        os::unix::{fs::PermissionsExt, process::ExitStatusExt},
        path::PathBuf,
        process::{Command, Output, Stdio},
    };

    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    use crate::process_capture::{
        ProcessCaptureResult, ProcessCaptureSet, ProcessIncidentReplay, ProcessObservation,
        ProcessReplayProof, ProcessStopObservation,
    };

    const E2E: &str = "e2e_management_browser_reconnect_later_gap_replay";
    const BROWSER_E2E: &str = "e2e_all_in_one_first_run_uses_normal_server_api_and_local_endpoint";
    const CAPTURE_ENV: &str = "ZODE_CAPTURE_MANAGEMENT_BROWSER_LATER_GAP";
    const RECOVER_ENV: &str = "ZODE_RECOVER_MANAGEMENT_BROWSER_LATER_GAP";
    const FULL_SUITE_CAPTURE_ENV: &str = "ZODE_CAPTURE_MANAGEMENT_BROWSER_FULL_SUITE_PRESEED_GAP";
    const RELATION: &str = "later_test_reproduction_of_gap";
    const CLASSIFICATION: &str = "UI_SSE_RECONNECT_STATUS_STUCK__later_test_reproduction_of_gap";
    const FIRST_OBSERVED: &str = "relation=later_test_reproduction_of_gap; browser_connection=Reconnecting; expected=Live; durable_assistant_reply_count=1; child_reap=observed_endpoint_reaped";
    const FULL_SUITE_CAPTURE_CLASSIFICATION: &str =
        "MANAGEMENT_BROWSER_FULL_SUITE_OBSERVATION__later_test_reproduction_of_gap";
    const FULL_SUITE_CAPTURE_OBSERVED: &str = "relation=later_test_reproduction_of_gap; same complete root suite and real browser/process entry; process observation flushed before success or marker classification";

    struct BrowserObservation {
        pid: u32,
        output: Output,
    }

    impl BrowserObservation {
        fn combined(&self) -> Vec<u8> {
            let mut combined = Vec::with_capacity(
                self.output
                    .stdout
                    .len()
                    .saturating_add(self.output.stderr.len()),
            );
            combined.extend_from_slice(&self.output.stdout);
            combined.extend_from_slice(&self.output.stderr);
            combined
        }

        fn is_red_reproduction(&self, require_http_capture: bool) -> bool {
            let combined = self.combined();
            !self.output.status.success()
                && (contains(&combined, b"UI_SSE_RECONNECT_STATUS_STUCK")
                    || contains(
                        &combined,
                        b"ZODE_E2E_UI_RECONNECT_OBSERVATION classification=UI_SSE_RECONNECT_STATUS_STUCK",
                    ))
                && (contains(
                    &combined,
                    b"ZODE_E2E_CHILD_REAP_OBSERVATION server_forced_sigkill=true endpoint_reaped=true",
                ) || contains(
                    &combined,
                    b"ZODE_E2E_CHILD_REAP_OBSERVATION server_forced_sigkill=false endpoint_reaped=true",
                ) || contains(
                    &combined,
                    b"Server exited without reaping its supervised Endpoint child",
                ))
                && (!require_http_capture
                    || contains(&combined, b"ZODE_E2E_LATER_GAP_CAPTURE "))
        }

        fn process_observation(&self) -> ProcessObservation {
            ProcessObservation {
                name: "real-playwright-management-browser-entry".to_owned(),
                stdout: self.output.stdout.clone(),
                stderr: self.output.stderr.clone(),
                exit_code: self.output.status.code(),
                signal: self
                    .output
                    .status
                    .signal()
                    .map(|signal| format!("signal-{signal}")),
                termination: "natural_exit_after_real_browser_and_process_cleanup".to_owned(),
                stop: Some(ProcessStopObservation {
                    observed_pids: vec![self.pid],
                    reaped_pids: vec![self.pid],
                    leaked_pids: Vec::new(),
                    timed_out: false,
                    flush_status: "ok".to_owned(),
                    proof: true,
                }),
            }
        }
    }

    fn repository() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn quarantine() -> PathBuf {
        repository()
            .join("target/test-recordings/quarantine")
            .join("management-browser-process-later")
    }

    fn cassette() -> PathBuf {
        repository()
            .join("web/e2e/fixtures/incidents")
            .join("management-browser-reconnect-later-gap-complete.v1.json")
    }

    fn replay_config() -> ProcessCaptureResult<Vec<u8>> {
        Ok(serde_json::to_vec(&json!({
            "schema": "zode.management-browser-gap-replay.v1",
            "e2e": E2E,
            "browser_e2e": BROWSER_E2E,
            "relation": RELATION,
            "entry": "vp run test --project=chromium --grep=<browser_e2e>",
            "expected_after_fix": {
                "connection": "Live",
                "durable_assistant_reply_count": 1,
                "server_reaps_built_in_endpoint": true
            }
        }))?)
    }

    fn assert_config(config: &[u8]) -> ProcessCaptureResult<()> {
        let value: Value = serde_json::from_slice(config)?;
        if value["schema"] != "zode.management-browser-gap-replay.v1"
            || value["e2e"] != E2E
            || value["browser_e2e"] != BROWSER_E2E
            || value["relation"] != RELATION
            || value["expected_after_fix"]["connection"] != "Live"
            || value["expected_after_fix"]["durable_assistant_reply_count"] != 1
            || value["expected_after_fix"]["server_reaps_built_in_endpoint"] != true
        {
            return Err(Error::other("management browser replay config is invalid").into());
        }
        Ok(())
    }

    fn observe_browser(
        config: &[u8],
        capture_http: bool,
    ) -> ProcessCaptureResult<BrowserObservation> {
        assert_config(config)?;
        let repository = repository();
        let server_binary = repository.join("server/target/debug/zode-server");
        if !server_binary.is_file() {
            return Err(Error::other(
                "management browser gap E2E requires server/target/debug/zode-server",
            )
            .into());
        }
        let mut command = Command::new("vp");
        command
            .current_dir(repository.join("web/e2e"))
            .args([
                "run",
                "test",
                "--project=chromium",
                &format!("--grep={BROWSER_E2E}"),
            ])
            .env("ZODE_ENDPOINT_BIN", env!("CARGO_BIN_EXE_zode"))
            .env("ZODE_SERVER_BIN", server_binary)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if capture_http {
            command.env("ZODE_UI_CAPTURE_LATER_RECONNECT_GAP", "1");
        } else {
            command.env_remove("ZODE_UI_CAPTURE_LATER_RECONNECT_GAP");
        }
        for variable in [
            "ZODE_E2E_LIVE_PROVIDER_BASE_URL",
            "ZODE_E2E_LIVE_PROVIDER_API_KEY",
            "OPENCODE_GO_API_KEY",
            "OPENCODE_API_KEY",
            "OPENAI_API_KEY",
            "OPENROUTER_API_KEY",
            "ANTHROPIC_API_KEY",
        ] {
            command.env_remove(variable);
        }
        let child = command.spawn()?;
        let pid = child.id();
        let output = child.wait_with_output()?;
        Ok(BrowserObservation { pid, output })
    }

    fn replay_proof(replay: &ProcessIncidentReplay) -> ProcessReplayProof {
        let fingerprint = format!(
            "{:x}",
            Sha256::digest(
                format!(
                    "{}\0{}\0red-reproduced",
                    replay.classification(),
                    replay.first_observed()
                )
                .as_bytes()
            )
        );
        ProcessReplayProof {
            matched: true,
            fingerprint,
            source_digest: replay.source_digest().to_owned(),
        }
    }

    fn assert_later_red_identity(replay: &ProcessIncidentReplay) -> ProcessCaptureResult<()> {
        if replay.config_label() != "management-browser-reconnect-entry"
            || replay.classification() != CLASSIFICATION
            || replay.first_observed() != FIRST_OBSERVED
            || replay.config_bytes() != replay_config()?
        {
            return Err(
                Error::other("later reproduction process cassette changed identity").into(),
            );
        }
        Ok(())
    }

    fn capture_same_entry_replay(
        replay: &ProcessIncidentReplay,
    ) -> ProcessCaptureResult<(bool, PathBuf)> {
        let mut capture = ProcessCaptureSet::new(quarantine(), E2E, &[])?;
        capture.capture_config("management-browser-reconnect-entry", replay.config_bytes())?;
        let observation = observe_browser(replay.config_bytes(), false)?;
        let is_expected_red = observation.is_red_reproduction(false);
        let (classification, first_observed) = if is_expected_red {
            (
                "UI_SSE_RECONNECT_STATUS_STUCK_REPLAYED__later_test_reproduction_of_gap",
                "relation=later_test_reproduction_of_gap; same public browser/process entry replayed Reconnecting with one durable assistant reply and observed child reap",
            )
        } else {
            (
                "HARNESS_SAME_ENTRY_REPLAY_CLASSIFICATION_MISMATCH__later_test_reproduction_of_gap",
                "relation=later_test_reproduction_of_gap; replay process observation retained before UI/child marker classification; expected typed red was not reproduced",
            )
        };
        capture.capture_process(observation.process_observation())?;
        let raw = capture.flush(classification, first_observed)?;
        Ok((is_expected_red, raw))
    }

    fn capture_full_suite_observation_before_classification(
        replay: &ProcessIncidentReplay,
    ) -> ProcessCaptureResult<(BrowserObservation, PathBuf)> {
        let mut capture = ProcessCaptureSet::new(quarantine(), E2E, &[])?;
        capture.capture_config("management-browser-full-suite-entry", replay.config_bytes())?;
        let observed = observe_browser(replay.config_bytes(), true)?;
        capture.capture_process(observed.process_observation())?;
        let raw = capture.flush(
            FULL_SUITE_CAPTURE_CLASSIFICATION,
            FULL_SUITE_CAPTURE_OBSERVED,
        )?;

        let metadata = fs::symlink_metadata(&raw)?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(Error::other(format!(
                "full-suite later reproduction was not retained as a regular 0600 raw: {}",
                raw.display()
            ))
            .into());
        }
        let recovered = ProcessIncidentReplay::load(&raw, E2E, &[])?;
        if recovered.config_label() != "management-browser-full-suite-entry"
            || recovered.config_bytes() != replay.config_bytes()
            || recovered.classification() != FULL_SUITE_CAPTURE_CLASSIFICATION
            || recovered.first_observed() != FULL_SUITE_CAPTURE_OBSERVED
        {
            return Err(Error::other(format!(
                "full-suite later reproduction raw was not recoverable with its frozen identity: {}",
                raw.display()
            ))
            .into());
        }
        eprintln!(
            "ZODE_E2E_FULL_SUITE_LATER_PROCESS_CAPTURE relation={RELATION} raw={}",
            raw.display()
        );
        Ok((observed, raw))
    }

    fn recover_and_promote(raw: PathBuf) -> ProcessCaptureResult<()> {
        let destination = cassette();
        if destination.exists() {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "management browser later-gap cassette is immutable",
            )
            .into());
        }
        let replay = ProcessIncidentReplay::load(&raw, E2E, &[])?;
        assert_later_red_identity(&replay)?;
        let (reproduced, replay_raw) = capture_same_entry_replay(&replay)?;
        if !reproduced {
            return Err(Error::other(format!(
                "same-entry replay observation was retained before classification but did not reproduce the typed red; process capture={}",
                replay_raw.display()
            ))
            .into());
        }
        replay.promote_immutable(&destination, &replay_proof(&replay), &[])?;
        Err(Error::other(format!(
            "public browser E2E remains red; relation={RELATION}; source={}; replay={}; cassette={}",
            raw.display(),
            replay_raw.display(),
            destination.display()
        ))
        .into())
    }

    fn capture_and_promote() -> ProcessCaptureResult<()> {
        let destination = cassette();
        if destination.exists() {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "management browser later-gap cassette is immutable",
            )
            .into());
        }
        let config = replay_config()?;
        let mut capture = ProcessCaptureSet::new(quarantine(), E2E, &[])?;
        capture.capture_config("management-browser-reconnect-entry", &config)?;
        let first = observe_browser(&config, true)?;
        let first_is_expected_red = first.is_red_reproduction(true);
        let (classification, first_observed) = if first_is_expected_red {
            (CLASSIFICATION, FIRST_OBSERVED)
        } else {
            (
                "HARNESS_LATER_REPRODUCTION_CLASSIFICATION_MISMATCH__later_test_reproduction_of_gap",
                "relation=later_test_reproduction_of_gap; process observation retained before UI/child marker classification; expected red markers were incomplete",
            )
        };
        capture.capture_process(first.process_observation())?;
        let raw = capture.flush(classification, first_observed)?;
        if !first_is_expected_red {
            return Err(Error::other(format!(
                "later reproduction did not retain both the Reconnecting UI red and child-reap observation; process capture={}",
                raw.display()
            ))
            .into());
        }

        let replay = ProcessIncidentReplay::load(&raw, E2E, &[])?;
        assert_later_red_identity(&replay)?;
        let (second_is_expected_red, second_raw) = capture_same_entry_replay(&replay)?;
        if !second_is_expected_red {
            return Err(Error::other(
                format!(
                    "same-entry replay did not reproduce both public browser and child-reap failures; process capture={}",
                    second_raw.display()
                ),
            )
            .into());
        }
        replay.promote_immutable(&destination, &replay_proof(&replay), &[])?;
        Err(Error::other(format!(
            "public browser E2E remains red; relation={RELATION}; raw={}; replay={}; cassette={}",
            raw.display(),
            second_raw.display(),
            destination.display()
        ))
        .into())
    }

    fn replay_after_fix() -> ProcessCaptureResult<()> {
        let destination = cassette();
        let replay = ProcessIncidentReplay::load(&destination, E2E, &[])?;
        if replay.classification() != CLASSIFICATION
            || replay.first_observed() != FIRST_OBSERVED
            || !replay.first_observed().contains(RELATION)
        {
            return Err(
                Error::other("tracked later-gap cassette lost its relation metadata").into(),
            );
        }
        let (observed, later_capture) = if env::var_os(FULL_SUITE_CAPTURE_ENV).is_some() {
            let (observed, raw) = capture_full_suite_observation_before_classification(&replay)?;
            (observed, Some(raw))
        } else {
            (observe_browser(replay.config_bytes(), false)?, None)
        };
        if !observed.output.status.success() {
            let combined = observed.combined();
            let classification = if contains(
                &combined,
                b"SHALLOW_NON_EVIDENCE barrier=server_all_in_one_bootstrap",
            ) {
                "ALL_IN_ONE_PRESEED_EXIT__later_test_reproduction_of_gap"
            } else if observed.is_red_reproduction(false) {
                "UI_SSE_RECONNECT_STATUS_STUCK__later_test_reproduction_of_gap"
            } else {
                "MANAGEMENT_BROWSER_REPLAY_EXIT__later_test_reproduction_of_gap"
            };
            return Err(Error::other(format!(
                "same later cassette and real browser entry remained red; classification={classification}; process_capture={}: {}",
                later_capture
                    .as_deref()
                    .map_or_else(|| "not_requested".to_owned(), |path| path.display().to_string()),
                bounded_output(&observed.output)
            ))
            .into());
        }
        let combined = observed.combined();
        if contains(&combined, b"UI_SSE_RECONNECT_STATUS_STUCK")
            || contains(
                &combined,
                b"ZODE_E2E_CHILD_REAP_OBSERVATION server_forced_sigkill=true",
            )
            || contains(
                &combined,
                b"Server exited without reaping its supervised Endpoint child",
            )
        {
            return Err(Error::other(
                "green replay retained a reconnect or child-reap failure marker",
            )
            .into());
        }
        Ok(())
    }

    fn bounded_output(output: &Output) -> String {
        const MAX: usize = 16 * 1024;
        let mut bytes = Vec::with_capacity(MAX);
        for source in [&output.stdout, &output.stderr] {
            let remaining = MAX.saturating_sub(bytes.len());
            bytes.extend_from_slice(&source[..source.len().min(remaining)]);
            if bytes.len() == MAX {
                break;
            }
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn contains(bytes: &[u8], marker: &[u8]) -> bool {
        !marker.is_empty() && bytes.windows(marker.len()).any(|window| window == marker)
    }

    #[test]
    fn e2e_management_browser_reconnect_later_gap_replay() -> ProcessCaptureResult<()> {
        if let Some(raw) = env::var_os(RECOVER_ENV) {
            recover_and_promote(PathBuf::from(raw))
        } else if env::var_os(CAPTURE_ENV).is_some() {
            capture_and_promote()
        } else if cassette().exists() {
            replay_after_fix()
        } else {
            Err(Error::other(
                "tracked later-gap cassette is missing; run the explicitly approved capture entry before production repair",
            )
            .into())
        }
    }
}

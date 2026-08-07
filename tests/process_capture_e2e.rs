//! Black-box E2E coverage for the shared process-incident capture/replay seam.

#[cfg(unix)]
#[path = "support/process_capture.rs"]
mod process_capture;

#[cfg(unix)]
mod unix_process_capture {

    use std::{
        env,
        fs::{self, File},
        io::{Error, Write},
        os::unix::{
            fs::{OpenOptionsExt, PermissionsExt},
            process::ExitStatusExt,
        },
        path::PathBuf,
        process::Command,
    };

    use serde_json::Value;
    use sha2::{Digest, Sha256};

    use crate::process_capture::{
        ProcessCaptureResult, ProcessCaptureSet, ProcessIncidentReplay, ProcessObservation,
        ProcessReplayProof, ProcessStopObservation,
    };

    const NULL_SIGNAL_E2E: &str = "e2e_process_capture_replays_natural_exit_with_null_signal";
    const RECOVERY_E2E: &str = "e2e_process_capture_promotes_flushed_raw_after_writer_exit";
    const WRITER_MODE: &str = "ZODE_PROCESS_CAPTURE_WRITER";
    const WRITER_ROOT: &str = "ZODE_PROCESS_CAPTURE_WRITER_ROOT";

    fn quarantine(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-recordings")
            .join("quarantine")
            .join(name)
    }

    #[test]
    fn e2e_process_capture_replays_natural_exit_with_null_signal() -> ProcessCaptureResult<()> {
        let quarantine = quarantine("process-capture-null-signal");
        let mut capture = ProcessCaptureSet::new(&quarantine, NULL_SIGNAL_E2E, &[])?;
        capture.capture_config("synthetic-config", br#"{"listen":"127.0.0.1:0"}"#)?;

        let child = Command::new("/bin/sh")
            .args(["-c", "printf 'natural-exit\\n'; exit 1"])
            .spawn()?;
        let pid = child.id();
        let output = child.wait_with_output()?;
        if output.status.code() != Some(1) {
            return Err(Error::other(format!(
                "real child did not naturally exit with code 1: {:?}",
                output.status
            ))
            .into());
        }

        capture.capture_process(ProcessObservation {
            name: "natural-exit-child".to_owned(),
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.status.code(),
            signal: None,
            termination: "natural_exit".to_owned(),
            stop: Some(ProcessStopObservation {
                observed_pids: vec![pid],
                reaped_pids: vec![pid],
                leaked_pids: Vec::new(),
                timed_out: false,
                flush_status: "ok".to_owned(),
                proof: true,
            }),
        })?;

        let raw = capture.flush("PROCESS_STARTUP_FAILURE", "natural_exit_code_1_signal_null")?;

        let replay = ProcessIncidentReplay::load(&raw, NULL_SIGNAL_E2E, &[]).map_err(|error| {
            Error::other(format!(
                "first occurrence raw at {} could not replay: {error}",
                raw.display()
            ))
        })?;
        assert_eq!(replay.classification(), "PROCESS_STARTUP_FAILURE");
        assert_eq!(replay.first_observed(), "natural_exit_code_1_signal_null");
        assert_eq!(replay.config_label(), "synthetic-config");
        assert_eq!(replay.config_bytes(), br#"{"listen":"127.0.0.1:0"}"#);
        Ok(())
    }

    #[test]
    fn e2e_process_capture_promotes_flushed_raw_after_writer_exit() -> ProcessCaptureResult<()> {
        let quarantine = quarantine("process-capture-recovery");
        if env::var_os(WRITER_MODE).is_some() {
            return writer_phase(
                &env::var_os(WRITER_ROOT)
                    .ok_or_else(|| Error::other("writer quarantine root is missing"))?,
            );
        }

        let executable = env::current_exe()?;
        let child_test_name = format!("unix_process_capture::{RECOVERY_E2E}");
        let output = Command::new(executable)
            .arg("--exact")
            .arg(&child_test_name)
            .arg("--nocapture")
            .env(WRITER_MODE, "1")
            .env(WRITER_ROOT, &quarantine)
            .output()?;
        if output.status.code() != Some(91) {
            return Err(Error::other(format!(
                "writer child did not exit at the crash-after-flush boundary: {:?}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ))
            .into());
        }
        let raw = String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("PROCESS_CAPTURE_RAW "))
            .map(PathBuf::from)
            .ok_or_else(|| Error::other("writer child did not publish its flushed raw path"))?;
        let raw_before = fs::read(&raw)?;
        let replay = ProcessIncidentReplay::load(&raw, RECOVERY_E2E, &[])?;
        let proof = ProcessReplayProof {
            matched: true,
            fingerprint: replay.source_digest().to_owned(),
            source_digest: replay.source_digest().to_owned(),
        };
        let destination = raw
            .parent()
            .ok_or_else(|| Error::other("flushed raw has no parent"))?
            .join("promoted")
            .join("recovered.v1.json");
        let promoted = replay.promote_immutable(&destination, &proof, &[])?;
        assert_eq!(fs::read(&promoted)?, raw_before);
        assert_eq!(fs::read(&raw)?, raw_before);
        let permissions = fs::metadata(&promoted)?.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o444);
        assert!(replay.promote_immutable(&promoted, &proof, &[]).is_err());
        Ok(())
    }

    #[test]
    fn e2e_process_capture_rejects_placeholder_empty_stop_proof() -> ProcessCaptureResult<()> {
        let root = quarantine("process-capture-empty-stop-proof");
        let mut capture = ProcessCaptureSet::new(
            &root,
            "e2e_process_capture_rejects_placeholder_empty_stop_proof",
            &[],
        )?;
        capture.capture_config("synthetic-config", br#"{"listen":"127.0.0.1:0"}"#)?;

        let child = Command::new("/bin/sh").args(["-c", "exit 1"]).spawn()?;
        let pid = child.id();
        let output = child.wait_with_output()?;
        let placeholder = ProcessObservation {
            name: "placeholder-stop-child".to_owned(),
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.status.code(),
            signal: None,
            termination: "natural_exit".to_owned(),
            stop: Some(ProcessStopObservation {
                observed_pids: Vec::new(),
                reaped_pids: Vec::new(),
                leaked_pids: Vec::new(),
                timed_out: false,
                flush_status: "ok".to_owned(),
                proof: true,
            }),
        };

        assert!(capture.capture_process(placeholder).is_err());
        assert!(capture
            .flush("PROCESS_STARTUP_FAILURE", "empty_stop_proof")
            .is_err());
        assert!(pid > 1);
        Ok(())
    }

    #[test]
    fn e2e_process_capture_rejects_invalid_stop_then_retry() -> ProcessCaptureResult<()> {
        let root = quarantine("process-capture-invalid-stop-retry");
        let mut capture = ProcessCaptureSet::new(
            &root,
            "e2e_process_capture_rejects_invalid_stop_then_retry",
            &[],
        )?;
        capture.capture_config("synthetic-config", br#"{"listen":"127.0.0.1:0"}"#)?;

        let child = Command::new("/bin/sh").args(["-c", "exit 1"]).spawn()?;
        let pid = child.id();
        let output = child.wait_with_output()?;
        let invalid = ProcessObservation {
            name: "invalid-stop-child".to_owned(),
            stdout: output.stdout.clone(),
            stderr: output.stderr.clone(),
            exit_code: output.status.code(),
            signal: None,
            termination: "natural_exit".to_owned(),
            stop: Some(ProcessStopObservation {
                observed_pids: Vec::new(),
                reaped_pids: Vec::new(),
                leaked_pids: Vec::new(),
                timed_out: false,
                flush_status: "ok".to_owned(),
                proof: true,
            }),
        };
        assert!(capture.capture_process(invalid).is_err());

        let retry = ProcessObservation {
            name: "retry-after-invalid-stop".to_owned(),
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.status.code(),
            signal: None,
            termination: "natural_exit".to_owned(),
            stop: Some(ProcessStopObservation {
                observed_pids: vec![pid],
                reaped_pids: vec![pid],
                leaked_pids: Vec::new(),
                timed_out: false,
                flush_status: "ok".to_owned(),
                proof: true,
            }),
        };
        assert!(capture.capture_process(retry).is_err());
        assert!(capture
            .flush("PROCESS_STARTUP_FAILURE", "invalid_stop_retry")
            .is_err());
        Ok(())
    }

    #[test]
    fn e2e_process_capture_rejects_malformed_exit_code() -> ProcessCaptureResult<()> {
        let raw = capture_natural_exit(
            "process-capture-malformed-exit-code",
            "e2e_process_capture_rejects_malformed_exit_code",
        )?;
        let mutated = write_mutated_envelope(&raw, "malformed-exit-code", |value| {
            value["processes"][0]["exit_code"] = Value::String("not-an-exit".to_owned());
        })?;
        assert!(ProcessIncidentReplay::load(
            &mutated,
            "e2e_process_capture_rejects_malformed_exit_code",
            &[],
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn e2e_process_capture_rejects_path_traversal_recording_id() -> ProcessCaptureResult<()> {
        let raw = capture_natural_exit(
            "process-capture-path-traversal-id",
            "e2e_process_capture_rejects_path_traversal_recording_id",
        )?;
        let mutated = write_mutated_envelope(&raw, "path-traversal-recording-id", |value| {
            value["recording_id"] = Value::String("../escaped-recording".to_owned());
        })?;
        assert!(ProcessIncidentReplay::load(
            &mutated,
            "e2e_process_capture_rejects_path_traversal_recording_id",
            &[],
        )
        .is_err());
        Ok(())
    }

    fn capture_natural_exit(root_name: &str, e2e_name: &str) -> ProcessCaptureResult<PathBuf> {
        let root = quarantine(root_name);
        let mut capture = ProcessCaptureSet::new(&root, e2e_name, &[])?;
        capture.capture_config("synthetic-config", br#"{"listen":"127.0.0.1:0"}"#)?;
        let child = Command::new("/bin/sh").args(["-c", "exit 1"]).spawn()?;
        let pid = child.id();
        let output = child.wait_with_output()?;
        if output.status.code() != Some(1) {
            return Err(Error::other("natural-exit fixture did not return code 1").into());
        }
        capture.capture_process(ProcessObservation {
            name: "mutation-source-child".to_owned(),
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.status.code(),
            signal: None,
            termination: "natural_exit".to_owned(),
            stop: Some(ProcessStopObservation {
                observed_pids: vec![pid],
                reaped_pids: vec![pid],
                leaked_pids: Vec::new(),
                timed_out: false,
                flush_status: "ok".to_owned(),
                proof: true,
            }),
        })?;
        capture.flush("PROCESS_STARTUP_FAILURE", "mutation_source")
    }

    fn write_mutated_envelope(
        raw: &std::path::Path,
        name: &str,
        mutate: impl FnOnce(&mut Value),
    ) -> ProcessCaptureResult<PathBuf> {
        let mut value: Value = serde_json::from_slice(&fs::read(raw)?)?;
        mutate(&mut value);
        value["integrity_sha256"] = Value::String(String::new());
        let unsigned = serde_json::to_string(&value)?;
        value["integrity_sha256"] =
            Value::String(format!("{:x}", Sha256::digest(unsigned.as_bytes())));
        let path = raw
            .parent()
            .ok_or_else(|| Error::other("raw mutation source has no parent"))?
            .join(format!("{name}.json"));
        let bytes = serde_json::to_vec_pretty(&value)?;
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        options.mode(0o600);
        let mut file = options.open(&path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        File::open(path.parent().expect("mutation parent").to_owned())?.sync_all()?;
        Ok(path)
    }

    fn writer_phase(root: &std::ffi::OsStr) -> ProcessCaptureResult<()> {
        let mut capture = ProcessCaptureSet::new(root, RECOVERY_E2E, &[])?;
        capture.capture_config("synthetic-config", br#"{"listen":"127.0.0.1:0"}"#)?;
        let mut child = Command::new("/bin/sleep").arg("30").spawn()?;
        let pid = child.id();
        child.kill()?;
        let output = child.wait_with_output()?;
        if output.status.signal().is_none() {
            return Err(Error::other("writer child did not observe a signal termination").into());
        }
        capture.capture_process(ProcessObservation {
            name: "crash-boundary-child".to_owned(),
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.status.code(),
            signal: Some("SIGKILL".to_owned()),
            termination: "signal_termination".to_owned(),
            stop: Some(ProcessStopObservation {
                observed_pids: vec![pid],
                reaped_pids: vec![pid],
                leaked_pids: Vec::new(),
                timed_out: false,
                flush_status: "ok".to_owned(),
                proof: true,
            }),
        })?;
        let raw = capture.flush("PROCESS_STARTUP_FAILURE", "crash_after_flush")?;
        println!("PROCESS_CAPTURE_RAW {}", raw.display());
        std::io::stdout().flush()?;
        std::process::exit(91);
    }
}

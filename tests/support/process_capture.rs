//! Test-only capture for process-start failures.
//!
//! This module is deliberately independent of the Endpoint/Server crates so a
//! Server integration test can include it with `#[path = ...]`.  It records
//! only a test-owned, synthetic-slot config input and bounded child-process
//! observations.  It is never compiled into production binaries.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Error as IoError, ErrorKind, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

pub type ProcessCaptureResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub const PROCESS_CAPTURE_SCHEMA: &str = "zode.process-incident-recording.v1";
const MAX_CONFIG_BYTES: usize = 2 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROCESSES: usize = 8;
const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_STOP_PIDS: usize = 1024;
const MAX_ENVELOPE_BYTES: usize = (MAX_TOTAL_BYTES * 2) + (MAX_PROCESSES * 4096);
static NEXT_CAPTURE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct ProcessObservation {
    pub name: String,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub termination: String,
    /// Optional proof returned by the shared process-stop seam.  A flushed
    /// startup incident must include this proof; keeping it optional here
    /// lets callers capture an intermediate child observation without making
    /// that observation promotable.
    pub stop: Option<ProcessStopObservation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProcessStopObservation {
    pub observed_pids: Vec<u32>,
    pub reaped_pids: Vec<u32>,
    pub leaked_pids: Vec<u32>,
    pub timed_out: bool,
    pub flush_status: String,
    pub proof: bool,
}

#[derive(Serialize)]
struct ConfigRecord<'a> {
    schema: &'static str,
    label: &'a str,
    bytes_hex: String,
    sha256: String,
}

#[derive(Serialize)]
struct ProcessRecord<'a> {
    schema: &'static str,
    name: &'a str,
    stdout_hex: String,
    stderr_hex: String,
    exit_code: Option<i32>,
    signal: Option<&'a str>,
    termination: &'a str,
    stop: Option<&'a ProcessStopObservation>,
}

#[derive(Serialize)]
struct CaptureEnvelope {
    schema: &'static str,
    version: u32,
    recording_id: String,
    e2e_name: String,
    classification: String,
    first_observed: String,
    config: ConfigRecordOwned,
    processes: Vec<ProcessRecordOwned>,
    integrity_sha256: String,
}

#[derive(Clone, Serialize)]
struct ConfigRecordOwned {
    label: String,
    bytes_hex: String,
    sha256: String,
}

#[derive(Clone, Serialize)]
struct ProcessRecordOwned {
    name: String,
    stdout_hex: String,
    stderr_hex: String,
    exit_code: Option<i32>,
    signal: Option<String>,
    termination: String,
    stop: Option<ProcessStopObservation>,
}

/// Proof supplied by the owning public replay E2E before promotion.  The
/// capture helper does not implement product replay; it only makes the proof
/// a required, typed input to the immutable-file transition.
#[derive(Clone, Debug)]
pub struct ProcessReplayProof {
    pub matched: bool,
    pub fingerprint: String,
    /// Digest of the exact flushed `capture.v1.json` used by the public
    /// replay.  A proof for another occurrence cannot be attached later.
    pub source_digest: String,
}

/// Read-only, validated projection of a process incident cassette.  The raw
/// JSON and child observations never escape this type; callers receive only
/// the slot-substituted config and safe incident metadata needed to replay the
/// real startup path.
#[derive(Clone, Debug)]
pub struct ProcessIncidentReplay {
    source_path: PathBuf,
    recording_id: String,
    e2e_name: String,
    config_label: String,
    config_bytes: Vec<u8>,
    classification: String,
    first_observed: String,
    source_digest: String,
}

impl ProcessIncidentReplay {
    pub fn load(
        path: impl AsRef<Path>,
        expected_e2e_name: impl AsRef<str>,
        forbidden_markers: &[&str],
    ) -> ProcessCaptureResult<Self> {
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() {
            return Err(IoError::other("process incident cassette is not a regular file").into());
        }
        let bytes = fs::read(path)?;
        let value = parse_valid_envelope(&bytes, None, Some(expected_e2e_name.as_ref()))?;
        let markers = marker_bytes(forbidden_markers);
        scan_incident_value(&value, &markers)?;
        let config = value
            .get("config")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| IoError::other("process incident config is invalid"))?;
        let config_label = config
            .get("label")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| IoError::other("process incident config label is invalid"))?
            .to_owned();
        let recording_id = value
            .get("recording_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| IoError::other("process incident recording identity is invalid"))?
            .to_owned();
        let e2e_name = value
            .get("e2e_name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| IoError::other("process incident e2e identity is invalid"))?
            .to_owned();
        let config_hex = config
            .get("bytes_hex")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| IoError::other("process incident config bytes are invalid"))?;
        let config_bytes = decode_hex(config_hex)?;
        let classification = value
            .get("classification")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| IoError::other("process incident classification is invalid"))?
            .to_owned();
        let first_observed = value
            .get("first_observed")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| IoError::other("process incident first observation is invalid"))?
            .to_owned();
        Ok(Self {
            source_path: path.to_path_buf(),
            recording_id,
            e2e_name,
            config_label,
            config_bytes,
            classification,
            first_observed,
            source_digest: digest(&bytes),
        })
    }

    pub fn config_label(&self) -> &str {
        &self.config_label
    }

    pub fn config_bytes(&self) -> &[u8] {
        &self.config_bytes
    }

    pub fn classification(&self) -> &str {
        &self.classification
    }

    pub fn first_observed(&self) -> &str {
        &self.first_observed
    }

    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }

    /// Recovery promotion for a flushed cassette after the capture owner has
    /// exited.  The source is read and validated again; this never trusts the
    /// projection retained by the previous process or rewrites the raw file.
    pub fn promote_immutable(
        &self,
        destination: impl AsRef<Path>,
        proof: &ProcessReplayProof,
        forbidden_markers: &[&str],
    ) -> ProcessCaptureResult<PathBuf> {
        let markers = marker_bytes(forbidden_markers);
        let bytes = read_validated_source(
            &self.source_path,
            Some(&self.recording_id),
            Some(&self.e2e_name),
            &markers,
        )?;
        let source_digest = digest(&bytes);
        if source_digest != self.source_digest {
            return Err(IoError::other("process incident source digest changed").into());
        }
        promote_bytes(
            &bytes,
            &self.recording_id,
            destination.as_ref(),
            proof,
            &source_digest,
        )
    }
}

pub struct ProcessCaptureSet {
    run_dir: PathBuf,
    recording_id: String,
    e2e_name: String,
    forbidden: Vec<Vec<u8>>,
    config: Option<ConfigRecordOwned>,
    processes: Vec<ProcessRecordOwned>,
    total_bytes: usize,
    flushed: Option<PathBuf>,
    failed: bool,
}

impl ProcessCaptureSet {
    /// Allocate a private run directory before the process is spawned.  The
    /// caller supplies real credential markers only in memory; they are never
    /// written to the capture or to an error message.
    pub fn new(
        quarantine_root: impl AsRef<Path>,
        e2e_name: impl Into<String>,
        forbidden_markers: &[&str],
    ) -> ProcessCaptureResult<Self> {
        let root = quarantine_root.as_ref().to_path_buf();
        create_private_dir(&root)?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let sequence = NEXT_CAPTURE.fetch_add(1, Ordering::Relaxed);
        let recording_id = format!("process-{}-{nonce}-{sequence}", std::process::id());
        let run_dir = root.join(&recording_id);
        create_private_dir(&run_dir)?;
        Ok(Self {
            run_dir,
            recording_id,
            e2e_name: bounded_text(e2e_name.into(), "e2e_name")?,
            forbidden: forbidden_markers
                .iter()
                .filter(|marker| !marker.is_empty())
                .map(|marker| marker.as_bytes().to_vec())
                .collect(),
            config: None,
            processes: Vec::new(),
            total_bytes: 0,
            flushed: None,
            failed: false,
        })
    }

    /// Record the exact synthetic-slot config bytes before starting the
    /// child.  The label is intentionally not a filesystem path, preventing
    /// secret-bearing path components from entering the cassette.
    pub fn capture_config(
        &mut self,
        label: impl Into<String>,
        bytes: &[u8],
    ) -> ProcessCaptureResult<()> {
        self.ensure_open()?;
        if self.config.is_some() {
            return Err(IoError::new(
                ErrorKind::AlreadyExists,
                "process capture config already recorded",
            )
            .into());
        }
        if bytes.is_empty() || bytes.len() > MAX_CONFIG_BYTES {
            return self.fail("process capture config exceeds its bound");
        }
        let label = match bounded_text(label.into(), "config label") {
            Ok(label) => label,
            Err(error) => return self.fail_with(error),
        };
        self.scan_or_fail(bytes)?;
        let record = ConfigRecord {
            schema: PROCESS_CAPTURE_SCHEMA,
            label: &label,
            bytes_hex: hex(bytes),
            sha256: digest(bytes),
        };
        if let Err(error) = write_new_json(&self.run_dir.join("config.json"), &record) {
            return self.fail_with(error);
        }
        self.total_bytes = bytes.len();
        self.config = Some(ConfigRecordOwned {
            label,
            bytes_hex: hex(bytes),
            sha256: digest(bytes),
        });
        Ok(())
    }

    /// Seal one real child observation.  Each observation is durably written
    /// before the next process may be started.
    pub fn capture_process(&mut self, observation: ProcessObservation) -> ProcessCaptureResult<()> {
        self.ensure_open()?;
        if self.config.is_none() {
            return self.fail("process capture config was not recorded before process output");
        }
        if self.processes.len() >= MAX_PROCESSES {
            return self.fail("process capture exceeded its process bound");
        }
        let name = match bounded_text(observation.name, "process name") {
            Ok(name) => name,
            Err(error) => return self.fail_with(error),
        };
        let termination = match bounded_text(observation.termination, "termination") {
            Ok(termination) => termination,
            Err(error) => return self.fail_with(error),
        };
        let signal = observation
            .signal
            .map(|signal| bounded_text(signal, "signal"))
            .transpose()
            .inspect_err(|_| {
                self.failed = true;
            })?;
        if let Some(stop) = observation.stop.as_ref() {
            if let Err(error) = validate_stop_observation(stop) {
                return self.fail_with(error);
            }
        }
        if observation.stdout.len() > MAX_OUTPUT_BYTES
            || observation.stderr.len() > MAX_OUTPUT_BYTES
        {
            return self.fail("process output exceeded its bound");
        }
        let bytes = observation.stdout.len() + observation.stderr.len();
        if self.total_bytes.saturating_add(bytes) > MAX_TOTAL_BYTES {
            return self.fail("process capture exceeded its total byte bound");
        }
        self.scan_or_fail(&observation.stdout)?;
        self.scan_or_fail(&observation.stderr)?;
        let record = ProcessRecord {
            schema: PROCESS_CAPTURE_SCHEMA,
            name: &name,
            stdout_hex: hex(&observation.stdout),
            stderr_hex: hex(&observation.stderr),
            exit_code: observation.exit_code,
            signal: signal.as_deref(),
            termination: &termination,
            stop: observation.stop.as_ref(),
        };
        let path = self
            .run_dir
            .join(format!("process-{:04}.json", self.processes.len()));
        if let Err(error) = write_new_json(&path, &record) {
            return self.fail_with(error);
        }
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        self.processes.push(ProcessRecordOwned {
            name,
            stdout_hex: hex(&observation.stdout),
            stderr_hex: hex(&observation.stderr),
            exit_code: observation.exit_code,
            signal,
            termination,
            stop: observation.stop,
        });
        Ok(())
    }

    /// Flush the bounded capture set before the caller asserts the failure or
    /// launches another process.  The returned path is ignored quarantine
    /// evidence and is never printed with its contents.
    pub fn flush(
        &mut self,
        classification: impl Into<String>,
        first_observed: impl Into<String>,
    ) -> ProcessCaptureResult<PathBuf> {
        self.ensure_open()?;
        if self.config.is_none() || self.processes.is_empty() {
            return self.fail("process capture set is incomplete");
        }
        if self
            .processes
            .iter()
            .any(|process| process.stop.as_ref().is_none_or(|stop| !stop.proof))
        {
            return self.fail("process capture lacks a successful stop/reap proof");
        }
        let classification = match bounded_text(classification.into(), "classification") {
            Ok(value) => value,
            Err(error) => return self.fail_with(error),
        };
        let first_observed = match bounded_text(first_observed.into(), "first observed") {
            Ok(value) => value,
            Err(error) => return self.fail_with(error),
        };
        let config = self.config.as_ref().expect("checked above");
        let mut envelope = CaptureEnvelope {
            schema: PROCESS_CAPTURE_SCHEMA,
            version: 1,
            recording_id: self.recording_id.clone(),
            e2e_name: self.e2e_name.clone(),
            classification,
            first_observed,
            config: config.clone(),
            processes: self.processes.clone(),
            integrity_sha256: String::new(),
        };
        envelope.integrity_sha256 = match envelope_digest(&envelope) {
            Ok(value) => value,
            Err(error) => return self.fail_with(error),
        };
        let path = self.run_dir.join("capture.v1.json");
        if let Err(error) = write_new_json(&path, &envelope) {
            return self.fail_with(error);
        }
        self.flushed = Some(path.clone());
        Ok(path)
    }

    pub fn flushed_path(&self) -> Option<&Path> {
        self.flushed.as_deref()
    }

    /// Make a reviewed capture immutable.  `proof` must come from the same
    /// real-process public replay E2E; a false/empty proof cannot promote.
    pub fn promote_immutable(
        &self,
        destination: impl AsRef<Path>,
        proof: &ProcessReplayProof,
    ) -> ProcessCaptureResult<PathBuf> {
        let source = self
            .flushed
            .as_ref()
            .ok_or_else(|| IoError::other("process capture must be flushed before promotion"))?;
        let bytes = read_validated_source(
            source,
            Some(&self.recording_id),
            Some(&self.e2e_name),
            &self.forbidden,
        )?;
        let source_digest = digest(&bytes);
        promote_bytes(
            &bytes,
            &self.recording_id,
            destination.as_ref(),
            proof,
            &source_digest,
        )
    }

    fn ensure_open(&self) -> ProcessCaptureResult<()> {
        if self.failed {
            return Err(IoError::other("process capture is failed closed").into());
        }
        if self.flushed.is_some() {
            return Err(IoError::other("process capture has already been flushed").into());
        }
        Ok(())
    }

    fn scan(&self, bytes: &[u8]) -> ProcessCaptureResult<()> {
        if self.forbidden.iter().any(|marker| contains(bytes, marker)) {
            return Err(
                IoError::other("process capture contained forbidden secret material").into(),
            );
        }
        Ok(())
    }

    fn scan_or_fail(&mut self, bytes: &[u8]) -> ProcessCaptureResult<()> {
        if let Err(error) = self.scan(bytes) {
            self.failed = true;
            return Err(error);
        }
        Ok(())
    }

    fn fail<T>(&mut self, message: &str) -> ProcessCaptureResult<T> {
        self.failed = true;
        Err(IoError::other(message.to_owned()).into())
    }

    fn fail_with<T>(&mut self, error: Box<dyn Error + Send + Sync>) -> ProcessCaptureResult<T> {
        self.failed = true;
        Err(error)
    }
}

fn marker_bytes(markers: &[&str]) -> Vec<Vec<u8>> {
    markers
        .iter()
        .filter(|marker| !marker.is_empty())
        .map(|marker| marker.as_bytes().to_vec())
        .collect()
}

fn read_validated_source(
    path: &Path,
    expected_recording_id: Option<&str>,
    expected_e2e_name: Option<&str>,
    forbidden_markers: &[Vec<u8>],
) -> ProcessCaptureResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(IoError::other("process incident source is not a regular file").into());
    }
    let bytes = fs::read(path)?;
    let value = parse_valid_envelope(&bytes, expected_recording_id, expected_e2e_name)?;
    scan_incident_value(&value, forbidden_markers)?;
    Ok(bytes)
}

fn promote_bytes(
    bytes: &[u8],
    recording_id: &str,
    destination: &Path,
    proof: &ProcessReplayProof,
    source_digest: &str,
) -> ProcessCaptureResult<PathBuf> {
    if !proof.matched
        || !valid_nonzero_digest(&proof.fingerprint)
        || !valid_digest(&proof.source_digest)
        || proof.source_digest != source_digest
    {
        return Err(IoError::other("process capture replay proof is missing").into());
    }
    let parent = destination
        .parent()
        .ok_or_else(|| IoError::other("process cassette destination has no parent"))?;
    create_private_dir(parent)?;
    validate_recording_id(recording_id)?;
    let temporary = parent.join(format!(".{}.tmp-{}", recording_id, std::process::id()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    set_open_mode(&mut options, 0o600);
    let write_result = (|| -> ProcessCaptureResult<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        set_mode(&temporary, 0o444)?;
        File::open(&temporary)?.sync_all()?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::hard_link(&temporary, destination) {
        let _ = fs::remove_file(&temporary);
        return Err(if error.kind() == ErrorKind::AlreadyExists {
            IoError::new(ErrorKind::AlreadyExists, "process cassette is immutable")
        } else {
            error
        }
        .into());
    }
    fs::remove_file(&temporary)?;
    sync_dir(parent)?;
    Ok(destination.to_path_buf())
}

fn create_private_dir(path: &Path) -> ProcessCaptureResult<()> {
    fs::create_dir_all(path)?;
    set_mode(path, 0o700)?;
    sync_dir(path)?;
    Ok(())
}

fn write_new_json<T: Serialize>(path: &Path, value: &T) -> ProcessCaptureResult<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    set_open_mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    sync_dir(
        path.parent()
            .ok_or_else(|| IoError::other("capture file has no parent"))?,
    )?;
    Ok(())
}

fn envelope_digest(envelope: &CaptureEnvelope) -> ProcessCaptureResult<String> {
    let mut unsigned = serde_json::to_value(envelope)?;
    unsigned["integrity_sha256"] = serde_json::Value::String(String::new());
    Ok(digest(serde_json::to_string(&unsigned)?.as_bytes()))
}

fn validate_stop_observation(stop: &ProcessStopObservation) -> ProcessCaptureResult<()> {
    if stop.flush_status.is_empty() || stop.flush_status.len() > 64 {
        return Err(IoError::other("process stop flush status is outside its bound").into());
    }
    let mut observed = stop.observed_pids.clone();
    let mut reaped = stop.reaped_pids.clone();
    let mut leaked = stop.leaked_pids.clone();
    for pids in [&mut observed, &mut reaped, &mut leaked] {
        if pids.len() > MAX_STOP_PIDS {
            return Err(IoError::other("process stop PID list exceeds its bound").into());
        }
        if pids.iter().any(|pid| *pid <= 1) {
            return Err(IoError::other("process stop PID is outside its bound").into());
        }
        pids.sort_unstable();
        if pids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(IoError::other("process stop PID list is not unique").into());
        }
    }
    if !reaped.iter().all(|pid| observed.binary_search(pid).is_ok())
        || !leaked.iter().all(|pid| observed.binary_search(pid).is_ok())
        || reaped.iter().any(|pid| leaked.binary_search(pid).is_ok())
    {
        return Err(IoError::other("process stop PID proof is inconsistent").into());
    }
    let derived = stop.flush_status == "ok" && !stop.timed_out && leaked.is_empty();
    if stop.proof != derived {
        return Err(IoError::other("process stop proof flag is inconsistent").into());
    }
    if stop.proof && (observed.is_empty() || reaped.is_empty()) {
        return Err(IoError::other("process stop proof has no observed or reaped PID").into());
    }
    if stop.proof
        && observed
            .iter()
            .any(|pid| reaped.binary_search(pid).is_err())
    {
        return Err(IoError::other("process stop proof omitted an observed PID").into());
    }
    Ok(())
}

/// Parse and validate an incident envelope without returning any unvalidated
/// fields to a caller.  The returned JSON is internal-only and is immediately
/// projected by `ProcessIncidentReplay` or used for promotion checks.
fn parse_valid_envelope(
    bytes: &[u8],
    expected_recording_id: Option<&str>,
    expected_e2e_name: Option<&str>,
) -> ProcessCaptureResult<serde_json::Value> {
    if bytes.is_empty() || bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(IoError::other("process capture envelope exceeds its bound").into());
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let object = value
        .as_object()
        .ok_or_else(|| IoError::other("process capture envelope is not an object"))?;
    if object.get("schema").and_then(serde_json::Value::as_str) != Some(PROCESS_CAPTURE_SCHEMA)
        || object.get("version").and_then(serde_json::Value::as_u64) != Some(1)
    {
        return Err(IoError::other("process capture envelope schema is invalid").into());
    }
    let recording_id = object
        .get("recording_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| IoError::other("process capture recording identity is missing"))?;
    validate_recording_id(recording_id)?;
    if expected_recording_id.is_some_and(|expected| expected != recording_id) {
        return Err(IoError::other("process capture recording identity is invalid").into());
    }
    let e2e_name = object
        .get("e2e_name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| IoError::other("process capture e2e identity is missing"))?;
    bounded_text(e2e_name.to_owned(), "e2e_name")?;
    if expected_e2e_name.is_some_and(|expected| expected != e2e_name) {
        return Err(IoError::other("process capture e2e identity is invalid").into());
    }
    for field in ["classification", "first_observed"] {
        let text = object
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| IoError::other(format!("process capture {field} is missing")))?;
        bounded_text(text.to_owned(), field)?;
    }
    let supplied = object
        .get("integrity_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| IoError::other("process capture envelope has no integrity digest"))?;
    if !valid_digest(supplied) {
        return Err(IoError::other("process capture envelope digest is invalid").into());
    }
    let mut unsigned = value.clone();
    unsigned["integrity_sha256"] = serde_json::Value::String(String::new());
    if supplied != digest(serde_json::to_string(&unsigned)?.as_bytes()) {
        return Err(IoError::other("process capture envelope digest did not match").into());
    }

    let config = object
        .get("config")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| IoError::other("process capture config is missing"))?;
    let label = config
        .get("label")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| IoError::other("process capture config label is invalid"))?;
    bounded_text(label.to_owned(), "config label")?;
    let config_hex = config
        .get("bytes_hex")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| IoError::other("process capture config bytes are invalid"))?;
    if config_hex.len() > MAX_CONFIG_BYTES.saturating_mul(2) {
        return Err(IoError::other("process capture config exceeds its bound").into());
    }
    let config_bytes = decode_hex(config_hex)?;
    if config_bytes.is_empty() || config_bytes.len() > MAX_CONFIG_BYTES {
        return Err(IoError::other("process capture config exceeds its bound").into());
    }
    let config_digest = config
        .get("sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| IoError::other("process capture config digest is missing"))?;
    if !valid_digest(config_digest) || config_digest != digest(&config_bytes) {
        return Err(IoError::other("process capture config digest did not match").into());
    }

    let processes = object
        .get("processes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| IoError::other("process capture envelope has no process observations"))?;
    if processes.is_empty() || processes.len() > MAX_PROCESSES {
        return Err(IoError::other("process capture envelope process bound is invalid").into());
    }
    let mut total_bytes = config_bytes.len();
    for process in processes {
        let process = process
            .as_object()
            .ok_or_else(|| IoError::other("process capture process is not an object"))?;
        let name = process
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| IoError::other("process capture process name is missing"))?;
        bounded_text(name.to_owned(), "process name")?;
        let termination = process
            .get("termination")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| IoError::other("process capture termination is missing"))?;
        bounded_text(termination.to_owned(), "termination")?;
        let exit_code = process
            .get("exit_code")
            .ok_or_else(|| IoError::other("process capture exit code is missing"))?;
        if !exit_code.is_null() {
            let exit_code = exit_code
                .as_i64()
                .ok_or_else(|| IoError::other("process capture exit code is invalid"))?;
            if !(i32::MIN as i64..=i32::MAX as i64).contains(&exit_code) {
                return Err(
                    IoError::other("process capture exit code is outside its bound").into(),
                );
            }
        }
        if let Some(signal) = process.get("signal") {
            if !signal.is_null() {
                let signal = signal
                    .as_str()
                    .ok_or_else(|| IoError::other("process capture signal is invalid"))?;
                bounded_text(signal.to_owned(), "signal")?;
            }
        }
        let stdout_hex = process
            .get("stdout_hex")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| IoError::other("process capture stdout is missing"))?;
        let stderr_hex = process
            .get("stderr_hex")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| IoError::other("process capture stderr is missing"))?;
        if stdout_hex.len() > MAX_OUTPUT_BYTES * 2 || stderr_hex.len() > MAX_OUTPUT_BYTES * 2 {
            return Err(IoError::other("process capture output exceeds its bound").into());
        }
        let stdout = decode_hex(stdout_hex)?;
        let stderr = decode_hex(stderr_hex)?;
        if stdout.len() > MAX_OUTPUT_BYTES || stderr.len() > MAX_OUTPUT_BYTES {
            return Err(IoError::other("process capture output exceeds its bound").into());
        }
        total_bytes = total_bytes
            .checked_add(stdout.len())
            .and_then(|value| value.checked_add(stderr.len()))
            .ok_or_else(|| IoError::other("process capture total byte bound overflow"))?;
        if total_bytes > MAX_TOTAL_BYTES {
            return Err(IoError::other("process capture exceeds its total byte bound").into());
        }
        let stop = process
            .get("stop")
            .ok_or_else(|| IoError::other("process capture envelope lacks stop proof"))?;
        let stop: ProcessStopObservation = serde_json::from_value(stop.clone())?;
        validate_stop_observation(&stop)?;
        if !stop.proof {
            return Err(
                IoError::other("process capture envelope lacks successful stop proof").into(),
            );
        }
    }
    Ok(value)
}

fn scan_incident_value(
    value: &serde_json::Value,
    forbidden_markers: &[Vec<u8>],
) -> ProcessCaptureResult<()> {
    if forbidden_markers.is_empty() {
        return Ok(());
    }
    let serialized = serde_json::to_vec(value)?;
    if forbidden_markers
        .iter()
        .any(|marker| contains(&serialized, marker))
    {
        return Err(IoError::other("process capture contained forbidden secret material").into());
    }
    let object = value
        .as_object()
        .ok_or_else(|| IoError::other("process capture envelope is not an object"))?;
    if let Some(config) = object.get("config").and_then(serde_json::Value::as_object) {
        if let Some(bytes_hex) = config.get("bytes_hex").and_then(serde_json::Value::as_str) {
            scan_decoded_markers(bytes_hex, forbidden_markers)?;
        }
    }
    if let Some(processes) = object
        .get("processes")
        .and_then(serde_json::Value::as_array)
    {
        for process in processes {
            if let Some(process) = process.as_object() {
                for field in ["stdout_hex", "stderr_hex"] {
                    if let Some(bytes_hex) = process.get(field).and_then(serde_json::Value::as_str)
                    {
                        scan_decoded_markers(bytes_hex, forbidden_markers)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn scan_decoded_markers(encoded: &str, forbidden_markers: &[Vec<u8>]) -> ProcessCaptureResult<()> {
    let decoded = decode_hex(encoded)?;
    if forbidden_markers
        .iter()
        .any(|marker| contains(&decoded, marker))
    {
        return Err(IoError::other("process capture contained forbidden secret material").into());
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_nonzero_digest(value: &str) -> bool {
    valid_digest(value) && value.bytes().any(|byte| byte != b'0')
}

fn validate_recording_id(value: &str) -> ProcessCaptureResult<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(
            IoError::other("process capture recording identity is outside its bound").into(),
        );
    }
    Ok(())
}

fn bounded_text(value: String, field: &str) -> ProcessCaptureResult<String> {
    if value.is_empty() || value.len() > 256 || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(IoError::other(format!("{field} is outside its bound")).into());
    }
    Ok(value)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> ProcessCaptureResult<Vec<u8>> {
    if !value.is_ascii() || !value.len().is_multiple_of(2) {
        return Err(IoError::other("process capture hex value is invalid").into());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])
            .ok_or_else(|| IoError::other("process capture hex value is invalid"))?;
        let low = hex_nibble(pair[1])
            .ok_or_else(|| IoError::other("process capture hex value is invalid"))?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn set_mode(path: &Path, mode: u32) -> ProcessCaptureResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

fn set_open_mode(options: &mut OpenOptions, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
}

fn sync_dir(path: &Path) -> ProcessCaptureResult<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

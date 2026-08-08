#[path = "../../tests/support/process_capture.rs"]
mod process_capture;

use std::{
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use process_capture::{
    ProcessCaptureSet, ProcessIncidentReplay, ProcessObservation, ProcessReplayProof,
    ProcessStopObservation,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const E2E_NAME: &str =
    "e2e_server_requires_canonical_distinct_management_and_callback_origins_before_ready";
const CAPTURE_ENV: &str = "ZODE_CAPTURE_FIRST_OCCURRENCE";
const RECOVER_ENV: &str = "ZODE_RECOVER_PROCESS_INCIDENT_ROOT";
const READY_PREFIX: &[u8] = b"ZODE_SERVER_READY ";
const START_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const SECRET_MARKER: &str = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
const SERVER_AUTHORITY: &str = "origin-startup-e2e-authority";
const MISSING_CASSETTE: &str =
    "tests/fixtures/incidents/server-origins-missing-fields-first-control-store-unavailable.v1.json";
const VALID_CASSETTE: &str =
    "tests/fixtures/incidents/server-origins-valid-distinct-first-rejected.v1.json";
const VALID_CONTROL_STORE_CASSETTE: &str =
    "tests/fixtures/incidents/server-origins-valid-distinct-later-control-store-unavailable.v1.json";
const VALID_CONTROL_STORE_CLASSIFICATION: &str =
    "valid_distinct_origins_reached_locked_control_store_after_schema_adoption";
const SAME_CASSETTE: &str =
    "tests/fixtures/incidents/server-origins-same-authority-first-schema-rejected.v1.json";
const AMBIGUOUS_SCHEME_CASSETTE: &str =
    "tests/fixtures/incidents/server-origins-ambiguous-scheme-first-schema-rejected.v1.json";
const DEFAULT_PORT_CASSETTE: &str =
    "tests/fixtures/incidents/server-origins-default-port-first-schema-rejected.v1.json";
const CREDENTIAL_CASSETTE: &str =
    "tests/fixtures/incidents/server-origins-credentials-first-schema-rejected.v1.json";
const PATH_CASSETTE: &str =
    "tests/fixtures/incidents/server-origins-path-first-schema-rejected.v1.json";
const QUERY_CASSETTE: &str =
    "tests/fixtures/incidents/server-origins-query-first-schema-rejected.v1.json";
const FRAGMENT_CASSETTE: &str =
    "tests/fixtures/incidents/server-origins-fragment-first-schema-rejected.v1.json";
const PUBLIC_HTTP_CASSETTE: &str =
    "tests/fixtures/incidents/server-origins-public-http-first-schema-rejected.v1.json";
const UNSUPPORTED_SCHEME_CASSETTE: &str =
    "tests/fixtures/incidents/server-origins-unsupported-scheme-first-schema-rejected.v1.json";
const MISSING_HOST_CASSETTE: &str =
    "tests/fixtures/incidents/server-origins-missing-host-first-schema-rejected.v1.json";
const MISSING_ORIGIN_FAILURE: &[u8] =
    b"ZODE_SERVER_STARTUP_FAILURE code=origin_missing phase=config";
const INVALID_ORIGIN_FAILURE: &[u8] =
    b"ZODE_SERVER_STARTUP_FAILURE code=origin_invalid phase=config";
const FIRST_CONTROL_STORE_FAILURE: &[u8] =
    b"ZODE_SERVER_STARTUP_FAILURE code=control_store_unavailable phase=control_store";
const FIRST_SCHEMA_FAILURE: &[u8] = b"server configuration JSON is invalid";

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[test]
fn e2e_server_requires_canonical_distinct_management_and_callback_origins_before_ready(
) -> TestResult {
    let cases = [
        OriginCase::new(
            "missing required origins",
            None,
            None,
            ObservedStartup::MissingOriginRejected,
            Some(MISSING_CASSETTE),
            "unexpected_server_ready_without_required_origins",
            FIRST_CONTROL_STORE_FAILURE,
        ),
        OriginCase::new(
            "valid distinct loopback origins",
            Some("http://127.0.0.1:18080"),
            Some("http://127.0.0.2:18080"),
            ObservedStartup::Ready,
            Some(VALID_CASSETTE),
            "valid_distinct_origins_rejected",
            FIRST_SCHEMA_FAILURE,
        )
        .with_followup(
            VALID_CONTROL_STORE_CASSETTE,
            VALID_CONTROL_STORE_CLASSIFICATION,
        ),
        OriginCase::new(
            "same management and callback origin",
            Some("https://same.origin-startup.test"),
            Some("https://same.origin-startup.test"),
            ObservedStartup::InvalidOriginRejected,
            Some(SAME_CASSETTE),
            "same_origins_schema_rejected_instead_of_canonical_validation",
            FIRST_SCHEMA_FAILURE,
        ),
        OriginCase::new(
            "different schemes with the same request authority",
            Some("http://127.0.0.1:18080"),
            Some("https://127.0.0.1:18080"),
            ObservedStartup::InvalidOriginRejected,
            Some(AMBIGUOUS_SCHEME_CASSETTE),
            "ambiguous_authorities_schema_rejected_instead_of_canonical_validation",
            FIRST_SCHEMA_FAILURE,
        ),
        OriginCase::new(
            "default port aliases the same request authority",
            Some("https://same-default.origin-startup.test"),
            Some("https://same-default.origin-startup.test:443"),
            ObservedStartup::InvalidOriginRejected,
            Some(DEFAULT_PORT_CASSETTE),
            "default_port_alias_schema_rejected_instead_of_canonical_validation",
            FIRST_SCHEMA_FAILURE,
        ),
        OriginCase::new(
            "origin with credentials",
            Some("https://user@management.origin-startup.test"),
            Some("https://callback.origin-startup.test"),
            ObservedStartup::InvalidOriginRejected,
            Some(CREDENTIAL_CASSETTE),
            "credential_origin_schema_rejected_instead_of_canonical_validation",
            FIRST_SCHEMA_FAILURE,
        ),
        OriginCase::new(
            "origin with non-root path",
            Some("https://management.origin-startup.test/path"),
            Some("https://callback.origin-startup.test"),
            ObservedStartup::InvalidOriginRejected,
            Some(PATH_CASSETTE),
            "path_origin_schema_rejected_instead_of_canonical_validation",
            FIRST_SCHEMA_FAILURE,
        ),
        OriginCase::new(
            "origin with query",
            Some("https://management.origin-startup.test?query=1"),
            Some("https://callback.origin-startup.test"),
            ObservedStartup::InvalidOriginRejected,
            Some(QUERY_CASSETTE),
            "query_origin_schema_rejected_instead_of_canonical_validation",
            FIRST_SCHEMA_FAILURE,
        ),
        OriginCase::new(
            "origin with fragment",
            Some("https://management.origin-startup.test#fragment"),
            Some("https://callback.origin-startup.test"),
            ObservedStartup::InvalidOriginRejected,
            Some(FRAGMENT_CASSETTE),
            "fragment_origin_schema_rejected_instead_of_canonical_validation",
            FIRST_SCHEMA_FAILURE,
        ),
        OriginCase::new(
            "non-loopback HTTP origin",
            Some("http://management.origin-startup.test"),
            Some("https://callback.origin-startup.test"),
            ObservedStartup::InvalidOriginRejected,
            Some(PUBLIC_HTTP_CASSETTE),
            "public_http_origin_schema_rejected_instead_of_canonical_validation",
            FIRST_SCHEMA_FAILURE,
        ),
        OriginCase::new(
            "unsupported origin scheme",
            Some("ftp://management.origin-startup.test"),
            Some("https://callback.origin-startup.test"),
            ObservedStartup::InvalidOriginRejected,
            Some(UNSUPPORTED_SCHEME_CASSETTE),
            "unsupported_scheme_schema_rejected_instead_of_canonical_validation",
            FIRST_SCHEMA_FAILURE,
        ),
        OriginCase::new(
            "origin without a host",
            Some("https:///"),
            Some("https://callback.origin-startup.test"),
            ObservedStartup::InvalidOriginRejected,
            Some(MISSING_HOST_CASSETTE),
            "missing_host_schema_rejected_instead_of_canonical_validation",
            FIRST_SCHEMA_FAILURE,
        ),
    ];
    let mut failures = Vec::new();

    for case in cases {
        if let Err(error) = run_case(&case) {
            failures.push(format!("{}: {error}", case.label));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(failures.join("; ")).into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservedStartup {
    Ready,
    MissingOriginRejected,
    InvalidOriginRejected,
    ControlStoreUnavailable,
    OtherRejection,
    TimedOut,
}

impl ObservedStartup {
    fn safe_name(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::MissingOriginRejected => "missing_origin_rejected_before_ready",
            Self::InvalidOriginRejected => "invalid_origin_rejected_before_ready",
            Self::ControlStoreUnavailable => "control_store_unavailable_before_ready",
            Self::OtherRejection => "other_rejection_before_ready",
            Self::TimedOut => "timed_out_before_ready",
        }
    }
}

struct OriginCase {
    label: &'static str,
    management_origin: Option<&'static str>,
    callback_origin: Option<&'static str>,
    expected: ObservedStartup,
    cassette: Option<&'static str>,
    classification: &'static str,
    first_stderr_marker: &'static [u8],
    followup_cassette: Option<&'static str>,
    followup_classification: Option<&'static str>,
}

impl OriginCase {
    const fn new(
        label: &'static str,
        management_origin: Option<&'static str>,
        callback_origin: Option<&'static str>,
        expected: ObservedStartup,
        cassette: Option<&'static str>,
        classification: &'static str,
        first_stderr_marker: &'static [u8],
    ) -> Self {
        Self {
            label,
            management_origin,
            callback_origin,
            expected,
            cassette,
            classification,
            first_stderr_marker,
            followup_cassette: None,
            followup_classification: None,
        }
    }

    const fn with_followup(mut self, cassette: &'static str, classification: &'static str) -> Self {
        self.followup_cassette = Some(cassette);
        self.followup_classification = Some(classification);
        self
    }

    fn incident_classification(&self, observed: ObservedStartup) -> &'static str {
        if observed == ObservedStartup::ControlStoreUnavailable {
            self.followup_classification.unwrap_or(self.classification)
        } else {
            self.classification
        }
    }

    fn incident_destination(&self, observed: ObservedStartup) -> Option<PathBuf> {
        if observed == ObservedStartup::ControlStoreUnavailable {
            self.followup_cassette.or(self.cassette).map(cassette_path)
        } else {
            self.cassette.map(cassette_path)
        }
    }
}

fn run_case(case: &OriginCase) -> TestResult {
    let temp = tempfile::tempdir()?;
    prepare_root(temp.path())?;
    let primary_cassette = case.cassette.map(cassette_path);
    if let (Some(destination), Some(raw_root)) = (
        primary_cassette.as_ref().filter(|path| !path.exists()),
        env::var_os(RECOVER_ENV).map(PathBuf::from),
    ) {
        let observation = recover_first_capture(case, temp.path(), &raw_root, destination)?;
        return Err(io::Error::other(format!(
            "expected {:?}, replayed retained first occurrence as {}; immutable cassette recovered at {}",
            case.expected,
            observation.startup.safe_name(),
            destination.display()
        ))
        .into());
    }
    let followup_cassette = case.followup_cassette.map(cassette_path);
    let selected_cassette = followup_cassette
        .as_ref()
        .filter(|path| path.exists())
        .or_else(|| primary_cassette.as_ref().filter(|path| path.exists()));
    let config = match selected_cassette {
        Some(path) => {
            let replay = ProcessIncidentReplay::load(path, E2E_NAME, &[SECRET_MARKER])?;
            let expected_classification = if followup_cassette.as_ref() == Some(path) {
                case.followup_classification
                    .ok_or_else(|| io::Error::other("follow-up cassette has no classification"))?
            } else {
                case.classification
            };
            if replay.config_label() != case.label
                || replay.classification() != expected_classification
                || replay.first_observed().is_empty()
            {
                return Err(io::Error::other(
                    "tracked process cassette does not belong to its origin case",
                )
                .into());
            }
            let config = replay.config_bytes().to_vec();
            if followup_cassette.as_ref() == Some(path) {
                let primary = ProcessIncidentReplay::load(
                    primary_cassette
                        .as_ref()
                        .ok_or_else(|| io::Error::other("follow-up cassette has no primary"))?,
                    E2E_NAME,
                    &[SECRET_MARKER],
                )?;
                if primary.config_label() != case.label
                    || primary.classification() != case.classification
                    || primary.config_bytes() != config
                {
                    return Err(io::Error::other(
                        "follow-up process cassette changed its primary config",
                    )
                    .into());
                }
            }
            config
        }
        None => config_bytes(case)?,
    };
    let quarantine = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-recordings/quarantine/server-origin-startup");
    let mut capture = ProcessCaptureSet::new(&quarantine, E2E_NAME, &[SECRET_MARKER])?;
    capture.capture_config(case.label, &config)?;
    let observation = observe_server(temp.path(), &config)?;
    if observation.startup == case.expected {
        assert_case_side_effects(case, temp.path())?;
        return Ok(());
    }

    capture.capture_process(observation.process_observation())?;
    let first_observed = format!("{}={}", case.label, observation.startup.safe_name());
    let classification = case.incident_classification(observation.startup);
    let raw = capture.flush(classification, &first_observed)?;
    let destination = case.incident_destination(observation.startup);
    if let (true, Some(destination)) = (
        env::var_os(CAPTURE_ENV).is_some(),
        destination.as_ref().filter(|path| !path.exists()),
    ) {
        promote_first_capture(
            case,
            classification,
            temp.path(),
            &capture,
            &raw,
            destination,
            observation.startup,
        )?;
    }

    Err(io::Error::other(format!(
        "expected {:?}, observed {}; first occurrence retained at {}",
        case.expected,
        observation.startup.safe_name(),
        raw.display()
    ))
    .into())
}

fn recover_first_capture(
    case: &OriginCase,
    replay_root: &Path,
    raw_root: &Path,
    destination: &Path,
) -> TestResult<ServerObservation> {
    let replay = find_retained_first_capture(case, raw_root)?;
    let observation = observe_server(replay_root, replay.config_bytes())?;
    let observed = format!("{}={}", case.label, observation.startup.safe_name());
    if replay.first_observed() != observed
        || !contains(&observation.stderr, case.first_stderr_marker)
        || observation.startup == case.expected
    {
        return Err(io::Error::other(
            "retained first occurrence did not replay the same public startup failure",
        )
        .into());
    }
    let proof = replay_proof(&replay, observation.startup);
    replay.promote_immutable(destination, &proof, &[SECRET_MARKER])?;
    Ok(observation)
}

fn find_retained_first_capture(
    case: &OriginCase,
    raw_root: &Path,
) -> TestResult<ProcessIncidentReplay> {
    let metadata = fs::symlink_metadata(raw_root)?;
    if !metadata.file_type().is_dir() {
        return Err(io::Error::other("process incident recovery root is not a directory").into());
    }
    let mut matched = Vec::new();
    for entry in fs::read_dir(raw_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path().join("capture.v1.json");
        if !path.exists() {
            continue;
        }
        let replay = ProcessIncidentReplay::load(&path, E2E_NAME, &[SECRET_MARKER])?;
        if replay.config_label() == case.label && replay.classification() == case.classification {
            matched.push(replay);
        }
    }
    if matched.len() != 1 {
        return Err(io::Error::other(format!(
            "expected one retained first occurrence for {}, found {}",
            case.label,
            matched.len()
        ))
        .into());
    }
    Ok(matched.pop().expect("one retained process incident"))
}

fn replay_proof(replay: &ProcessIncidentReplay, observed: ObservedStartup) -> ProcessReplayProof {
    let fingerprint = format!(
        "{:x}",
        Sha256::digest(
            format!(
                "{}\0{}\0{}",
                replay.classification(),
                replay.first_observed(),
                observed.safe_name()
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

fn promote_first_capture(
    case: &OriginCase,
    classification: &str,
    first_root: &Path,
    capture: &ProcessCaptureSet,
    raw: &Path,
    destination: &Path,
    first: ObservedStartup,
) -> TestResult {
    let replay = ProcessIncidentReplay::load(raw, E2E_NAME, &[SECRET_MARKER])?;
    if replay.config_label() != case.label
        || replay.classification() != classification
        || replay.first_observed().is_empty()
    {
        return Err(
            io::Error::other("process incident replay metadata did not match its case").into(),
        );
    }
    let replay_root = first_root.join("same-entry-replay");
    fs::create_dir(&replay_root)?;
    prepare_root(&replay_root)?;
    let second = observe_server(&replay_root, replay.config_bytes())?;
    if second.startup != first {
        return Err(io::Error::other(format!(
            "same-entry process replay changed from {} to {}",
            first.safe_name(),
            second.startup.safe_name()
        ))
        .into());
    }
    capture.promote_immutable(destination, &replay_proof(&replay, second.startup))?;
    Ok(())
}

fn prepare_root(root: &Path) -> TestResult {
    fs::create_dir_all(root.join("secrets"))?;
    let subject_key = root.join("subject.key");
    fs::write(&subject_key, SECRET_MARKER.as_bytes())?;
    restrict_file(&subject_key)?;
    Ok(())
}

fn config_bytes(case: &OriginCase) -> TestResult<Vec<u8>> {
    let mut config = base_config_value();
    match (case.management_origin, case.callback_origin) {
        (None, None) => {}
        (Some(management), Some(callback)) => set_origins(&mut config, management, callback)?,
        (Some(_), None) | (None, Some(_)) => {
            return Err(io::Error::other("test case defined only one origin").into())
        }
    }
    Ok(serde_json::to_vec_pretty(&config)?)
}

fn base_config_value() -> Value {
    json!({
        "schema": "zode.server-config.v1",
        "listen": "127.0.0.1:0",
        "server_authority_id": SERVER_AUTHORITY,
        "deployment": "server_only",
        "ui_mode": "api_only",
        "control_database": "control.sqlite",
        "secret_directory": "secrets",
        "access": {
            "issuer": "https://access.origin-startup.invalid/",
            "audiences": ["origin-startup-e2e"],
            "jwks_url": "https://access.origin-startup.invalid/cdn-cgi/access/certs",
            "subject_key_file": "subject.key",
            "subject_key_version": 1
        }
    })
}

fn set_origins(config: &mut Value, management: &str, callback: &str) -> TestResult {
    let object = config
        .as_object_mut()
        .ok_or_else(|| io::Error::other("test config was not an object"))?;
    object.insert(
        "management_origin".to_owned(),
        Value::String(management.to_owned()),
    );
    object.insert(
        "callback_origin".to_owned(),
        Value::String(callback.to_owned()),
    );
    Ok(())
}

fn assert_case_side_effects(case: &OriginCase, root: &Path) -> TestResult {
    let database_exists = root.join("control.sqlite").exists();
    match case.expected {
        ObservedStartup::Ready if !database_exists => {
            Err(io::Error::other("ready Server did not initialize its control store").into())
        }
        ObservedStartup::MissingOriginRejected | ObservedStartup::InvalidOriginRejected
            if database_exists =>
        {
            Err(io::Error::other(
                "origin-invalid Server touched its control store before rejecting configuration",
            )
            .into())
        }
        ObservedStartup::TimedOut => {
            Err(io::Error::other("timed out startup cannot satisfy an origin case").into())
        }
        ObservedStartup::OtherRejection => {
            Err(io::Error::other("an unrelated rejection cannot satisfy an origin case").into())
        }
        ObservedStartup::ControlStoreUnavailable => {
            Err(io::Error::other("a control-store failure cannot satisfy an origin case").into())
        }
        ObservedStartup::Ready
        | ObservedStartup::MissingOriginRejected
        | ObservedStartup::InvalidOriginRejected => Ok(()),
    }
}

struct ServerObservation {
    startup: ObservedStartup,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: ExitStatus,
    pid: u32,
    killed_by_test: bool,
}

impl ServerObservation {
    fn process_observation(&self) -> ProcessObservation {
        ProcessObservation {
            name: "zode-server".to_owned(),
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
            exit_code: self.status.code(),
            signal: exit_signal(&self.status).map(|signal| signal.to_string()),
            termination: if self.killed_by_test {
                "test_stop_after_observation"
            } else {
                "process_exit"
            }
            .to_owned(),
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

fn observe_server(root: &Path, config: &[u8]) -> TestResult<ServerObservation> {
    observe_server_run(root, root, "server.json", config)
}

fn observe_server_run(
    config_root: &Path,
    run_root: &Path,
    config_name: &str,
    config: &[u8],
) -> TestResult<ServerObservation> {
    fs::create_dir_all(run_root)?;
    let config_path = config_root.join(config_name);
    fs::write(&config_path, config)?;
    let stdout_path = run_root.join("server.stdout");
    let stderr_path = run_root.join("server.stderr");
    let stdout = private_log(&stdout_path)?;
    let stderr = private_log(&stderr_path)?;
    let mut child = Command::new(server_binary()?)
        .current_dir(config_root)
        .arg("--config")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?;
    let pid = child.id();
    let deadline = Instant::now() + START_TIMEOUT;
    let mut startup = ObservedStartup::TimedOut;
    let mut killed_by_test = false;

    loop {
        if contains(&fs::read(&stdout_path)?, READY_PREFIX) {
            startup = ObservedStartup::Ready;
            child.kill()?;
            killed_by_test = true;
            break;
        }
        if child.try_wait()?.is_some() {
            startup = ObservedStartup::OtherRejection;
            break;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            killed_by_test = true;
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }

    let status = child.wait()?;
    sync_file(&stdout_path)?;
    sync_file(&stderr_path)?;
    let stdout = read_bounded(&stdout_path, 4 * 1024 * 1024)?;
    let stderr = read_bounded(&stderr_path, 4 * 1024 * 1024)?;
    if startup == ObservedStartup::OtherRejection {
        startup = classify_rejection(&stderr);
    }
    if contains(&stdout, SECRET_MARKER.as_bytes()) || contains(&stderr, SECRET_MARKER.as_bytes()) {
        return Err(
            io::Error::other("Server process output contained the subject key marker").into(),
        );
    }
    Ok(ServerObservation {
        startup,
        stdout,
        stderr,
        status,
        pid,
        killed_by_test,
    })
}

fn classify_rejection(stderr: &[u8]) -> ObservedStartup {
    if contains(stderr, MISSING_ORIGIN_FAILURE) {
        ObservedStartup::MissingOriginRejected
    } else if contains(stderr, INVALID_ORIGIN_FAILURE) {
        ObservedStartup::InvalidOriginRejected
    } else if contains(stderr, FIRST_CONTROL_STORE_FAILURE) {
        ObservedStartup::ControlStoreUnavailable
    } else {
        ObservedStartup::OtherRejection
    }
}

fn private_log(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn sync_file(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn read_bounded(path: &Path, maximum: usize) -> TestResult<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(maximum + 1);
    file.take((maximum + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(io::Error::other("Server process output exceeded its test bound").into());
    }
    Ok(bytes)
}

fn server_binary() -> TestResult<PathBuf> {
    env::var_os("ZODE_SERVER_BIN")
        .or_else(|| env::var_os("CARGO_BIN_EXE_zode-server"))
        .or_else(|| env::var_os("CARGO_BIN_EXE_zode_server"))
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "zode-server binary is unavailable").into()
        })
}

fn cassette_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn restrict_file(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(unix)]
fn exit_signal(status: &ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn exit_signal(_status: &ExitStatus) -> Option<i32> {
    None
}

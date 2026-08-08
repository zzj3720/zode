#[path = "../../tests/support/process_capture.rs"]
mod process_capture;

use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs::{self, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{mpsc, Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use process_capture::{
    ProcessCaptureSet, ProcessIncidentReplay, ProcessObservation, ProcessReplayProof,
    ProcessStopObservation,
};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const READY_PREFIX: &str = "ZODE_SERVER_READY ";
const STARTUP_FAILURE_PREFIX: &str = "ZODE_SERVER_STARTUP_FAILURE ";
const MISSING_SUBJECT_KEY_FAILURE: &str = "code=missing_subject_key phase=access_subject_key";
const SERVER_ALREADY_OWNED_FAILURE: &str = "code=server_already_owned phase=server_store_lock";
const CONTROL_STORE_INTEGRITY_FAILURE: &str = "code=control_store_integrity phase=control_store";
const CAPTURE_FIRST_OCCURRENCE_ENV: &str = "ZODE_CAPTURE_FIRST_OCCURRENCE";
const METADATA_CAPTURE_ENV: &str = "ZODE_CAPTURE_READINESS_METADATA_LATER_GAP";
const METADATA_RECOVER_ENV: &str = "ZODE_RECOVER_READINESS_METADATA_LATER_GAP";
const METADATA_E2E: &str = "e2e_initialized_server_missing_metadata_never_reinitializes";
const METADATA_RELATION: &str = "later_test_reproduction_of_gap";
const METADATA_CLASSIFICATION: &str =
    "CONTROL_STORE_METADATA_DAMAGE_MUTATED_PERSISTENT_FILES__later_test_reproduction_of_gap";
const METADATA_FIRST_OBSERVED: &str = "relation=later_test_reproduction_of_gap; startup=non_ready_bind_failure_after_metadata_recreation; singleton_row_store_unchanged=false; metadata_table_store_unchanged=false";
const METADATA_CASSETTE: &str =
    "tests/fixtures/incidents/server-readiness-missing-metadata-later-gap.v1.json";
const ALIAS_CAPTURE_ENV: &str = "ZODE_CAPTURE_READINESS_DATABASE_ALIAS_LATER_GAP";
const ALIAS_RECOVER_EXACT_ENV: &str = "ZODE_RECOVER_READINESS_DATABASE_ALIAS_EXACT_LATER_GAP";
const ALIAS_RECOVER_HARDLINK_ENV: &str = "ZODE_RECOVER_READINESS_DATABASE_ALIAS_HARDLINK_LATER_GAP";
const ALIAS_E2E: &str =
    "e2e_second_server_control_database_alias_with_distinct_secret_store_never_becomes_ready";
const ALIAS_RELATION: &str = "later_test_reproduction_of_gap";
const ALIAS_CLASSIFICATION: &str =
    "CONTROL_STORE_DATABASE_ALIAS_REJECTION_MISCLASSIFIED__later_test_reproduction_of_gap";
const STARTUP_FAILURE_EXIT_CODE: i32 = 1;
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const SERVER_AUTHORITY: &str = "readiness-e2e-authority";
const SECRET_MARKER: &str = "readiness-e2e-secret-marker";

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[test]
fn e2e_server_missing_subject_key_never_becomes_ready() -> TestResult {
    let temp = tempfile::tempdir()?;
    let config = ConfigFixture::new(temp.path())?;

    let mut baseline = ServerChild::spawn(&config.config_path)?;
    let baseline_observation = baseline.observe(READY_TIMEOUT)?;
    let baseline_running =
        matches!(&baseline_observation, Observation::Ready) && baseline.is_running()?;
    let baseline_stopped = baseline.stop()?;
    assert_safe_output(
        "missing-key baseline",
        &baseline_stopped,
        &config.forbidden_markers(),
    )?;
    if !baseline_running || !baseline_stopped.contains_ready() {
        return Err(io::Error::other(
            "existing subject key did not establish a stable READY baseline",
        )
        .into());
    }

    fs::remove_file(&config.subject_key_file)?;
    let before_failure = config.live_store_snapshot()?;
    let mut server = ServerChild::spawn(&config.config_path)?;
    let observation = server.observe(READY_TIMEOUT)?;
    let stopped = server.stop()?;
    let startup_result = assert_startup_failure(
        "missing subject key",
        &observation,
        &stopped,
        MISSING_SUBJECT_KEY_FAILURE,
        &config.forbidden_markers(),
    );
    let after_failure = config.live_store_snapshot()?;
    if before_failure != after_failure {
        return Err(
            io::Error::other("missing subject key startup changed control store files").into(),
        );
    }
    config.assert_persistent_secret_free()?;
    startup_result
}

#[test]
fn e2e_server_corrupt_existing_control_store_failure_removes_new_ownership_sidecars() -> TestResult
{
    let temp = tempfile::tempdir()?;
    let config = ConfigFixture::new(temp.path())?;
    let corrupt = Connection::open(&config.control_database)?;
    corrupt.execute_batch(
        "PRAGMA journal_mode=DELETE;
         CREATE TABLE unrelated_corruption(value INTEGER);
         INSERT INTO unrelated_corruption(value) VALUES (1);",
    )?;
    drop(corrupt);
    restrict_file(&config.control_database)?;
    let before = config.live_store_snapshot()?;
    let mut server = ServerChild::spawn(&config.config_path)?;
    let observation = server.observe(READY_TIMEOUT)?;
    let stopped = server.stop()?;
    let after = config.live_store_snapshot()?;
    let forbidden = config.forbidden_markers();
    assert_safe_output("corrupt existing control store", &stopped, &forbidden)?;
    let capture = capture_first_readiness_failure(
        "server-readiness-corrupt-existing-v1",
        "e2e_server_corrupt_existing_control_store_failure_removes_new_ownership_sidecars",
        "corrupt existing control store must not leave ownership sidecars",
        config.listen_addr,
        CONTROL_STORE_INTEGRITY_FAILURE,
        &observation,
        false,
        &stopped,
        &before,
        &after,
        &forbidden,
    );
    let startup = assert_startup_failure(
        "corrupt existing control store",
        &observation,
        &stopped,
        CONTROL_STORE_INTEGRITY_FAILURE,
        &forbidden,
    );
    assert_listen_released(config.listen_addr)?;
    if before != after {
        return Err(io::Error::other(
            "corrupt-store startup changed the persistent store file set/content/mode",
        )
        .into());
    }
    let file_name = config
        .control_database
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("control database had no usable filename"))?;
    let [wal, shm] = sqlite_sidecars(&config.control_database)?;
    for path in [
        config
            .control_database
            .with_file_name(format!("{file_name}.server.lock")),
        config
            .control_database
            .with_file_name(format!("{file_name}.server.lock.anchor")),
        config
            .control_database
            .with_file_name(format!("{file_name}.server-owner")),
        wal,
        shm,
    ] {
        if path.exists() {
            return Err(io::Error::other(format!(
                "corrupt-store startup left ownership/SQLite sidecar {}",
                path.display()
            ))
            .into());
        }
    }
    config.assert_persistent_secret_free()?;
    capture?;
    startup
}

#[test]
fn e2e_server_zero_byte_existing_control_store_failure_removes_new_ownership_sidecars() -> TestResult
{
    let temp = tempfile::tempdir()?;
    let config = ConfigFixture::new(temp.path())?;
    let empty = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&config.control_database)?;
    empty.sync_all()?;
    drop(empty);
    restrict_file(&config.control_database)?;
    let before = config.live_store_snapshot()?;
    let mut server = ServerChild::spawn(&config.config_path)?;
    let observation = server.observe(READY_TIMEOUT)?;
    let stopped = server.stop()?;
    let after = config.live_store_snapshot()?;
    let forbidden = config.forbidden_markers();
    assert_safe_output("zero-byte existing control store", &stopped, &forbidden)?;
    let capture = capture_first_readiness_failure(
        "server-readiness-zero-byte-existing-v1",
        "e2e_server_zero_byte_existing_control_store_failure_removes_new_ownership_sidecars",
        "zero-byte existing control store must not leave ownership sidecars",
        config.listen_addr,
        CONTROL_STORE_INTEGRITY_FAILURE,
        &observation,
        false,
        &stopped,
        &before,
        &after,
        &forbidden,
    );
    let startup = assert_startup_failure(
        "zero-byte existing control store",
        &observation,
        &stopped,
        CONTROL_STORE_INTEGRITY_FAILURE,
        &forbidden,
    );
    assert_listen_released(config.listen_addr)?;
    if before != after {
        return Err(io::Error::other(
            "zero-byte-store startup changed the persistent store file set/content/mode",
        )
        .into());
    }
    let file_name = config
        .control_database
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("control database had no usable filename"))?;
    let [wal, shm] = sqlite_sidecars(&config.control_database)?;
    for path in [
        config
            .control_database
            .with_file_name(format!("{file_name}.server.lock")),
        config
            .control_database
            .with_file_name(format!("{file_name}.server.lock.anchor")),
        config
            .control_database
            .with_file_name(format!("{file_name}.server-owner")),
        wal,
        shm,
    ] {
        if path.exists() {
            return Err(io::Error::other(format!(
                "zero-byte-store startup left ownership/SQLite sidecar {}",
                path.display()
            ))
            .into());
        }
    }
    config.assert_persistent_secret_free()?;
    capture?;
    startup
}

#[cfg(unix)]
#[test]
fn e2e_server_existing_control_store_owner_marker_identity_mismatch_failure_removes_new_ownership_sidecars(
) -> TestResult {
    let temp = tempfile::tempdir()?;
    let config = ConfigFixture::new(temp.path())?;
    establish_ready_baseline(&config, "owner marker identity mismatch")?;
    let file_name = config
        .control_database
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("control database had no usable filename"))?;
    let lock_path = config.root.join(format!("{file_name}.server.lock"));
    let anchor_path = config.root.join(format!("{file_name}.server.lock.anchor"));
    let owner_marker = config.root.join(format!("{file_name}.server-owner"));
    let mut marker = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&owner_marker)?;
    marker.write_all(&[b'X'; 32])?;
    marker.sync_all()?;
    drop(marker);
    restrict_file(&owner_marker)?;
    fs::rename(&lock_path, config.root.join("control-marker-lock.original"))?;
    fs::rename(
        &anchor_path,
        config.root.join("control-marker-anchor.original"),
    )?;
    let before = config.live_store_snapshot()?;
    let mut server = ServerChild::spawn(&config.config_path)?;
    let observation = server.observe(READY_TIMEOUT)?;
    let stopped = server.stop()?;
    let after = config.live_store_snapshot()?;
    let forbidden = config.forbidden_markers();
    assert_safe_output("owner marker identity mismatch", &stopped, &forbidden)?;
    let capture = capture_first_readiness_failure(
        "server-readiness-owner-marker-identity-v1",
        "e2e_server_existing_control_store_owner_marker_identity_mismatch_failure_removes_new_ownership_sidecars",
        "owner marker identity mismatch must not create replacement sidecars",
        config.listen_addr,
        SERVER_ALREADY_OWNED_FAILURE,
        &observation,
        false,
        &stopped,
        &before,
        &after,
        &forbidden,
    );
    let startup = assert_startup_failure(
        "owner marker identity mismatch",
        &observation,
        &stopped,
        SERVER_ALREADY_OWNED_FAILURE,
        &forbidden,
    );
    assert_listen_released(config.listen_addr)?;
    if before != after {
        return Err(io::Error::other(
            "owner marker identity mismatch changed the persistent store file set/content/mode",
        )
        .into());
    }
    let [wal, shm] = sqlite_sidecars(&config.control_database)?;
    for path in [lock_path, anchor_path, wal, shm] {
        if path.exists() {
            return Err(io::Error::other(format!(
                "owner marker identity mismatch left replacement sidecar {}",
                path.display()
            ))
            .into());
        }
    }
    config.assert_persistent_secret_free()?;
    capture?;
    startup
}

#[cfg(unix)]
#[test]
fn e2e_server_existing_control_store_lock_marker_identity_mismatch_failure_removes_new_ownership_sidecars(
) -> TestResult {
    let temp = tempfile::tempdir()?;
    let config = ConfigFixture::new(temp.path())?;
    establish_ready_baseline(&config, "lock marker identity mismatch")?;
    let file_name = config
        .control_database
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("control database had no usable filename"))?;
    let lock_path = config.root.join(format!("{file_name}.server.lock"));
    let anchor_path = config.root.join(format!("{file_name}.server.lock.anchor"));
    let owner_marker = config.root.join(format!("{file_name}.server-owner"));
    let secret_owner_marker = config.secret_directory.join(".server-owner");
    for path in [&owner_marker, &secret_owner_marker] {
        let mut identity = fs::read(path)?;
        if identity.len() != 32 {
            return Err(io::Error::other("owner marker had an unexpected identity length").into());
        }
        identity[16..].fill(b'Y');
        let mut marker = OpenOptions::new().write(true).truncate(true).open(path)?;
        marker.write_all(&identity)?;
        marker.sync_all()?;
        drop(marker);
        restrict_file(path)?;
    }
    fs::rename(
        &lock_path,
        config.root.join("control-lock-marker-lock.original"),
    )?;
    fs::rename(
        &anchor_path,
        config.root.join("control-lock-marker-anchor.original"),
    )?;
    let before = config.live_store_snapshot()?;
    let mut server = ServerChild::spawn(&config.config_path)?;
    let observation = server.observe(READY_TIMEOUT)?;
    let stopped = server.stop()?;
    let after = config.live_store_snapshot()?;
    let forbidden = config.forbidden_markers();
    assert_safe_output("lock marker identity mismatch", &stopped, &forbidden)?;
    let capture = capture_first_readiness_failure(
        "server-readiness-lock-marker-identity-v1",
        "e2e_server_existing_control_store_lock_marker_identity_mismatch_failure_removes_new_ownership_sidecars",
        "lock marker identity mismatch must not create replacement sidecars",
        config.listen_addr,
        SERVER_ALREADY_OWNED_FAILURE,
        &observation,
        false,
        &stopped,
        &before,
        &after,
        &forbidden,
    );
    let startup = assert_startup_failure(
        "lock marker identity mismatch",
        &observation,
        &stopped,
        SERVER_ALREADY_OWNED_FAILURE,
        &forbidden,
    );
    assert_listen_released(config.listen_addr)?;
    if before != after {
        return Err(io::Error::other(
            "lock marker identity mismatch changed the persistent store file set/content/mode",
        )
        .into());
    }
    let [wal, shm] = sqlite_sidecars(&config.control_database)?;
    for path in [lock_path, anchor_path, wal, shm] {
        if path.exists() {
            return Err(io::Error::other(format!(
                "lock marker identity mismatch left replacement sidecar {}",
                path.display()
            ))
            .into());
        }
    }
    config.assert_persistent_secret_free()?;
    capture?;
    startup
}

#[test]
fn e2e_second_server_on_same_stores_never_becomes_ready() -> TestResult {
    let temp = tempfile::tempdir()?;
    let config = ConfigFixture::new(temp.path())?;

    let mut first = ServerChild::spawn(&config.config_path)?;
    let first_observation = first.observe(READY_TIMEOUT)?;
    let first_stopped_before_second =
        if matches!(&first_observation, Observation::Ready) && first.is_running()? {
            None
        } else {
            Some(first.stop()?)
        };
    if let Some(stopped) = first_stopped_before_second {
        assert_safe_output(
            "first server readiness",
            &stopped,
            &config.forbidden_markers(),
        )?;
        if stopped.contains_ready() {
            return Err(io::Error::other(
                "first server emitted READY before becoming a stable owner",
            )
            .into());
        }
        return Err(io::Error::other(first_observation.failure_summary("first server")).into());
    }
    if !first.is_running()? {
        let stopped = first.stop()?;
        assert_safe_output(
            "first server after READY",
            &stopped,
            &config.forbidden_markers(),
        )?;
        return Err(io::Error::other("first server exited immediately after READY").into());
    }

    let before_second = config.live_store_snapshot()?;
    let mut second = ServerChild::spawn(&config.config_path)?;
    let second_observation = second.observe(READY_TIMEOUT)?;
    let second_stopped = second.stop()?;
    let startup_result = assert_startup_failure(
        "second server same stores",
        &second_observation,
        &second_stopped,
        SERVER_ALREADY_OWNED_FAILURE,
        &config.forbidden_markers(),
    );
    let after_second = config.live_store_snapshot()?;
    if before_second != after_second {
        let first_stopped = first.stop()?;
        assert_safe_output(
            "first server after second store mutation",
            &first_stopped,
            &config.forbidden_markers(),
        )?;
        return Err(io::Error::other("second server changed store files").into());
    }
    if !first.is_running()? {
        let first_stopped = first.stop()?;
        assert_safe_output(
            "first server after second rejection",
            &first_stopped,
            &config.forbidden_markers(),
        )?;
        return Err(io::Error::other(
            "first server did not remain running while second was rejected",
        )
        .into());
    }

    let first_stopped = first.graceful_stop()?;
    assert_safe_output(
        "first server after second rejection",
        &first_stopped,
        &config.forbidden_markers(),
    )?;

    let mut replacement = ServerChild::spawn(&config.config_path)?;
    let replacement_observation = replacement.observe(READY_TIMEOUT)?;
    let replacement_running =
        matches!(&replacement_observation, Observation::Ready) && replacement.is_running()?;
    let replacement_stopped = replacement.stop()?;
    assert_safe_output(
        "replacement server after first exit",
        &replacement_stopped,
        &config.forbidden_markers(),
    )?;
    if replacement_stopped.contains_ready()
        && !matches!(&replacement_observation, Observation::Ready)
    {
        return Err(io::Error::other(
            "replacement server emitted READY but the readiness barrier was lost",
        )
        .into());
    }
    config.assert_persistent_secret_free()?;
    startup_result?;
    match replacement_observation {
        Observation::Ready if replacement_running => Ok(()),
        Observation::Ready => Err(io::Error::other(
            "replacement server emitted READY but was not still running",
        )
        .into()),
        Observation::Exited(status) => Err(io::Error::other(format!(
            "replacement server exited before READY ({})",
            status_summary(&status),
        ))
        .into()),
        Observation::TimedOut => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "replacement server did not become ready after the first server exited",
        )
        .into()),
    }
}

#[cfg(unix)]
#[test]
fn e2e_server_control_lock_sidecar_replacement_cannot_allow_second_owner() -> TestResult {
    let temp = tempfile::tempdir()?;
    let config = ConfigFixture::new(temp.path())?;
    let mut first = ServerChild::spawn(&config.config_path)?;
    let first_observation = first.observe(READY_TIMEOUT)?;
    if !matches!(first_observation, Observation::Ready) || !first.is_running()? {
        let stopped = first.stop()?;
        assert_safe_output(
            "first lock-sidecar owner",
            &stopped,
            &config.forbidden_markers(),
        )?;
        return Err(io::Error::other(
            "first Server did not establish the lock-sidecar ownership baseline",
        )
        .into());
    }

    let lock_path = config
        .control_database
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| config.root.join(format!("{name}.server.lock")))
        .ok_or_else(|| io::Error::other("control database had no usable filename"))?;
    let lock_backup = config.root.join("control-readiness-lock.original");
    fs::rename(&lock_path, &lock_backup)?;
    let replacement = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)?;
    replacement.sync_all()?;
    drop(replacement);
    restrict_file(&lock_path)?;

    let peer_secret_directory = config.root.join("peer-lock-secret");
    fs::create_dir(&peer_secret_directory)?;
    let (peer_config, peer_listen_addr) = config.write_peer_config(
        "peer-lock-replacement.json",
        &config.control_database,
        &peer_secret_directory,
    )?;
    let mut second = ServerChild::spawn(&peer_config)?;
    let second_observation = second.observe(READY_TIMEOUT)?;
    let second_stopped = second.stop()?;
    let first_stopped = first.graceful_stop()?;
    let forbidden =
        config.forbidden_markers_for(&[peer_secret_directory.as_path(), peer_config.as_path()]);
    assert_safe_output(
        "lock-sidecar replacement second Server",
        &second_stopped,
        &forbidden,
    )?;
    assert_safe_output(
        "lock-sidecar replacement first Server",
        &first_stopped,
        &forbidden,
    )?;
    assert_listen_released(peer_listen_addr)?;
    assert_startup_failure(
        "lock-sidecar replacement second Server",
        &second_observation,
        &second_stopped,
        CONTROL_STORE_INTEGRITY_FAILURE,
        &forbidden,
    )
}

#[cfg(unix)]
#[test]
fn e2e_server_control_lock_sidecar_hardlink_is_rejected_before_ready() -> TestResult {
    let temp = tempfile::tempdir()?;
    let config = ConfigFixture::new(temp.path())?;
    let lock_path = config
        .control_database
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| config.root.join(format!("{name}.server.lock")))
        .ok_or_else(|| io::Error::other("control database had no usable filename"))?;
    let hardlink_path = config.root.join("control-readiness-lock-peer");
    let lock = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)?;
    lock.sync_all()?;
    drop(lock);
    restrict_file(&lock_path)?;
    fs::hard_link(&lock_path, &hardlink_path)?;

    let mut server = ServerChild::spawn(&config.config_path)?;
    let observation = server.observe(READY_TIMEOUT)?;
    let stopped = server.stop()?;
    let forbidden = config.forbidden_markers_for(&[hardlink_path.as_path()]);
    assert_safe_output("multiply-linked lock sidecar", &stopped, &forbidden)?;
    assert_listen_released(config.listen_addr)?;
    assert_startup_failure(
        "multiply-linked lock sidecar",
        &observation,
        &stopped,
        SERVER_ALREADY_OWNED_FAILURE,
        &forbidden,
    )
}

#[cfg(unix)]
#[test]
fn e2e_server_control_lock_pair_replacement_cannot_allow_second_owner() -> TestResult {
    let temp = tempfile::tempdir()?;
    let config = ConfigFixture::new(temp.path())?;
    let mut first = ServerChild::spawn(&config.config_path)?;
    let first_observation = first.observe(READY_TIMEOUT)?;
    if !matches!(first_observation, Observation::Ready) || !first.is_running()? {
        let stopped = first.stop()?;
        assert_safe_output(
            "first lock-pair owner",
            &stopped,
            &config.forbidden_markers(),
        )?;
        return Err(io::Error::other(
            "first Server did not establish the lock-pair ownership baseline",
        )
        .into());
    }

    let lock_path = config
        .control_database
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| config.root.join(format!("{name}.server.lock")))
        .ok_or_else(|| io::Error::other("control database had no usable filename"))?;
    let anchor_path = config
        .control_database
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| config.root.join(format!("{name}.server.lock.anchor")))
        .ok_or_else(|| io::Error::other("control database had no usable filename"))?;
    fs::rename(
        &lock_path,
        config.root.join("control-readiness-lock.original"),
    )?;
    fs::rename(
        &anchor_path,
        config.root.join("control-readiness-anchor.original"),
    )?;
    let replacement = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)?;
    replacement.sync_all()?;
    drop(replacement);
    restrict_file(&lock_path)?;
    fs::hard_link(&lock_path, &anchor_path)?;

    let peer_secret_directory = config.root.join("peer-lock-pair-secret");
    fs::create_dir(&peer_secret_directory)?;
    let (peer_config, peer_listen_addr) = config.write_peer_config(
        "peer-lock-pair-replacement.json",
        &config.control_database,
        &peer_secret_directory,
    )?;
    let mut second = ServerChild::spawn(&peer_config)?;
    let second_observation = second.observe(READY_TIMEOUT)?;
    let second_stopped = second.stop()?;
    let first_stopped = first.graceful_stop()?;
    let forbidden =
        config.forbidden_markers_for(&[peer_secret_directory.as_path(), peer_config.as_path()]);
    assert_safe_output(
        "lock-pair replacement second Server",
        &second_stopped,
        &forbidden,
    )?;
    assert_safe_output(
        "lock-pair replacement first Server",
        &first_stopped,
        &forbidden,
    )?;
    assert_listen_released(peer_listen_addr)?;
    assert_startup_failure(
        "lock-pair replacement second Server",
        &second_observation,
        &second_stopped,
        CONTROL_STORE_INTEGRITY_FAILURE,
        &forbidden,
    )
}

#[cfg(unix)]
#[test]
fn e2e_server_control_owner_markers_removal_and_lock_pair_replacement_cannot_allow_second_owner(
) -> TestResult {
    let temp = tempfile::tempdir()?;
    let config = ConfigFixture::new(temp.path())?;
    let mut first = ServerChild::spawn(&config.config_path)?;
    let first_observation = first.observe(READY_TIMEOUT)?;
    if !matches!(first_observation, Observation::Ready) || !first.is_running()? {
        let stopped = first.stop()?;
        assert_safe_output(
            "first owner-marker owner",
            &stopped,
            &config.forbidden_markers(),
        )?;
        return Err(
            io::Error::other("first Server did not establish the owner-marker baseline").into(),
        );
    }

    let file_name = config
        .control_database
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("control database had no usable filename"))?;
    let lock_path = config.root.join(format!("{file_name}.server.lock"));
    let anchor_path = config.root.join(format!("{file_name}.server.lock.anchor"));
    let owner_marker = config.root.join(format!("{file_name}.server-owner"));
    let secret_owner_marker = config.secret_directory.join(".server-owner");
    fs::rename(&lock_path, config.root.join("control-owner-lock.original"))?;
    fs::rename(
        &anchor_path,
        config.root.join("control-owner-anchor.original"),
    )?;
    fs::remove_file(&owner_marker)?;
    fs::remove_file(&secret_owner_marker)?;
    let replacement = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)?;
    replacement.sync_all()?;
    drop(replacement);
    restrict_file(&lock_path)?;
    fs::hard_link(&lock_path, &anchor_path)?;

    let (peer_config, peer_listen_addr) = config.write_peer_config(
        "peer-owner-marker-removal.json",
        &config.control_database,
        &config.secret_directory,
    )?;
    let mut second = ServerChild::spawn(&peer_config)?;
    let second_observation = second.observe(READY_TIMEOUT)?;
    let second_stopped = second.stop()?;
    let first_stopped = first.graceful_stop()?;
    let forbidden = config.forbidden_markers_for(&[peer_config.as_path()]);
    assert_safe_output(
        "owner-marker replacement second Server",
        &second_stopped,
        &forbidden,
    )?;
    assert_safe_output(
        "owner-marker replacement first Server",
        &first_stopped,
        &forbidden,
    )?;
    assert_listen_released(peer_listen_addr)?;
    assert_startup_failure(
        "owner-marker replacement second Server",
        &second_observation,
        &second_stopped,
        SERVER_ALREADY_OWNED_FAILURE,
        &forbidden,
    )
}

#[cfg(unix)]
#[test]
fn e2e_server_control_database_and_lock_pair_replacement_cannot_allow_second_owner() -> TestResult {
    let temp = tempfile::tempdir()?;
    let config = ConfigFixture::new(temp.path())?;
    let mut first = ServerChild::spawn(&config.config_path)?;
    let first_observation = first.observe(READY_TIMEOUT)?;
    if !matches!(first_observation, Observation::Ready) || !first.is_running()? {
        let stopped = first.stop()?;
        assert_safe_output(
            "first database-pair owner",
            &stopped,
            &config.forbidden_markers(),
        )?;
        return Err(io::Error::other(
            "first Server did not establish the database-pair ownership baseline",
        )
        .into());
    }

    let file_name = config
        .control_database
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("control database had no usable filename"))?;
    let lock_path = config.root.join(format!("{file_name}.server.lock"));
    let anchor_path = config.root.join(format!("{file_name}.server.lock.anchor"));
    fs::rename(
        &config.control_database,
        config.root.join("control-readiness-database.original"),
    )?;
    fs::rename(
        &lock_path,
        config.root.join("control-readiness-database-lock.original"),
    )?;
    fs::rename(
        &anchor_path,
        config
            .root
            .join("control-readiness-database-anchor.original"),
    )?;
    let replacement_database = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&config.control_database)?;
    replacement_database.sync_all()?;
    drop(replacement_database);
    restrict_file(&config.control_database)?;
    let replacement_lock = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)?;
    replacement_lock.sync_all()?;
    drop(replacement_lock);
    restrict_file(&lock_path)?;
    fs::hard_link(&lock_path, &anchor_path)?;

    let (peer_config, peer_listen_addr) = config.write_peer_config(
        "peer-database-pair-replacement.json",
        &config.control_database,
        &config.secret_directory,
    )?;
    let mut second = ServerChild::spawn(&peer_config)?;
    let second_observation = second.observe(READY_TIMEOUT)?;
    let second_stopped = second.stop()?;
    let first_stopped = first.graceful_stop()?;
    let forbidden = config.forbidden_markers_for(&[peer_config.as_path()]);
    assert_safe_output(
        "database-pair replacement second Server",
        &second_stopped,
        &forbidden,
    )?;
    assert_safe_output(
        "database-pair replacement first Server",
        &first_stopped,
        &forbidden,
    )?;
    assert_listen_released(peer_listen_addr)?;
    assert_startup_failure(
        "database-pair replacement second Server",
        &second_observation,
        &second_stopped,
        SERVER_ALREADY_OWNED_FAILURE,
        &forbidden,
    )
}

#[test]
fn e2e_server_control_database_path_with_uri_delimiter_restarts_ready() -> TestResult {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("uri?root#fixture");
    fs::create_dir(&root)?;
    let config = ConfigFixture::new(&root)?;
    let mut first = ServerChild::spawn(&config.config_path)?;
    let first_observation = first.observe(READY_TIMEOUT)?;
    let first_stopped = first.graceful_stop()?;
    assert_safe_output(
        "URI-delimiter first Server",
        &first_stopped,
        &config.forbidden_markers(),
    )?;
    if !matches!(first_observation, Observation::Ready) {
        return Err(io::Error::other(
            first_observation.failure_summary("URI-delimiter first Server"),
        )
        .into());
    }

    let mut second = ServerChild::spawn(&config.config_path)?;
    let second_observation = second.observe(READY_TIMEOUT)?;
    let second_stopped = second.graceful_stop()?;
    assert_safe_output(
        "URI-delimiter restarted Server",
        &second_stopped,
        &config.forbidden_markers(),
    )?;
    if !matches!(second_observation, Observation::Ready) {
        return Err(io::Error::other(
            second_observation.failure_summary("URI-delimiter restarted Server"),
        )
        .into());
    }
    assert_listen_released(config.listen_addr)
}

#[test]
fn e2e_initialized_server_missing_metadata_never_reinitializes() -> TestResult {
    if let Some(raw) = env::var_os(METADATA_RECOVER_ENV) {
        return recover_metadata_reproduction(PathBuf::from(raw));
    }
    if env::var_os(METADATA_CAPTURE_ENV).is_some() {
        return capture_metadata_reproduction();
    }
    let cassette = metadata_cassette();
    if cassette.exists() {
        return replay_metadata_after_fix(&cassette);
    }
    Err(io::Error::other(
        "tracked readiness metadata later-gap cassette is missing; use the explicitly approved capture entry before production repair",
    )
    .into())
}

fn run_metadata_cases_without_capture() -> TestResult {
    let mut failures = Vec::new();
    for damage in [MetadataDamage::SingletonRow, MetadataDamage::Table] {
        match observe_missing_metadata_case(damage, None) {
            Ok(outcome) if !outcome.store_unchanged => failures.push(format!(
                "{}: failed restart changed persistent store file set/content/mode",
                damage.label()
            )),
            Ok(outcome) if !outcome.damage_preserved => failures.push(format!(
                "{}: failed restart recreated missing authority metadata",
                damage.label()
            )),
            Ok(outcome) if !outcome.non_ready => {
                failures.push(format!("{}: failed restart emitted READY", damage.label()))
            }
            Ok(outcome) if outcome.startup_failure_error.is_some() => failures.push(format!(
                "{}: {}",
                damage.label(),
                outcome
                    .startup_failure_error
                    .expect("guarded startup failure is present")
            )),
            Ok(_) => {}
            Err(error) => failures.push(format!("{}: {error}", damage.label())),
        }
    }
    finish_cases("missing metadata authority", failures)
}

#[test]
fn e2e_initialized_server_missing_metadata_with_wal_without_shm_never_creates_sqlite_sidecars(
) -> TestResult {
    let temp = tempfile::tempdir()?;
    let config = ConfigFixture::new(temp.path())?;
    establish_ready_baseline(&config, "missing metadata with WAL without SHM")?;
    let sidecars = sqlite_sidecars(&config.control_database)?;
    let holder = Connection::open(&config.control_database)?;
    holder.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA wal_autocheckpoint = 0;
         DELETE FROM server_metadata;
         CREATE TABLE IF NOT EXISTS readiness_wal_holder(value INTEGER);
         INSERT INTO readiness_wal_holder(value) VALUES (42);",
    )?;
    let deadline = Instant::now() + READY_TIMEOUT;
    while (!sidecars[0].is_file()
        || fs::metadata(&sidecars[0])?.len() == 0
        || !sidecars[1].is_file())
        && Instant::now() < deadline
    {
        thread::sleep(POLL_INTERVAL);
    }
    if !sidecars[0].is_file() || fs::metadata(&sidecars[0])?.len() == 0 || !sidecars[1].is_file() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "SQLite holder did not establish a non-empty WAL and SHM pair",
        )
        .into());
    }
    holder.execute_batch("BEGIN; SELECT COUNT(*) FROM readiness_wal_holder;")?;
    fs::remove_file(&sidecars[1])?;
    let before = config.live_store_snapshot()?;
    let held_listen = hold_public_listen(config.listen_addr)?;
    let mut restarted = ServerChild::spawn(&config.config_path)?;
    let observation = restarted.observe(READY_TIMEOUT)?;
    let stopped = restarted.stop()?;
    drop(held_listen);
    let after = config.live_store_snapshot()?;
    let forbidden = config.forbidden_markers();
    assert_safe_output(
        "missing metadata with WAL without SHM",
        &stopped,
        &forbidden,
    )?;
    let capture = capture_first_readiness_failure(
        "server-readiness-metadata-with-wal-without-shm-v1",
        "e2e_initialized_server_missing_metadata_with_wal_without_shm_never_creates_sqlite_sidecars",
        "missing metadata with WAL without SHM",
        config.listen_addr,
        CONTROL_STORE_INTEGRITY_FAILURE,
        &observation,
        false,
        &stopped,
        &before,
        &after,
        &forbidden,
    );
    let port_released = assert_listen_released(config.listen_addr);
    let startup = assert_startup_failure(
        "missing metadata with WAL without SHM",
        &observation,
        &stopped,
        CONTROL_STORE_INTEGRITY_FAILURE,
        &forbidden,
    );
    let recreated_shm = sidecars[1].exists();
    holder.execute_batch("ROLLBACK;")?;
    drop(holder);
    config.assert_persistent_secret_free()?;
    capture?;
    port_released?;
    if before != after {
        return Err(
            io::Error::other("missing metadata preflight changed the SQLite sidecars").into(),
        );
    }
    if recreated_shm {
        return Err(io::Error::other(
            "missing metadata preflight recreated the removed SQLite SHM sidecar",
        )
        .into());
    }
    startup
}

#[cfg(unix)]
#[test]
fn e2e_initialized_server_wal_shm_hardlink_is_rejected_before_ready() -> TestResult {
    let temp = tempfile::tempdir()?;
    let config = ConfigFixture::new(temp.path())?;
    establish_ready_baseline(&config, "WAL SHM hardlink")?;
    let sidecars = sqlite_sidecars(&config.control_database)?;
    let holder = Connection::open(&config.control_database)?;
    holder.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA wal_autocheckpoint = 0;
         CREATE TABLE IF NOT EXISTS readiness_wal_link(value INTEGER);
         INSERT INTO readiness_wal_link(value) VALUES (42);",
    )?;
    let deadline = Instant::now() + READY_TIMEOUT;
    while (!sidecars[0].is_file()
        || fs::metadata(&sidecars[0])?.len() == 0
        || !sidecars[1].is_file())
        && Instant::now() < deadline
    {
        thread::sleep(POLL_INTERVAL);
    }
    if !sidecars[0].is_file() || fs::metadata(&sidecars[0])?.len() == 0 || !sidecars[1].is_file() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "SQLite holder did not establish a non-empty WAL and SHM pair",
        )
        .into());
    }
    holder.execute_batch("BEGIN; SELECT COUNT(*) FROM readiness_wal_link;")?;
    let unrelated = config.root.join("unrelated-shm");
    fs::rename(&sidecars[1], &unrelated)?;
    fs::hard_link(&unrelated, &sidecars[1])?;
    let before = config.live_store_snapshot()?;
    let held_listen = hold_public_listen(config.listen_addr)?;
    let mut restarted = ServerChild::spawn(&config.config_path)?;
    let observation = restarted.observe(READY_TIMEOUT)?;
    let stopped = restarted.stop()?;
    drop(held_listen);
    let after = config.live_store_snapshot()?;
    let forbidden = config.forbidden_markers_for(&[unrelated.as_path()]);
    assert_safe_output("WAL SHM hardlink", &stopped, &forbidden)?;
    let capture = capture_first_readiness_failure(
        "server-readiness-wal-shm-hardlink-v1",
        "e2e_initialized_server_wal_shm_hardlink_is_rejected_before_ready",
        "WAL SHM hardlink must fail closed without mutating the peer file",
        config.listen_addr,
        CONTROL_STORE_INTEGRITY_FAILURE,
        &observation,
        false,
        &stopped,
        &before,
        &after,
        &forbidden,
    );
    let startup = assert_startup_failure(
        "WAL SHM hardlink",
        &observation,
        &stopped,
        CONTROL_STORE_INTEGRITY_FAILURE,
        &forbidden,
    );
    holder.execute_batch("ROLLBACK;")?;
    drop(holder);
    config.assert_persistent_secret_free()?;
    capture?;
    assert_listen_released(config.listen_addr)?;
    if before != after {
        return Err(io::Error::other("WAL SHM hardlink preflight changed SQLite sidecars").into());
    }
    startup
}

#[test]
fn e2e_second_server_control_database_alias_with_distinct_secret_store_never_becomes_ready(
) -> TestResult {
    if let Some(raw) = env::var_os(ALIAS_RECOVER_EXACT_ENV) {
        return recover_control_database_alias(ControlDatabaseAlias::ExactPath, PathBuf::from(raw));
    }
    if let Some(raw) = env::var_os(ALIAS_RECOVER_HARDLINK_ENV) {
        return recover_control_database_alias(ControlDatabaseAlias::HardLink, PathBuf::from(raw));
    }
    if env::var_os(ALIAS_CAPTURE_ENV).is_some() {
        return capture_control_database_alias_sources();
    }
    for alias in [
        ControlDatabaseAlias::ExactPath,
        ControlDatabaseAlias::HardLink,
    ] {
        let replay =
            ProcessIncidentReplay::load(alias_cassette(alias), ALIAS_E2E, &[SECRET_MARKER])?;
        assert_alias_replay_identity(alias, &replay)?;
    }
    let mut failures = Vec::new();
    for alias in [
        ControlDatabaseAlias::ExactPath,
        ControlDatabaseAlias::HardLink,
    ] {
        if let Err(error) = run_control_database_alias_case(alias, None) {
            failures.push(format!("{}: {error}", alias.label()));
        }
    }
    finish_cases("control database ownership alias", failures)
}

#[derive(Clone, Copy)]
enum MetadataDamage {
    SingletonRow,
    Table,
}

struct MetadataCaseOutcome {
    store_unchanged: bool,
    damage_preserved: bool,
    non_ready: bool,
    startup_failure_error: Option<String>,
}

impl MetadataDamage {
    fn label(self) -> &'static str {
        match self {
            Self::SingletonRow => "missing singleton row",
            Self::Table => "missing metadata table",
        }
    }

    fn evidence_id(self) -> &'static str {
        match self {
            Self::SingletonRow => "server-readiness-metadata-row-fixed-listen-first-ready-v2",
            Self::Table => "server-readiness-metadata-table-fixed-listen-first-ready-v2",
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::SingletonRow => "metadata-singleton-row",
            Self::Table => "metadata-table",
        }
    }

    fn apply(self, database: &Path) -> TestResult {
        let connection = Connection::open(database)?;
        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        match self {
            Self::SingletonRow => {
                let changed =
                    connection.execute("DELETE FROM server_metadata WHERE singleton = 1", [])?;
                if changed != 1 {
                    return Err(io::Error::other(
                        "initialized control store did not contain exactly one metadata singleton",
                    )
                    .into());
                }
            }
            Self::Table => connection.execute_batch("DROP TABLE server_metadata;")?,
        }
        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        drop(connection);
        if !self.is_present(database)? {
            return Err(io::Error::other("metadata damage was not established").into());
        }
        Ok(())
    }

    fn is_present(self, database: &Path) -> TestResult<bool> {
        let connection = Connection::open(database)?;
        let metadata_table = connection
            .query_row(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'server_metadata'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        Ok(match self {
            Self::SingletonRow if metadata_table => {
                connection.query_row("SELECT COUNT(*) FROM server_metadata", [], |row| {
                    row.get::<_, i64>(0)
                })? == 0
            }
            Self::SingletonRow => false,
            Self::Table => !metadata_table,
        })
    }
}

fn sqlite_sidecars(database: &Path) -> TestResult<[PathBuf; 2]> {
    let file_name = database
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("control database had no usable filename"))?;
    Ok([
        database.with_file_name(format!("{file_name}-wal")),
        database.with_file_name(format!("{file_name}-shm")),
    ])
}

#[derive(Clone, Copy)]
enum ControlDatabaseAlias {
    ExactPath,
    HardLink,
}

impl ControlDatabaseAlias {
    fn label(self) -> &'static str {
        match self {
            Self::ExactPath => "same database path",
            Self::HardLink => "hardlink database inode alias",
        }
    }
}

fn observe_missing_metadata_case(
    damage: MetadataDamage,
    capture: Option<&mut ProcessCaptureSet>,
) -> TestResult<MetadataCaseOutcome> {
    let temp = tempfile::tempdir()?;
    let config = ConfigFixture::new(temp.path())?;
    establish_ready_baseline(&config, damage.label())?;
    damage.apply(&config.control_database)?;
    let before = config.live_store_snapshot()?;
    let held_listen = hold_public_listen(config.listen_addr)?;
    let mut restarted = ServerChild::spawn(&config.config_path)?;
    let restarted_pid = restarted.pid()?;
    let observation = restarted.observe(READY_TIMEOUT)?;
    let stopped = restarted.stop()?;
    if held_listen.local_addr()? != config.listen_addr {
        return Err(io::Error::other("metadata failure listen guard changed address").into());
    }
    drop(held_listen);
    let after = config.live_store_snapshot()?;
    let forbidden = config.forbidden_markers();
    if let Some(capture) = capture {
        capture.capture_process(process_observation(damage, restarted_pid, &stopped))?;
    }
    assert_safe_output(damage.label(), &stopped, &forbidden)?;
    let capture = capture_first_readiness_failure(
        damage.evidence_id(),
        "e2e_initialized_server_missing_metadata_never_reinitializes",
        damage.label(),
        config.listen_addr,
        CONTROL_STORE_INTEGRITY_FAILURE,
        &observation,
        false,
        &stopped,
        &before,
        &after,
        &forbidden,
    );
    let port_released = assert_listen_released(config.listen_addr);
    let startup_failure_error = assert_startup_failure(
        damage.label(),
        &observation,
        &stopped,
        CONTROL_STORE_INTEGRITY_FAILURE,
        &forbidden,
    )
    .err()
    .map(|error| error.to_string());
    let non_ready = !matches!(observation, Observation::Ready) && !stopped.contains_ready();
    let damage_preserved = damage.is_present(&config.control_database)?;
    config.assert_persistent_secret_free()?;
    capture?;
    port_released?;
    Ok(MetadataCaseOutcome {
        store_unchanged: before == after,
        damage_preserved,
        non_ready,
        startup_failure_error,
    })
}

fn metadata_quarantine() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-recordings/quarantine")
        .join("server-readiness-metadata-later")
}

fn metadata_cassette() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(METADATA_CASSETTE)
}

fn metadata_replay_config() -> TestResult<Vec<u8>> {
    Ok(serde_json::to_vec(&json!({
        "schema": "zode.server-readiness-metadata-gap-replay.v1",
        "e2e": METADATA_E2E,
        "relation": METADATA_RELATION,
        "entry": "real zode-server --config with a pre-damaged initialized control store",
        "damage": ["missing_metadata_singleton_row", "missing_metadata_table"],
        "expected_after_fix": {
            "ready": false,
            "startup_failure": CONTROL_STORE_INTEGRITY_FAILURE,
            "persistent_store_unchanged": true
        }
    }))?)
}

fn assert_metadata_replay_identity(replay: &ProcessIncidentReplay) -> TestResult {
    let config: Value = serde_json::from_slice(replay.config_bytes())?;
    if replay.config_label() != "server-readiness-metadata-damage"
        || replay.classification() != METADATA_CLASSIFICATION
        || replay.first_observed() != METADATA_FIRST_OBSERVED
        || config["schema"] != "zode.server-readiness-metadata-gap-replay.v1"
        || config["e2e"] != METADATA_E2E
        || config["relation"] != METADATA_RELATION
        || config["expected_after_fix"]["ready"] != false
        || config["expected_after_fix"]["startup_failure"] != CONTROL_STORE_INTEGRITY_FAILURE
        || config["expected_after_fix"]["persistent_store_unchanged"] != true
        || replay.config_bytes() != metadata_replay_config()?
    {
        return Err(io::Error::other(
            "readiness metadata later-gap cassette changed identity or relation",
        )
        .into());
    }
    Ok(())
}

fn observe_metadata_cases_captured(capture: &mut ProcessCaptureSet) -> TestResult<bool> {
    let singleton = observe_missing_metadata_case(MetadataDamage::SingletonRow, Some(capture))?;
    let table = observe_missing_metadata_case(MetadataDamage::Table, Some(capture))?;
    Ok(!singleton.store_unchanged
        && singleton.non_ready
        && !table.store_unchanged
        && table.non_ready)
}

fn flush_metadata_observation(
    capture: &mut ProcessCaptureSet,
    expected_red: bool,
) -> TestResult<PathBuf> {
    let (classification, first_observed) = if expected_red {
        (METADATA_CLASSIFICATION, METADATA_FIRST_OBSERVED)
    } else {
        (
            "HARNESS_READINESS_METADATA_LATER_CLASSIFICATION_MISMATCH__later_test_reproduction_of_gap",
            "relation=later_test_reproduction_of_gap; both real process observations were retained before classification but the expected store-mutation red was incomplete",
        )
    };
    capture.flush(classification, first_observed)
}

fn capture_metadata_same_entry_replay(
    replay: &ProcessIncidentReplay,
) -> TestResult<(bool, PathBuf)> {
    let mut capture =
        ProcessCaptureSet::new(metadata_quarantine(), METADATA_E2E, &[SECRET_MARKER])?;
    capture.capture_config("server-readiness-metadata-damage", replay.config_bytes())?;
    let expected_red = observe_metadata_cases_captured(&mut capture)?;
    let raw = flush_metadata_observation(&mut capture, expected_red)?;
    Ok((expected_red, raw))
}

fn metadata_replay_proof(replay: &ProcessIncidentReplay) -> ProcessReplayProof {
    let fingerprint = format!(
        "{:x}",
        Sha256::digest(
            format!(
                "{}\0{}\0same-public-entry-red-reproduced",
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

fn promote_metadata_after_replay(replay: &ProcessIncidentReplay, source: &Path) -> TestResult {
    assert_metadata_replay_identity(replay)?;
    let (expected_red, replay_raw) = capture_metadata_same_entry_replay(replay)?;
    if !expected_red {
        return Err(io::Error::other(format!(
            "same-entry readiness replay was retained before classification but did not reproduce the typed store-mutation red; replay={}",
            replay_raw.display()
        ))
        .into());
    }
    let destination = metadata_cassette();
    replay.promote_immutable(
        &destination,
        &metadata_replay_proof(replay),
        &[SECRET_MARKER],
    )?;
    Err(io::Error::other(format!(
        "readiness metadata hardening remains red; relation={METADATA_RELATION}; source={}; replay={}; cassette={}",
        source.display(),
        replay_raw.display(),
        destination.display()
    ))
    .into())
}

fn capture_metadata_reproduction() -> TestResult {
    if metadata_cassette().exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "readiness metadata later-gap cassette is immutable",
        )
        .into());
    }
    let config = metadata_replay_config()?;
    let mut capture =
        ProcessCaptureSet::new(metadata_quarantine(), METADATA_E2E, &[SECRET_MARKER])?;
    capture.capture_config("server-readiness-metadata-damage", &config)?;
    let expected_red = observe_metadata_cases_captured(&mut capture)?;
    let raw = flush_metadata_observation(&mut capture, expected_red)?;
    if !expected_red {
        return Err(io::Error::other(format!(
            "later readiness reproduction did not retain both typed store-mutation reds; process capture={}",
            raw.display()
        ))
        .into());
    }
    let replay = ProcessIncidentReplay::load(&raw, METADATA_E2E, &[SECRET_MARKER])?;
    promote_metadata_after_replay(&replay, &raw)
}

fn recover_metadata_reproduction(raw: PathBuf) -> TestResult {
    if metadata_cassette().exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "readiness metadata later-gap cassette is immutable",
        )
        .into());
    }
    let replay = ProcessIncidentReplay::load(&raw, METADATA_E2E, &[SECRET_MARKER])?;
    promote_metadata_after_replay(&replay, &raw)
}

fn replay_metadata_after_fix(cassette: &Path) -> TestResult {
    let replay = ProcessIncidentReplay::load(cassette, METADATA_E2E, &[SECRET_MARKER])?;
    assert_metadata_replay_identity(&replay)?;
    run_metadata_cases_without_capture()
}

fn alias_quarantine(alias: ControlDatabaseAlias) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-recordings/quarantine")
        .join("server-readiness-database-alias-later")
        .join(alias.label_slug())
}

fn alias_cassette(alias: ControlDatabaseAlias) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/incidents")
        .join(format!(
            "server-readiness-database-alias-{}-later-gap.v1.json",
            alias.label_slug()
        ))
}

fn alias_first_observed(alias: ControlDatabaseAlias) -> String {
    format!(
        "relation={ALIAS_RELATION}; alias={}; expected=server_already_owned/server_store_lock; actual=control_store_integrity/control_store; ready_emitted=false",
        alias.label_slug()
    )
}

fn alias_replay_config(alias: ControlDatabaseAlias) -> TestResult<Vec<u8>> {
    Ok(serde_json::to_vec(&json!({
        "schema": "zode.server-readiness-database-alias-gap-replay.v1",
        "e2e": ALIAS_E2E,
        "relation": ALIAS_RELATION,
        "entry": "real zode-server --config sharing an already-owned control database",
        "alias": alias.label_slug(),
        "expected_after_fix": {
            "ready": false,
            "startup_failure": SERVER_ALREADY_OWNED_FAILURE,
            "first_server_running": true,
            "persistent_store_unchanged": true
        }
    }))?)
}

fn capture_control_database_alias_source(alias: ControlDatabaseAlias) -> TestResult<PathBuf> {
    let config = alias_replay_config(alias)?;
    let mut capture = ProcessCaptureSet::new(alias_quarantine(alias), ALIAS_E2E, &[SECRET_MARKER])?;
    capture.capture_config(
        format!("server-readiness-database-alias-{}", alias.label_slug()),
        &config,
    )?;
    let observed = run_control_database_alias_case(alias, Some(&mut capture));
    let raw = capture
        .flushed_path()
        .ok_or_else(|| io::Error::other("database alias process capture was not flushed"))?
        .to_path_buf();
    if observed.is_ok() {
        return Err(io::Error::other(format!(
            "{} unexpectedly matched the stable ownership rejection while capturing a required red; raw={}",
            alias.label(),
            raw.display()
        ))
        .into());
    }
    let replay = ProcessIncidentReplay::load(&raw, ALIAS_E2E, &[SECRET_MARKER])?;
    assert_alias_replay_identity(alias, &replay)?;
    Ok(raw)
}

fn capture_control_database_alias_sources() -> TestResult {
    let exact = capture_control_database_alias_source(ControlDatabaseAlias::ExactPath)?;
    let hardlink = capture_control_database_alias_source(ControlDatabaseAlias::HardLink)?;
    Err(io::Error::other(format!(
        "database alias later reproductions retained before repair; relation={ALIAS_RELATION}; exact={}; hardlink={}",
        exact.display(),
        hardlink.display()
    ))
    .into())
}

fn assert_alias_replay_identity(
    alias: ControlDatabaseAlias,
    replay: &ProcessIncidentReplay,
) -> TestResult {
    let config: Value = serde_json::from_slice(replay.config_bytes())?;
    if replay.config_label() != format!("server-readiness-database-alias-{}", alias.label_slug())
        || replay.classification() != ALIAS_CLASSIFICATION
        || replay.first_observed() != alias_first_observed(alias)
        || config["schema"] != "zode.server-readiness-database-alias-gap-replay.v1"
        || config["e2e"] != ALIAS_E2E
        || config["relation"] != ALIAS_RELATION
        || config["alias"] != alias.label_slug()
        || config["expected_after_fix"]["ready"] != false
        || config["expected_after_fix"]["startup_failure"] != SERVER_ALREADY_OWNED_FAILURE
        || config["expected_after_fix"]["first_server_running"] != true
        || config["expected_after_fix"]["persistent_store_unchanged"] != true
        || replay.config_bytes() != alias_replay_config(alias)?
    {
        return Err(io::Error::other(
            "database alias later-gap cassette changed identity or relation",
        )
        .into());
    }
    Ok(())
}

fn alias_replay_proof(
    source: &ProcessIncidentReplay,
    replay: &ProcessIncidentReplay,
) -> ProcessReplayProof {
    let fingerprint = format!(
        "{:x}",
        Sha256::digest(
            format!(
                "{}\0{}\0{}\0same-public-entry-red-reproduced",
                source.classification(),
                source.first_observed(),
                replay.source_digest()
            )
            .as_bytes()
        )
    );
    ProcessReplayProof {
        matched: true,
        fingerprint,
        source_digest: source.source_digest().to_owned(),
    }
}

fn recover_control_database_alias(alias: ControlDatabaseAlias, source_path: PathBuf) -> TestResult {
    let destination = alias_cassette(alias);
    if destination.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "database alias later-gap cassette is immutable",
        )
        .into());
    }
    let source = ProcessIncidentReplay::load(&source_path, ALIAS_E2E, &[SECRET_MARKER])?;
    assert_alias_replay_identity(alias, &source)?;
    let replay_path = capture_control_database_alias_source(alias)?;
    let replay = ProcessIncidentReplay::load(&replay_path, ALIAS_E2E, &[SECRET_MARKER])?;
    assert_alias_replay_identity(alias, &replay)?;
    source.promote_immutable(
        &destination,
        &alias_replay_proof(&source, &replay),
        &[SECRET_MARKER],
    )?;
    Err(io::Error::other(format!(
        "database alias readiness hardening remains red; relation={ALIAS_RELATION}; alias={}; source={}; replay={}; cassette={}",
        alias.label_slug(),
        source_path.display(),
        replay_path.display(),
        destination.display()
    ))
    .into())
}

fn classify_alias_rejection(
    alias: ControlDatabaseAlias,
    observation: &Observation,
    stopped: &StoppedProcess,
) -> (String, String) {
    let actual = if contains_startup_failure(stopped, SERVER_ALREADY_OWNED_FAILURE) {
        "server_already_owned/server_store_lock"
    } else if contains_startup_failure(stopped, CONTROL_STORE_INTEGRITY_FAILURE) {
        "control_store_integrity/control_store"
    } else if matches!(observation, Observation::Ready) || stopped.contains_ready() {
        "ready"
    } else if matches!(observation, Observation::TimedOut) {
        "timeout"
    } else {
        "unclassified_non_ready_exit"
    };
    let matched = actual == "server_already_owned/server_store_lock";
    let classification = if matched {
        "CONTROL_STORE_DATABASE_ALIAS_REJECTION_MATCHED__later_test_reproduction_of_gap"
    } else {
        "CONTROL_STORE_DATABASE_ALIAS_REJECTION_MISCLASSIFIED__later_test_reproduction_of_gap"
    };
    (
        classification.to_owned(),
        if matched {
            format!(
                "relation={ALIAS_RELATION}; alias={}; expected=server_already_owned/server_store_lock; actual={actual}; ready_emitted={}",
                alias.label_slug(),
                stopped.contains_ready()
            )
        } else if actual == "control_store_integrity/control_store" && !stopped.contains_ready() {
            alias_first_observed(alias)
        } else {
            format!(
                "relation={ALIAS_RELATION}; alias={}; expected=server_already_owned/server_store_lock; actual={actual}; ready_emitted={}",
                alias.label_slug(),
                stopped.contains_ready()
            )
        },
    )
}

fn contains_startup_failure(stopped: &StoppedProcess, expected_failure: &str) -> bool {
    let expected_line = format!("{STARTUP_FAILURE_PREFIX}{expected_failure}");
    String::from_utf8_lossy(&stopped.output.stderr)
        .lines()
        .any(|line| line.trim_end() == expected_line)
}

fn run_control_database_alias_case(
    alias: ControlDatabaseAlias,
    capture: Option<&mut ProcessCaptureSet>,
) -> TestResult {
    let temp = tempfile::tempdir()?;
    let config = ConfigFixture::new(temp.path())?;
    let mut first = ServerChild::spawn(&config.config_path)?;
    let (first_observation, first_port_contacted) =
        first.observe_at(READY_TIMEOUT, config.listen_addr)?;
    if !matches!(first_observation, Observation::Ready)
        || !first_port_contacted
        || !first.is_running()?
    {
        let stopped = first.stop()?;
        assert_safe_output(alias.label(), &stopped, &config.forbidden_markers())?;
        return Err(io::Error::other(first_observation.failure_summary("first server")).into());
    }

    let peer_database = match alias {
        ControlDatabaseAlias::ExactPath => config.control_database.clone(),
        ControlDatabaseAlias::HardLink => {
            let path = temp.path().join("control-readiness-inode-alias.sqlite3");
            fs::hard_link(&config.control_database, &path)?;
            path
        }
    };
    assert_database_alias(alias, &config.control_database, &peer_database)?;
    let peer_secret_directory = temp
        .path()
        .join(format!("peer-secret-{}", alias.label_slug()));
    fs::create_dir(&peer_secret_directory)?;
    assert_distinct_directories(&config.secret_directory, &peer_secret_directory)?;
    let (peer_config, peer_listen_addr) = config.write_peer_config(
        &format!("peer-{}.json", alias.label_slug()),
        &peer_database,
        &peer_secret_directory,
    )?;
    if peer_listen_addr == config.listen_addr {
        return Err(
            io::Error::other("peer Server did not receive a distinct listen address").into(),
        );
    }
    let forbidden = config.forbidden_markers_for(&[
        peer_database.as_path(),
        peer_secret_directory.as_path(),
        peer_config.as_path(),
    ]);
    let before = config.live_store_snapshot()?;
    let control_database_identity_before = database_file_identity(&config.control_database)?;
    let peer_database_identity_before = database_file_identity(&peer_database)?;

    let held_peer_listen = hold_public_listen(peer_listen_addr)?;
    let mut second = ServerChild::spawn(&peer_config)?;
    let second_pid = second.pid()?;
    let second_observation = second.observe(READY_TIMEOUT)?;
    let second_stopped = second.stop()?;
    if let Some(capture) = capture {
        capture.capture_process(alias_process_observation(
            alias,
            second_pid,
            &second_stopped,
        ))?;
        let (classification, first_observed) =
            classify_alias_rejection(alias, &second_observation, &second_stopped);
        capture.flush(classification, first_observed)?;
    }
    if held_peer_listen.local_addr()? != peer_listen_addr {
        return Err(io::Error::other("ownership failure listen guard changed address").into());
    }
    drop(held_peer_listen);
    let control_database_identity_after = database_file_identity(&config.control_database);
    let peer_database_identity_after = database_file_identity(&peer_database);
    let database_alias_after_rejection =
        assert_database_alias(alias, &config.control_database, &peer_database);
    let after = config.live_store_snapshot()?;
    assert_safe_output(alias.label(), &second_stopped, &forbidden)?;
    let capture = capture_first_readiness_failure(
        alias.evidence_id(),
        "e2e_second_server_control_database_alias_with_distinct_secret_store_never_becomes_ready",
        alias.label(),
        peer_listen_addr,
        SERVER_ALREADY_OWNED_FAILURE,
        &second_observation,
        false,
        &second_stopped,
        &before,
        &after,
        &forbidden,
    );
    let peer_port_released = assert_listen_released(peer_listen_addr);
    let startup = assert_startup_failure(
        alias.label(),
        &second_observation,
        &second_stopped,
        SERVER_ALREADY_OWNED_FAILURE,
        &forbidden,
    );
    let unchanged = before == after;
    let first_still_running = first.is_running()?;
    let first_stopped = first.graceful_stop()?;
    assert_safe_output(alias.label(), &first_stopped, &forbidden)?;
    let first_port_released = assert_listen_released(config.listen_addr);
    config.assert_persistent_secret_free()?;

    capture?;
    peer_port_released?;
    first_port_released?;
    if control_database_identity_before != control_database_identity_after? {
        return Err(io::Error::other(
            "rejected second Server changed control database dev/inode/nlink",
        )
        .into());
    }
    if peer_database_identity_before != peer_database_identity_after? {
        return Err(io::Error::other(
            "rejected second Server changed peer database dev/inode/nlink",
        )
        .into());
    }
    database_alias_after_rejection?;
    if !unchanged {
        return Err(io::Error::other("rejected second Server changed store files").into());
    }
    if !first_still_running {
        return Err(io::Error::other("first Server exited during ownership rejection").into());
    }
    startup
}

impl ControlDatabaseAlias {
    fn label_slug(self) -> &'static str {
        match self {
            Self::ExactPath => "exact",
            Self::HardLink => "hardlink",
        }
    }

    fn evidence_id(self) -> &'static str {
        match self {
            Self::ExactPath => "server-readiness-shared-database-fixed-listen-first-ready-v2",
            Self::HardLink => "server-readiness-database-hardlink-fixed-listen-first-ready-v2",
        }
    }
}

fn establish_ready_baseline(config: &ConfigFixture, label: &str) -> TestResult {
    let mut baseline = ServerChild::spawn(&config.config_path)?;
    let (observation, public_port_contacted) =
        baseline.observe_at(READY_TIMEOUT, config.listen_addr)?;
    let running = matches!(observation, Observation::Ready)
        && public_port_contacted
        && baseline.is_running()?;
    let stopped = baseline.graceful_stop()?;
    assert_safe_output(label, &stopped, &config.forbidden_markers())?;
    assert_listen_released(config.listen_addr)?;
    if !running || !stopped.contains_ready() {
        return Err(io::Error::other(observation.failure_summary("baseline Server")).into());
    }
    Ok(())
}

fn finish_cases(label: &str, failures: Vec<String>) -> TestResult {
    if failures.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(format!("{label} failures: {}", failures.join("; "))).into())
    }
}

fn unused_loopback_addr(excluded: &[SocketAddr]) -> TestResult<SocketAddr> {
    for _ in 0..32 {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        drop(listener);
        if address.port() != 0 && !excluded.contains(&address) {
            return Ok(address);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "could not reserve a distinct nonzero loopback listen address",
    )
    .into())
}

fn hold_public_listen(address: SocketAddr) -> TestResult<TcpListener> {
    if address.port() == 0 || !address.ip().is_loopback() {
        return Err(io::Error::other(
            "readiness bind guard requires a fixed nonzero loopback address",
        )
        .into());
    }
    let listener = TcpListener::bind(address)?;
    if listener.local_addr()? != address {
        return Err(
            io::Error::other("readiness bind guard did not hold the configured address").into(),
        );
    }
    Ok(listener)
}

fn assert_listen_released(address: SocketAddr) -> TestResult {
    let deadline = Instant::now() + STOP_TIMEOUT;
    loop {
        match TcpListener::bind(address) {
            Ok(listener) => {
                drop(listener);
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "zode-server public listener remained bound after child reap",
                    )
                    .into());
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
struct DatabaseFileIdentity {
    dev: u64,
    inode: u64,
    nlink: u64,
}

#[cfg(unix)]
fn database_file_identity(path: &Path) -> TestResult<DatabaseFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path)?;
    Ok(DatabaseFileIdentity {
        dev: metadata.dev(),
        inode: metadata.ino(),
        nlink: metadata.nlink(),
    })
}

#[cfg(not(unix))]
#[derive(Debug, PartialEq, Eq)]
struct DatabaseFileIdentity {
    canonical_path: PathBuf,
}

#[cfg(not(unix))]
fn database_file_identity(path: &Path) -> TestResult<DatabaseFileIdentity> {
    Ok(DatabaseFileIdentity {
        canonical_path: path.canonicalize()?,
    })
}

#[cfg(unix)]
fn assert_database_alias(alias: ControlDatabaseAlias, original: &Path, peer: &Path) -> TestResult {
    let original_identity = database_file_identity(original)?;
    let peer_identity = database_file_identity(peer)?;
    if original_identity.dev != peer_identity.dev || original_identity.inode != peer_identity.inode
    {
        return Err(io::Error::other("control database paths are not the same inode").into());
    }
    if matches!(alias, ControlDatabaseAlias::HardLink)
        && (original == peer || original_identity.nlink < 2 || peer_identity.nlink < 2)
    {
        return Err(io::Error::other("hardlink control database alias was not established").into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn assert_database_alias(alias: ControlDatabaseAlias, original: &Path, peer: &Path) -> TestResult {
    if matches!(alias, ControlDatabaseAlias::ExactPath) && original != peer {
        return Err(io::Error::other("exact control database alias was not established").into());
    }
    Ok(())
}

#[cfg(unix)]
fn assert_distinct_directories(first: &Path, second: &Path) -> TestResult {
    use std::os::unix::fs::MetadataExt;

    let first_metadata = fs::metadata(first)?;
    let second_metadata = fs::metadata(second)?;
    if first_metadata.dev() == second_metadata.dev()
        && first_metadata.ino() == second_metadata.ino()
    {
        return Err(
            io::Error::other("peer secret directory aliases the first secret store").into(),
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn assert_distinct_directories(first: &Path, second: &Path) -> TestResult {
    if first.canonicalize()? == second.canonicalize()? {
        return Err(
            io::Error::other("peer secret directory aliases the first secret store").into(),
        );
    }
    Ok(())
}

struct ConfigFixture {
    config_path: PathBuf,
    control_database: PathBuf,
    secret_directory: PathBuf,
    subject_key_file: PathBuf,
    listen_addr: SocketAddr,
    root: PathBuf,
}

impl ConfigFixture {
    fn new(root: &Path) -> TestResult<Self> {
        let control_database = root.join("control-readiness-path.sqlite3");
        let secret_directory = root.join("secret-readiness-path");
        let subject_key_file = root.join("subject-readiness-key");
        fs::create_dir(&secret_directory)?;
        let mut subject_key = [0_u8; 32];
        subject_key[..SECRET_MARKER.len()].copy_from_slice(SECRET_MARKER.as_bytes());
        fs::write(&subject_key_file, subject_key)?;
        restrict_file(&subject_key_file)?;
        let listen_addr = unused_loopback_addr(&[])?;
        let callback_addr = unused_loopback_addr(&[listen_addr])?;

        let value = json!({
            "schema": "zode.server-config.v1",
            "listen": listen_addr.to_string(),
            "management_origin": format!("http://{listen_addr}"),
            "callback_origin": format!("http://{callback_addr}"),
            "server_authority_id": SERVER_AUTHORITY,
            "deployment": "server_only",
            "ui_mode": "api_only",
            "control_database": control_database,
            "secret_directory": secret_directory,
            "access": {
                "issuer": "https://access.readiness.invalid/",
                "audiences": ["readiness-e2e"],
                "jwks_url": "https://access.readiness.invalid/cdn-cgi/access/certs",
                "subject_key_file": subject_key_file,
                "subject_key_version": 1
            }
        });
        let config_path = root.join("server-readiness-config.json");
        fs::write(&config_path, serde_json::to_vec_pretty(&value)?)?;

        Ok(Self {
            config_path,
            control_database,
            secret_directory,
            subject_key_file,
            listen_addr,
            root: root.to_path_buf(),
        })
    }

    fn forbidden_markers(&self) -> Vec<String> {
        self.forbidden_markers_for(&[])
    }

    fn forbidden_markers_for(&self, extra: &[&Path]) -> Vec<String> {
        let mut markers = [
            SECRET_MARKER.to_owned(),
            SERVER_AUTHORITY.to_owned(),
            self.root.to_string_lossy().into_owned(),
            self.config_path.to_string_lossy().into_owned(),
            self.control_database.to_string_lossy().into_owned(),
            self.secret_directory.to_string_lossy().into_owned(),
            self.subject_key_file.to_string_lossy().into_owned(),
        ]
        .into_iter()
        .filter(|marker| !marker.is_empty())
        .collect::<Vec<_>>();
        markers.extend(
            extra
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .filter(|marker| !marker.is_empty()),
        );
        markers
    }

    fn write_peer_config(
        &self,
        name: &str,
        control_database: &Path,
        secret_directory: &Path,
    ) -> TestResult<(PathBuf, SocketAddr)> {
        let listen_addr = unused_loopback_addr(&[self.listen_addr])?;
        let callback_addr = unused_loopback_addr(&[self.listen_addr, listen_addr])?;
        let value = json!({
            "schema": "zode.server-config.v1",
            "listen": listen_addr.to_string(),
            "management_origin": format!("http://{listen_addr}"),
            "callback_origin": format!("http://{callback_addr}"),
            "server_authority_id": SERVER_AUTHORITY,
            "deployment": "server_only",
            "ui_mode": "api_only",
            "control_database": control_database,
            "secret_directory": secret_directory,
            "access": {
                "issuer": "https://access.readiness.invalid/",
                "audiences": ["readiness-e2e"],
                "jwks_url": "https://access.readiness.invalid/cdn-cgi/access/certs",
                "subject_key_file": self.subject_key_file,
                "subject_key_version": 1
            }
        });
        let path = self.root.join(name);
        fs::write(&path, serde_json::to_vec_pretty(&value)?)?;
        Ok((path, listen_addr))
    }

    fn live_store_snapshot(&self) -> TestResult<StoreSnapshot> {
        // The owning process may still be alive here. Hash file bytes without
        // parsing them; secret scans happen only after all children stop.
        let mut files = BTreeMap::new();
        collect_live_files(&self.root, &self.root, &mut files)?;
        Ok(StoreSnapshot(files))
    }

    fn assert_persistent_secret_free(&self) -> TestResult {
        let mut files = Vec::new();
        collect_persistent_files(&self.root, &self.subject_key_file, &mut files)?;
        for path in files {
            let bytes = fs::read(&path)?;
            if bytes
                .windows(SECRET_MARKER.len())
                .any(|window| window == SECRET_MARKER.as_bytes())
            {
                return Err(io::Error::other(
                    "stopped control SQLite/WAL/journal or secret directory contained a secret marker",
                )
                .into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct StoreSnapshot(BTreeMap<String, FileStamp>);

#[derive(Debug, PartialEq, Eq)]
struct FileStamp {
    kind: &'static str,
    mode: u32,
    content_sha256: String,
}

fn collect_live_files(
    base: &Path,
    current: &Path,
    files: &mut BTreeMap<String, FileStamp>,
) -> TestResult {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path
            .strip_prefix(base)
            .map_err(|_| io::Error::other("store snapshot path escaped test root"))?
            .to_string_lossy()
            .into_owned();
        files.insert(relative.clone(), FileStamp::from_path(&path, &metadata)?);
        if metadata.is_dir() {
            collect_live_files(base, &path, files)?;
        }
    }
    Ok(())
}

fn collect_persistent_files(root: &Path, excluded: &Path, files: &mut Vec<PathBuf>) -> TestResult {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path == excluded {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            collect_persistent_files(&path, excluded, files)?;
        } else if metadata.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

impl FileStamp {
    fn from_path(path: &Path, metadata: &fs::Metadata) -> TestResult<Self> {
        let (kind, content_sha256) = if metadata.is_file() {
            ("file", sha256_file(path)?)
        } else if metadata.is_dir() {
            ("directory", sha256_bytes(&[]))
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(path)?;
            ("symlink", sha256_path(&target))
        } else {
            ("other", sha256_bytes(&[]))
        };
        Ok(Self {
            kind,
            mode: file_mode(metadata),
            content_sha256,
        })
    }
}

impl StoreSnapshot {
    fn digest(&self) -> String {
        let mut digest = Sha256::new();
        for (path, stamp) in &self.0 {
            update_digest_field(&mut digest, path.as_bytes());
            update_digest_field(&mut digest, stamp.kind.as_bytes());
            update_digest_field(&mut digest, &stamp.mode.to_le_bytes());
            update_digest_field(&mut digest, stamp.content_sha256.as_bytes());
        }
        hex_digest(&digest.finalize())
    }
}

fn update_digest_field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;

    metadata.mode()
}

#[cfg(not(unix))]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

#[cfg(unix)]
fn sha256_path(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;

    sha256_bytes(path.as_os_str().as_bytes())
}

#[cfg(not(unix))]
fn sha256_path(path: &Path) -> String {
    sha256_bytes(path.to_string_lossy().as_bytes())
}

fn sha256_file(path: &Path) -> TestResult<String> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex_digest(&digest.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_digest(&Sha256::digest(bytes))
}

fn hex_digest(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> TestResult {
    Ok(())
}

#[derive(Debug)]
enum Observation {
    Ready,
    Exited(ExitStatus),
    TimedOut,
}

impl Observation {
    fn failure_summary(&self, label: &str) -> String {
        match self {
            Self::Ready => {
                format!("{label} emitted READY unexpectedly")
            }
            Self::Exited(status) => {
                format!("{label} exited before READY ({})", status_summary(status))
            }
            Self::TimedOut => format!("{label} timed out before READY"),
        }
    }
}

struct CapturedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl CapturedOutput {
    fn contains_ready(&self) -> bool {
        String::from_utf8_lossy(&self.stdout)
            .lines()
            .any(|line| line.starts_with(READY_PREFIX))
    }
}

struct StoppedProcess {
    status: ExitStatus,
    output: CapturedOutput,
}

impl StoppedProcess {
    fn contains_ready(&self) -> bool {
        self.output.contains_ready()
    }
}

fn process_observation(
    damage: MetadataDamage,
    pid: u32,
    stopped: &StoppedProcess,
) -> ProcessObservation {
    ProcessObservation {
        name: format!("zode-server-missing-{}", damage.slug()),
        stdout: stopped.output.stdout.clone(),
        stderr: stopped.output.stderr.clone(),
        exit_code: stopped.status.code(),
        signal: exit_signal(&stopped.status).map(|signal| format!("signal-{signal}")),
        termination: "natural_exit_after_control_store_integrity_rejection".to_owned(),
        stop: Some(ProcessStopObservation {
            observed_pids: vec![pid],
            reaped_pids: vec![pid],
            leaked_pids: Vec::new(),
            timed_out: false,
            flush_status: "ok".to_owned(),
            proof: true,
        }),
    }
}

fn alias_process_observation(
    alias: ControlDatabaseAlias,
    pid: u32,
    stopped: &StoppedProcess,
) -> ProcessObservation {
    ProcessObservation {
        name: format!("zode-server-database-alias-{}", alias.label_slug()),
        stdout: stopped.output.stdout.clone(),
        stderr: stopped.output.stderr.clone(),
        exit_code: stopped.status.code(),
        signal: exit_signal(&stopped.status).map(|signal| format!("signal-{signal}")),
        termination: "bounded_stop_after_database_alias_rejection".to_owned(),
        stop: Some(ProcessStopObservation {
            observed_pids: vec![pid],
            reaped_pids: vec![pid],
            leaked_pids: Vec::new(),
            timed_out: false,
            flush_status: "ok".to_owned(),
            proof: true,
        }),
    }
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

struct ServerChild {
    child: Option<Child>,
    ready_rx: mpsc::Receiver<String>,
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    readers: Vec<JoinHandle<()>>,
}

impl ServerChild {
    fn spawn(config_path: &Path) -> TestResult<Self> {
        let binary = env::var_os("CARGO_BIN_EXE_zode-server")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "zode-server binary missing"))?;
        let mut child = Command::new(binary)
            .arg("--config")
            .arg(config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout_pipe = match child.stdout.take() {
            Some(pipe) => pipe,
            None => {
                terminate_child(&mut child);
                return Err(io::Error::other("zode-server stdout was not piped").into());
            }
        };
        let stderr_pipe = match child.stderr.take() {
            Some(pipe) => pipe,
            None => {
                terminate_child(&mut child);
                return Err(io::Error::other("zode-server stderr was not piped").into());
            }
        };

        let stdout = Arc::new(Mutex::new(Vec::new()));
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let (ready_tx, ready_rx) = mpsc::channel();
        let stdout_store = Arc::clone(&stdout);
        let stdout_reader = thread::spawn(move || {
            let mut reader = BufReader::new(stdout_pipe);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        if let Ok(mut captured) = stdout_store.lock() {
                            captured.extend_from_slice(line.as_bytes());
                        }
                        if ready_tx.send(line.clone()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        let stderr_store = Arc::clone(&stderr);
        let stderr_reader = thread::spawn(move || {
            let mut reader = BufReader::new(stderr_pipe);
            let mut bytes = Vec::new();
            let _ = reader.read_to_end(&mut bytes);
            if let Ok(mut captured) = stderr_store.lock() {
                captured.extend_from_slice(&bytes);
            }
        });

        Ok(Self {
            child: Some(child),
            ready_rx,
            stdout,
            stderr,
            readers: vec![stdout_reader, stderr_reader],
        })
    }

    fn observe(&mut self, timeout: Duration) -> TestResult<Observation> {
        let deadline = Instant::now() + timeout;
        loop {
            while let Ok(line) = self.ready_rx.try_recv() {
                if line.starts_with(READY_PREFIX) {
                    return Ok(Observation::Ready);
                }
            }

            if let Some(child) = self.child.as_mut() {
                if let Some(status) = child.try_wait()? {
                    return Ok(Observation::Exited(status));
                }
            } else {
                return Err(io::Error::other("zode-server child was already reaped").into());
            }

            if Instant::now() >= deadline {
                return Ok(Observation::TimedOut);
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn pid(&self) -> TestResult<u32> {
        self.child
            .as_ref()
            .map(Child::id)
            .ok_or_else(|| io::Error::other("zode-server child was already reaped").into())
    }

    fn observe_at(
        &mut self,
        timeout: Duration,
        listen_addr: SocketAddr,
    ) -> TestResult<(Observation, bool)> {
        if listen_addr.port() == 0 || !listen_addr.ip().is_loopback() {
            return Err(io::Error::other(
                "readiness evidence requires a fixed nonzero loopback listen address",
            )
            .into());
        }
        let deadline = Instant::now() + timeout;
        let mut public_port_contacted = false;
        let mut ready = false;
        loop {
            if !public_port_contacted
                && TcpStream::connect_timeout(&listen_addr, POLL_INTERVAL).is_ok()
            {
                public_port_contacted = true;
            }

            while let Ok(line) = self.ready_rx.try_recv() {
                if line.starts_with(READY_PREFIX) {
                    ready = true;
                }
            }
            if ready && public_port_contacted {
                return Ok((Observation::Ready, true));
            }

            if let Some(child) = self.child.as_mut() {
                if let Some(status) = child.try_wait()? {
                    return Ok((
                        if ready {
                            Observation::Ready
                        } else {
                            Observation::Exited(status)
                        },
                        public_port_contacted,
                    ));
                }
            } else {
                return Err(io::Error::other("zode-server child was already reaped").into());
            }

            if Instant::now() >= deadline {
                return Ok((
                    if ready {
                        Observation::Ready
                    } else {
                        Observation::TimedOut
                    },
                    public_port_contacted,
                ));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn is_running(&mut self) -> TestResult<bool> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::other("zode-server child was already reaped"))?;
        Ok(child.try_wait()?.is_none())
    }

    fn stop(&mut self) -> TestResult<StoppedProcess> {
        self.finish_stop()
    }

    #[cfg(unix)]
    fn graceful_stop(&mut self) -> TestResult<StoppedProcess> {
        let pid = {
            let child = self
                .child
                .as_mut()
                .ok_or_else(|| io::Error::other("zode-server child was already reaped"))?;
            if child.try_wait()?.is_some() {
                None
            } else {
                Some(child.id())
            }
        };
        if let Some(pid) = pid {
            let mut signaler = Command::new("/bin/kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .spawn()?;
            let result = wait_child_bounded(&mut signaler)?;
            if !result.success() {
                let still_running = self
                    .child
                    .as_mut()
                    .ok_or_else(|| io::Error::other("zode-server child was already reaped"))?
                    .try_wait()?
                    .is_none();
                if still_running {
                    return Err(io::Error::other(format!(
                        "graceful server shutdown signal was not delivered (exit code {:?})",
                        result.code(),
                    ))
                    .into());
                }
            }
        }
        self.finish_stop()
    }

    #[cfg(not(unix))]
    fn graceful_stop(&mut self) -> TestResult<StoppedProcess> {
        self.stop()
    }

    fn finish_stop(&mut self) -> TestResult<StoppedProcess> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::other("zode-server child was already reaped"))?;
        let status = reap_child_bounded(child)?;
        let _ = self.child.take();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        let stdout = self
            .stdout
            .lock()
            .map_err(|_| io::Error::other("stdout capture lock poisoned"))?
            .clone();
        let stderr = self
            .stderr
            .lock()
            .map_err(|_| io::Error::other("stderr capture lock poisoned"))?
            .clone();
        Ok(StoppedProcess {
            status,
            output: CapturedOutput { stdout, stderr },
        })
    }
}

impl Drop for ServerChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            terminate_child(&mut child);
        }
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

fn terminate_child(child: &mut Child) {
    let _ = reap_child_bounded(child);
}

fn reap_child_bounded(child: &mut Child) -> TestResult<ExitStatus> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    let _ = child.kill();
    wait_child_bounded(child)
}

fn wait_child_bounded(child: &mut Child) -> TestResult<ExitStatus> {
    let deadline = Instant::now() + STOP_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "zode-server child did not stop before the shutdown deadline",
            )
            .into());
        }
        thread::sleep(POLL_INTERVAL);
    }
}

#[allow(clippy::too_many_arguments)]
fn capture_first_readiness_failure(
    recording_id: &str,
    test_name: &str,
    phase: &str,
    listen_addr: SocketAddr,
    expected_failure: &str,
    observation: &Observation,
    public_port_contacted: bool,
    stopped: &StoppedProcess,
    before: &StoreSnapshot,
    after: &StoreSnapshot,
    forbidden_markers: &[String],
) -> TestResult {
    if env::var_os(CAPTURE_FIRST_OCCURRENCE_ENV).is_none() {
        return Ok(());
    }

    assert_safe_output(phase, stopped, forbidden_markers)?;
    let quarantine =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-recordings/quarantine");
    fs::create_dir_all(&quarantine)?;
    let destination = quarantine.join(recording_id);
    create_private_directory(&destination)?;

    let stdout_path = destination.join("server.stdout.bin");
    let stderr_path = destination.join("server.stderr.bin");
    write_private_new(&stdout_path, &stopped.output.stdout)?;
    write_private_new(&stderr_path, &stopped.output.stderr)?;

    let observed = match observation {
        Observation::Ready => "ready",
        Observation::Exited(_) => "active_nonzero",
        Observation::TimedOut => "timeout_or_harness",
    };
    let captured_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("system clock predates Unix epoch"))?
        .as_millis();
    let evidence = serde_json::to_vec_pretty(&json!({
        "schema": "zode.server-readiness-exit-evidence.v1",
        "version": 1,
        "recording_id": recording_id,
        "owner": test_name,
        "boundary": "zode-server startup before public listen",
        "phase": phase,
        "captured_at_unix_ms": captured_at_ms,
        "listen": listen_addr.to_string(),
        "http_exchanges": [],
        "http_exchange_note": "No HTTP request was sent; the contract is failure before public bind.",
        "expected": {
            "ready": false,
            "public_port_contacted": false,
            "exit_code": STARTUP_FAILURE_EXIT_CODE,
            "startup_failure": expected_failure,
        },
        "observed": {
            "outcome": observed,
            "ready_emitted": stopped.contains_ready(),
            "public_port_contacted": public_port_contacted,
            "stopped_status": status_summary(&stopped.status),
            "stdout_bytes": stopped.output.stdout.len(),
            "stdout_sha256": sha256_bytes(&stopped.output.stdout),
            "stderr_bytes": stopped.output.stderr.len(),
            "stderr_sha256": sha256_bytes(&stopped.output.stderr),
            "store_before_file_count": before.0.len(),
            "store_before_sha256": before.digest(),
            "store_after_file_count": after.0.len(),
            "store_after_sha256": after.digest(),
            "store_unchanged": before == after,
        },
    }))?;
    let evidence_path = destination.join("evidence.json");
    write_private_new(&evidence_path, &evidence)?;

    for path in [&stdout_path, &stderr_path, &evidence_path] {
        let bytes = fs::read(path)?;
        let text = String::from_utf8_lossy(&bytes);
        if forbidden_markers.iter().any(|marker| text.contains(marker)) {
            return Err(io::Error::other(
                "first-occurrence readiness evidence contained a forbidden marker",
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> TestResult {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> TestResult {
    fs::create_dir(path)?;
    Ok(())
}

#[cfg(unix)]
fn write_private_new(path: &Path, bytes: &[u8]) -> TestResult {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_new(path: &Path, bytes: &[u8]) -> TestResult {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn assert_startup_failure(
    label: &str,
    observation: &Observation,
    stopped: &StoppedProcess,
    expected_failure: &str,
    forbidden_markers: &[String],
) -> TestResult {
    assert_safe_output(label, stopped, forbidden_markers)?;
    if matches!(observation, Observation::Ready) || stopped.contains_ready() {
        return Err(
            io::Error::other(format!("{label} emitted READY before its startup failure",)).into(),
        );
    }
    let status = match observation {
        Observation::Exited(status) => status,
        Observation::TimedOut => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{label} did not fail before the readiness deadline"),
            )
            .into());
        }
        Observation::Ready => unreachable!(),
    };
    if status.code() != Some(STARTUP_FAILURE_EXIT_CODE) {
        return Err(io::Error::other(format!(
            "{label} did not exit with the stable startup failure code",
        ))
        .into());
    }
    let expected_line = format!("{STARTUP_FAILURE_PREFIX}{expected_failure}");
    if !String::from_utf8_lossy(&stopped.output.stderr)
        .lines()
        .any(|line| line.trim_end() == expected_line)
    {
        return Err(io::Error::other(format!(
            "{label} stderr did not contain the stable startup failure code and phase",
        ))
        .into());
    }
    Ok(())
}

fn assert_safe_output(
    label: &str,
    stopped: &StoppedProcess,
    forbidden_markers: &[String],
) -> TestResult {
    for (stream_name, bytes) in [
        ("stdout", &stopped.output.stdout),
        ("stderr", &stopped.output.stderr),
    ] {
        let text = String::from_utf8_lossy(bytes);
        if forbidden_markers.iter().any(|marker| text.contains(marker)) {
            return Err(io::Error::other(format!(
                "{label} {stream_name} contained a forbidden secret/path marker",
            ))
            .into());
        }
    }
    Ok(())
}

fn status_summary(status: &ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit code {code}"),
        None => "signal termination".to_owned(),
    }
}

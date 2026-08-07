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

use rusqlite::{Connection, OptionalExtension};
use serde_json::json;
use sha2::{Digest, Sha256};

const READY_PREFIX: &str = "ZODE_SERVER_READY ";
const STARTUP_FAILURE_PREFIX: &str = "ZODE_SERVER_STARTUP_FAILURE ";
const MISSING_SUBJECT_KEY_FAILURE: &str = "code=missing_subject_key phase=access_subject_key";
const SERVER_ALREADY_OWNED_FAILURE: &str = "code=server_already_owned phase=server_store_lock";
const CONTROL_STORE_INTEGRITY_FAILURE: &str = "code=control_store_integrity phase=control_store";
const CAPTURE_FIRST_OCCURRENCE_ENV: &str = "ZODE_CAPTURE_FIRST_OCCURRENCE";
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

#[test]
fn e2e_initialized_server_missing_metadata_never_reinitializes() -> TestResult {
    let mut failures = Vec::new();
    for damage in [MetadataDamage::SingletonRow, MetadataDamage::Table] {
        if let Err(error) = run_missing_metadata_case(damage) {
            failures.push(format!("{}: {error}", damage.label()));
        }
    }
    finish_cases("missing metadata authority", failures)
}

#[test]
fn e2e_second_server_control_database_alias_with_distinct_secret_store_never_becomes_ready(
) -> TestResult {
    let mut failures = Vec::new();
    for alias in [
        ControlDatabaseAlias::ExactPath,
        ControlDatabaseAlias::HardLink,
    ] {
        if let Err(error) = run_control_database_alias_case(alias) {
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

fn run_missing_metadata_case(damage: MetadataDamage) -> TestResult {
    let temp = tempfile::tempdir()?;
    let config = ConfigFixture::new(temp.path())?;
    establish_ready_baseline(&config, damage.label())?;
    damage.apply(&config.control_database)?;
    let before = config.live_store_snapshot()?;
    let held_listen = hold_public_listen(config.listen_addr)?;
    let mut restarted = ServerChild::spawn(&config.config_path)?;
    let observation = restarted.observe(READY_TIMEOUT)?;
    let stopped = restarted.stop()?;
    if held_listen.local_addr()? != config.listen_addr {
        return Err(io::Error::other("metadata failure listen guard changed address").into());
    }
    drop(held_listen);
    let after = config.live_store_snapshot()?;
    let forbidden = config.forbidden_markers();
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
    let startup = assert_startup_failure(
        damage.label(),
        &observation,
        &stopped,
        CONTROL_STORE_INTEGRITY_FAILURE,
        &forbidden,
    );
    let damage_preserved = damage.is_present(&config.control_database)?;
    config.assert_persistent_secret_free()?;
    capture?;
    port_released?;
    if before != after {
        return Err(io::Error::other(
            "failed restart changed persistent store file set/content/mode",
        )
        .into());
    }
    if !damage_preserved {
        return Err(io::Error::other("failed restart recreated missing authority metadata").into());
    }
    startup
}

fn run_control_database_alias_case(alias: ControlDatabaseAlias) -> TestResult {
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
    let second_observation = second.observe(READY_TIMEOUT)?;
    let second_stopped = second.stop()?;
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

        let value = json!({
            "schema": "zode.server-config.v1",
            "listen": listen_addr.to_string(),
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
        let value = json!({
            "schema": "zode.server-config.v1",
            "listen": listen_addr.to_string(),
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

#![allow(dead_code)]

mod support;

use std::{
    error::Error,
    fs,
    io::{Error as IoError, ErrorKind},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};

use serde_json::{json, Value};
use support::{
    kill_and_reap, reap_child_on_drop, write_endpoint_config, ConfiguredServer, TempDatabase,
    TestResult,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader, Lines},
    process::{Child, ChildStdout, Command},
    time::timeout,
};

const READY_PREFIX: &str = "ZODE_READY ";
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const FAILURE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;

fn config_with_listen(
    database: &TempDatabase,
    listen: &str,
    tools: Vec<Value>,
) -> TestResult<PathBuf> {
    let path = write_endpoint_config(database.path(), tools, 1)?;
    let mut config: Value = serde_json::from_slice(&fs::read(&path)?)?;
    config["listen"] = Value::String(listen.to_owned());
    fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    Ok(path)
}

fn reserved_wait_for_tool() -> Value {
    json!({
        "name": "wait_for",
        "description": "HTTP tool using a runtime-reserved name",
        "input_schema": {"type": "object"},
        "completion_mode": "response",
        "auto_wait_timeout_seconds": 20,
        "recovery": {
            "on_running_restart": "unknown_outcome",
            "retry_dispatch": "never"
        },
        "adapter": {
            "kind": "http",
            "url": "http://127.0.0.1:1/invoke"
        }
    })
}

fn sidecar_path(database: &Path, suffix: &str) -> PathBuf {
    let mut value = database.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn assert_active_nonzero_failure(label: &str, error: &dyn Error) -> TestResult<()> {
    let message = error.to_string();
    if message.contains("did not become ready") {
        return Err(IoError::other(format!(
            "{label} was treated as a readiness timeout: {message}"
        ))
        .into());
    }
    if !message.contains("non-zero") {
        return Err(IoError::other(format!(
            "{label} did not report an active non-zero child exit: {message}"
        ))
        .into());
    }
    Ok(())
}

struct RawProcess {
    child: Option<Child>,
    lines: Lines<BufReader<ChildStdout>>,
    pid: u32,
    exit_status: Option<ExitStatus>,
}

impl RawProcess {
    async fn spawn(
        current_dir: &Path,
        config: Option<&Path>,
        database: Option<&Path>,
        listen: Option<&str>,
        environment: &[(&str, String)],
    ) -> TestResult<Self> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_zode"));
        if let Some(config) = config {
            command.arg("--config").arg(config);
        }
        if let Some(database) = database {
            command.arg("--database").arg(database);
        }
        if let Some(listen) = listen {
            command.arg("--listen").arg(listen);
        }
        command
            .current_dir(current_dir)
            .env_remove("ZODE_DATABASE")
            .env_remove("ZODE_DB_PATH")
            .env_remove("ZODE_LISTEN")
            .env_remove("ZODE_LISTEN_ADDR")
            .env_remove("ZODE_SNAPSHOT_EVERY")
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for (name, value) in environment {
            command.env(name, value);
        }
        let mut child = command.spawn()?;
        let pid = match child.id() {
            Some(pid) => pid,
            None => {
                let _ = kill_and_reap(child).await;
                return Err(IoError::other("zode child did not expose a pid").into());
            }
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let _ = kill_and_reap(child).await;
                return Err(IoError::other(format!(
                    "zode pid {pid} did not expose readiness output"
                ))
                .into());
            }
        };
        Ok(Self {
            child: Some(child),
            lines: BufReader::new(stdout).lines(),
            pid,
            exit_status: None,
        })
    }

    async fn wait_ready(&mut self, deadline: Duration) -> TestResult<String> {
        let line = match timeout(deadline, self.lines.next_line()).await {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) => {
                let status = self.reap().await?;
                return Err(IoError::other(format!(
                    "zode pid {} exited before readiness with {} process status {status}",
                    self.pid,
                    if status.success() { "zero" } else { "non-zero" }
                ))
                .into());
            }
            Ok(Err(error)) => {
                let status = self.reap().await?;
                return Err(IoError::other(format!(
                    "zode pid {} readiness output failed ({error}); child exited with {} process status {status}",
                    self.pid,
                    if status.success() { "zero" } else { "non-zero" }
                ))
                .into());
            }
            Err(_) => {
                self.stop().await?;
                return Err(IoError::new(
                    ErrorKind::TimedOut,
                    format!("zode pid {} did not become ready", self.pid),
                )
                .into());
            }
        };
        let Some(url) = line.strip_prefix(READY_PREFIX) else {
            self.stop().await?;
            return Err(IoError::other(format!(
                "zode pid {} emitted invalid readiness output",
                self.pid
            ))
            .into());
        };
        Ok(url.trim().to_owned())
    }

    async fn expect_nonzero_exit(&mut self, deadline: Duration) -> TestResult<()> {
        match timeout(deadline, self.lines.next_line()).await {
            Ok(Ok(Some(line))) => {
                self.stop().await?;
                return Err(IoError::other(format!(
                    "zode pid {} emitted output before bounded config failure: {line}",
                    self.pid
                ))
                .into());
            }
            Ok(Err(error)) => {
                let _ = self.stop().await;
                return Err(error.into());
            }
            Err(_) => {
                self.stop().await?;
                return Err(IoError::new(
                    ErrorKind::TimedOut,
                    format!("zode pid {} did not become ready", self.pid),
                )
                .into());
            }
            Ok(Ok(None)) => {}
        }
        let status = self.reap_naturally(FAILURE_TIMEOUT).await?;
        if status.success() {
            return Err(IoError::other(format!(
                "zode pid {} exited successfully instead of non-zero: {status}",
                self.pid
            ))
            .into());
        }
        Ok(())
    }

    async fn reap(&mut self) -> TestResult<ExitStatus> {
        let child = self
            .child
            .take()
            .ok_or_else(|| IoError::other("zode child was already reaped"))?;
        let status = kill_and_reap(child).await?;
        self.exit_status = Some(status);
        Ok(status)
    }

    async fn reap_naturally(&mut self, deadline: Duration) -> TestResult<ExitStatus> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| IoError::other("zode child was already reaped"))?;
        let result = timeout(deadline, child.wait()).await;
        match result {
            Ok(status) => {
                let status = status?;
                self.exit_status = Some(status);
                Ok(status)
            }
            Err(_) => {
                let status = kill_and_reap(child).await?;
                self.exit_status = Some(status);
                Err(IoError::new(
                    ErrorKind::TimedOut,
                    format!("zode pid {} did not become ready", self.pid),
                )
                .into())
            }
        }
    }

    async fn stop(&mut self) -> TestResult<()> {
        if self.child.is_some() {
            self.reap().await?;
        }
        Ok(())
    }
}

impl Drop for RawProcess {
    fn drop(&mut self) {
        reap_child_on_drop(self.child.take());
    }
}

struct FifoWriter {
    child: Option<Child>,
}

impl FifoWriter {
    async fn start(path: &Path) -> TestResult<Self> {
        let status = timeout(
            Duration::from_secs(2),
            Command::new("mkfifo").arg(path).status(),
        )
        .await??;
        if !status.success() {
            return Err(IoError::other(format!("mkfifo failed with status {status}")).into());
        }
        let block_count = MAX_CONFIG_BYTES / 1_048_576;
        let remainder = MAX_CONFIG_BYTES % 1_048_576 + 1;
        let script = format!(
            "exec 3>\"$1\"; dd if=/dev/zero bs=1048576 count={block_count} >&3 2>/dev/null; head -c {remainder} /dev/zero >&3; tail -f /dev/null"
        );
        let child = Command::new("sh")
            .arg("-c")
            .arg(script)
            .arg("config-fifo-writer")
            .arg(path)
            .kill_on_drop(true)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        Ok(Self { child: Some(child) })
    }

    async fn stop(&mut self) -> TestResult<()> {
        if let Some(child) = self.child.take() {
            kill_and_reap(child).await?;
        }
        Ok(())
    }
}

impl Drop for FifoWriter {
    fn drop(&mut self) {
        reap_child_on_drop(self.child.take());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_reserved_wait_for_tool_name_is_rejected_before_ready() -> TestResult<()> {
    let database = TempDatabase::new("config-reserved-wait-for")?;
    let config = config_with_listen(&database, "127.0.0.1:0", vec![reserved_wait_for_tool()])?;
    let result = ConfiguredServer::start(&database, &config).await;
    match result {
        Err(error) => assert_active_nonzero_failure("reserved wait_for config", error.as_ref()),
        Ok(mut server) => {
            server.stop().await?;
            Err(IoError::other("Endpoint became ready with configured wait_for HTTP tool").into())
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_model_stream_idle_timeout_zero_is_rejected_before_ready() -> TestResult<()> {
    let database = TempDatabase::new("config-model-stream-idle-timeout")?;
    let config = write_endpoint_config(&database, Vec::new(), 1)?;
    let mut value: Value = serde_json::from_slice(&fs::read(&config)?)?;
    value["runtime"]["model_stream_idle_timeout_ms"] = json!(0);
    fs::write(&config, serde_json::to_vec_pretty(&value)?)?;

    let result = ConfiguredServer::start(&database, &config).await;
    match result {
        Err(error) => {
            assert_active_nonzero_failure("zero model stream idle timeout", error.as_ref())?;
            assert!(
                !database.path().exists(),
                "invalid model stream timeout created the runtime SQLite path"
            );
            Ok(())
        }
        Ok(mut server) => {
            server.stop().await?;
            Err(
                IoError::other("Endpoint became ready with a zero model stream idle timeout")
                    .into(),
            )
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_cli_listen_override_beats_invalid_config_listen() -> TestResult<()> {
    let database = TempDatabase::new("config-cli-listen")
        .map_err(|error| IoError::other(format!("temporary setup failed: {error}")))?;
    let config = config_with_listen(&database, "invalid", Vec::new())?;
    let mut server = ConfiguredServer::start(&database, &config)
        .await
        .map_err(|error| IoError::other(format!("valid --listen override did not win: {error}")))?;
    server.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_cli_listen_override_beats_invalid_environment_listen() -> TestResult<()> {
    let database = TempDatabase::new("config-cli-env-listen")?;
    let current_dir = database
        .parent()
        .ok_or_else(|| IoError::other("temporary database has no parent"))?;
    let mut process = RawProcess::spawn(
        current_dir,
        None,
        Some(database.path()),
        Some("127.0.0.1:0"),
        &[("ZODE_LISTEN", "invalid".to_owned())],
    )
    .await?;
    let ready = process.wait_ready(READY_TIMEOUT).await;
    process.stop().await?;
    ready.map(|_| ())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_environment_database_is_not_authoritative_without_config() -> TestResult<()> {
    let database = TempDatabase::new("config-env-database")
        .map_err(|error| IoError::other(format!("temporary setup failed: {error}")))?;
    let current_dir = database
        .parent()
        .ok_or_else(|| IoError::other("temporary database has no parent"))?;
    let environment_database = current_dir.join("environment.sqlite3");
    let default_database = current_dir.join("zode.sqlite3");
    let mut process = RawProcess::spawn(
        current_dir,
        None,
        None,
        Some("127.0.0.1:0"),
        &[(
            "ZODE_DATABASE",
            environment_database.to_string_lossy().into_owned(),
        )],
    )
    .await?;
    let ready = process.wait_ready(READY_TIMEOUT).await?;
    assert!(ready.starts_with("http://127.0.0.1:"));
    process.stop().await?;
    assert!(
        default_database.exists(),
        "no-config startup did not use cwd/zode.sqlite3"
    );
    assert!(
        !environment_database.exists(),
        "ZODE_DATABASE unexpectedly selected the runtime SQLite path"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_oversized_fifo_config_exits_before_writer_eof() -> TestResult<()> {
    let database = TempDatabase::new("config-fifo-bound")
        .map_err(|error| IoError::other(format!("temporary setup failed: {error}")))?;
    let fifo = database
        .parent()
        .ok_or_else(|| IoError::other("temporary database has no parent"))?
        .join("streamed-config.json");
    let mut writer = FifoWriter::start(&fifo).await?;
    let mut process = RawProcess::spawn(
        database.parent().unwrap_or_else(|| Path::new(".")),
        Some(&fifo),
        Some(database.path()),
        Some("127.0.0.1:0"),
        &[],
    )
    .await?;
    let process_result = process.expect_nonzero_exit(FAILURE_TIMEOUT).await;
    let writer_result = writer.stop().await;
    let fifo_result = fs::remove_file(&fifo)
        .map_err(|error| IoError::other(format!("FIFO cleanup failed: {error}")));
    process_result?;
    writer_result?;
    fifo_result?;
    Ok(())
}

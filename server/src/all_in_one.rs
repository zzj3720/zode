use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::Path,
    process::Stdio,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use getrandom::fill as fill_random;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpStream,
    process::{Child, Command},
    task::JoinHandle,
    time::{timeout, Duration},
};

use crate::{
    catalog::{Catalog, EndpointProbe},
    config::{Deployment, LocalEndpointConfig, ServerConfig},
    store::{hex, ControlStore, LocalBootstrapPhase, LocalEndpointCommit, StoreError},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const READY_TIMEOUT: Duration = Duration::from_secs(15);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const SECRET_BYTES: usize = 32;

#[derive(Debug, Error)]
pub(crate) enum LocalEndpointError {
    #[error("local Endpoint configuration is unavailable")]
    Configuration,
    #[error("local Endpoint authority is unavailable")]
    Authority,
    #[error("local Endpoint process is unavailable")]
    Process,
    #[error("local Endpoint identity is unavailable")]
    Identity,
    #[error("local Endpoint catalog is unavailable")]
    Catalog,
}

pub(crate) struct AllInOneComposition {
    pub(crate) local_endpoint_id: Option<String>,
    pub(crate) supervisor: Option<LocalEndpointSupervisor>,
}

pub(crate) struct LocalEndpointSupervisor {
    child: Child,
    stdout: JoinHandle<()>,
    stderr: JoinHandle<()>,
}

struct Secret(Vec<u8>);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub(crate) async fn compose(
    config: &ServerConfig,
    store: Arc<ControlStore>,
    catalog: Arc<Catalog>,
) -> Result<AllInOneComposition, LocalEndpointError> {
    if config.deployment() == Deployment::ServerOnly {
        return Ok(AllInOneComposition {
            local_endpoint_id: None,
            supervisor: None,
        });
    }
    let local = config
        .local_endpoint()
        .ok_or(LocalEndpointError::Configuration)?;
    let keys = store.keys();
    let secret_ref = hex(&keys.digest(
        b"local-endpoint-control-secret-ref-v1",
        &[config.server_authority_id().as_bytes()],
    ));
    let bootstrap_exists = store
        .local_endpoint_bootstrap_phase()
        .map_err(map_store_authority)?
        .is_some();
    let secret = match store
        .load_endpoint_secret(&secret_ref)
        .map_err(map_store_authority)?
    {
        Some(secret) => Secret(secret),
        None if !bootstrap_exists => {
            let mut random = [0_u8; SECRET_BYTES];
            fill_random(&mut random).map_err(|_| LocalEndpointError::Authority)?;
            let generated = Secret(hex(&random).into_bytes());
            random.fill(0);
            store
                .stage_endpoint_secret(&secret_ref, &generated.0)
                .map_err(map_store_authority)?;
            generated
        }
        None => return Err(LocalEndpointError::Authority),
    };
    let fingerprint = keys.digest(
        b"local-endpoint-controller-secret-v1",
        &[config.server_authority_id().as_bytes(), &secret.0],
    );
    let phase = store
        .begin_local_endpoint_bootstrap(&fingerprint)
        .map_err(map_store_authority)?;
    if phase == LocalBootstrapPhase::Pending {
        ensure_seed(local.bootstrap_controller_secret_file(), &secret.0)?;
    }
    let bearer = std::str::from_utf8(&secret.0).map_err(|_| LocalEndpointError::Authority)?;

    let occupied = endpoint_address_occupied(local).await?;
    let mut supervisor = if occupied {
        None
    } else {
        Some(LocalEndpointSupervisor::start(local).await?)
    };
    let result = probe_and_commit(
        config,
        local,
        &store,
        &catalog,
        &fingerprint,
        &secret_ref,
        bearer,
    )
    .await;
    match result {
        Ok(endpoint_id) => Ok(AllInOneComposition {
            local_endpoint_id: Some(endpoint_id),
            supervisor,
        }),
        Err(error) => {
            if let Some(owned) = supervisor.take() {
                let _ = owned.shutdown().await;
            }
            Err(error)
        }
    }
}

async fn endpoint_address_occupied(
    local: &LocalEndpointConfig,
) -> Result<bool, LocalEndpointError> {
    match timeout(CONNECT_TIMEOUT, TcpStream::connect(local.listen_addr())).await {
        Ok(Ok(stream)) => {
            drop(stream);
            Ok(true)
        }
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => Ok(false),
        Ok(Err(_)) | Err(_) => Err(LocalEndpointError::Process),
    }
}

async fn probe_and_commit(
    config: &ServerConfig,
    local: &LocalEndpointConfig,
    store: &ControlStore,
    catalog: &Catalog,
    fingerprint: &[u8; 32],
    secret_ref: &str,
    bearer: &str,
) -> Result<String, LocalEndpointError> {
    let probe = catalog
        .probe_local_endpoint(&local.origin(), bearer)
        .await
        .map_err(|_| LocalEndpointError::Identity)?;
    validate_probe(config, &probe)?;
    let endpoint_id = probe.identity.endpoint_id.clone();
    store
        .commit_local_endpoint(
            fingerprint,
            LocalEndpointCommit {
                endpoint_id: endpoint_id.clone(),
                base_url: local.origin(),
                controller_authority_id: probe.identity.authority_id,
                controller_credential_revision: probe.identity.revision,
                protocol_version: probe.identity.protocol_version,
                provider_adapter_kinds: probe.capabilities.provider_adapter_kinds,
                tools: probe
                    .capabilities
                    .tools
                    .into_iter()
                    .map(|tool| tool.name)
                    .collect(),
                secret_ref: secret_ref.to_owned(),
                observed_at_ms: unix_millis()?,
            },
        )
        .map_err(|_| LocalEndpointError::Catalog)?;
    Ok(endpoint_id)
}

fn validate_probe(_config: &ServerConfig, probe: &EndpointProbe) -> Result<(), LocalEndpointError> {
    if probe.identity.endpoint_id != probe.capabilities.endpoint_id
        || probe.identity.protocol_version != probe.capabilities.protocol_version
    {
        return Err(LocalEndpointError::Identity);
    }
    Ok(())
}

impl LocalEndpointSupervisor {
    async fn start(local: &LocalEndpointConfig) -> Result<Self, LocalEndpointError> {
        let mut child = Command::new(local.executable())
            .arg("--config")
            .arg(local.config())
            .arg("--listen")
            .arg(local.listen_addr().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(false)
            .spawn()
            .map_err(|_| LocalEndpointError::Process)?;
        let stdout = child
            .stdout
            .take()
            .expect("piped child stdout is available");
        let stderr = child
            .stderr
            .take()
            .expect("piped child stderr is available");
        let stderr = tokio::spawn(drain(stderr));
        let mut lines = BufReader::new(stdout).lines();
        let expected = format!("ZODE_READY {}", local.origin());
        let ready = timeout(READY_TIMEOUT, async {
            while let Some(line) = lines
                .next_line()
                .await
                .map_err(|_| LocalEndpointError::Process)?
            {
                if line.starts_with("ZODE_READY ") {
                    return if line == expected {
                        Ok(())
                    } else {
                        Err(LocalEndpointError::Identity)
                    };
                }
            }
            Err(LocalEndpointError::Process)
        })
        .await
        .map_err(|_| LocalEndpointError::Process)?;
        if let Err(error) = ready {
            let supervisor = Self {
                child,
                stdout: tokio::spawn(drain(lines.into_inner())),
                stderr,
            };
            let _ = supervisor.shutdown().await;
            return Err(error);
        }
        Ok(Self {
            child,
            stdout: tokio::spawn(drain(lines.into_inner())),
            stderr,
        })
    }

    pub(crate) async fn shutdown(mut self) -> Result<(), LocalEndpointError> {
        let running = self
            .child
            .try_wait()
            .map_err(|_| LocalEndpointError::Process)?
            .is_none();
        if running {
            let terminated = self.child.id().is_some_and(|pid| terminate(pid).is_ok());
            if !terminated
                && self
                    .child
                    .try_wait()
                    .map_err(|_| LocalEndpointError::Process)?
                    .is_none()
            {
                self.child
                    .start_kill()
                    .map_err(|_| LocalEndpointError::Process)?;
            }
        }
        if timeout(STOP_TIMEOUT, self.child.wait()).await.is_err() {
            self.child
                .start_kill()
                .map_err(|_| LocalEndpointError::Process)?;
            self.child
                .wait()
                .await
                .map_err(|_| LocalEndpointError::Process)?;
        }
        let _ = timeout(STOP_TIMEOUT, self.stdout).await;
        let _ = timeout(STOP_TIMEOUT, self.stderr).await;
        Ok(())
    }
}

async fn drain<R>(mut reader: R)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
}

#[cfg(unix)]
fn terminate(pid: u32) -> Result<(), LocalEndpointError> {
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if result == 0 {
        Ok(())
    } else {
        Err(LocalEndpointError::Process)
    }
}

#[cfg(not(unix))]
fn terminate(_pid: u32) -> Result<(), LocalEndpointError> {
    Err(LocalEndpointError::Process)
}

fn ensure_seed(path: &Path, secret: &[u8]) -> Result<(), LocalEndpointError> {
    let parent = path.parent().ok_or(LocalEndpointError::Configuration)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(LocalEndpointError::Configuration)?;
    let pending = parent.join(format!(".{name}.zode-server-pending"));
    for _ in 0..2 {
        if let Some(existing) = read_private(path, secret.len() + 1)? {
            if existing.len() == secret.len() && bool::from(existing.as_slice().ct_eq(secret)) {
                remove_matching_pending(&pending, parent, secret)?;
                return Ok(());
            }
            return Err(LocalEndpointError::Authority);
        }
        ensure_private_candidate(&pending, secret)?;
        match fs::hard_link(&pending, path) {
            Ok(()) => {
                sync_directory(parent)?;
                fs::remove_file(&pending).map_err(|_| LocalEndpointError::Authority)?;
                return sync_directory(parent);
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(LocalEndpointError::Authority),
        }
    }
    Err(LocalEndpointError::Authority)
}

fn ensure_private_candidate(path: &Path, secret: &[u8]) -> Result<(), LocalEndpointError> {
    if let Some(existing) = read_private(path, secret.len() + 1)? {
        return if existing.len() == secret.len() && bool::from(existing.as_slice().ct_eq(secret)) {
            Ok(())
        } else {
            Err(LocalEndpointError::Authority)
        };
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| LocalEndpointError::Authority)?;
    file.write_all(secret)
        .map_err(|_| LocalEndpointError::Authority)?;
    file.sync_all().map_err(|_| LocalEndpointError::Authority)
}

fn remove_matching_pending(
    path: &Path,
    parent: &Path,
    secret: &[u8],
) -> Result<(), LocalEndpointError> {
    let Some(existing) = read_private(path, secret.len() + 1)? else {
        return Ok(());
    };
    if existing.len() != secret.len() || !bool::from(existing.as_slice().ct_eq(secret)) {
        return Err(LocalEndpointError::Authority);
    }
    fs::remove_file(path).map_err(|_| LocalEndpointError::Authority)?;
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> Result<(), LocalEndpointError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| LocalEndpointError::Authority)
}

fn read_private(path: &Path, max_bytes: usize) -> Result<Option<Vec<u8>>, LocalEndpointError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(LocalEndpointError::Authority),
    };
    if !metadata.file_type().is_file() {
        return Err(LocalEndpointError::Authority);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(LocalEndpointError::Authority);
        }
    }
    let file = File::open(path).map_err(|_| LocalEndpointError::Authority)?;
    let mut bytes = Vec::with_capacity(max_bytes);
    file.take(max_bytes as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| LocalEndpointError::Authority)?;
    if bytes.len() >= max_bytes {
        return Err(LocalEndpointError::Authority);
    }
    Ok(Some(bytes))
}

fn unix_millis() -> Result<i64, LocalEndpointError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LocalEndpointError::Catalog)?
        .as_millis();
    i64::try_from(millis).map_err(|_| LocalEndpointError::Catalog)
}

fn map_store_authority(_error: StoreError) -> LocalEndpointError {
    LocalEndpointError::Authority
}

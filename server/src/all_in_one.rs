use std::{
    io::ErrorKind,
    process::Stdio,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

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
    store::{hex, ControlStore, LocalEndpointCommit, StoreError},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const READY_TIMEOUT: Duration = Duration::from_secs(15);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

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
    let fingerprint = keys.digest(
        b"local-endpoint-identity-v1",
        &[
            config.server_authority_id().as_bytes(),
            local.origin().as_bytes(),
        ],
    );
    store
        .begin_local_endpoint_bootstrap(&fingerprint)
        .map_err(map_store_authority)?;

    let occupied = endpoint_address_occupied(local).await?;
    let mut supervisor = if occupied {
        None
    } else {
        Some(LocalEndpointSupervisor::start(local).await?)
    };
    let result = probe_and_commit(config, local, &store, &catalog, &fingerprint, &secret_ref).await;
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
) -> Result<String, LocalEndpointError> {
    let probe = catalog
        .probe_local_endpoint(&local.origin(), "")
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

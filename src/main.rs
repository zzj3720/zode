mod config;

use std::{
    env,
    future::{Future, IntoFuture},
    io::Write,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use config::EndpointConfig;
use zode::{
    control::ControlState,
    http,
    provider::{AimuxProvider, ProviderExecutionPolicy},
    replicas::FileReplicaStore,
    runtime::{Runtime, TimerArm, TimerPort},
    storage::SqliteEventStore,
    timer::{SleepTimer, SystemClock},
    tools::HttpToolExecutor,
};

const ENDPOINT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct Cli {
    config_path: Option<PathBuf>,
    database_path: Option<PathBuf>,
    listen_addr: Option<String>,
    snapshot_every: Option<u64>,
}

struct Composition {
    runtime_options: zode::runtime::RuntimeOptions,
    control: Arc<ControlState>,
    replicas: Arc<FileReplicaStore>,
    provider_policy: ProviderExecutionPolicy,
    tool_specs: Vec<zode::tools::HttpToolSpec>,
    blob_store: Option<Arc<dyn zode::runtime::BlobStore>>,
    health_body: Vec<u8>,
    capabilities_body: Vec<u8>,
}

impl Cli {
    fn parse() -> Result<Self, String> {
        let mut config_path = None;
        let mut database_path = None;
        let mut listen_addr = None;
        let mut snapshot_every = None;

        let mut args = env::args().skip(1);
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--config" => {
                    if config_path.is_some() {
                        return Err("--config may only be supplied once".to_owned());
                    }
                    config_path = Some(
                        args.next()
                            .ok_or_else(|| "--config requires a JSON path".to_owned())?
                            .into(),
                    );
                }
                "--database" | "--db" => {
                    if database_path.is_some() {
                        return Err("--database may only be supplied once".to_owned());
                    }
                    database_path = Some(
                        args.next()
                            .ok_or_else(|| format!("{argument} requires a path"))?
                            .into(),
                    );
                }
                "--listen" => {
                    if listen_addr.is_some() {
                        return Err("--listen may only be supplied once".to_owned());
                    }
                    listen_addr = Some(
                        args.next()
                            .ok_or_else(|| format!("{argument} requires an address"))?,
                    );
                }
                "--snapshot-every" => {
                    if snapshot_every.is_some() {
                        return Err("--snapshot-every may only be supplied once".to_owned());
                    }
                    let value = args
                        .next()
                        .ok_or_else(|| format!("{argument} requires a positive integer"))?;
                    snapshot_every = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| format!("invalid snapshot interval {value}"))?,
                    );
                }
                "--help" | "-h" => {
                    return Err("usage: zode [--config JSON] [--database PATH] [--listen ADDR] [--snapshot-every N]".into());
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }

        Ok(Self {
            config_path,
            database_path,
            listen_addr,
            snapshot_every,
        })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = match Cli::parse() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };

    let config = EndpointConfig::load(
        cli.config_path.as_deref(),
        cli.listen_addr.as_deref(),
        cli.database_path.as_deref(),
        cli.snapshot_every,
    )?;
    let control = Arc::new(ControlState::open(
        config.runtime_store_path(),
        config.credential_replica_directory(),
    )?);
    let database_path = control.runtime_store_path().to_path_buf();
    let listen_addr = config.listen_addr()?;
    let runtime_options = config.runtime_options();
    let credential_replica_directory = control.credential_replica_directory().map(PathBuf::from);
    let replicas = Arc::new(FileReplicaStore::open(
        credential_replica_directory.as_deref(),
    )?);
    let (adapter_kinds, allowed_origins, transport_retry) = config.provider_execution_policy();
    let capabilities_body = http::build_capabilities_body_with_callback(
        control.endpoint_id(),
        adapter_kinds.clone(),
        config.capability_tools(),
        true,
    )?;
    let health_body = http::build_health_body(control.endpoint_id())?;
    let provider_policy =
        ProviderExecutionPolicy::new(adapter_kinds, allowed_origins, transport_retry);
    let tool_specs = config.tool_specs();
    let blob_store = config
        .blob_store_directory()
        .map(zode::tools::FileBlobStore::open)
        .transpose()?;
    let blob_store = blob_store.map(|store| Arc::new(store) as Arc<dyn zode::runtime::BlobStore>);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(
        database_path,
        listen_addr,
        Composition {
            runtime_options,
            control,
            replicas,
            provider_policy,
            tool_specs,
            blob_store,
            health_body,
            capabilities_body,
        },
    ))
}

async fn run(
    database_path: PathBuf,
    listen_addr: std::net::SocketAddr,
    composition: Composition,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(
        tokio::task::spawn_blocking(move || SqliteEventStore::open(database_path)).await??,
    );
    let provider = Arc::new(AimuxProvider::new(composition.provider_policy.clone()));
    let tools = match composition.blob_store {
        Some(blob_store) => Arc::new(HttpToolExecutor::new_with_blob_store(
            composition.tool_specs,
            blob_store,
        )),
        None => Arc::new(HttpToolExecutor::new(composition.tool_specs)),
    };
    let clock = Arc::new(SystemClock);
    let (due_tx, mut due_rx) = tokio::sync::mpsc::unbounded_channel::<TimerArm>();
    let timer = Arc::new(SleepTimer::new(clock.clone(), due_tx));
    let runtime = Runtime::new_with_options(
        store,
        provider,
        tools,
        composition.runtime_options,
        clock,
        timer.clone(),
        Arc::new(composition.provider_policy.clone()),
        composition.replicas.clone(),
    );
    let expire = runtime.clone();
    tokio::spawn(async move {
        while let Some(arm) = due_rx.recv().await {
            expire.expire_wait(arm).await;
        }
    });
    runtime.queue_startup_recovery().await?;
    let state = http::AppState::new(
        composition.control,
        runtime.clone(),
        composition.health_body,
        composition.capabilities_body,
    );
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    let address = listener.local_addr()?;

    println!("ZODE_READY http://{address}");
    std::io::stdout().flush()?;

    let shutdown_signal = arm_shutdown_signal()?;
    tokio::pin!(shutdown_signal);
    let (shutdown, shutdown_requested) = tokio::sync::oneshot::channel::<()>();
    let serving = axum::serve(listener, http::router(state))
        .with_graceful_shutdown(async {
            let _ = shutdown_requested.await;
        })
        .into_future();
    tokio::pin!(serving);

    let result = tokio::select! {
        result = &mut serving => result,
        () = &mut shutdown_signal => {
            // Stop HTTP admission first; then refuse new wakes before sleeps are dropped.
            let _ = shutdown.send(());
            runtime.shutdown().await;
            match tokio::time::timeout(ENDPOINT_DRAIN_TIMEOUT, &mut serving).await {
                Ok(result) => result,
                Err(_) => Ok(()),
            }
        }
    };
    runtime.shutdown().await;
    timer.shutdown();
    result?;
    Ok(())
}

#[cfg(unix)]
fn arm_shutdown_signal() -> Result<impl Future<Output = ()>, std::io::Error> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    Ok(async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    })
}

#[cfg(not(unix))]
fn arm_shutdown_signal() -> Result<impl Future<Output = ()>, std::io::Error> {
    Ok(async {
        let _ = tokio::signal::ctrl_c().await;
    })
}

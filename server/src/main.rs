mod access;
mod all_in_one;
mod app;
mod catalog;
mod config;
mod provider_authority;
mod session_proxy;
mod store;
mod ui_assets;

use std::{
    env, future::IntoFuture, io::Write, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration,
};

use access::AccessVerifier;
use all_in_one::{LocalEndpointError, LocalEndpointSupervisor};
use axum::Router;
use catalog::Catalog;
use config::{ConfigError, ServerConfig};
use provider_authority::ProviderAuthority;
use session_proxy::SessionProxy;
use store::{ControlStore, StartupError};

const USAGE: &str = "usage: zode-server --config <path>";
const SERVER_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

struct Cli {
    config_path: PathBuf,
}

impl Cli {
    fn parse() -> Result<Self, &'static str> {
        let mut config_path = None;
        let mut arguments = env::args_os().skip(1);
        while let Some(argument) = arguments.next() {
            if argument == "--config" {
                if config_path.is_some() {
                    return Err("--config may be provided only once");
                }
                config_path = Some(arguments.next().ok_or("--config requires a path")?.into());
            } else {
                return Err("unknown command-line argument");
            }
        }
        Ok(Self {
            config_path: config_path.ok_or("--config is required")?,
        })
    }
}

fn main() {
    let cli = match Cli::parse() {
        Ok(cli) => cli,
        Err(error) => {
            eprintln!("{error}\n{USAGE}");
            std::process::exit(2);
        }
    };
    let config = match ServerConfig::load(&cli.config_path) {
        Ok(config) => config,
        Err(ConfigError::MissingOrigin) => config_startup_failure("origin_missing"),
        Err(ConfigError::InvalidOrigin) => config_startup_failure("origin_invalid"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    };
    let listen_addr = match config.listen_addr() {
        Ok(address) => address,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    };
    let ui_assets = match ui_assets::UiAssets::load(config.ui_mode(), config.ui_assets_directory())
    {
        Ok(ui_assets) => ui_assets,
        Err(error) => {
            eprintln!(
                "ZODE_SERVER_STARTUP_FAILURE code=ui_assets_invalid phase=ui_assets: {error}"
            );
            std::process::exit(1);
        }
    };
    let store = match ControlStore::open(&config) {
        Ok(store) => Arc::new(store),
        Err(error) => startup_failure(error),
    };
    let access = match AccessVerifier::new(config.access(), store.keys()) {
        Ok(access) => Arc::new(access),
        Err(()) => {
            eprintln!(
                "ZODE_SERVER_STARTUP_FAILURE code=access_verifier_unavailable phase=access_verifier"
            );
            std::process::exit(1);
        }
    };
    let catalog = match Catalog::new(Arc::clone(&store)) {
        Ok(catalog) => Arc::new(catalog),
        Err(()) => {
            eprintln!(
                "ZODE_SERVER_STARTUP_FAILURE code=endpoint_client_unavailable phase=endpoint_catalog"
            );
            std::process::exit(1);
        }
    };
    let providers = Arc::new(ProviderAuthority::new(
        Arc::clone(&store),
        Arc::clone(&catalog),
    ));
    let sessions = match SessionProxy::new(Arc::clone(&store), config.callback_origin().to_owned())
    {
        Ok(sessions) => Arc::new(sessions),
        Err(()) => {
            eprintln!(
                "ZODE_SERVER_STARTUP_FAILURE code=endpoint_client_unavailable phase=session_proxy"
            );
            std::process::exit(1);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cannot start server runtime: {error}");
            std::process::exit(1);
        }
    };
    let composition = match runtime.block_on(all_in_one::compose(
        &config,
        Arc::clone(&store),
        Arc::clone(&catalog),
    )) {
        Ok(composition) => composition,
        Err(error) => local_endpoint_startup_failure(error),
    };
    let router = app::router(
        access,
        catalog,
        providers,
        sessions,
        ui_assets,
        app::RouterConfig {
            management_authority: config.management_authority(),
            management_default_port: config.management_default_port(),
            callback_authority: config.callback_authority(),
            callback_default_port: config.callback_default_port(),
            deployment: config.deployment(),
            local_endpoint_id: composition.local_endpoint_id,
        },
    );
    if let Err(error) = runtime.block_on(serve(listen_addr, router, composition.supervisor)) {
        eprintln!("server stopped: {error}");
        std::process::exit(1);
    }
}

fn config_startup_failure(code: &str) -> ! {
    eprintln!("ZODE_SERVER_STARTUP_FAILURE code={code} phase=config");
    std::process::exit(1);
}

fn startup_failure(error: StartupError) -> ! {
    let (code, phase) = error.code_and_phase();
    eprintln!("ZODE_SERVER_STARTUP_FAILURE code={code} phase={phase}");
    std::process::exit(1);
}

fn local_endpoint_startup_failure(error: LocalEndpointError) -> ! {
    eprintln!(
        "ZODE_SERVER_STARTUP_FAILURE code=local_endpoint_unavailable phase=local_endpoint: {error}"
    );
    std::process::exit(1);
}

async fn serve(
    listen_addr: SocketAddr,
    router: Router,
    supervisor: Option<LocalEndpointSupervisor>,
) -> Result<(), std::io::Error> {
    let result = serve_until_shutdown(listen_addr, router).await;
    if let Some(supervisor) = supervisor {
        supervisor.shutdown().await.map_err(std::io::Error::other)?;
    }
    result
}

async fn serve_until_shutdown(
    listen_addr: SocketAddr,
    router: Router,
) -> Result<(), std::io::Error> {
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    let address = listener.local_addr()?;

    println!("ZODE_SERVER_READY http://{address}");
    std::io::stdout().flush()?;

    let (shutdown, shutdown_requested) = tokio::sync::oneshot::channel::<()>();
    let serving = axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = shutdown_requested.await;
        })
        .into_future();
    tokio::pin!(serving);

    tokio::select! {
        result = &mut serving => result,
        () = shutdown_signal() => {
            let _ = shutdown.send(());
            match tokio::time::timeout(SERVER_DRAIN_TIMEOUT, &mut serving).await {
                Ok(result) => result,
                Err(_) => Ok(()),
            }
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
        tokio::select! {
            _ = terminate.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

mod access;
mod app;
mod catalog;
mod config;
mod store;
mod ui_assets;

use std::{env, io::Write, net::SocketAddr, path::PathBuf, sync::Arc};

use access::AccessVerifier;
use axum::Router;
use catalog::Catalog;
use config::ServerConfig;
use store::{ControlStore, StartupError};

const USAGE: &str = "usage: zode-server --config <path>";

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
    let ui_assets = match ui_assets::UiAssets::load(
        config.ui_mode(),
        config.ui_assets_directory(),
    ) {
        Ok(ui_assets) => ui_assets,
        Err(error) => {
            eprintln!("ZODE_SERVER_STARTUP_FAILURE code=ui_assets_invalid phase=ui_assets: {error}");
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
    let router = app::router(access, catalog, ui_assets);
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
    if let Err(error) = runtime.block_on(serve(listen_addr, router)) {
        eprintln!("server stopped: {error}");
        std::process::exit(1);
    }
}

fn startup_failure(error: StartupError) -> ! {
    let (code, phase) = error.code_and_phase();
    eprintln!("ZODE_SERVER_STARTUP_FAILURE code={code} phase={phase}");
    std::process::exit(1);
}

async fn serve(listen_addr: SocketAddr, router: Router) -> Result<(), std::io::Error> {
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    let address = listener.local_addr()?;

    println!("ZODE_SERVER_READY http://{address}");
    std::io::stdout().flush()?;

    axum::serve(listener, router).await
}

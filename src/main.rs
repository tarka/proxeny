mod certificates;
mod config;
mod errors;
mod proxy;

use std::sync::Arc;
use std::thread;

use anyhow::Result;
use camino::Utf8PathBuf;
use tokio::sync::watch;
use tracing::level_filters::LevelFilter;
use tracing_log::log::info;

use crate::{
    certificates::{external::ExternalProvider, store::CertStore},
    config::{Config, DEFAULT_CONFIG_FILE},
};

fn init_logging(level: u8) -> Result<()> {
    let log_level = match level {
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        3 => LevelFilter::TRACE,
        _ => LevelFilter::WARN,
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .init();

    info!("Logging initialised");
    Ok(())
}

pub struct RunContext {
    pub config: Config,

    pub quit_tx: watch::Sender<bool>,
    pub quit_rx: watch::Receiver<bool>,
}

impl RunContext {
    pub fn new(config: Config) -> Self {
        let (quit_tx, quit_rx) = watch::channel(false);
        Self {
            config,
            quit_tx, quit_rx,
        }
    }

    pub fn quit(&self) -> Result<()> {
        info!("Sending quit signal to runtimes");
        self.quit_tx.send(true)?;
        Ok(())
    }
}

fn main() -> Result<()> {
    let cli = config::CliOptions::from_args();

    init_logging(cli.verbose)?;
    info!("Starting");

    let config_file = cli.config
        .unwrap_or(Utf8PathBuf::from(DEFAULT_CONFIG_FILE));
    let config = Config::from_file(&config_file)?;

    rustls::crypto::aws_lc_rs::default_provider().install_default()
        .expect("Failed to install Rustls crypto provider");

    let context = Arc::new(RunContext::new(config));

    let ext_provider = ExternalProvider::new(context.clone())?;
    // Alternatively have ExternalProvider inject certs ala acme?
    let certs = ext_provider.read_certs();

    let certstore = Arc::new(CertStore::new(certs, context.clone())?);

    ///// Runtime start

    let cert_handle = {
        let certstore = certstore.clone();
        let context = context.clone();
        thread::spawn(move || -> Result<()> {
            info!("Starting Certificate Management runtime");
            let cert_runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_time()
                .enable_io()
                .build()?;

            cert_runtime.block_on(
                certificates::run_indefinitely(certstore, context)
            )?;

            Ok(())
        })
    };

    info!("Starting Proxeny");
    proxy::run_indefinitely(certstore, context.clone())?;

    context.quit()?;
    cert_handle.join()
        .expect("Failed to finalise certificate management tasks")?;

    info!("Proxeny finished.");
    Ok(())
}

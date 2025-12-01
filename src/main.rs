mod certificates;
mod config;
mod errors;
mod proxy;

use std::sync::Arc;
use std::thread;

use anyhow::Result;
use camino::Utf8PathBuf;
use tokio::sync::{mpsc, watch};
use tracing::level_filters::LevelFilter;
use tracing_log::log::info;

use crate::{
    certificates::{
        CertificateProvider, HostCertificate, external::ExternalProvider, store::CertStore,
    },
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

// TODO: Should be in certificates/mod.rs?
pub struct RunContext {
    pub config: Config,

    pub quit_tx: watch::Sender<bool>,
    pub quit_rx: watch::Receiver<bool>,

    pub cert_tx: mpsc::Sender<Arc<HostCertificate>>,
    pub cert_rx: mpsc::Receiver<Arc<HostCertificate>>,
}

impl RunContext {
    pub fn new(config: Config) -> Self {
        let (quit_tx, quit_rx) = watch::channel(false);
        let (cert_tx, cert_rx) = mpsc::channel(8);
        Self {
            config,
            quit_tx, quit_rx,
            cert_tx, cert_rx,
        }
    }

    // pub fn send_cert(&self, cert: Arc<HostCertificate>) -> Result<()> {
    //     self.cert_tx.send(cert)?;
    //     Ok(())
    // }

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

    let context = Arc::new(RunContext::new(config));

    let providers = vec![
        ExternalProvider::new(context.clone())?,
    ];
    let certs = providers.iter()
        .map(|cp| cp.read_certs())
        .flatten()
        .collect();

    let certstore = Arc::new(CertStore::new(certs, context.clone())?);


    ///// Runtime start

    let cert_handle = {
        let certstore = certstore.clone();
        let context = context.clone();
        thread::spawn(move || -> Result<()> {
            info!("Starting Certificate Management runtime");
            let cert_runtime = tokio::runtime::Builder::new_current_thread()
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

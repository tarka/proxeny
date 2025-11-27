
mod certificates;
mod config;
mod errors;
mod proxy;

use std::sync::Arc;
use std::thread;

use anyhow::Result;
use camino::Utf8PathBuf;
use crossbeam_channel::{bounded, Receiver, Sender};
use tracing::level_filters::LevelFilter;
use tracing_log::log::info;

use crate::{
    certificates::{external::ExternalProvider, store::CertStore, watcher::CertWatcher, CertificateProvider, HostCertificate},
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

pub struct Context {
    pub quit_tx: Sender<()>,
    pub quit_rx: Receiver<()>,

    pub cert_tx: Sender<Arc<HostCertificate>>,
    pub cert_rx: Receiver<Arc<HostCertificate>>,
}

impl Context {
    pub fn new() -> Self {
        let (quit_tx, quit_rx) = bounded(1);
        let (cert_tx, cert_rx) = bounded(1);
        Self {
            quit_tx, quit_rx,
            cert_tx, cert_rx,
        }
    }

    pub fn quit(&self) -> Result<()> {
        info!("Sending watcher quit signal");
        self.quit_tx.send(())?;
        Ok(())
    }
}

fn main() -> Result<()> {
    let cli = config::CliOptions::from_args();

    init_logging(cli.verbose)?;
    info!("Starting");

    let config_file = cli.config
        .unwrap_or(Utf8PathBuf::from(DEFAULT_CONFIG_FILE));
    let config = Arc::new(Config::from_file(&config_file)?);

    let context = Arc::new(Context::new());

    let providers = vec![
        ExternalProvider::new(config.clone())?,
    ];
    let certs = providers.iter()
        .map(|cp| cp.read_certs())
        .flatten()
        .collect();

    let certstore = Arc::new(CertStore::new(certs, context.clone())?);
    let certwatcher = Arc::new(CertWatcher::new(certstore.clone(), context.clone()));

    let server_handle = {
        let certstore = certstore.clone();
        let config = config.clone();
        thread::spawn(move || -> Result<()> {
            info!("Starting Proxy");
            proxy::run_indefinitely(certstore, config)?;
            Ok(())
        })
    };

    let watcher_handle = {
        let certwatcher = certwatcher.clone();
        thread::spawn(move || -> Result<()> {
            info!("Starting cert watcher");
            certwatcher.watch()?;
            Ok(())
        })
    };

    server_handle.join()
        .expect("Failed to finalise server task")?;

    context.quit()?;
    watcher_handle.join()
        .expect("Failed to finalise watcher task")?;

    info!("Proxeny finished.");
    Ok(())
}

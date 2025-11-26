
mod certificates;
mod config;
mod errors;
mod proxy;

use std::sync::Arc;
use std::thread;

use anyhow::Result;
use camino::Utf8PathBuf;
use tracing::level_filters::LevelFilter;
use tracing_log::log::info;

use crate::{
    certificates::{acme::Acme, external::ExternalProvider, store::CertStore, watcher::CertWatcher, CertificateProvider},
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

fn main() -> Result<()> {
    let cli = config::CliOptions::from_args();

    init_logging(cli.verbose)?;
    info!("Starting");

    let config_file = cli.config
        .unwrap_or(Utf8PathBuf::from(DEFAULT_CONFIG_FILE));
    let config = Arc::new(Config::from_file(&config_file)?);

    let extcerts = ExternalProvider::new(config.clone());
    let certs = extcerts.read_certs()?;

    let certstore = Arc::new(CertStore::new(certs)?);

    let certwatcher = Arc::new(CertWatcher::new(certstore.clone()));

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

    certwatcher.quit()?;
    watcher_handle.join()
        .expect("Failed to finalise watcher task")?;

    info!("Proxeny finished.");
    Ok(())
}

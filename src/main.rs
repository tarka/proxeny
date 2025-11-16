
mod certificates;
mod config;
mod proxy;

use std::thread;
use std::sync::Arc;

use anyhow::Result;
use camino::Utf8PathBuf;
use tracing::info;
use tracing::level_filters::LevelFilter;

use crate::{certificates::{store::CertStore, watcher::CertWatcher}, config::DEFAULT_CONFIG_FILE};

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
    info!("Loading config {config_file}");
    let config = Arc::new(config::read_config(&config_file)?);

    let certstore = Arc::new(CertStore::new(&config)?);
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


mod certificates;
mod config;
mod proxy;

use std::thread;
use std::sync::Arc;

use anyhow::Result;
use camino::Utf8PathBuf;
use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

use crate::certificates::{CertStore, CertWatcher};


fn init_logging(level: u8) -> anyhow::Result<()> {
    let log_level = match level {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };

    let env_log = EnvFilter::builder()
        .with_default_directive(log_level.into())
        .from_env_lossy();

    tracing_log::LogTracer::init()?;
    let fmt = tracing_subscriber::fmt()
        .with_env_filter(env_log)
        .finish();
    tracing::subscriber::set_global_default(fmt)?;

    Ok(())
}

fn main() -> Result<()> {
    let cli = config::CliOptions::from_args();

    init_logging(cli.verbose)?;
    info!("Starting");

    let config_file = cli.config
        .unwrap_or(Utf8PathBuf::from("/etc/proxeny/proxeny.corn"));
    info!("Loading config {config_file}");
    let config = config::read_config(&config_file)?;

    let certstore = Arc::new(CertStore::new(&config)?);
    let certwatcher = Arc::new(CertWatcher::new(certstore.clone()));

    let certstore_server = certstore.clone();
    let server_handle = thread::spawn(move || -> Result<()> {
        info!("Starting Proxy");
        proxy::run_indefinitely(certstore_server)?;
        Ok(())
    });

    let cwc = certwatcher.clone();
    let watcher_handle = thread::spawn(move || -> Result<()> {
        info!("Starting cert watcher");
        cwc.watch()?;
        Ok(())
    });

    server_handle.join()
        .expect("Failed to finalise server task")?;

    certwatcher.quit()?;
    watcher_handle.join()
        .expect("Failed to finalise watcher task")?;

    info!("Proxeny finished.");
    Ok(())
}

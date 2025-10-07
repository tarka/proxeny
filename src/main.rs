
mod certificates;
mod proxy;

use std::thread;
use std::{str::FromStr, sync::Arc};

use anyhow::Result;
use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

use crate::certificates::{CertStore, CertWatcher};

const TEST_HOSTS: [&str; 2] = ["dvalinn.haltcondition.net", "adguard.haltcondition.net"];


fn init_logging(level: &Option<String>) -> anyhow::Result<()> {
    let lf = level.clone()
        .map(|s| LevelFilter::from_str(&s).expect("Invalid log string"))
        .unwrap_or(LevelFilter::INFO);

    let env_log = EnvFilter::builder()
        .with_default_directive(lf.into())
        .from_env_lossy();

    tracing_log::LogTracer::init()?;
    let fmt = tracing_subscriber::fmt()
        .with_env_filter(env_log)
        .finish();
    tracing::subscriber::set_global_default(fmt)?;

    Ok(())
}

fn main() -> Result<()> {
    init_logging(&Some("info".to_string()))?;
    info!("Starting");

    let certstore = Arc::new(CertStore::new(Vec::from(TEST_HOSTS))?);
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

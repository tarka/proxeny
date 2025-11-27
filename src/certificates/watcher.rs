use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use camino::Utf8PathBuf;
use crossbeam_channel::{self as cbc, Receiver, Sender, select};
use itertools::Itertools;
use notify::{EventKind, RecursiveMode};
use notify_debouncer_full::{self as debouncer, DebounceEventResult, DebouncedEvent};
use tracing::{info, warn};

use crate::certificates::store::CertStore;


const RELOAD_GRACE: Duration = Duration::from_millis(1500);

pub struct CertWatcher {
    certstore: Arc<CertStore>,
    tx: Sender<DebounceEventResult>,
    rx: Receiver<DebounceEventResult>,
    q_tx: Sender<()>,
    q_rx: Receiver<()>,
}

impl CertWatcher {
    pub fn new(certstore: Arc<CertStore>) -> Self {
        let (tx, rx) = cbc::unbounded();
        let (q_tx, q_rx) = cbc::bounded(1);
        Self {certstore, tx, rx, q_tx, q_rx}
    }

    pub fn watch(&self) -> Result<()> {

        let mut watcher = debouncer::new_debouncer(RELOAD_GRACE, None, self.tx.clone())?;
        for file in &self.certstore.watchlist() {
            info!("Starting watch of {file}");
            watcher.watch(file, RecursiveMode::NonRecursive)?;
        }

        loop {
            select! {
                recv(&self.q_rx) -> _r => {
                    info!("Quitting certificate watcher loop.");
                    break;
                },
                recv(&self.rx) -> events => {
                    match events? {
                        Err(errs) => warn!("Received errors from cert watcher: {errs:#?}"),
                        Ok(evs) => self.process_events(evs)?,
                    }
                }
            };
        }

        Ok(())
    }

    fn process_events(&self, events: Vec<DebouncedEvent>) -> Result<()> {
        let certs = events.into_iter()
            .filter(|dev| matches!(dev.event.kind,
                                   EventKind::Create(_)
                                   | EventKind::Modify(_)
                                   | EventKind::Remove(_)))
            .flat_map(|dev| dev.paths.clone())
            .unique()
            .map(|path| {
                let cert_path = Utf8PathBuf::from_path_buf(path)
                    .map_err(|p| anyhow!("Invalid path encoding: {p:#?}"))?
                    .canonicalize_utf8()?;
                Ok(cert_path)
            })
            .collect::<Result<Vec<Utf8PathBuf>>>()?;

        self.certstore.file_update(certs)?;

        Ok(())
    }

    pub fn quit(&self) -> Result<()> {
        info!("Sending watcher quit signal");
        self.q_tx.send(())?;
        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::thread;
    use tempfile::tempdir;
    use crate::certificates::CertificateProvider;
    use crate::certificates::tests::*;

    #[test]
    fn test_cert_watcher_file_updates() -> Result<()> {
        let temp_dir = tempdir()?;
        let key_path = temp_dir.path().join("test.key");
        let cert_path = temp_dir.path().join("test.crt");

        fs::copy("tests/data/certs/snakeoil.key", &key_path)?;
        fs::copy("tests/data/certs/snakeoil.crt", &cert_path)?;

        let provider = TestProvider::new(
            key_path.to_str().unwrap(),
            cert_path.to_str().unwrap(),
            true,
        );
        let store = Arc::new(CertStore::new(provider.read_certs())?);
        let original_host = provider.cert.host.clone();

        let original_cert = store.by_host(&original_host).unwrap();
        let original_expiry = original_cert.certs[0].not_after().to_string();

        let watcher = Arc::new(CertWatcher::new(store.clone()));
        let watcher_clone = watcher.clone();

        let watcher_thread = thread::spawn(move || {
            watcher_clone.watch()
        });

        // Wait for the watcher to start
        thread::sleep(Duration::from_millis(100));

        // Update the files
        fs::copy("tests/data/certs/snakeoil-2.key", &key_path)?;
        fs::copy("tests/data/certs/snakeoil-2.pem", &cert_path)?;

        // Wait for the watcher to process the event
        thread::sleep(RELOAD_GRACE + Duration::from_millis(500));

        let updated_cert = store.by_host(&original_host).unwrap();
        let updated_expiry = updated_cert.certs[0].not_after().to_string();

        assert_ne!(original_expiry, updated_expiry);

        // Stop the watcher
        watcher.quit()?;
        watcher_thread.join().unwrap()?;

        Ok(())
    }
}

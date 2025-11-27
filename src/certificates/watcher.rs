use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use camino::Utf8PathBuf;
use itertools::Itertools;
use notify::{EventKind, RecursiveMode};
use notify_debouncer_full::{self as debouncer, DebounceEventResult, DebouncedEvent};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::{certificates::store::CertStore, Context};


const RELOAD_GRACE: Duration = Duration::from_millis(1500);

pub struct CertWatcher {
    context: Arc<Context>,
    certstore: Arc<CertStore>,
    ev_tx: mpsc::Sender<DebounceEventResult>,
    ev_rx: mpsc::Receiver<DebounceEventResult>,
}

impl CertWatcher {
    pub fn new(certstore: Arc<CertStore>, context: Arc<Context>) -> Self {
        let (ev_tx, ev_rx) = mpsc::channel(16);
        Self {
            context,
            certstore,
            ev_tx, ev_rx,
        }
    }

    pub async fn watch(&self) -> Result<()> {
        info!("Starting cert watcher");

        let handler = {
            let ev_tx = self.ev_tx.clone();
            move |ev: DebounceEventResult| { ev_tx.blocking_send(ev).unwrap(); }
        };

        let mut watcher = debouncer::new_debouncer(RELOAD_GRACE, None, handler)?;
        for file in &self.certstore.watchlist() {
            info!("Starting watch of {file}");
            watcher.watch(file, RecursiveMode::NonRecursive)?;
        }

        let mut quit_rx = self.context.quit_rx.clone();
        loop {
            tokio::select! {
                _ = quit_rx.changed() => {
                    info!("Quitting certificate watcher loop.");
                    break;
                },
                // Some(events) = &self.ev_rx.recv() => {
                //     match events {
                //         Err(errs) => warn!("Received errors from cert watcher: {errs:#?}"),
                //         Ok(evs) => self.process_events(evs)?,
                //     }
                // }
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

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::thread;
    use tempfile::tempdir;
    use crate::certificates::CertificateProvider;
    use crate::certificates::tests::*;

//     #[test]
//     fn test_cert_watcher_file_updates() -> Result<()> {
//         let temp_dir = tempdir()?;
//         let key_path = temp_dir.path().join("test.key");
//         let cert_path = temp_dir.path().join("test.crt");

//         let context = Arc::new(Context::new());

//         fs::copy("tests/data/certs/snakeoil.key", &key_path)?;
//         fs::copy("tests/data/certs/snakeoil.crt", &cert_path)?;

//         let provider = TestProvider::new(
//             key_path.to_str().unwrap(),
//             cert_path.to_str().unwrap(),
//             true,
//         );
//         let store = Arc::new(CertStore::new(provider.read_certs(), context.clone())?);
//         let original_host = provider.cert.host.clone();

//         let original_cert = store.by_host(&original_host).unwrap();
//         let original_expiry = original_cert.certs[0].not_after().to_string();

//         let watcher = Arc::new(CertWatcher::new(store.clone(), context.clone()));
//         let watcher_clone = watcher.clone();

//         let watcher_thread = thread::spawn(move || {
//             watcher_clone.watch()
//         });

//         // Wait for the watcher to start
//         thread::sleep(Duration::from_millis(100));

//         // Update the files
//         fs::copy("tests/data/certs/snakeoil-2.key", &key_path)?;
//         fs::copy("tests/data/certs/snakeoil-2.pem", &cert_path)?;

//         // Wait for the watcher to process the event
//         thread::sleep(RELOAD_GRACE + Duration::from_millis(500));

//         let updated_cert = store.by_host(&original_host).unwrap();
//         let updated_expiry = updated_cert.certs[0].not_after().to_string();

//         assert_ne!(original_expiry, updated_expiry);

//         // Stop the watcher
//         context.quit()?;
//         watcher_thread.join().unwrap()?;

//         Ok(())
//     }
}

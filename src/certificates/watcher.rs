use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use camino::Utf8PathBuf;
use itertools::Itertools;
use notify::{EventKind, RecursiveMode};
use notify_debouncer_full::{self as debouncer, DebounceEventResult, DebouncedEvent};
use tokio::sync::mpsc;
use tracing_log::log::{info, warn};

use crate::{certificates::store::CertStore, RunContext};


pub const RELOAD_GRACE: Duration = Duration::from_millis(1500);

pub struct CertWatcher {
    context: Arc<RunContext>,
    certstore: Arc<CertStore>,
    ev_tx: mpsc::Sender<DebounceEventResult>,
    ev_rx: mpsc::Receiver<DebounceEventResult>,
}

impl CertWatcher {
    pub fn new(certstore: Arc<CertStore>, context: Arc<RunContext>) -> Self {
        let (ev_tx, ev_rx) = mpsc::channel(16);
        Self {
            context,
            certstore,
            ev_tx, ev_rx,
        }
    }

    pub async fn watch(&mut self) -> Result<()> {
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
                events = self.ev_rx.recv() => {
                    match events {
                        Some(Err(errs)) => warn!("Received errors from cert watcher: {errs:#?}"),
                        Some(Ok(evs)) => self.process_events(evs)?,
                        None => {
                            warn!("Notify watcher channel closed; quitting");
                            break;
                        }
                    }
                },
                _ = quit_rx.changed() => {
                    info!("Quitting certificate watcher loop.");
                    break;
                },
            };
        }

        Ok(())
    }

    fn process_events(&self, events: Vec<DebouncedEvent>) -> Result<()> {
        info!("Processing {} files update events", events.len());
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

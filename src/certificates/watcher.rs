use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use camino::Utf8PathBuf;
use itertools::Itertools;
use notify::{EventKind, RecursiveMode};
use notify_debouncer_full::{self as debouncer, DebounceEventResult, DebouncedEvent};
use tokio::sync::mpsc;
use tracing_log::log::{debug, info, warn};

use crate::{certificates::{store::CertStore, HostCertificate}, errors::ProxenyError, RunContext};


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
        info!("Starting certificate watcher runtime");

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
                    info!("Quitting certificate watcher runtime");
                    break;
                },
            };
        }

        Ok(())
    }

    fn process_events(&self, events: Vec<DebouncedEvent>) -> Result<()> {
        info!("Processing {} files update events", events.len());
        let paths = events.into_iter()
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

        self.process_paths(paths)?;

        Ok(())
    }

    fn process_paths(&self, paths: Vec<Utf8PathBuf>) -> Result<()> {
        debug!("Processing updated paths: {paths:#?}");
        let certs = paths.iter()
            .map(|path| {
                let cert = self.certstore.by_file(path)
                 .ok_or(anyhow!("Path not found in store: {path}"))?
                    .clone();
                Ok(cert)
            })
            // 2-pass as .unique() doesn't work with Results
            .collect::<Result<Vec<Arc<HostCertificate>>>>()?
            .iter()
            .unique()
            .filter_map(|existing| {
                // Attempt to reload the relevant HostCertificate.
                // However as errors can be expected while the certs
                // are being replaced externally we just warn and pass
                // for now.
                match HostCertificate::from(existing) {
                    Ok(hc) => Some(Ok(Arc::new(hc))),
                    Err(err) => {
                        if err.is::<ProxenyError>() {
                            let perr = err.downcast::<ProxenyError>()
                                .expect("Error downcasting ProxenyError after check; this shouldn't happen");
                            if matches!(perr, ProxenyError::CertificateMismatch(_, _)) {
                                warn!("Possible error on reload: {perr}. This may be transient.");
                                None
                            } else {
                                Some(Err(perr.into()))
                            }
                        } else {
                            Some(Err(err))
                        }
                    },
                }
            })
            .collect::<Result<Vec<Arc<HostCertificate>>>>()?;

        for cert in certs {
            self.certstore.update(cert)?;
        }

        Ok(())
    }
}

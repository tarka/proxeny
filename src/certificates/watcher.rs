use std::{sync::Arc, time::Duration};

use anyhow::Result;
use camino::Utf8PathBuf;
use crossbeam_channel::{self as cbc, Receiver, Sender, select};
use itertools::Itertools;
use notify::{EventKind, RecursiveMode};
use notify_debouncer_full::{self as debouncer, DebounceEventResult, DebouncedEvent};
use tracing::{info, warn};

use crate::certificates::{HostCertificate, store::CertStore};


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
        for f in &self.certstore.watchlist() {
            info!("Starting watch of {f}");
            watcher.watch(f, RecursiveMode::NonRecursive)?;
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
                let up = Utf8PathBuf::from_path_buf(path)
                    .expect("Invalid path encoding: {path}")
                    .canonicalize_utf8()
                    .expect("Invalid UTF8 path: {path}");
                self.certstore.by_file(&up)
                    .expect("Unexpected cert path: {up}")
                    .clone()
            })
            .collect::<Vec<Arc<HostCertificate>>>();

        for cert in certs {
            let newcert = Arc::new(HostCertificate::from(&cert)?);
            self.certstore.replace(newcert)?;
        }

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
    use http::Uri;

    use super::*;
    use crate::{
        certificates::store::gen_watchlist,
        config::{
            Backend,
            Config,
            TlsConfig,
            TlsConfigType,
            TlsFilesConfig,
        }
    };


    #[test]
    fn test_gen_simple_watchlist() -> Result<()> {
        let config = Config {
            hostname: "host1".to_owned(),
            listen: "[::]".to_owned(),
            insecure: None,
            tls: TlsConfig {
                port: 443,
                config: TlsConfigType::Files(TlsFilesConfig {
                    keyfile: Utf8PathBuf::from("keyfile1.key"),
                    certfile: Utf8PathBuf::from("certfile1.crt"),
                    reload: true,
                })
            },
            backends: vec![
                Backend {
                    context: None,
                    url: Uri::from_static("http://localhost")
                }
            ]
        };

        let watchlist = gen_watchlist(&config);

        assert_eq!(2, watchlist.len());
        assert_eq!(Utf8PathBuf::from("keyfile1.key"), watchlist[0]);
        assert_eq!(Utf8PathBuf::from("certfile1.crt"), watchlist[1]);

        Ok(())
    }
}

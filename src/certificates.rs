

use std::{sync::{Arc, RwLock}, time::Duration};

use anyhow::{bail, Result};
use async_trait::async_trait;
use camino::Utf8PathBuf;
use crossbeam_channel::{
    self as cbc,
    select,
    Receiver,
    Sender
};
use itertools::Itertools;
use notify::{
    EventKind,
    RecursiveMode,
};
use notify_debouncer_full::{
    self as debouncer,
    DebounceEventResult,
    DebouncedEvent,
};
use pingora::{
    listeners::TlsAccept,
    protocols::tls::TlsRef,
    tls::{
        pkey::{PKey, Private},
        ssl::NameType,
        x509::X509
    }
};
use tracing::{info, warn};


// FIXME: Move to config
const TEST_DIR: &str = "tests/data/certs/acme";

#[derive(Debug)]
struct HostCertificate {
    host: String,
    keyfile: Utf8PathBuf,
    key: PKey<Private>,
    certfile: Utf8PathBuf,
    certs: Vec<X509>,
}

impl HostCertificate {

    fn new(host: String, keyfile: Utf8PathBuf, certfile: Utf8PathBuf) -> Result<Self> {
        let (key, certs) = load_cert_files(&keyfile, &certfile)?;

        Ok(HostCertificate {
            host,
            keyfile,
            key,
            certfile,
            certs,
        })
    }

    fn reload(&mut self) -> Result<()> {
        info!("Reloading TLS certificate files for {}", self.host);
        let (key, certs) = load_cert_files(&self.keyfile, &self.certfile)?;
        self.key = key;
        self.certs = certs;
        Ok(())
    }
}

fn load_host_certs(host: &str) -> Result<HostCertificate> {
    // FIXME
    let keyfile = Utf8PathBuf::from(format!("{TEST_DIR}/{host}.key"))
        .canonicalize_utf8()?;
    let certfile = Utf8PathBuf::from(format!("{TEST_DIR}/{host}.crt"))
        .canonicalize_utf8()?;

    let hostcert = HostCertificate::new(host.to_owned(),
                                        keyfile, certfile)?;

    Ok(hostcert)
}

fn load_cert_files(keyfile: &Utf8PathBuf, certfile: &Utf8PathBuf) -> Result<(PKey<Private>, Vec<X509>)> {
    let key = std::fs::read(keyfile)?;
    let cert = std::fs::read(certfile)?;

    let key = PKey::private_key_from_pem(&key)?;
    let certs = X509::stack_from_pem(&cert)?;
    if certs.is_empty() {
        bail!("No certificates found in TLS .crt file");
    }
    Ok((key, certs))
}


pub struct CertStore {
    by_host: papaya::HashMap<String, Arc<RwLock<HostCertificate>>>,
    by_file: papaya::HashMap<Utf8PathBuf, Arc<RwLock<HostCertificate>>>,
}

impl CertStore {
    pub fn new(hosts: Vec<&str>) -> Result<Self> {
        info!("Loading host certificates");

        let certs: Vec<Arc<RwLock<HostCertificate>>> = hosts.iter()
            .map(|host| {
                let host = load_host_certs(host)?;
                Ok(Arc::new(RwLock::new(host)))
            })
            .collect::<Result<_>>()?;

        let by_host = certs.iter()
            .map(|cert| (cert.read().expect("Failed to read cert; this shouldn't happen")
                         .host.clone(),
                         cert.clone()))
            .collect();

        let by_file = certs.iter()
            .flat_map(|cert| {
                let hc = cert.read().expect("Failed to read cert; this shouldn't happen");
                vec!(
                    (hc.keyfile.clone(), cert.clone()),
                    (hc.certfile.clone(), cert.clone()),
                )
            })
            .collect();


        let certstore = Self {
            by_host,
            by_file
        };

        info!("Loaded {} certificates", certs.len());

        Ok(certstore)
    }

    pub fn file_list(&self) -> Vec<Utf8PathBuf> {
        self.by_file.pin()
            .keys()
            .cloned()
            .collect()
    }
}


const RELOAD_GRACE: Duration = Duration::from_secs(2);

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
        let files = self.certstore.file_list();

        let mut watcher = debouncer::new_debouncer(RELOAD_GRACE, None, self.tx.clone())?;
        for f in files {
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
        let matching = events.into_iter()
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
                self.certstore.by_file.pin().get(&up)
                    .expect("Unexpected cert path: {up}")
                    .clone()
            })
            .collect::<Vec<Arc<RwLock<HostCertificate>>>>();

        for ev in matching {
            info!("EV: {ev:?}");
        }

        Ok(())
    }

    pub fn quit(&self) -> Result<()> {
        info!("Sending watcher quit signal");
        self.q_tx.send(())?;
        Ok(())
    }

}


pub struct CertHandler {
    certstore: Arc<CertStore>,
}

impl CertHandler {
    pub fn new(certstore: Arc<CertStore>) -> Self {
        Self {
            certstore
        }
    }
}

#[async_trait]
impl TlsAccept for CertHandler {

    // NOTE:This is all boringssl specific as pingora doesn't
    // currently support dynamic certs with rustls.
    async fn certificate_callback(&self, ssl: &mut TlsRef) -> () {
        let host = ssl.servername(NameType::HOST_NAME)
            .expect("No servername in TLS handshake");

        info!("TLS Host is {host}; loading certs");

        // FIXME: This should be a `get()` in CertStore, but papaya
        // guard lifetimes make it pointless (we'd have to generate a
        // guard here anyway). There may be another way to do it
        // cleanly?
        let pmap = self.certstore.by_host.pin();
        let cert = pmap.get(&host.to_string())
            .expect("Certificate for host not found")
            .read()
            .expect("Unable to acquire readlock for host");

        ssl.set_private_key(&cert.key)
            .expect("Failed to set private key");
        ssl.set_certificate(&cert.certs[0])
            .expect("Failed to set certificate");

        if cert.certs.len() > 1 {
            for c in cert.certs[1..].iter() {
                ssl.add_chain_cert(&c)
                    .expect("Failed to add chain certificate");
            }
        }
    }

}

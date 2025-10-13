

use std::{fs, sync::Arc};

use anyhow::{bail, Result};
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use crossbeam_channel::{
    self as cbc,
    select,
    Receiver,
    Sender
};
use notify::{
    Event,
    EventKind,
    RecommendedWatcher,
    RecursiveMode,
    Watcher
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
use tracing::{debug, info, warn};

use crate::{config::{Config, TlsConfigType}};


struct HostCertificate {
    host: String,
    keyfile: Utf8PathBuf,
    key: PKey<Private>,
    certfile: Utf8PathBuf,
    certs: Vec<X509>,
}

fn load_certs(keyfile: &Utf8Path, certfile: &Utf8Path) -> Result<(PKey<Private>, Vec<X509>)> {
    let kdata = fs::read(keyfile)?;
    let cdata = fs::read(certfile)?;

    let key = PKey::private_key_from_pem(&kdata)?;
    let certs = X509::stack_from_pem(&cdata)?;
    if certs.is_empty() {
        bail!("No certificates found in TLS .crt file");
    }
    Ok((key, certs))
}


pub struct CertStore {
    by_host: papaya::HashMap<String, Arc<HostCertificate>>,
    by_file: papaya::HashMap<Utf8PathBuf, Arc<HostCertificate>>,
}

impl CertStore {
    pub fn new(config: &Config) -> Result<Self> {
        info!("Loading host certificates");

        let certs = config.servers.iter()
            .filter(|s| matches!(s.tls, TlsConfigType::Files(_)))
            .map(|s| match &s.tls {
                TlsConfigType::Files(tfc) => {
                    debug!("Loading {} certs from {}, {}", s.hostname, tfc.keyfile, tfc.certfile);
                    let (key, certs) = load_certs(&tfc.keyfile, &tfc.certfile)?;
                    let hostcert = HostCertificate {
                        host: s.hostname.to_owned(),
                        keyfile: tfc.keyfile.clone(),
                        key,
                        certfile: tfc.certfile.clone(),
                        certs,
                    };
                    Ok(Arc::new(hostcert))
                }
                _ => unreachable!("Found filtered value")
            })
            .collect::<Result<Vec<Arc<HostCertificate>>>>()?;

        let by_host = certs.iter()
            .map(|cert| (cert.host.clone(), cert.clone()))
            .collect();

        let by_file = certs.iter()
            .flat_map(|cert| vec!(
                (cert.keyfile.clone(), cert.clone()),
                (cert.certfile.clone(), cert.clone()),
            ))
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


pub struct CertWatcher {
    certstore: Arc<CertStore>,
    tx: Sender<notify::Result<Event>>,
    rx: Receiver<notify::Result<Event>>,
    q_tx: Sender<()>,
    q_rx: Receiver<()>,
}

impl CertWatcher {
    pub fn new(certstore: Arc<CertStore>) -> Self {
        let (tx, rx) = cbc::unbounded();
        let (q_tx, q_rx) = cbc::unbounded();
        Self {certstore, tx, rx, q_tx, q_rx}
    }

    pub fn watch(&self) -> Result<()> {
        let files = self.certstore.file_list();

        let mut watcher = RecommendedWatcher::new(self.tx.clone(), notify::Config::default())?;
        for f in files {
            info!("Starting watch of {f}");
            watcher.watch(f.as_ref(), RecursiveMode::NonRecursive)?;
        }

        loop {
            select! {
                recv(&self.q_rx) -> _r => {
                    info!("Quitting certificate watcher loop.");
                    break;
                },
                recv(&self.rx) -> ev => {
                    match ev?? {
                        Event {
                            kind: k @ EventKind::Create(_)
                                | k @ EventKind::Modify(_)
                                | k @ EventKind::Remove(_),
                            paths,
                            ..
                        } => {
                            info!("Update: {k:?} -> {paths:?}");
                        }
                        Event {kind, paths, ..} =>
                            warn!("Unexpected update {kind:?} for {paths:?}")
                    }
                }
            };
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
            .expect("Certificate for host not found");

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

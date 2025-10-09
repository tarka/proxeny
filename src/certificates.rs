

use std::sync::Arc;

use anyhow::{bail, Result};
use async_trait::async_trait;
use camino::Utf8PathBuf;
use crossbeam_channel::{
    self as cbc, Receiver, Select, Sender
};
use notify::{
    event::EventAttributes,
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
use tracing::{info, warn};


// FIXME: Move to config
const TEST_DIR: &str = "tests/data/certs/acme";

struct HostCertificate {
    host: String,
    keyfile: Utf8PathBuf,
    key: PKey<Private>,
    certfile: Utf8PathBuf,
    certs: Vec<X509>,
}

fn load_cert_files(host: &str) -> Result<HostCertificate> {
    // FIXME
    let keyfile = Utf8PathBuf::from(format!("{TEST_DIR}/{host}.key"));
    let certfile = Utf8PathBuf::from(format!("{TEST_DIR}/{host}.crt"));
    let key = std::fs::read(&keyfile)?;
    let cert = std::fs::read(&certfile)?;

    let key = PKey::private_key_from_pem(&key)?;
    let certs = X509::stack_from_pem(&cert)?;
    if certs.is_empty() {
        bail!("No certificates found in TLS .crt file");
    }

    let hostcert = HostCertificate {
        host: host.to_owned(),
        keyfile,
        key,
        certfile,
        certs,
    };

    Ok(hostcert)
}


pub struct CertStore {
    by_host: papaya::HashMap<String, Arc<HostCertificate>>,
    by_file: papaya::HashMap<Utf8PathBuf, Arc<HostCertificate>>,
}

impl CertStore {
    pub fn new(hosts: Vec<&str>) -> Result<Self> {
        info!("Loading host certificates");

        let certs: Vec<Arc<HostCertificate>> = hosts.iter()
            .map(|host| {
                let cert = load_cert_files(host)?;
                Ok(Arc::new(cert))
            })
            .collect::<Result<_>>()?;

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

const QUIT_STR: &str = "PROXENY_QUIT";

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

        let mut select = Select::new();
        let _s_notify = select.recv(&self.rx);
        let s_quit = select.recv(&self.q_rx);

        loop {
            let selected = select.select();
            let nchan = selected.index();
            println!("nchan = {nchan}");

            if nchan == s_quit {
                info!("Quitting certificate watcher loop.");
                selected.recv(&self.q_rx)?;
                break;
            }

            let ev = selected.recv(&self.rx)?;

//        for ev in &self.rx {
            match ev? {
                Event {
                    kind: k @ EventKind::Create(_)
                        | k @ EventKind::Modify(_)
                        | k @ EventKind::Remove(_),
                    paths,
                    ..
                } => {
                    info!("Update: {k:?} -> {paths:?}");
                }
                // Event { kind: EventKind::Other, attrs, .. }
                // if attrs.info() == Some(QUIT_STR) => {
                //     info!("Quitting certificate watcher loop.");
                //     break;
                // }
                Event {kind, paths, ..} => warn!("Unexpected update {kind:?} for {paths:?}")
            }
        }

        Ok(())
    }

    pub fn quit(&self) -> Result<()> {
        // // Repurpose notify Event attributes to signal shutdown. This
        // // is slightly hacky and could be done via a second channel
        // // and select! instead, but this works well enough.
        // let mut attrs = EventAttributes::new();
        // attrs.set_info(QUIT_STR);
        // let quit = Event {
        //     kind: EventKind::Other,
        //     paths: Vec::new(),
        //     attrs,
        // };
        // self.tx.send(Ok(quit))?;
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

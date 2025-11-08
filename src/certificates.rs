
use std::{fs, sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use crossbeam_channel::{
    self as cbc,
    select,
    Receiver,
    Sender
};
use http::Uri;
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
    listeners::TlsAccept, protocols::tls::TlsRef, tls::{
        pkey::{PKey, Private}, ssl::NameType, x509::X509
    }, ErrorType, OkOrErr
};
use tracing::{debug, info, warn};

use crate::config::{Config, TlsConfigType, TlsFilesConfig};


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
        let (key, certs) = load_certs(&keyfile, &certfile)?;

        Ok(HostCertificate {
            host,
            keyfile,
            key,
            certfile,
            certs,
        })
    }

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

fn gen_watchlist(config: &Config) -> Vec<Utf8PathBuf> {
    // We only watch user-supplied certs that are flagged to
    // reload. Acme certs are ignored.
    config.servers.iter()
        .filter_map(|s| match &s.tls.config {
            TlsConfigType::Files(TlsFilesConfig {keyfile, certfile, reload: true}) => {
                Some(vec![
                    keyfile.clone(),
                    certfile.clone(),
                ])
            }
            _ => None
        })
        .flatten()
        .collect()

}

pub struct CertStore {
    by_host: papaya::HashMap<String, Arc<HostCertificate>>,
    by_file: papaya::HashMap<Utf8PathBuf, Arc<HostCertificate>>,
    // Watched files; this may be a subset of all files as some are
    // unwatched, either by configuration or policy
    // (i.e. acme-generated).
    watchlist: Vec<Utf8PathBuf>,
}

fn cn_host(cn: String) -> Result<String> {
    let host = cn.split('=')
        .nth(1)
        .or_err(ErrorType::InvalidCert, "Failed to find host in cert 'CN=...'")?;
    Ok(host.to_string())
}

fn uri_host(uri: &String) -> Result<String> {
    let parsed = Uri::try_from(uri)?;
    let host = parsed.host()
        .context("Failed to find host in servername '{uri}'")?;
    Ok(host.to_string())
}

impl CertStore {
    pub fn new(config: &Config) -> Result<Self> {
        info!("Loading host certificates");

        let certs = config.servers.iter()
            .filter(|s| matches!(s.tls.config, TlsConfigType::Files(_)))
            .map(|s| match &s.tls.config {
                TlsConfigType::Files(tfc) => {
                    debug!("Loading {} certs from {}, {}", s.hostname, tfc.keyfile, tfc.certfile);
                    let (key, certs) = load_certs(&tfc.keyfile, &tfc.certfile)?;

                    let cn = cn_host(certs[0].subject_name().print_ex(0)
                                     .or_err(ErrorType::InvalidCert, "No host/CN in certificate")?)?;
                    let s_host = uri_host(&s.hostname)?;
                    if s_host != cn {
                        bail!("Certificate {cn} doesn't match server host {s_host}");
                    }

                    let hostcert = HostCertificate {
                        host: cn,
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
            .map(|cert| (cert.host.clone(),
                         cert.clone()))
            .collect();

        let by_file = certs.iter()
            .flat_map(|cert| {
                vec!((cert.keyfile.clone(), cert.clone()),
                     (cert.certfile.clone(), cert.clone()))
            })
            .collect();

        let watchlist = gen_watchlist(config);

        let certstore = Self {
            by_host,
            by_file,
            watchlist,
        };

        info!("Loaded {} certificates", certs.len());

        Ok(certstore)
    }

    fn replace(&self, newcert: Arc<HostCertificate>) -> Result<()> {
        let host = newcert.host.clone();
        info!("Replacing certificate for {host}");

        self.by_host.pin().update(host, |_old| newcert.clone());

        let by_file = self.by_file.pin();
        let keyfile = newcert.keyfile.clone();
        by_file.update(keyfile, |_old| newcert.clone());
        let certfile = newcert.keyfile.clone();
        by_file.update(certfile, |_old| newcert.clone());

        Ok(())
    }

    pub fn file_list(&self) -> Vec<Utf8PathBuf> {
        self.by_file.pin()
            .keys()
            .cloned()
            .collect()
    }
}


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
        for f in &self.certstore.watchlist {
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
                self.certstore.by_file.pin().get(&up)
                    .expect("Unexpected cert path: {up}")
                    .clone()
            })
            .collect::<Vec<Arc<HostCertificate>>>();

        for cert in certs {
            let newcert = Arc::new(HostCertificate::new(cert.host.clone(),
                                                        cert.keyfile.clone(),
                                                        cert.certfile.clone())?);
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
        info!("Certificate found: {:?}, expires {}", cert.certs[0].subject_name(), cert.certs[0].not_after());
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



#[cfg(test)]
mod tests {
    use http::Uri;
    use zone_update::gandi::Auth;

    use super::*;
    use crate::config::{AcmeChallenge, AcmeProvider, Backend, DnsProvider, Server, TlsAcmeConfig, TlsConfig, TlsFilesConfig};


    #[test]
    fn test_watchlist_exclusion() -> Result<()> {
        let config = Config {
            servers: vec![
                Server {
                    hostname: "host1".to_owned(),
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
                },
                Server {
                    hostname: "host2".to_owned(),
                    tls: TlsConfig {
                        port: 443,
                        config: TlsConfigType::Files(TlsFilesConfig {
                            keyfile: Utf8PathBuf::from("keyfile2.key"),
                            certfile: Utf8PathBuf::from("certfile2.crt"),
                            reload: false,
                        })
                    },
                    backends: vec![
                        Backend {
                            context: None,
                            url: Uri::from_static("http://localhost")
                        }
                    ]
                },
                Server {
                    hostname: "host3".to_owned(),
                    tls: TlsConfig {
                        port: 443,
                        config: TlsConfigType::Acme(TlsAcmeConfig {
                            provider: AcmeProvider::LetsEncrypt,
                            challenge_type: AcmeChallenge::Dns01,
                            contact: "myname@example.com".to_string(),
                            dns_provider: DnsProvider::Gandi(Auth::ApiKey("test".to_string())),
                        })}
                    ,
                    backends: vec![
                        Backend {
                            context: None,
                            url: Uri::from_static("http://localhost")
                        }
                    ]
                },
            ]
        };

        let watchlist = gen_watchlist(&config);

        assert_eq!(2, watchlist.len());
        assert_eq!(Utf8PathBuf::from("keyfile1.key"), watchlist[0]);
        assert_eq!(Utf8PathBuf::from("certfile1.crt"), watchlist[1]);

        Ok(())
    }
}

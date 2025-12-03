use std::sync::Arc;

use anyhow::Result;
use camino::Utf8PathBuf;
use tracing_log::log::{info, warn};

use crate::{certificates::{store::CertStore, CertificateProvider, HostCertificate}, config::TlsConfigType, RunContext};

const CERT_BASE_DEFAULT: &str = "/var/lib/proxeny/acme";
const EXPIRY_WINDOW: i64 = 30;

struct AcmeHost {
    host: String,
    contact: String,
    keyfile: Utf8PathBuf,
    certfile: Utf8PathBuf,
    // TODO:
    // acme_provider: AcmeProvider,
    // challenge_type: AcmeChallenge,
    cert: Option<Arc<HostCertificate>>,
}

pub struct AcmeProvider {
    context: Arc<RunContext>,
    certstore: Arc<CertStore>,
    hosts: Vec<AcmeHost>,
}

impl AcmeProvider {

    pub fn new(certstore: Arc<CertStore>, context: Arc<RunContext>) -> Result<Self> {
        // FIXME: Should come from config eventually
        let cert_base = Utf8PathBuf::from(CERT_BASE_DEFAULT);

        let acme_hosts = context.config.servers().iter()
            .filter_map(|s| match &s.tls.config {
                TlsConfigType::Files(_) => None,
                TlsConfigType::Acme(aconf) => Some(aconf),
            })
            .map(|aconf| {
                // Default;
                // keyfile  -> /var/lib/proxeny/acme/www.example.com/www.example.com.key
                // certfile -> /var/lib/proxeny/acme/www.example.com/www.example.com.crt
                let host = context.config.hostname.clone();
                let cert_file = cert_base
                    .join(&host)
                    .join(&host);
                let keyfile = cert_file.with_extension(".key");
                let certfile = cert_file.with_extension(".crt");

                let cert = if keyfile.exists() && certfile.exists() {
                    Some(Arc::new(HostCertificate::new(keyfile.clone(), certfile.clone(), false)?))
                } else {
                    None
                };

                let acme_host = AcmeHost {
                    cert,
                    host,
                    keyfile,
                    certfile,
                    contact: aconf.contact.clone(),
                };
                Ok(acme_host)
            })
            .collect::<Result<Vec<AcmeHost>>>()?;

        Ok(Self {
            context,
            certstore,
            hosts: acme_hosts,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        let existing = self.hosts.iter()
            .filter_map(|ah| if let Some(cert) = &ah.cert {
                Some(cert.clone())
            } else {
                None
            })
            .collect::<Vec<Arc<HostCertificate>>>();

        // Initial load
        for cert in existing.into_iter() {
            self.certstore.upsert(cert)?;
        }

        let mut quit_rx = self.context.quit_rx.clone();
        loop {
            tokio::select! {
                // events = self.ev_rx.recv() => {
                //     match events {
                //         Some(Err(errs)) => warn!("Received errors from cert watcher: {errs:#?}"),
                //         Some(Ok(evs)) => self.process_events(evs)?,
                //         None => {
                //             warn!("Notify watcher channel closed; quitting");
                //             break;
                //         }
                //     }
                // },
                _ = quit_rx.changed() => {
                    info!("Quitting certificate watcher loop.");
                    break;
                },
            };
        }

        Ok(())
    }

    /// Returns certs that need creating or refreshing
    fn pending(&self) -> Vec<&AcmeHost> {
        self.hosts.iter()
            // Either None or expiring with 30 days
            .filter(|ah| ! ah.cert.as_ref()
                    .is_some_and(|cert| ! cert.is_expiring_in(EXPIRY_WINDOW)))
            .collect()
    }

}

impl CertificateProvider for AcmeProvider {
    fn read_certs(&self) -> Vec<Arc<HostCertificate>> {
        self.hosts.iter()
            .filter_map(|h| h.cert.clone())
            .collect()
    }
}

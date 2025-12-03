use std::sync::Arc;

use anyhow::Result;
use camino::Utf8PathBuf;
use tracing_log::log::{info, warn};

use crate::{certificates::{store::CertStore, HostCertificate}, config::{AcmeChallenge, AcmeProvider, DnsProvider, TlsConfigType}, RunContext};

const CERT_BASE_DEFAULT: &str = "/var/lib/proxeny/acme";
const EXPIRY_WINDOW: i64 = 30;

struct AcmeHost {
    host: String,
    contact: String,
    keyfile: Utf8PathBuf,
    certfile: Utf8PathBuf,
    acme_provider: AcmeProvider,
    challenge_type: AcmeChallenge,
}

pub struct AcmeRuntime {
    context: Arc<RunContext>,
    certstore: Arc<CertStore>,
    hosts: Vec<AcmeHost>,
}

impl AcmeRuntime {

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

                let acme_host = AcmeHost {
                    host,
                    keyfile,
                    certfile,
                    acme_provider: aconf.acme_provider,
                    challenge_type: aconf.challenge_type.clone(),
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
            .filter(|ah| ah.keyfile.exists() && ah.certfile.exists())
            .map(|ah| Ok(Arc::new(HostCertificate::new(ah.keyfile.clone(), ah.certfile.clone(), false)?)))
            .collect::<Result<Vec<Arc<HostCertificate>>>>()?;

        // Initial load of existing certs. NOTE: This is slightly hacky
        // as we're possibly loading expired certs only to immediately
        // replace them, but it simplifies pending() etc.
        for cert in existing.into_iter() {
            self.certstore.upsert(cert)?;
        }

        for host in self.pending() {
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

    async fn renew_cert(&self, host: &AcmeHost) -> Result<()> {
        match host.challenge_type {
            AcmeChallenge::Dns01(ref provider) => self.renew_dns01(host, &provider).await,
            AcmeChallenge::Http01 => self.renew_http01(host).await,
        }
    }

    async fn renew_dns01(&self, host: &AcmeHost, provider: &DnsProvider) -> Result<()> {
        let dns_config = zone_update::Config {
            domain: provider.domain.clone(),
            dry_run: false,
        };
        let email = format!("mailto:{}", host.contact);

        let dns_impl = provider.dns_provider.async_impl(dns_config);

        Ok(())
    }

    async fn renew_http01(&self, host: &AcmeHost) -> Result<()> {
        unimplemented!()
    }

    /// Returns certs that need creating or refreshing
    fn pending(&self) -> Vec<&AcmeHost> {
        self.hosts.iter()
            // Either None or expiring with 30 days
            .filter(|ah| ! self.certstore.by_host(&ah.host)
                    .is_some_and(|cert| ! cert.is_expiring_in(EXPIRY_WINDOW)))
            .collect()
    }

}

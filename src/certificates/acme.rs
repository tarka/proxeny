use std::{sync::Arc, time::Duration};

use acme_micro::{create_p384_key, Certificate, Directory, DirectoryUrl};
use anyhow::{anyhow, Result};
use camino::Utf8PathBuf;
use tracing_log::log::{info, warn};

use crate::{
    certificates::{store::CertStore, HostCertificate}, config::{AcmeChallenge, AcmeProvider, DnsProvider, TlsConfigType}, RunContext
};

const CERT_BASE_DEFAULT: &str = "/var/lib/proxeny/acme";
const EXPIRY_WINDOW: i64 = 30;

struct AcmeHost {
    hostname: String,
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
                    hostname: host,
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

    async fn renew_dns01(&self, ahost: &AcmeHost, provider: &DnsProvider) -> Result<()> {
        // TODO: We're using acme-micro here as it's the simplest to
        // use/debug. However as it doesn't have an async impl we need
        // to wrap it in `spawn_blocking`. An async-native ACME client
        // such as `lers` would be better, but it seems unmaintained
        // and didn't work out of the box. This could be revisited.
        let hostname = ahost.hostname.clone();
        let domain = provider.domain.clone();
        let contact = ahost.contact.clone();
        let provider = provider.clone();

        let cert = tokio::task::spawn_blocking(
            move || renew_acme_micro(hostname, domain, contact, provider)
        ).await??;

        Ok(())
    }

    async fn renew_http01(&self, host: &AcmeHost) -> Result<()> {
        unimplemented!()
    }

    /// Returns certs that need creating or refreshing
    fn pending(&self) -> Vec<&AcmeHost> {
        self.hosts.iter()
        // Either None or expiring with 30 days
            .filter(|ah| ! self.certstore.by_host(&ah.hostname)
                    .is_some_and(|cert| ! cert.is_expiring_in(EXPIRY_WINDOW)))
            .collect()
    }

}


fn renew_acme_micro(hostname: String, domain: String, contact: String, provider: DnsProvider) -> Result<Certificate> {
    let email = format!("mailto:{}", contact);
    let txt_name = format!("_acme-challenge.{}", hostname);
    let fqdn = format!("{}.{}", hostname, domain);

    let dns_config = zone_update::Config {
        domain: provider.domain.clone(),
        dry_run: false,
    };
    let dns_client = provider.dns_provider.blocking_impl(dns_config);

    let dir = Directory::from_url(DirectoryUrl::LetsEncrypt)?;

    // TODO: Save/load accounts

    info!("Registering ACME account");
    let acc = dir.register_account(vec![email])?;

    info!("Placing ACME order");
    let mut ord_new = acc.new_order(&fqdn, &[])?;

    let ord_csr = loop {

        // If the domain(s) has already been authorized in a previous
        // order we may be able to skip validation. The ACME API decides.
        if let Some(ord_csr) = ord_new.confirm_validations() {
            break ord_csr;
        }

        let auths = ord_new.authorizations()?;

        let challenge = auths[0].dns_challenge()
            .ok_or(anyhow!("Failed to retrieve challenge token for {txt_name}"))?;
        let token = challenge.dns_proof()?;

        info!("Creating challenge TXT record '{txt_name}' -> '{token}'");
        dns_client.create_txt_record(&txt_name, &token)?;

        println!("Requesting validation from ACME");
        challenge.validate(Duration::from_millis(5000))?;

        ord_new.refresh()?;
    };

    let pkey_pri = create_p384_key()?;
    let ord_cert = ord_csr.finalize_pkey(pkey_pri, Duration::from_millis(5000))?;

    // Finally download the certificate.
    info!("Certificate created; downloading");
    let cert = ord_cert.download_cert()?;

    Ok(cert)
}

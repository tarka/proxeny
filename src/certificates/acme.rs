use std::{fs::create_dir_all, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use camino::Utf8PathBuf;
use chrono::Utc;
use dnsclient::{r#async::DNSClient, UpstreamServer};
use instant_acme::{Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewOrder, OrderStatus, RetryPolicy};
use itertools::Itertools;
use tokio::fs;
use tracing_log::log::{debug, error, info, warn};
use zone_update::async_impl::AsyncDnsProvider;

use crate::{
    RunContext,
    certificates::{HostCertificate, store::CertStore},
    config::{AcmeChallenge, AcmeProvider, DnsProvider, TlsConfigType},
};

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
    acme_hosts: Vec<AcmeHost>,
}

struct PemCertificate {
    private_key: String,
    cert_chain: String,
}

struct AcmeParams<'a> {
    hostname: &'a String,
    txt_name: &'a String,
    txt_fqdn: &'a String,
    contact: &'a String,
}

impl AcmeRuntime {

    pub fn new(certstore: Arc<CertStore>, context: Arc<RunContext>) -> Result<Self> {
        let acme_hosts = context.config.servers().iter()
            .filter_map(|s| match &s.tls.config {
                TlsConfigType::Files(_) => None,
                TlsConfigType::Acme(aconf) => Some(aconf),
            })
            .map(|aconf| {
                // Default;
                // keyfile  -> /var/lib/vicarian/acme/www.example.com/www.example.com.key
                // certfile -> /var/lib/vicarian/acme/www.example.com/www.example.com.crt
                let host = context.config.hostname.clone();

                let cert_base = Utf8PathBuf::from(aconf.directory.clone());
                let cert_dir = cert_base
                    .join(&host);
                info!("Creating ACME certificate dir {cert_base}");
                create_dir_all(&cert_dir)
                    .context("Error creating directory {cert_base}")?;

                let cert_file = cert_dir
                    .join(&host);
                let keyfile = cert_file.with_extension("key");
                let certfile = cert_file.with_extension("crt");

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
            acme_hosts,
        })
    }

    pub async fn run(&self) -> Result<()> {
        info!("Starting ACME runtime");

        let existing = self.acme_hosts.iter()
            .filter(|ah| ah.keyfile.exists() && ah.certfile.exists())
            .map(|ah| Ok(Arc::new(HostCertificate::new(ah.keyfile.clone(), ah.certfile.clone(), false)?)))
            .collect::<Result<Vec<Arc<HostCertificate>>>>()?;

        // Initial load of existing certs. NOTE: This is slightly hacky
        // as we're possibly loading expired certs only to immediately
        // replace them, but it simplifies pending() etc.
        for cert in existing.into_iter() {
            self.certstore.upsert(cert)?;
        }

        self.renew_all_pending().await?;

        let mut quit_rx = self.context.quit_rx.clone();
        loop {

            let next = self.next_expiring_secs()
                .map(|s| tokio::time::Duration::from_secs(s));
            if let Some(d) = next {
                let dt = Utc::now() + d;
                info!("Wait for next expiry at {dt}");
            } else {
                // TODO: Should we just quit?
                info!("Nothing expiring, just hanging for now");
            }

            tokio::select! {
                _ = tokio::time::sleep(next.unwrap()), if next.is_some() => {
                    info!("Woken up for ACME renewal; processing all pending certs");
                    self.renew_all_pending().await?;
                }

                _ = quit_rx.changed() => {
                    info!("Quitting ACME runtime");
                    break;
                },
            };
        }

        Ok(())
    }

    async fn renew_all_pending(&self) -> Result<()> {
        for ahost in self.pending() {
            info!("ACME host {} requires renewal, initiating...", ahost.hostname);
            match ahost.challenge_type {
                AcmeChallenge::Dns01(ref provider) => {
                    self.renew_dns01(&ahost, provider).await?;
                }
                AcmeChallenge::Http01 => {
                    self.renew_http01(&ahost).await?;
                }
            }
        }
        Ok(())
    }

    fn next_expiring_secs(&self) -> Option<u64> {
        self.acme_hosts.iter()
            // TODO: This currently just skips missing hosts.
            .filter_map(|ah| self.certstore.by_host(&ah.hostname))
            .map(|hc| hc.expires_in())
            .sorted()
            .next()
            .map(|s| s.max(0) as u64)
    }

    async fn renew_dns01(&self, acme_host: &AcmeHost, provider: &DnsProvider) -> Result<Arc<HostCertificate>> {
        let contact = format!("mailto:{}", acme_host.contact);
        let shortname = acme_host.hostname
            .strip_suffix(&format!(".{}", provider.domain))
            .ok_or(anyhow!("Failed to strip domain from host {}", acme_host.hostname))?;

        let txt_name = format!("_acme-challenge.{}", shortname);
        let txt_fqdn = format!("{txt_name}.{}", provider.domain);

        let params = AcmeParams {
            hostname: &acme_host.hostname,
            txt_name: &txt_name,
            txt_fqdn: &txt_fqdn,
            contact: &contact,
        };

        let dns_config = zone_update::Config {
            domain: provider.domain.clone(),
            dry_run: false,
        };
        let dns_client = provider.dns_provider.async_impl(dns_config);

        let certificate_r = self.renew_instant_acme(params, &dns_client).await;

        // Cleanup before evaluating certificate for errors
        attempt_dns_cleanup(txt_name, dns_client).await;

        let pem_certificate = match certificate_r {
            Ok(cert) => cert,
            Err(err) => {
                error!("Error renewing certificate: {err}");
                return Err(err)
            }
        };

        debug!("====== Cert Chain ======\n{}", pem_certificate.cert_chain);

        info!("Writing certificate and key");
        fs::write(&acme_host.keyfile, pem_certificate.private_key.as_bytes()).await?;
        fs::write(&acme_host.certfile, pem_certificate.cert_chain.as_bytes()).await?;

        info!("Loading new certificate");
        let hc = Arc::new(HostCertificate::new(acme_host.keyfile.clone(), acme_host.certfile.clone(), false)?);
        self.certstore.upsert(hc.clone())?;

        Ok(hc)
    }

    async fn renew_http01(&self, _host: &AcmeHost) -> Result<Arc<HostCertificate>> {
        todo!()
    }

    /// Returns certs that need creating or refreshing
    fn pending(&self) -> Vec<&AcmeHost> {
        self.acme_hosts.iter()
        // Either None or expiring with 30 days.
        // TODO: This could use renewal_info() in instant-acme.
            .filter(|ah| ! self.certstore.by_host(&ah.hostname)
                    .is_some_and(|cert| ! cert.is_expiring_in(EXPIRY_WINDOW)))
            .collect()
    }


    async fn renew_instant_acme(&self, params: AcmeParams<'_>, dns_client: &Box<dyn AsyncDnsProvider>) -> Result<PemCertificate> {
        info!("Initialising ACME account");
        let acme_url = if self.context.config.dev_mode {
            info!("Using staging ACME server");
            LetsEncrypt::Staging.url().to_owned()
        } else {
            LetsEncrypt::Production.url().to_owned()
        };
        let (account, _credentials) = Account::builder()?
            .create(
                &instant_acme::NewAccount {
                    contact: &[params.contact],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                acme_url,
                None,
            )
            .await?;
        info!("Create order for {}", params.hostname);
        let hid = Identifier::Dns(params.hostname.clone());
        let mut order = account.new_order(&NewOrder::new(&[hid])).await?;
        let mut authz = order.authorizations();
        let mut auth = authz.next().await
            .ok_or(anyhow!("No authorisation found for {} in order", params.hostname))??;
        info!("Processing {:?}", auth.status);
        match auth.status {
            AuthorizationStatus::Pending => {}
            // It's technically possibly to pick up an old auth order here
            // which returns ::Valid?
            _ => todo!(),
        }
        info!("Creating challenge");
        let mut challenge = auth
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| anyhow::anyhow!("No DNS-01 challenge found"))?;
        let token = challenge.key_authorization().dns_value();
        info!("Creating TXT: {} -> {}", params.txt_name, token);
        dns_client.create_txt_record(params.txt_name, &token).await?;

        wait_for_dns(params.txt_fqdn).await?;

        info!("Setting challenge to ready");
        challenge.set_ready().await?;

        info!("Polling challenge status");
        let status = order.poll_ready(&RetryPolicy::default()).await?;
        if status != OrderStatus::Ready {
            dns_client.delete_txt_record(params.txt_name).await?;
            return Err(anyhow!("Unexpected order status: {status:?}"));
        }

        let private_key = order.finalize().await?;
        let cert_chain = order.poll_certificate(&RetryPolicy::default()).await?;

        Ok(PemCertificate {
            cert_chain,
            private_key,
        })
    }
}

async fn wait_for_dns(txt_fqdn: &String) -> Result<(), anyhow::Error> {
    info!("Waiting for record {txt_fqdn} to go live");

    // TODO: For now we use a 'known good' DNS server for now to avoid
    // complications from local DNS setups (e.g. NXDOMAIN caching). We
    // may want to change this?
    let upstream = UpstreamServer::new(SocketAddr::from(([1,1,1,1], 53)));
    let lookup = DNSClient::new(vec![upstream]);

    for _i in 0..30 {
        debug!("Lookup for {txt_fqdn}");
        let txts = lookup.query_txt(&txt_fqdn).await?;
        if txts.len() > 0 {
            info!("Found {txt_fqdn}");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Err(anyhow!("Failed to find record {txt_fqdn} in public DNS"))
}

async fn attempt_dns_cleanup(txt_name: String, dns_client: Box<dyn AsyncDnsProvider>) {
    info!("Attempting cleanup of {txt_name} record");
    // FIXME: Doesn't handle multiple records currently. We need to
    // add this to zone-update.
    match dns_client.delete_txt_record(&txt_name).await {
        Ok(_) => {},
        Err(d_err) => {
            warn!("Failed to delete DNS record {txt_name}: {d_err}");
        }
    }
}

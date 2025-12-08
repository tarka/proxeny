use std::{fs::create_dir_all, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use camino::Utf8PathBuf;
use dnsclient::{r#async::DNSClient, UpstreamServer};
use instant_acme::{Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewOrder, OrderStatus, RetryPolicy};
use tracing_log::log::{debug, info, error};

use crate::{
    certificates::{store::CertStore, HostCertificate}, config::{AcmeChallenge, AcmeProvider, DnsProvider, TlsConfigType}, RunContext
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
    hosts: Vec<AcmeHost>,
}

struct PemCertificate {
    private_key: String,
    cert_chain: String,
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
                // keyfile  -> /var/lib/proxeny/acme/www.example.com/www.example.com.key
                // certfile -> /var/lib/proxeny/acme/www.example.com/www.example.com.crt
                let host = context.config.hostname.clone();

                let cert_base = Utf8PathBuf::from(aconf.directory.clone());
                let cert_dir = cert_base
                    .join(&host);
                create_dir_all(&cert_dir)
                    .context("Creating ACME certificate dir {cert_base}")?;

                let cert_file = cert_dir
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

    pub async fn run(&self) -> Result<()> {
        info!("Starting ACME runtime");

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
        // let cert = renew_acme_micro(ahost, provider).await?;
        let cert = match renew_acme_micro(ahost, provider).await {
            Ok(cert) => {
                info!("Cert OK");
                cert
            }
            Err(err) => {
                error!("Error renewing certificate: {err}");
                return Err(err)
            }
        };

        Ok(())
    }

    async fn renew_http01(&self, _host: &AcmeHost) -> Result<()> {
        todo!()
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


async fn renew_acme_micro(acme_host: &AcmeHost, provider: &DnsProvider) -> Result<PemCertificate> {
    let contact = format!("mailto:{}", acme_host.contact);
    let shortname = acme_host.hostname
        .strip_suffix(&format!(".{}", provider.domain))
        .ok_or(anyhow!("Failed to strip domain from host {}", acme_host.hostname))?;

    let txt_name = format!("_acme-challenge.{}", shortname);
    let txt_fqdn = format!("{txt_name}.{}", provider.domain);

    let dns_config = zone_update::Config {
        domain: provider.domain.clone(),
        dry_run: false,
    };
    let dns_client = provider.dns_provider.async_impl(dns_config);

    // TODO: Save/load account
    info!("Initialising ACME account");
    let (account, _credentials) = Account::builder()?
        .create(
            &instant_acme::NewAccount {
                contact: &[&contact],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            LetsEncrypt::Staging.url().to_owned(),
            None,
        )
        .await?;

    let hid = Identifier::Dns(acme_host.hostname.clone());
    info!("Create order for {}", acme_host.hostname);
    let mut order = account.new_order(&NewOrder::new(&[hid])).await?;

    let mut authz = order.authorizations();
    let mut auth = authz.next().await
        .ok_or(anyhow!("No authorisation found for {shortname} in order"))??;

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
    info!("Creating TXT: {txt_name} -> {}", token);
    dns_client.create_txt_record(&txt_name, &token).await?;

    wait_for_dns(txt_fqdn).await?;

    info!("Setting challenge to ready");
    challenge.set_ready().await?;

    info!("Polling challenge status");
    let status = order.poll_ready(&RetryPolicy::default()).await?;
    if status != OrderStatus::Ready {
        dns_client.delete_txt_record(&txt_name).await?;
        return Err(anyhow!("Unexpected order status: {status:?}"));
    }

    let private_key = order.finalize().await?;
    let cert_chain = order.poll_certificate(&RetryPolicy::default()).await?;

    info!("====== Cert Chain ======\n{cert_chain}");

    Ok(PemCertificate {
        cert_chain,
        private_key,
    })
}

async fn wait_for_dns(txt_fqdn: String) -> Result<(), anyhow::Error> {
    info!("Waiting for record {txt_fqdn} to go live");

    // TODO: Use a 'known good' DNS server for now to avoid
    // complications from local DNS setups (e.g. NXDOMAIN caching). We
    // may want to change this?
    let upstream = UpstreamServer::new(SocketAddr::from(([1,1,1,1], 53)));
    let lookup = DNSClient::new(vec![upstream]);

    for _i in 0..30 {
        debug!("Lookup for {txt_fqdn}");
        let txts = lookup.query_txt(&txt_fqdn).await?;
        if txts.len() > 0 {
            info!("Found {txt_fqdn}");
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}

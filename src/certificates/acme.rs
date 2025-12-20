use std::{fs::create_dir_all, iter, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, anyhow};
use camino::Utf8PathBuf;
use chrono::{TimeDelta, Utc};
use dnsclient::{UpstreamServer, r#async::DNSClient};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeHandle, ChallengeType, Identifier,
    LetsEncrypt, NewOrder, OrderStatus, RetryPolicy,
};
use itertools::Itertools;
use tokio::{
    fs::{self, File, read_to_string},
    io::AsyncWriteExt,
};
use tracing_log::log::{debug, error, info, warn};
use zone_update::async_impl::AsyncDnsProvider;

use crate::{
    RunContext,
    certificates::{HostCertificate, store::CertStore},
    config::{AcmeChallenge, DnsProvider, TlsConfigType},
};

const LE_PROFILE: &str = "shortlived";
const _EXPIRY_WINDOW_DAYS: i64 = 30;
const _EXPIRY_WINDOW_SECS: i64 = _EXPIRY_WINDOW_DAYS * 24 * 60 * 60;
const EXPIRY_WINDOW_SHORTLIVED_DAYS: i64 = 6;
const EXPIRY_WINDOW_SHORTLIVED_SECS: i64 = EXPIRY_WINDOW_SHORTLIVED_DAYS * 24 * 60 * 60;

const ONE_SECOND: TimeDelta = TimeDelta::new(1, 0).unwrap();

struct AcmeHost {
    fqdn: String,
    aliases: Vec<String>,
    domain: String,
    contact: String,
    contactfile: Utf8PathBuf,
    keyfile: Utf8PathBuf,
    certfile: Utf8PathBuf,
    challenge_type: AcmeChallenge,
}

impl AcmeHost {
    pub fn hostnames(&self) -> Vec<&String> {
        iter::once(&self.fqdn)
            .chain(self.aliases.iter())
            .unique()
            .collect()
    }
}

pub struct AcmeRuntime {
    context: Arc<RunContext>,
    certstore: Arc<CertStore>,
    acme_hosts: Vec<AcmeHost>,
    challenges: papaya::HashMap<String, ChallengeTokens>,
}

struct PemCertificate {
    private_key: String,
    cert_chain: String,
}

#[derive(Clone, Debug)]
pub struct ChallengeTokens {
    pub token: String,
    pub key_auth: String,
}

impl AcmeRuntime {

    pub fn new(certstore: Arc<CertStore>, context: Arc<RunContext>) -> Result<Self> {
        let acme_hosts = context.config.servers().iter()
            .filter_map(|s| match &s.tls.config {
                TlsConfigType::Files(_) => None, // Handled elsewhere
                TlsConfigType::Acme(aconf) => Some(aconf),
            })
            .map(|aconf| {
                // Default;
                // keyfile  -> /var/lib/vicarian/acme/www.example.com/www.example.com.key
                // certfile -> /var/lib/vicarian/acme/www.example.com/www.example.com.crt
                let fqdn = context.config.hostname.clone();

                let domain_psl = psl::domain(fqdn.as_bytes())
                    .ok_or(anyhow!("Failed to find base domain for {fqdn}"))?;
                let domain = String::from_utf8(domain_psl.as_bytes().to_vec())?;

                let cert_base = Utf8PathBuf::from(aconf.directory.clone());
                let cert_dir = cert_base
                    .join(&fqdn);
                info!("Creating ACME certificate dir {cert_base}");
                create_dir_all(&cert_dir)
                    .context("Error creating directory {cert_base}")?;

                let cert_file = cert_dir
                    .join(&fqdn);
                let keyfile = cert_file.with_extension("key");
                let certfile = cert_file.with_extension("crt");

                let contact = aconf.contact.clone();
                let contact_dir = cert_base
                    .join(&contact);
                create_dir_all(&contact_dir)
                    .context("Error creating directory {contact_dir}")?;

                let contactfile = contact_dir
                    .join(&contact)
                    .with_extension("conf");

                let acme_host = AcmeHost {
                    fqdn,
                    aliases: context.config.aliases.clone(),
                    domain,
                    keyfile,
                    certfile,
                    contact,
                    contactfile,
                    challenge_type: aconf.challenge_type.clone(),
                };
                Ok(acme_host)
            })
            .collect::<Result<Vec<AcmeHost>>>()?;

        Ok(Self {
            context,
            certstore,
            acme_hosts,
            challenges: papaya::HashMap::new(),
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
            let next = self.certstore.next_expiring_secs()
                .map(|s| (s - EXPIRY_WINDOW_SHORTLIVED_SECS).max(0))
                .map(|s| TimeDelta::new(s, 0))
                .flatten();
            if let Some(d) = next {
                let dt = Utc::now() + d;
                info!("Wait for next expiry at {dt}");
            } else {
                // TODO: Should we just quit?
                info!("Nothing expiring, just hanging for now");
            }

            tokio::select! {
                _ = tokio::time::sleep(next.unwrap().to_std()?), if next.is_some() => {
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
            info!("ACME host {} requires renewal, initiating...", ahost.fqdn);
            self.renew_acme(&ahost).await?;
        }
        Ok(())
    }

    async fn renew_acme(&self, acme_host: &AcmeHost) -> Result<Arc<HostCertificate>> {

        let certificate_r = self.renew_instant_acme(acme_host).await;

        // Cleanup before evaluating certificate for errors
        self.cleanup_provisioning(acme_host).await;

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


    /// Returns certs that need creating or refreshing
    fn pending(&self) -> Vec<&AcmeHost> {
        self.acme_hosts.iter()
            // Either None or expiring within window.
            // TODO: This could use renewal_info() in instant-acme.
            .filter(|ah| ! self.certstore.by_host(&ah.fqdn)
                    .is_some_and(|cert| ! cert.is_expiring_in_secs(EXPIRY_WINDOW_SHORTLIVED_DAYS)))
            .collect()
    }


    async fn renew_instant_acme(&self, acme_host: &AcmeHost) -> Result<PemCertificate> {
        info!("Initialising ACME account");
        let account = self.fetch_account(acme_host).await?;

        info!("Create order for {}", acme_host.fqdn);
        let hids = acme_host.hostnames().into_iter()
            .cloned()
            .map(Identifier::Dns)
            .collect::<Vec<Identifier>>();

        let no = NewOrder::new(&hids)
            .profile(LE_PROFILE);
        let mut order = account.new_order(&no).await?;

        let mut authorisations = order.authorizations();


        while let Some(result) = authorisations.next().await {
            let mut auth = result?;

            info!("Processing {:?}", auth.status);
            match auth.status {
                AuthorizationStatus::Pending => {}
                // It's technically possibly to pick up an old auth order here
                // which returns ::Valid?
                AuthorizationStatus::Valid => break,
                _ => todo!(),
            }

            info!("Creating challenge");
            let mut challenge = auth
                .challenge(ChallengeType::from(&acme_host.challenge_type))
                .ok_or_else(|| anyhow!("No {:?} challenge found", acme_host.challenge_type))?;

            // As DNS providers generally don't allow concurrent
            // updates to a zone we need to process these series.
            //
            // TODO: We could process the post-provision checks and
            // set_ready() in parallel with futures/join_all.
            self.provision_challenge(&acme_host, &challenge).await?;

            info!("Setting challenge to ready");
            challenge.set_ready().await?;
        }

        info!("Polling challenge status");
        let status = order.poll_ready(&RetryPolicy::default()).await?;
        if status != OrderStatus::Ready {
            // Will cleanup on return
            return Err(anyhow!("Unexpected order status: {status:?}"));
        }

        let private_key = order.finalize().await?;
        let cert_chain = order.poll_certificate(&RetryPolicy::default()).await?;

        Ok(PemCertificate {
            cert_chain,
            private_key,
        })
    }

    async fn fetch_account(&self, acme_host: &AcmeHost) -> Result<Account> {
        let acme_url = if self.context.config.dev_mode {
            info!("Using staging ACME server");
            LetsEncrypt::Staging.url().to_owned()
        } else {
            LetsEncrypt::Production.url().to_owned()
        };

        let account = if acme_host.contactfile.exists() {
            let creds_str = read_to_string(&acme_host.contactfile).await?;
            let creds: AccountCredentials = serde_json::from_str(&creds_str)?;
            let account = Account::builder()?
                .from_credentials(creds).await?;
            info!("Loaded account credentials for {}", acme_host.contact);

            account

        } else {
            let contact_url = format!("mailto:{}", acme_host.contact);

            let (account, credentials) = Account::builder()?
                .create(
                    &instant_acme::NewAccount {
                        contact: &[&contact_url],
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    acme_url,
                    None,
                )
                .await?;

            info!("Saving account credentials for {}", acme_host.contact);
            let creds_str = serde_json::to_vec(&credentials)?;
            let mut fd = File::create(&acme_host.contactfile).await?;
            fd.write_all(&creds_str).await?;

            account
        };
        Ok(account)
    }

    async fn provision_challenge(&self, acme_host: &AcmeHost, challenge: &ChallengeHandle<'_>) -> Result<()> {
        match &acme_host.challenge_type {
            AcmeChallenge::Dns01(provider) => {

                let fqdn = challenge.identifier().to_string();
                let txt_name = self.to_txt_name(acme_host, &fqdn)?;
                let txt_fqdn = format!("_acme-challenge.{fqdn}");
                let token = challenge.key_authorization().dns_value();

                info!("Creating TXT: {} -> {}", txt_name, token);
                let dns_client = get_dns_client(acme_host, provider);
                dns_client.create_txt_record(&txt_name, &token).await?;

                wait_for_dns(&txt_fqdn).await?;
            }
            AcmeChallenge::Http01 => {
                let fqdn = challenge.identifier().to_string();
                let tokens = ChallengeTokens {
                    token: challenge.token.clone(),
                    key_auth: challenge.key_authorization().as_str().to_string(),
                };

                info!("Storing HTTP-01 challenge: {} -> {:?}", fqdn, tokens);
                let pin = self.challenges.pin();
                pin.insert(fqdn, tokens);

            }
        }
        Ok(())
    }

    async fn cleanup_provisioning(&self, acme_host: &AcmeHost) {
        match &acme_host.challenge_type {
            AcmeChallenge::Dns01(provider) => {
                for hostname in acme_host.hostnames() {
                    let txt_name = match self.to_txt_name(acme_host, hostname) {
                        Ok(txt_name) => txt_name,
                        Err(_) => {
                            warn!("Failed to cleanup {hostname} TXT record");
                            continue;
                        }
                    };

                    info!("Attempting cleanup of {txt_name} record");
                    // FIXME: Doesn't handle multiple records currently. We need to
                    // add this to zone-update.
                    let dns_client = get_dns_client(acme_host, provider);
                    match dns_client.delete_txt_record(&txt_name).await {
                        Ok(_) => {},
                        Err(d_err) => {
                            warn!("Failed to delete DNS record {txt_name}: {d_err}");
                        }
                    }
                }
            }
            AcmeChallenge::Http01 => {
                for hostname in acme_host.hostnames() {
                    info!("Removing HTTP-01 challenge: {}", hostname);
                    let pin = self.challenges.pin();
                    let opt = pin.remove(hostname);
                    if opt.is_none() {
                        warn!("Challenge for {} not found", acme_host.fqdn);
                    }
                }

            }
        }
    }

    pub fn challenge_tokens(&self, fqdn: &str) -> Option<ChallengeTokens> {
        let pin = self.challenges.pin();
        pin.get(fqdn).cloned()
    }

    fn strip_domain(&self, acme_host: &AcmeHost, fqdn: &str) -> Result<String> {
        fqdn.strip_suffix(&format!(".{}", acme_host.domain))
            .ok_or(anyhow!("Failed to strip domain {} from {}", acme_host.domain, fqdn))
            .map(str::to_owned)
    }

    fn to_txt_name(&self, acme_host: &AcmeHost, fqdn: &str) -> Result<String> {
        let id = self.strip_domain(&acme_host, fqdn)?;
        if id == "" {
            Ok("_acme-challenge".to_string())
        } else {
            Ok(format!("_acme-challenge.{id}"))
        }
    }

}

fn get_dns_client(acme_host: &AcmeHost, provider: &DnsProvider) -> Box<dyn AsyncDnsProvider> {
    // It's slightly inefficient to create this each time, but it simplifies the code.
    let dns_config = zone_update::Config {
        domain: acme_host.domain.clone(),
        dry_run: false,
    };
    provider.dns_provider.async_impl(dns_config)
}

impl From<&AcmeChallenge> for ChallengeType {
    fn from(value: &AcmeChallenge) -> Self {
        match value {
            AcmeChallenge::Dns01(_) => ChallengeType::Dns01,
            AcmeChallenge::Http01 => ChallengeType::Http01,
        }
    }
}


async fn wait_for_dns(txt_fqdn: &String) -> Result<()> {
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
        tokio::time::sleep(ONE_SECOND.to_std()?).await;
    }

    Err(anyhow!("Failed to find record {txt_fqdn} in public DNS"))
}

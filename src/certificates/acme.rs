use std::{fs::create_dir_all, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow};
use camino::Utf8PathBuf;
use chrono::Utc;
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

const EXPIRY_WINDOW: i64 = 30;

struct AcmeHost {
    fqdn: String,
    domain: String,
    contact: String,
    contactfile: Utf8PathBuf,
    keyfile: Utf8PathBuf,
    certfile: Utf8PathBuf,
    challenge_type: AcmeChallenge,
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

struct AcmeParams<'a> {
    acme_host: &'a AcmeHost,
    txt_name: &'a String,
    txt_fqdn: &'a String,
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
            info!("ACME host {} requires renewal, initiating...", ahost.fqdn);
            self.renew_acme(&ahost).await?;
        }
        Ok(())
    }

    fn next_expiring_secs(&self) -> Option<u64> {
        self.acme_hosts.iter()
            // TODO: This currently just skips missing hosts.
            .filter_map(|ah| self.certstore.by_host(&ah.fqdn))
            .map(|hc| hc.expires_in())
            .sorted()
            .next()
            .map(|s| s.max(0) as u64)
    }

    async fn renew_acme(&self, acme_host: &AcmeHost) -> Result<Arc<HostCertificate>> {
        let shortname = acme_host.fqdn
            .strip_suffix(&format!(".{}", acme_host.domain))
            .ok_or(anyhow!("Failed to strip domain from host {}", acme_host.fqdn))?;

        let txt_name = format!("_acme-challenge.{}", shortname);
        let txt_fqdn = format!("{txt_name}.{}", acme_host.domain);

        let params = AcmeParams {
            acme_host: &acme_host,
            txt_name: &txt_name,
            txt_fqdn: &txt_fqdn,
        };


        let certificate_r = self.renew_instant_acme(&params).await;

        // Cleanup before evaluating certificate for errors
        self.cleanup_provisioning(&params).await;

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
        // Either None or expiring with 30 days.
        // TODO: This could use renewal_info() in instant-acme.
            .filter(|ah| ! self.certstore.by_host(&ah.fqdn)
                    .is_some_and(|cert| ! cert.is_expiring_in(EXPIRY_WINDOW)))
            .collect()
    }


    async fn renew_instant_acme(&self, params: &AcmeParams<'_>) -> Result<PemCertificate> {
        info!("Initialising ACME account");
        let account = self.fetch_account(&params).await?;

        info!("Create order for {}", params.acme_host.fqdn);
        let hid = Identifier::Dns(params.acme_host.fqdn.clone());

        let mut order = account.new_order(&NewOrder::new(&[hid])).await?;
        let mut authorisations = order.authorizations();


        while let Some(result) = authorisations.next().await {
            let mut auth = result?;

            info!("Processing {:?}", auth.status);
            match auth.status {
                AuthorizationStatus::Pending => {}
                // It's technically possibly to pick up an old auth order here
                // which returns ::Valid?
                AuthorizationStatus::Valid => {},
                _ => todo!(),
            }

            info!("Creating challenge");
            let mut challenge = auth
                .challenge(ChallengeType::from(&params.acme_host.challenge_type))
                .ok_or_else(|| anyhow!("No {:?} challenge found", params.acme_host.challenge_type))?;

            // As DNS providers generally don't allow concurrent
            // updates to a zone we need to process these series.
            //
            // TODO: We could process the post-provision checks and
            // set_ready() in parallel with futures/join_all.
            self.provision_challenge(&params, &challenge).await?;

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

    async fn fetch_account(&self, params: &AcmeParams<'_>) -> Result<Account> {
        let acme_url = if self.context.config.dev_mode {
            info!("Using staging ACME server");
            LetsEncrypt::Staging.url().to_owned()
        } else {
            LetsEncrypt::Production.url().to_owned()
        };

        let account = if params.acme_host.contactfile.exists() {
            let creds_str = read_to_string(&params.acme_host.contactfile).await?;
            let creds: AccountCredentials = serde_json::from_str(&creds_str)?;
            let account = Account::builder()?
                .from_credentials(creds).await?;
            info!("Loaded account credentials for {}", params.acme_host.contact);

            account

        } else {
            let contact_url = format!("mailto:{}", params.acme_host.contact);

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

            info!("Saving account credentials for {}", params.acme_host.contact);
            let creds_str = serde_json::to_vec(&credentials)?;
            let mut fd = File::create(&params.acme_host.contactfile).await?;
            fd.write_all(&creds_str).await?;

            account
        };
        Ok(account)
    }

    async fn provision_challenge(&self, params: &AcmeParams<'_>, challenge: &ChallengeHandle<'_>) -> Result<()> {
        match &params.acme_host.challenge_type {
            AcmeChallenge::Dns01(provider) => {

                let token = challenge.key_authorization().dns_value();

                info!("Creating TXT: {} -> {}", params.txt_name, token);
                let dns_client = get_dns_client(params, provider);
                dns_client.create_txt_record(params.txt_name, &token).await?;

                wait_for_dns(params.txt_fqdn).await?;
            }
            AcmeChallenge::Http01 => {
                let tokens = ChallengeTokens {
                    token: challenge.token.clone(),
                    key_auth: challenge.key_authorization().as_str().to_string(),
                };

                info!("Storing HTTP-01 challenge: {} -> {:?}", params.acme_host.fqdn, tokens);
                let pin = self.challenges.pin();
                pin.insert(params.acme_host.fqdn.clone(), tokens);

            }
        }
        Ok(())
    }

    async fn cleanup_provisioning(&self, params: &AcmeParams<'_>) {
        match &params.acme_host.challenge_type {
            AcmeChallenge::Dns01(provider) => {
                let dns_client = get_dns_client(params, provider);
                let txt_name = params.txt_name;

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
            AcmeChallenge::Http01 => {
                info!("Removing HTTP-01 challenge: {}", params.acme_host.fqdn);
                let pin = self.challenges.pin();
                let opt = pin.remove(&params.acme_host.fqdn);
                if opt.is_none() {
                    warn!("Challenge for {} not found", params.acme_host.fqdn);
                }

            }
        }
    }

    pub fn challenge_tokens(&self, fqdn: &str) -> Option<ChallengeTokens> {
        let pin = self.challenges.pin();
        pin.get(fqdn).cloned()
    }

}

fn get_dns_client(params: &AcmeParams<'_>, provider: &DnsProvider) -> Box<dyn AsyncDnsProvider> {
    // It's slightly inefficient to create this each time, but it simplifies the code.
    let dns_config = zone_update::Config {
        domain: params.acme_host.domain.clone(),
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
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Err(anyhow!("Failed to find record {txt_fqdn} in public DNS"))
}


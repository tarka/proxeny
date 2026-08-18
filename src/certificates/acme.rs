use std::{fs::create_dir_all, iter, net::SocketAddr, sync::{Arc, RwLock}};

use anyhow::{Context, Result, anyhow, bail};
use camino::Utf8PathBuf;
use dnsclient::{UpstreamServer, r#async::DNSClient};
use futures_lite::{stream, StreamExt};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeHandle, ChallengeType, Identifier,
    LetsEncrypt, NewOrder, OrderStatus, RetryPolicy,
};
use itertools::Itertools;
use metrics::{counter, gauge};
use phf_macros::phf_map;
use tokio::{
    fs::{self, File, read_to_string},
    io::AsyncWriteExt,
};
use time::{Duration, OffsetDateTime, UtcOffset};
use tracing_log::log::{debug, error, info, warn};
use zone_update::{RecordType, async_impl::AsyncDnsProvider};

use crate::{
    RunContext,
    certificates::{HostCertificate, store::CertStore},
    config::{AcmeChallenge, DnsProvider, TlsConfig},
    metrics::{METRIC_ACME_NEXT_RENEWAL_TIMESTAMP_SECS, METRIC_ACME_RENEW_ERROR_TOTAL, METRIC_ACME_RENEW_SUCCESS_TOTAL},
};

const DAYS_TO_SECS: i64 =  24 * 60 * 60;
// TODO: Fuzz range calculated from profile
const FUZZY_RANGE: (i64, i64) = (30, 120);
const ONE_SECOND: Duration = Duration::seconds(1);

#[derive(Debug)]
struct LeProfile {
    name: &'static str,
    _validity_days: i64,
    exp_window_secs: i64,
}

static LE_PROFILES: phf::Map<&'static str, LeProfile> = phf_map! {
    "tlsserver" => LeProfile {
        name: "tlsserver",
        _validity_days: 90, // TODO: Will be reduced to 45 in 2026
        exp_window_secs: 30 * DAYS_TO_SECS,
    },
    "shortlived" => LeProfile {
        name: "shortlived",
        _validity_days: 6,
        exp_window_secs: 4 * DAYS_TO_SECS,
    },
    "classic" => LeProfile {
        name: "classic",
        _validity_days: 90, // TODO: Will be reduced to 64-days in 2027
        exp_window_secs: 30 * DAYS_TO_SECS,
    },
};


#[derive(Debug)]
struct AcmeHost {
    fqdn: String,
    aliases: Vec<String>,
    domain: String,
    contact: String,
    contactfile: Utf8PathBuf,
    keyfile: Utf8PathBuf,
    certfile: Utf8PathBuf,
    challenge: AcmeChallenge,
    profile: &'static LeProfile,
    renewal: RwLock<Renewal>,
}

impl AcmeHost {
    pub fn hostnames(&self) -> Vec<&String> {
        iter::once(&self.fqdn)
            .chain(self.aliases.iter())
            .unique()
            .collect()
    }
}

#[derive(Debug)]
struct Renewal {
    renew_at: OffsetDateTime,
    tries: u64,
}

impl Renewal {
    const BACKOFF: Duration = Duration::hours(1);

    fn new(renew_at: OffsetDateTime) -> Self {
        Self {
            renew_at,
            tries: 0,
        }
    }

    fn is_renewable_in(&self, secs: i64) -> bool {
        let in_secs = self.renewable_in_secs(secs);
        in_secs <= 0
    }

    pub fn renewable_in_secs(&self, secs: i64) -> i64 {
        let now = OffsetDateTime::now_utc();
        let diff = if self.tries > 0 {
            // We've backed-off, so we are already inside the renewal
            // window, just return the backoff-until time.
            self.renew_at - now
        } else {
            self.renew_at - now - Duration::seconds(secs)
        };
        diff.whole_seconds()
    }

    fn backoff(&self) -> Self {
        // We could do a simple exponetial backoff here but a flat
        // backoff is probably fine assuming the errors are due to
        // upstream issues with DNS providers or LetsEncrypt.
        Self {
            renew_at: OffsetDateTime::now_utc() + Self::BACKOFF,
            tries: self.tries + 1,
        }
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
        let acme_hosts = context.config.vhosts.iter()
            .filter_map(|vhost| match &vhost.tls {
                TlsConfig::Files(_) => None, // Handled elsewhere
                TlsConfig::Acme(aconf) => Some((vhost, aconf)),
            })
            .map(|(vhost, aconf)| {
                let domain_psl = psl::domain(vhost.hostname.as_bytes())
                    .ok_or(anyhow!("Failed to find base domain for {}", vhost.hostname))?;
                let domain = String::from_utf8(domain_psl.as_bytes().to_vec())?;
                let is_wildcard = matches!(aconf.challenge, AcmeChallenge::Dns01(DnsProvider {wildcard: true, dns_provider: _}));

                let (cert_hostname, cert_fname) = if is_wildcard {
                    let wildcard_domain = if vhost.hostname == domain {
                        &domain
                    } else {
                        vhost.hostname.split_once('.')
                            .map(|(_host, domain)| domain)
                            .ok_or(anyhow!("Invalid host for wildcard certificate: {}", vhost.hostname))?
                    };
                    (format!("*.{wildcard_domain}"), format!("_.{wildcard_domain}"))
                } else {
                    (vhost.hostname.clone(), vhost.hostname.clone())
                };


                let cert_base = Utf8PathBuf::from(&aconf.directory);
                let cert_dir = cert_base
                    .join(&cert_fname);
                info!("Creating ACME certificate dir {cert_base}");
                create_dir_all(&cert_dir)
                    .context(format!("Error creating directory {cert_base}"))?;

                let cert_file = cert_dir
                    .join(&cert_fname);
                let keyfile = cert_file.with_added_extension("key");
                let certfile = cert_file.with_added_extension("crt");

                let contact = aconf.contact.clone();
                let contact_dir = cert_base
                    .join(&contact);
                create_dir_all(&contact_dir)
                    .context(format!("Error creating directory {contact_dir}"))?;

                let contactfile = contact_dir
                    .join(&contact)
                    .with_added_extension("conf");

                let profile = LE_PROFILES.get(aconf.profile.into())
                        .ok_or(anyhow!("No supported profile {:?}", aconf.profile))?;

                let renewal = RwLock::new(Renewal::new(OffsetDateTime::UNIX_EPOCH));

                let acme_host = AcmeHost {
                    fqdn: cert_hostname,
                    aliases: vhost.aliases.clone(),
                    domain,
                    keyfile,
                    certfile,
                    contact,
                    contactfile,
                    challenge: aconf.challenge.clone(),
                    profile,
                    renewal,
                };
                Ok(acme_host)
            })
            // Filter out duplicate wildcard hosts
            .unique_by(|ahost| ahost.as_ref().ok()
                       .map(|ahost| ahost.fqdn.clone()))
            .collect::<Result<Vec<AcmeHost>>>()?;

        Ok(Self {
            context,
            certstore,
            acme_hosts,
            challenges: papaya::HashMap::new(),
        })
    }

    pub async fn run(&self) -> Result<()> {
        if self.acme_hosts.is_empty() {
            info!("No ACME hosts configured, not starting ACME runtime.");
            return Ok(())
        }

        info!("Starting ACME runtime");
        let existing = stream::iter(self.acme_hosts.iter())
            .filter(|ah| ah.keyfile.exists() && ah.certfile.exists())
            .then(|ah| async move {
                info!("Loading certs from {}, {}", ah.keyfile, ah.certfile);
                let hc = HostCertificate::new(ah.keyfile.clone(), ah.certfile.clone(), false).await?;

                {
                    let mut renewal = ah.renewal.write()
                        .map_err(|e| anyhow!("Failed to lock renewal struct: {e}"))?;
                    *renewal = Renewal::new(*hc.expires());
                }

                Ok(hc)
            })
            .collect::<Vec<Result<HostCertificate>>>().await
            .into_iter().collect::<Result<Vec<HostCertificate>>>()?;

        // Initial load of existing certs. NOTE: This is slightly hacky
        // as we're possibly loading expired certs only to immediately
        // replace them, but it simplifies pending() etc.
        self.certstore.upsert_all(existing)?;

        self.renew_all_pending().await?;

        let mut quit_rx = self.context.quit_rx.clone();
        loop {
            let next_secs = self.next_renewable_secs()?
                .ok_or(anyhow!("Nothing expiring; this shouldn't really happen. Exiting."))?;

            let fuzzy = fastrand::i64(FUZZY_RANGE.0..FUZZY_RANGE.1);
            let expiring_secs = next_secs + Duration::seconds(fuzzy);
            let local_offset = UtcOffset::current_local_offset()
                .unwrap_or(UtcOffset::UTC);
            let expiring_abs = OffsetDateTime::now_utc() + expiring_secs;
            gauge!(METRIC_ACME_NEXT_RENEWAL_TIMESTAMP_SECS)
                .set(expiring_abs.unix_timestamp() as f64);

            info!("Wait for next expiry at {}", expiring_abs.to_offset(local_offset));
            tokio::select! {
                _ = tokio::time::sleep(expiring_secs.try_into()?) => {
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
        for ahost in self.pending()? {
            info!("ACME host {} requires renewal, initiating...", ahost.fqdn);

            match self.renew_acme(ahost).await {
                Ok(hc) => {
                    let mut lock = ahost.renewal.write()
                        .map_err(|e| anyhow!("Failed to lock renewal for {}: {e}", ahost.fqdn))?;
                    *lock = Renewal::new(*hc.expires());
                },
                // TODO: Differentiate network vs local errors?
                Err(e) => {
                    let mut renew = ahost.renewal.write()
                        .map_err(|le| anyhow!("Failed to lock renewal for {}: {le}", ahost.fqdn))?;
                    let backoff = renew.backoff();
                    warn!("Failed to renew {} due to {e} (attempt {}), retrying later", ahost.fqdn, backoff.tries);
                    *renew = backoff;
                }
            }

        }
        Ok(())
    }

    /// Returns certs that need creating or refreshing
    fn pending(&self) -> Result<Vec<&AcmeHost>> {
      self.acme_hosts.iter()
            .map(|ah| {
                let renew = ah.renewal.read()
                    .map_err(|e| anyhow!("Failed to lock renewal info for {}: {e}", ah.fqdn))?;
                Ok((ah, renew.is_renewable_in(ah.profile.exp_window_secs)))
          })
          .filter_ok(|(_, is_due)| *is_due)
          .map_ok(|(ah, _)| ah)
          .collect()
    }

    fn next_renewable_secs(&self) -> Result<Option<Duration>> {
        let next = self.acme_hosts.iter()
            .map(|ah| {
                let renew = ah.renewal.read()
                    .map_err(|e| anyhow!("Failed to read renewal: {e}"))?;
                let exp_in = renew.renewable_in_secs(ah.profile.exp_window_secs);
                Ok::<i64, anyhow::Error>(exp_in.max(0))
            })
            .process_results(|iter| iter.sorted())?
            .next()
            .map(Duration::seconds);
        Ok(next)
    }

    async fn renew_acme(&self, acme_host: &AcmeHost) -> Result<HostCertificate> {

        let certificate_r = self.renew_instant_acme(acme_host).await;

        // Cleanup before evaluating certificate for errors
        self.cleanup_provisioning(acme_host).await;

        let pem_certificate = match certificate_r {
            Ok(cert) => cert,
            Err(err) => {
                counter!(METRIC_ACME_RENEW_ERROR_TOTAL).increment(1);
                error!("Error renewing certificate: {err}");
                return Err(err)
            }
        };
        counter!(METRIC_ACME_RENEW_SUCCESS_TOTAL).increment(1);

        debug!("====== Cert Chain ======\n{}", pem_certificate.cert_chain);

        info!("Writing certificate and key");
        fs::write(&acme_host.keyfile, pem_certificate.private_key.as_bytes()).await
            .context("Failed to write keyfile {keyfile}")?;
        fs::write(&acme_host.certfile, pem_certificate.cert_chain.as_bytes()).await
            .context("Failed to write certfile {certfile}")?;

        info!("Loading new certificate");
        let hc = HostCertificate::new(acme_host.keyfile.clone(), acme_host.certfile.clone(), false).await?;
        self.certstore.upsert(hc.clone())?;

        Ok(hc)
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
            .profile(acme_host.profile.name);
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
                _ => bail!("Failed to renew {} due to unexpected upstream status {:?}", acme_host.fqdn, auth.status),
            }

            info!("Creating challenge");
            let mut challenge = auth
                .challenge(ChallengeType::from(&acme_host.challenge))
                .ok_or_else(|| anyhow!("No {:?} challenge found", acme_host.challenge))?;

            // As DNS providers generally don't allow concurrent
            // updates to a zone we need to process these series.
            //
            // TODO: We could process the post-provision checks and
            // set_ready() in parallel with futures/join_all.
            self.provision_challenge(acme_host, &challenge).await?;

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
        match &acme_host.challenge {
            AcmeChallenge::Dns01(provider) => {

                let fqdn = challenge.identifier().to_string();
                let txt_name = to_txt_name(&acme_host.domain, &fqdn);
                let txt_fqdn = format!("{txt_name}.{}", acme_host.domain);
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
        match &acme_host.challenge {
            AcmeChallenge::Dns01(provider) => {
                for hostname in acme_host.hostnames() {
                    let txt_name = to_txt_name(&acme_host.domain, hostname);

                    info!("Attempting cleanup of {txt_name} record");
                    // FIXME: Doesn't handle multiple records currently. We need to
                    // add this to zone-update.
                    let dns_client = get_dns_client(acme_host, provider);
                    match dns_client.delete_all_records(RecordType::TXT, &txt_name).await {
                        Ok(_) => (),
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


}

fn get_dns_client(acme_host: &AcmeHost, provider: &DnsProvider) -> Box<dyn AsyncDnsProvider> {
    // It's slightly inefficient to create this each time, but it simplifies the code.
    let dns_config = zone_update::Config {
        domain: acme_host.domain.clone(),
        dry_run: false,
    };
    provider.dns_provider.async_impl(dns_config)
}

pub(crate) fn to_txt_name(domain: &str, fqdn: &str) -> String {
    let fqdn = fqdn.strip_prefix("*.")
        .unwrap_or(fqdn);

    if let Some(stripped) = fqdn.strip_suffix(&format!(".{domain}"))
        && !stripped.is_empty()
    {
        format!("_acme-challenge.{}", stripped)
    } else {
        "_acme-challenge".to_string()
    }
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
        let txts = lookup.query_txt(txt_fqdn).await?;
        if ! txts.is_empty() {
            info!("Found {txt_fqdn}");
            return Ok(());
        }
        tokio::time::sleep(ONE_SECOND.try_into()?).await;
    }

    Err(anyhow!("Failed to find record {txt_fqdn} in public DNS"))
}

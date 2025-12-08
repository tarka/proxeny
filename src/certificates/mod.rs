pub mod acme;
pub mod external;
pub mod handler;
#[cfg(test)]
mod tests;
pub mod store;
pub mod watcher;

use std::{fs, hash::{Hash, Hasher}, sync::Arc};

use anyhow::{anyhow, bail, Result};
use boring::asn1::{Asn1Time, Asn1TimeRef};
//use boring::asn1::{Asn1Time, Asn1TimeRef};
use camino::{Utf8Path, Utf8PathBuf};
use chrono::{DateTime, Duration, Utc};

use futures::future::try_join_all;
use pingora_core::{ErrorType, OkOrErr};
use pingora_boringssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use tracing_log::log::info;

use crate::{certificates::{acme::AcmeRuntime, store::CertStore, watcher::CertWatcher}, errors::ProxenyError, RunContext};

#[derive(Debug)]
pub struct HostCertificate {
    host: String,
    keyfile: Utf8PathBuf,
    key: PKey<Private>,
    certfile: Utf8PathBuf,
    certs: Vec<X509>,
    expires: DateTime<Utc>,
    watch: bool,
}

impl HostCertificate {

    /// Load and check a public/private keypair & certs. Checks are
    /// performed, and Error::CertificateMismatch may be returned; as
    /// this may be expected (e.g. while certs are being updated) it
    /// should be checked for if necessary.
    pub fn new(keyfile: Utf8PathBuf, certfile: Utf8PathBuf, watch: bool) -> Result<Self> {
        let (key, certs) = load_certs(&keyfile, &certfile)?;

        let host = cn_host(certs[0].subject_name().print_ex(0)
                         .or_err(ErrorType::InvalidCert, "No host/CN in certificate")?)?;
        info!("Certificate found: {:?}, expires {}", certs[0].subject_name(), certs[0].not_after());

        let not_after = certs[0].not_after();
        let expires = asn1time_to_datetime(not_after)?;

        Ok(HostCertificate {
            host,
            keyfile,
            key,
            certfile,
            certs,
            expires,
            watch,
        })
    }

    /// Generates a fresh certificate from an existing one. This is
    /// effectively a reload.
    pub fn from(hc: &Arc<HostCertificate>) -> Result<HostCertificate> {
        HostCertificate::new(hc.keyfile.clone(), hc.certfile.clone(), hc.watch)
    }


    pub fn expires(&self) -> &DateTime<Utc> {
        &self.expires
    }

    pub fn is_expiring_in(&self, days: i64) -> bool {
        let in_days = Utc::now() + Duration::days(days);
        in_days >= self.expires
    }
}

fn asn1time_to_datetime(not_after: &Asn1TimeRef) -> Result<DateTime<Utc>> {
    let epoch = Asn1Time::from_unix(0)?;
    let time_diff = not_after.diff(&epoch)?; // Returns -(expected_value)

    // Calculate total seconds and convert to positive
    let total_seconds = -((time_diff.days as i64 * 86400) + time_diff.secs as i64);

    let datetime = DateTime::<Utc>::from_timestamp(total_seconds as i64, 0)
        .ok_or(anyhow!("Failed to create DateTime from timestamp"))?;

    Ok(datetime)
}

impl PartialEq<HostCertificate> for HostCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.host == other.host
    }

    fn ne(&self, other: &Self) -> bool {
        self.host != other.host
    }
}

impl Eq for HostCertificate {
}

impl Hash for HostCertificate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.host.hash(state)
    }
}

fn cn_host(cn: String) -> Result<String> {
    let host = cn.split(',')
        .find_map(|s| s.trim().strip_prefix("CN="))
        .or_err(ErrorType::InvalidCert, "Failed to find host in cert 'CN=...'")?
        .trim();
    Ok(host.to_string())
}

fn load_certs(keyfile: &Utf8Path, certfile: &Utf8Path) -> Result<(PKey<Private>, Vec<X509>)> {
    let kdata = fs::read(keyfile)?;
    let cdata = fs::read(certfile)?;

    let key = PKey::private_key_from_pem(&kdata)?;
    let certs = X509::stack_from_pem(&cdata)?;
    if certs.is_empty() {
        bail!("No certificates found in TLS .crt file");
    }

    // Verify that the private key and cert match
    let cert_pubkey = certs[0].public_key()?;
    if !key.public_eq(&cert_pubkey) {
        let err = ProxenyError::CertificateMismatch(
            keyfile.to_path_buf(),
            certfile.to_path_buf())
            .into();
        return Err(err)
    }

    Ok((key, certs))
}


pub async fn run_indefinitely(certstore: Arc<CertStore>, context: Arc<RunContext>) -> Result<()> {

    let acme = AcmeRuntime::new(certstore.clone(), context.clone())?;
    let acme_handle = tokio::spawn(async move {
        acme.run().await
    });

    let mut certwatcher = CertWatcher::new(certstore.clone(), context.clone());
    let watcher_handle = tokio::spawn(async move {
        certwatcher.watch().await
    });

    try_join_all(vec![acme_handle, watcher_handle]).await?;

    Ok(())
}


pub mod acme;
pub mod external;
pub mod handler;
pub mod store;
pub mod watcher;

use std::{fs, hash::{Hash, Hasher}, sync::Arc};

use anyhow::{bail, Result};
use camino::{Utf8Path, Utf8PathBuf};
use pingora_core::{ErrorType, OkOrErr};
use pingora_boringssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use tracing_log::log::info;

#[derive(Debug)]
pub struct HostCertificate {
    host: String,
    keyfile: Utf8PathBuf,
    key: PKey<Private>,
    certfile: Utf8PathBuf,
    certs: Vec<X509>,
    watch: bool,
}

impl HostCertificate {
    pub fn new(keyfile: Utf8PathBuf, certfile: Utf8PathBuf, watch: bool) -> Result<Self> {
        let (key, certs) = load_certs(&keyfile, &certfile)?;

        let host = cn_host(certs[0].subject_name().print_ex(0)
                         .or_err(ErrorType::InvalidCert, "No host/CN in certificate")?)?;
        info!("Certificate found: {:?}, expires {}", certs[0].subject_name(), certs[0].not_after());

        Ok(HostCertificate {
            host,
            keyfile,
            key,
            certfile,
            certs,
            watch,
        })
    }

    pub fn from(hc: &Arc<HostCertificate>) -> Result<HostCertificate> {
        HostCertificate::new(hc.keyfile.clone(), hc.certfile.clone(), hc.watch)
    }

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
    let host = cn.split('=')
        .nth(1)
        .or_err(ErrorType ::InvalidCert, "Failed to find host in cert 'CN=...'")?;
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

    // Verify that the private key matches the first certificate
    let cert_pubkey = certs[0].public_key()?;
    if !key.public_eq(&cert_pubkey) {
        bail!("Private key does not match the certificate");
    }

    Ok((key, certs))
}




pub trait CertificateProvider {
    fn read_certs(&self) -> Result<Vec<Arc<HostCertificate>>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_certs_valid_pair() -> Result<()> {
        let key_path = Utf8Path::new("tests/data/certs/snakeoil.key");
        let cert_path = Utf8Path::new("tests/data/certs/snakeoil.crt");

        let result = load_certs(key_path, cert_path);
        assert!(result.is_ok());

        let (key, certs) = result.unwrap();
        assert!(!certs.is_empty());

        let cert_pubkey = certs[0].public_key()?;
        assert!(key.public_eq(&cert_pubkey));

        Ok(())
    }

    #[test]
    fn test_load_certs_invalid_pair() -> Result<()> {
        let key_path = Utf8Path::new("tests/data/certs/snakeoil.key");
        let other_cert_path = Utf8Path::new("tests/data/certs/snakeoil-2.pem");

        let result = load_certs(key_path, other_cert_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Private key does not match the certificate"));

        Ok(())
    }

    #[test]
    fn test_load_certs_nonexistent_files() {
        let key_path = Utf8Path::new("nonexistent.key");
        let cert_path = Utf8Path::new("nonexistent.crt");

        let result = load_certs(key_path, cert_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_certs_empty_cert_file() -> Result<()> {
        let mut empty_cert_file = NamedTempFile::new()?;
        empty_cert_file.write_all(b"")?;
        let empty_cert_path = Utf8PathBuf::from(empty_cert_file.path().to_str().unwrap());

        let key_path = Utf8Path::new("tests/data/certs/snakeoil.key");

        let result = load_certs(&key_path, &empty_cert_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No certificates found in TLS .crt file"));

        Ok(())
    }
}

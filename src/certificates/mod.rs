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

use crate::errors::ProxenyError;

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

    /// Load and check a public/private keypair & certs. Checks are
    /// performed, and Error::CertificateMismatch may be returned; as
    /// this may be expected (e.g. while certs are being updated) it
    /// should be checked for if necessary.
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

    /// Generates a fresh certificate from an existing one. This is
    /// effectively a reload.
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


pub trait CertificateProvider {
    fn read_certs(&self) -> Vec<Arc<HostCertificate>>;
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Common test utils
    pub fn test_cert(key: &str, cert: &str, watch: bool) -> HostCertificate {
        let keyfile = Utf8PathBuf::from(key);
        let certfile = Utf8PathBuf::from(cert);
        HostCertificate::new(keyfile, certfile, watch)
            .expect("Failed to create test HostCertificate")
    }

    #[derive(Clone)]
    pub struct TestProvider {
        pub cert: Arc<HostCertificate>
    }
    impl TestProvider {
        pub fn new(key: &str, cert: &str, watch: bool) -> Self {
            let cert = test_cert(key, cert, watch);
            Self { cert: Arc::new(cert) }
        }
    }
    impl CertificateProvider for TestProvider {
        fn read_certs(&self) -> Vec<Arc<HostCertificate>> {
            vec![self.cert.clone()]
        }
    }


    #[test]
    fn test_cn_host_valid_cn() -> Result<()> {
        let cn_string = "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=proxeny.example.com".to_string();
        let host = cn_host(cn_string)?;
        assert_eq!(host, "proxeny.example.com");
        Ok(())
    }

    #[test]
    fn test_cn_host_no_cn() {
        let cn_string = "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd".to_string();
        let result = cn_host(cn_string);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to find host in cert 'CN=...'"));
    }

    #[test]
    fn test_cn_host_multiple_equals_in_cn() -> Result<()> {
        let cn_string = "C=US, O=Example Inc., CN=my.host=name.com".to_string();
        let host = cn_host(cn_string)?;
        assert_eq!(host, "my.host=name.com");
        Ok(())
    }

    #[test]
    fn test_cn_host_cn_with_spaces() -> Result<()> {
        let cn_string = "C=US, CN=  another.example.com  ".to_string();
        let host = cn_host(cn_string)?;
        // strip_prefix also trims, so the result should be trimmed
        assert_eq!(host, "another.example.com");
        Ok(())
    }

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
        let err: ProxenyError = result.unwrap_err().downcast()?;
        assert!(matches!(err, ProxenyError::CertificateMismatch(_, _)));

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

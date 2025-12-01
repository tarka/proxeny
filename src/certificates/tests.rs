
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

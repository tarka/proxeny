use crate::{certificates::{store::CertStore, watcher::{CertWatcher, RELOAD_GRACE}}, config::Config, RunContext};

use super::*;
use std::{io::Write, time::Duration};
use tempfile::{tempdir, NamedTempFile};

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


#[tokio::test]
async fn test_cert_watcher_file_updates() -> Result<()> {
    let temp_dir = tempdir()?;
    let key_path = temp_dir.path().join("test.key");
    let cert_path = temp_dir.path().join("test.crt");

    let context = Arc::new(RunContext::new(crate::config::Config::empty()));

    fs::copy("tests/data/certs/snakeoil.key", &key_path)?;
    fs::copy("tests/data/certs/snakeoil.crt", &cert_path)?;

    let provider = TestProvider::new(
        key_path.to_str().unwrap(),
        cert_path.to_str().unwrap(),
        true,
    );
    let store = Arc::new(CertStore::new(provider.read_certs(), context.clone())?);
    let original_host = provider.cert.host.clone();

    let original_cert = store.by_host(&original_host).unwrap();
    let original_expiry = original_cert.certs[0].not_after().to_string();

    let mut watcher = CertWatcher::new(store.clone(), context.clone());

    // Start the watcher in a separate task
    let watcher_handle = tokio::spawn(async move {
        watcher.watch().await
    });

    // Wait for the watcher to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Update the files
    info!("Updating cert files");
    fs::copy("tests/data/certs/snakeoil-2.key", &key_path)?;
    fs::copy("tests/data/certs/snakeoil-2.pem", &cert_path)?;

    // Wait for the watcher to process the event
    tokio::time::sleep(RELOAD_GRACE + Duration::from_millis(500)).await;

    info!("Checking updated certs");
    let updated_cert = store.by_host(&original_host).unwrap();
    let updated_expiry = updated_cert.certs[0].not_after().to_string();

    assert_ne!(original_expiry, updated_expiry);

    // Stop the watcher
    context.quit()?;
    watcher_handle.await??;

    Ok(())
}


#[test]
fn test_cert_store_new() {
    let provider = TestProvider::new(
        "tests/data/certs/snakeoil.key",
        "tests/data/certs/snakeoil.crt",
        false
    );
    let context = Arc::new(RunContext::new(Config::empty()));
    let store = CertStore::new(provider.read_certs(), context).unwrap();

    assert!(store.by_host(&provider.cert.host).is_some());
    assert!(store.by_file(&"tests/data/certs/snakeoil.key".into()).is_some());
    assert!(store.by_file(&"tests/data/certs/snakeoil.crt".into()).is_some());
}

#[test]
fn test_by_host() {
    let provider = TestProvider::new(
        "tests/data/certs/snakeoil.key",
        "tests/data/certs/snakeoil.crt",
        false
    );
    let context = Arc::new(RunContext::new(Config::empty()));
    let store = CertStore::new(provider.read_certs(), context).unwrap();
    let found = store.by_host(&provider.cert.host).unwrap();

    assert_eq!(found.host, provider.cert.host);
}

#[test]
fn test_by_file() {
    let provider = TestProvider::new(
        "tests/data/certs/snakeoil.key",
        "tests/data/certs/snakeoil.crt",
        false
    );
    let context = Arc::new(RunContext::new(Config::empty()));
    let store = CertStore::new(provider.read_certs(), context).unwrap();
    let found = store.by_file(&"tests/data/certs/snakeoil.key".into()).unwrap();

    assert_eq!(found.host, provider.cert.host);
}

#[test]
fn test_watchlist() -> Result<()> {
    let hc1 = Arc::new(HostCertificate::new(
        "tests/data/certs/snakeoil.key".into(),
        "tests/data/certs/snakeoil.crt".into(),
        true
    )?);
    let hc2 = Arc::new(HostCertificate::new(
        "tests/data/certs/snakeoil-2.key".into(),
        "tests/data/certs/snakeoil-2.pem".into(),
        false
    )?);

    let context = Arc::new(RunContext::new(Config::empty()));
    let certs = vec![hc1, hc2];
    let store = CertStore::new(certs, context).unwrap();
    let watchlist = store.watchlist();

    assert_eq!(watchlist.len(), 2);
    assert!(watchlist.contains(&Utf8PathBuf::from("tests/data/certs/snakeoil.key")));
    assert!(watchlist.contains(&Utf8PathBuf::from("tests/data/certs/snakeoil.crt")));
    Ok(())
}

#[test]
fn test_file_update_success() -> Result<()> {
    let temp_dir = tempdir()?;
    let key_path = temp_dir.path().join("test.key");
    let cert_path = temp_dir.path().join("test.crt");
    fs::copy("tests/data/certs/snakeoil.key", &key_path)?;
    fs::copy("tests/data/certs/snakeoil.crt", &cert_path)?;

    let provider = TestProvider::new(
        key_path.to_str().unwrap(),
        cert_path.to_str().unwrap(),
        true
    );
    let context = Arc::new(RunContext::new(Config::empty()));
    let store = CertStore::new(provider.read_certs(), context)?;
    let original_host = provider.cert.host.clone();

    // The original cert is snakeoil
    let first_cert = store.by_host(&original_host).unwrap();
    assert!(first_cert.certs[0].subject_name().print_ex(0).unwrap().contains("proxeny.example.com"));

    // Now update the files to snakeoil-2
    fs::copy("tests/data/certs/snakeoil-2.key", &key_path)?;
    fs::copy("tests/data/certs/snakeoil-2.pem", &cert_path)?;
    let newcert = Arc::new(HostCertificate::from(&first_cert)?);

    store.update(newcert)?;

    let updated_cert_from_file = test_cert(
        key_path.to_str().unwrap(),
        cert_path.to_str().unwrap(),
        true
    );
    let new_host = updated_cert_from_file.host;

    // The store should have updated the certificate.
    let updated_cert_from_store = store.by_host(&new_host).expect("Cert not found for new host");
    assert_eq!(updated_cert_from_store.host, new_host);

    // The old entry should not exist anymore if the host has changed.
    if original_host != new_host {
        assert!(store.by_host(&original_host).is_none(), "Old host entry should be removed");
    }

    Ok(())
}

#[test]
fn sanity_check_pending_filter() {
    // Simplified test of acme->pending() logic
    struct Cert {
        exp: Option<bool>,
        name: &'static str,
    }
    let hosts = vec![
        Cert{exp: Some(false), name: "ok" },
        Cert{exp: None, name: "new" },
        Cert{exp: Some(false), name: "ok" },
        Cert{exp: Some(true), name: "expiring" },
    ];

    let pending = hosts.iter()
    // Either None or expiring with 30 days
        .filter(|cert| ! cert.exp
                .is_some_and(|v| ! v))
        .collect::<Vec<&Cert>>();

    assert_eq!(2, pending.len());
    assert_eq!("new", pending[0].name);
    assert_eq!("expiring", pending[1].name);
}

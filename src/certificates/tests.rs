use crate::{
    RunContext,
    certificates::{
        store::CertStore,
        watcher::{CertWatcher, RELOAD_GRACE},
    },
    config::Config,
};

use super::*;
use std::{
    fs::create_dir_all,
    io::Write,
    process::Command,
    sync::LazyLock, time::Duration,
};

use anyhow::Result;
use boring::asn1::Asn1Time;
use chrono::{Days, NaiveDate, TimeZone};
use tempfile::{NamedTempFile, tempdir};

// Common test utils
fn test_cert(key: &str, cert: &str, watch: bool) -> HostCertificate {
    let keyfile = Utf8PathBuf::from(key);
    let certfile = Utf8PathBuf::from(cert);
    HostCertificate::new(keyfile, certfile, watch)
        .expect("Failed to create test HostCertificate")
}

const CERT_BASE: &'static str = "target/certs";

struct TestCerts {
    pub vicarian_ss1: Arc<HostCertificate>,
    pub vicarian_ss2: Arc<HostCertificate>,
    pub www_ss: Arc<HostCertificate>,
}

impl TestCerts {
    fn new() -> Result<Self> {
        create_dir_all(CERT_BASE)?;

        let not_before = Utc::now().date_naive();
        let not_after = not_before.clone().checked_add_days(Days::new(365)).unwrap();

        let host = "vicarian.example.com";
        let name = "snakeoil-1";

        let vicarian_ss1 = gen_cert(host, name, true, not_before, not_after)?;

        let name = "snakeoil-2";
        let not_after = not_before.clone().checked_add_days(Days::new(720)).unwrap();
        let vicarian_ss2 = gen_cert(host, name, true, not_before, not_after)?;

        let name = "www.example.com";
        let www_ss = gen_cert(name, name, false, not_before, not_after)?;

        Ok(Self {
            vicarian_ss1,
            vicarian_ss2,
            www_ss,
        })
    }
}

fn gen_cert(host: &str,
            name: &str,
            watch: bool,
            not_before: NaiveDate,
            not_after: NaiveDate)
            -> Result<Arc<HostCertificate>>
{
    let base = Utf8PathBuf::try_from(CERT_BASE)?;
    let keyfile = base.join(name).with_extension("key");
    let certfile = base.join(name).with_extension("crt");

    if ! (keyfile.exists() && certfile.exists()) {

        let out = Command::new("openssl")
            .arg("req")
            .arg("-x509")
            .arg("-noenc")
            .arg("-not_before").arg(not_before.format("%Y%m%d000000Z").to_string())
            .arg("-not_after").arg(not_after.format("%Y%m%d000000Z").to_string())
            .arg("-out").arg(&certfile)
            .arg("-keyout").arg(&keyfile)
            .arg("-subj").arg(format!("/CN={host}"))
            .output()?;
        info!("OPENSSL: {out:#?}");
    }

    let host_certificate = HostCertificate::new(keyfile, certfile, watch)?;

    Ok(Arc::new(host_certificate))
}

static TEST_CERTS: LazyLock<TestCerts> = LazyLock::new(|| TestCerts::new().unwrap());

#[test]
fn test_load_certs_valid_pair() -> Result<()> {
    let so = &TEST_CERTS.vicarian_ss1;
    let result = load_certs(&so.keyfile, &so.certfile);
    assert!(result.is_ok());

    let (key, certs) = result.unwrap();
    assert!(!certs.is_empty());

    let cert_pubkey = certs[0].public_key()?;
    assert!(key.public_eq(&cert_pubkey));

    Ok(())
}

#[test]
fn test_load_certs_invalid_pair() -> Result<()> {
    let so1 = TEST_CERTS.vicarian_ss1.clone();
    let so2 = TEST_CERTS.vicarian_ss2.clone();
    let key_path = &so1.keyfile;
    let other_cert_path = &so2.certfile;

    let result = load_certs(key_path, other_cert_path);
    assert!(result.is_err());
    let err: VicarianError = result.unwrap_err().downcast()?;
    assert!(matches!(err, VicarianError::CertificateMismatch(_, _)));

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

    let so1 = TEST_CERTS.vicarian_ss1.clone();

    let result = load_certs(&so1.keyfile, &empty_cert_path);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("No certificates found in TLS .crt file"));

    Ok(())
}


#[tokio::test]
#[test_log::test]
async fn test_cert_watcher_file_updates() -> Result<()> {
    let temp_dir = tempdir()?;
    let key_path = Utf8PathBuf::from_path_buf(temp_dir.path().join("test.key")).unwrap();
    let cert_path = Utf8PathBuf::from_path_buf(temp_dir.path().join("test.crt")).unwrap();

    let context = Arc::new(RunContext::new(crate::config::Config::empty()));

    let so1 = TEST_CERTS.vicarian_ss1.clone();
    fs::copy(&so1.keyfile, &key_path)?;
    fs::copy(&so1.certfile, &cert_path)?;

    let hc = Arc::new(HostCertificate::new(key_path.clone(), cert_path.clone(), true)?);
    let certs = vec![hc.clone()];
    let store = Arc::new(CertStore::new(certs, context.clone())?);
    let original_host = hc.hostnames[0].clone();

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
    println!("Updating cert files");
    let so2 = TEST_CERTS.vicarian_ss2.clone();
    fs::copy(&so2.keyfile, &key_path)?;
    fs::copy(&so2.certfile, &cert_path)?;

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
fn test_by_host() {
    let cert = TEST_CERTS.vicarian_ss1.clone();
    let certs = vec![cert.clone()];
    let context = Arc::new(RunContext::new(Config::empty()));
    let store = CertStore::new(certs, context).unwrap();
    let found = store.by_host(&cert.hostnames[0]).unwrap();

    assert_eq!(found, cert);
}

#[test]
fn test_by_file() {
    let cert = TEST_CERTS.vicarian_ss1.clone();
    let certs = vec![cert.clone()];
    let context = Arc::new(RunContext::new(Config::empty()));
    let store = CertStore::new(certs, context).unwrap();
    let found = store.by_file(&"target/certs/snakeoil-1.key".into()).unwrap();

    assert_eq!(found, cert);
}

#[test]
fn test_watchlist() -> Result<()> {
    let hc1 = TEST_CERTS.vicarian_ss1.clone();
    let hc2 = TEST_CERTS.www_ss.clone();

    let context = Arc::new(RunContext::new(Config::empty()));
    let certs = vec![hc1, hc2];
    let store = CertStore::new(certs, context)?;
    let watchlist = store.watchlist();

    assert_eq!(watchlist.len(), 2);
    assert!(watchlist.contains(&Utf8PathBuf::from("target/certs/snakeoil-1.key")));
    assert!(watchlist.contains(&Utf8PathBuf::from("target/certs/snakeoil-1.crt")));
    Ok(())
}

#[test]
fn test_file_update_success() -> Result<()> {

    let temp_dir = tempdir()?;
    let key_path = temp_dir.path().join("test.key");
    let cert_path = temp_dir.path().join("test.crt");
    let cert = TEST_CERTS.vicarian_ss1.clone();
    fs::copy(&cert.keyfile, &key_path)?;
    fs::copy(&cert.certfile, &cert_path)?;


    let certs = vec![cert.clone()];
    let context = Arc::new(RunContext::new(Config::empty()));
    let store = CertStore::new(certs, context)?;
    let original_host = cert.hostnames[0].clone();

    // The original cert is snakeoil
    let first_cert = store.by_host(&original_host).unwrap();
    assert!(first_cert.certs[0].subject_name().print_ex(0).unwrap().contains("vicarian.example.com"));

    // Now update the files to snakeoil-2
    let cert = TEST_CERTS.vicarian_ss2.clone();
    fs::copy(&cert.keyfile, &key_path)?;
    fs::copy(&cert.certfile, &cert_path)?;
    let newcert = Arc::new(HostCertificate::from(&first_cert)?);

    store.update(newcert)?;

    let updated_cert_from_file = test_cert(
        key_path.to_str().unwrap(),
        cert_path.to_str().unwrap(),
        true
    );
    let new_host = updated_cert_from_file.hostnames[0].clone();

    // The store should have updated the certificate.
    let updated_cert_from_store = store.by_host(&new_host).expect("Cert not found for new host");
    assert_eq!(updated_cert_from_store.hostnames[0], new_host);

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


#[test]
fn test_asn1time_to_datetime() -> Result<()> {
    let past = DateTime::parse_from_rfc3339("2023-01-01 00:00:00+00:00")? // Jan 1, 2023
        .timestamp();
    let asn1_time = Asn1Time::from_unix(past).expect("Failed to create ASN.1 time");
    let datetime = asn1time_to_datetime(&asn1_time.as_ref()).expect("Failed to convert ASN.1 time");

    let expected = Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).single().expect("Invalid date");
    assert_eq!(datetime, expected);
    Ok(())
}

#[test]
fn test_asn1time_to_datetime_epoch() {
    // Test conversion of ASN.1 time at Unix epoch
    let asn1_time = Asn1Time::from_unix(0).expect("Failed to create ASN.1 time");
    let datetime = asn1time_to_datetime(&asn1_time.as_ref()).expect("Failed to convert ASN.1 time");

    let expected = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).single().expect("Invalid date");
    assert_eq!(datetime, expected);
}

#[test]
fn test_asn1time_to_datetime_future() -> Result<()> {
    let datetime = DateTime::parse_from_rfc3339("2038-01-19 03:14:07+00:00")? // Jan 1, 2023
        .timestamp();
    let asn1_time = Asn1Time::from_unix(datetime).expect("Failed to create ASN.1 time"); // Year 2038
    let datetime = asn1time_to_datetime(&asn1_time.as_ref()).expect("Failed to convert ASN.1 time");

    let expected = Utc.with_ymd_and_hms(2038, 1, 19, 3, 14, 7).single().expect("Invalid date");
    assert_eq!(datetime, expected);

    Ok(())
}

#[test]
fn test_no_subject() {
    let _no_subject = test_cert("tests/data/certs/www.vicarian.no-subject.key",
                               "tests/data/certs/www.vicarian.no-subject.crt",
                               false);
}

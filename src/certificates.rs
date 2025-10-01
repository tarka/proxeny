

use std::sync::Arc;

use anyhow::{bail, Result};
use async_trait::async_trait;
use camino::Utf8PathBuf;
use pingora::{listeners::TlsAccept, protocols::tls::TlsRef, tls::{pkey::{PKey, Private}, ssl::NameType, x509::X509}};
use tracing::info;


const TEST_DIR: &str = "tests/data/certs/acme";

struct HostCertificate {
    key: PKey<Private>,
    certs: Vec<X509>,
}


fn load_cert_files(host: &str) -> Result<HostCertificate> {
    let keyfile = Utf8PathBuf::from(format!("{TEST_DIR}/{host}.key"));
    let certfile = Utf8PathBuf::from(format!("{TEST_DIR}/{host}.crt"));
    let key = std::fs::read(&keyfile)?;
    let cert = std::fs::read(&certfile)?;

    let key = PKey::private_key_from_pem(&key)?;
    let certs = X509::stack_from_pem(&cert)?;
    if certs.is_empty() {
        bail!("No certificates found in TLS .crt file");
    }

    let hostcert = HostCertificate {key, certs,};

    Ok(hostcert)
}


pub struct CertStore {
    certmap: papaya::HashMap<String, HostCertificate>,
}

pub struct CertHandler {
    certstore: Arc<CertStore>,
}

impl CertStore {
    pub fn new(hosts: Vec<&str>) -> Result<Self> {
        info!("Loading host certificates");

        let certmap = hosts.iter()
            .map(|host| {
                let cert = load_cert_files(host)?;
                Ok((host.to_string(), cert))
            })
            .collect::<Result<_>>()?;

        let handler = Self { certmap };

        info!("Loaded {} certificates", handler.certmap.len());

        Ok(handler)
    }
}

impl CertHandler {
    pub fn new(certstore: Arc<CertStore>) -> Self {
        Self {
            certstore
        }
    }
}

#[async_trait]
impl TlsAccept for CertHandler {

    // NOTE:This is all boringssl specific as pingora doesn't
    // currently support dynamic certs with rustls.
    async fn certificate_callback(&self, ssl: &mut TlsRef) -> () {
        let host = ssl.servername(NameType::HOST_NAME)
            .expect("No servername in TLS handshake");

        info!("TLS Host is {host}; loading certs");

        // FIXME: This should be a `get()` in CertStore, but papaya
        // guard lifetimes make it pointless (we'd have to generate a
        // guard here anyway). There may be another way to do it
        // cleanly?
        let pmap = self.certstore.certmap.pin();
        let cert = pmap.get(&host.to_string())
            .expect("Certificate for host not found");

        ssl.set_private_key(&cert.key)
            .expect("Failed to set private key");
        ssl.set_certificate(&cert.certs[0])
            .expect("Failed to set certificate");

        if cert.certs.len() > 1 {
            for c in cert.certs[1..].iter() {
                ssl.add_chain_cert(&c)
                    .expect("Failed to add chain certificate");
            }
        }
    }

}

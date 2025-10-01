

use std::sync::Arc;

use anyhow::{bail, Result};
use async_trait::async_trait;
use pingora::{listeners::TlsAccept, protocols::tls::TlsRef, tls::{pkey::{PKey, Private}, ssl::NameType, x509::X509}};
use tracing::info;


const TEST_DIR: &str = "tests/data/certs/acme";

struct HostCertificate {
    key: PKey<Private>,
    certs: Vec<X509>,
}


fn load_cert_files(host: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let keyfile = std::fs::read(format!("{TEST_DIR}/{host}.key"))?;
    let certfile = std::fs::read(format!("{TEST_DIR}/{host}.crt"))?;

    Ok((keyfile, certfile))
}

fn from_files(keyfile: Vec<u8>, certfile: Vec<u8>) -> Result<HostCertificate> {
    let key = PKey::private_key_from_pem(&keyfile)?;
    let certs = X509::stack_from_pem(&certfile)?;
    if certs.is_empty() {
        bail!("No certificates found in TLS .crt file");
    }

    let hostcert = HostCertificate { key, certs };

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
                let (key, cert) = load_cert_files(host)?;
                let cert = from_files(key, cert)?;
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

async fn do_nothing() -> usize {
    1
}

#[async_trait]
impl TlsAccept for CertHandler {

    // NOTE:This is all boringssl specific as pingora doesn't
    // currently support dynamic certs with rustls.
    async fn certificate_callback(&self, ssl: &mut TlsRef) -> () {
        let host = ssl.servername(NameType::HOST_NAME)
            .expect("No servername in TLS handshake");

        info!("TLS Host is {host}; loading certs");

        // let amap = self.certstore.certmap.pin_owned();
        // let cert = amap.get(&host.to_string())
        //     .expect("Certificate for host not found");
        let amap = self.certstore.certmap.pin();
//        do_nothing().await;
        let cert = amap.get(&host.to_string())
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

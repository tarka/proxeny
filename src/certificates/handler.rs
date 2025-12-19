use std::sync::Arc;

use async_trait::async_trait;
use pingora_boringssl::ssl::NameType;
use pingora_core::{listeners::TlsAccept, protocols::tls::TlsRef};
use tracing_log::log::debug;

use crate::certificates::store::CertStore;


pub struct CertHandler {
    certstore: Arc<CertStore>,
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

        debug!("TLS Host is {host}; loading certs");

        let cert = self.certstore.by_host(&host.to_string())
            .expect("Certificate for host not found");
        debug!("Found certificate for {host}");

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

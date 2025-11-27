use std::sync::Arc;

use anyhow::Result;
use camino::Utf8PathBuf;

use crate::{certificates::{CertificateProvider, HostCertificate}, config::{AcmeChallenge, Config, TlsAcmeConfig, TlsConfigType}};

const CERT_BASE_DEFAULT: &str = "/var/lib/proxeny/acme";

struct AcmeHost {
    host: String,
    contact: String,
    keyfile: Utf8PathBuf,
    certfile: Utf8PathBuf,
    // pub acme_provider: AcmeProvider,
    //    challenge_type: AcmeChallenge,
    cert: Option<Arc<HostCertificate>>,
}

pub struct AcmeProvider {
    config: Arc<Config>,
    hosts: Vec<AcmeHost>,
}



impl AcmeProvider {

    pub fn new(config: Arc<Config>) -> Result<Self> {
        // FIXME: Should come from config eventually
        let cert_base = Utf8PathBuf::from(CERT_BASE_DEFAULT);

        let acme_hosts = config.servers().iter()
            .filter_map(|s| match &s.tls.config {
                TlsConfigType::Files(_) => None,
                TlsConfigType::Acme(aconf) => {
                    // Default;
                    // keyfile  -> /var/lib/proxeny/acme/www.example.com/www.example.com.key
                    // certfile -> /var/lib/proxeny/acme/www.example.com/www.example.com.crt
                    let host = config.hostname.clone();
                    let cert_file = cert_base
                        .join(&host)
                        .join(&host);
                    let keyfile = cert_file.with_extension(".key");
                    let certfile = cert_file.with_extension(".crt");

                    let acme_host = AcmeHost {
                        cert: None, // Placeholder for loading
                        host,
                        keyfile,
                        certfile,
                        contact: aconf.contact.clone(),
                    };
                    Some(acme_host)
                }
            })
            .collect();

        let zelf = Self {
            config,
            hosts: acme_hosts,
        };

        Ok(zelf)
    }

}

impl CertificateProvider for AcmeProvider {
    fn read_certs(&self) -> Vec<Arc<HostCertificate>> {
        self.hosts.iter()
            .filter_map(|h| h.cert.clone())
            .collect()
    }
}

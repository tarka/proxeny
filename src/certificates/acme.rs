use std::sync::Arc;

use anyhow::Result;
use camino::Utf8PathBuf;

use crate::config::{AcmeChallenge, Config, TlsAcmeConfig};

// FIXME: Move to config
const CERT_BASE_DEFAULT: &str = "/var/lib/proxeny/acme";

struct AcmeHost {
    // pub acme_provider: AcmeProvider,
//    challenge_type: AcmeChallenge,
    contact: String,
    keyfile: Utf8PathBuf,
    certfile: Utf8PathBuf,
    host: String,

}

pub struct Acme {
    config: Arc<Config>,
    hosts: Vec<AcmeHost>,
}



impl Acme {
    pub fn new(config: Arc<Config>, acme_conf: &TlsAcmeConfig) -> Result<Self> {
        // FIXME: Should come from config eventually?
        let cert_base = Utf8PathBuf::from(CERT_BASE_DEFAULT);

        // Default;
        // keyfile  -> /var/lib/proxeny/acme/www.example.com/www.example.com.key
        // certfile -> /var/lib/proxeny/acme/www.example.com/www.example.com.crt
        let host = config.hostname.clone();
        let cert_file = cert_base
            .join(&host)
            .join(&host);
        let keyfile = cert_file.with_extension(".key");
        let certfile = cert_file.with_extension(".crt");

        let host = AcmeHost {
            host,
            keyfile,
            certfile,
            contact: acme_conf.contact.clone(),
//            challenge_type: acme_conf.challenge_type,
        };
        Ok(Acme {
            config,
            hosts: vec![host],
        })
    }
}

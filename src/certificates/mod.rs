
pub mod handler;
pub mod store;
pub mod watcher;

use anyhow::Result;
use camino::Utf8PathBuf;
use pingora_boringssl::{pkey::{PKey, Private}, x509::X509};

use crate::certificates::store::load_certs;

#[derive(Debug)]
pub struct HostCertificate {
    host: String,
    keyfile: Utf8PathBuf,
    key: PKey<Private>,
    certfile: Utf8PathBuf,
    certs: Vec<X509>,
}

impl HostCertificate {
    pub fn new(host: String, keyfile: Utf8PathBuf, certfile: Utf8PathBuf) -> Result<Self> {
        let (key, certs) = load_certs(&keyfile, &certfile)?;

        Ok(HostCertificate {
            host,
            keyfile,
            key,
            certfile,
            certs,
        })
    }

}



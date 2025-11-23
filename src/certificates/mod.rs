pub mod handler;
pub mod store;
pub mod watcher;

use std::fs;

use anyhow::{bail, Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use http::Uri;
use pingora_core::{ErrorType, OkOrErr};
use pingora_boringssl::{
    pkey::{PKey, Private},
    x509::X509,
};

#[derive(Debug)]
pub struct HostCertificate {
    host: String,
    keyfile: Utf8PathBuf,
    key: PKey<Private>,
    certfile: Utf8PathBuf,
    certs: Vec<X509>,
}

impl HostCertificate {
    pub fn new(keyfile: Utf8PathBuf, certfile: Utf8PathBuf) -> Result<Self> {
        let (key, certs) = load_certs(&keyfile, &certfile)?;

        let host = cn_host(certs[0].subject_name().print_ex(0)
                         .or_err(ErrorType::InvalidCert, "No host/CN in certificate")?)?;

        Ok(HostCertificate {
            host,
            keyfile,
            key,
            certfile,
            certs,
        })
    }

}

fn cn_host(cn: String) -> Result<String> {
    let host = cn.split('=')
        .nth(1)
        .or_err(ErrorType ::InvalidCert, "Failed to find host in cert 'CN=...'")?;
    Ok(host.to_string())
}

fn uri_host(uri: &String) -> Result<String> {
    let parsed = Uri::try_from(uri)?;
    let host = parsed.host()
        .context("Failed to find host in servername '{uri}'")?;
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
    Ok((key, certs))
}


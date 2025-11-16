
use std::{fs, sync::Arc};

use anyhow::{bail, Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use http::Uri;
use pingora_boringssl::{pkey::{PKey, Private}, x509::X509};
use pingora_core::{ErrorType, OkOrErr};
use tracing::{debug, info};

use crate::{certificates::HostCertificate, config::{Config, TlsConfigType, TlsFilesConfig}};


pub fn load_certs(keyfile: &Utf8Path, certfile: &Utf8Path) -> Result<(PKey<Private>, Vec<X509>)> {
    let kdata = fs::read(keyfile)?;
    let cdata = fs::read(certfile)?;

    let key = PKey::private_key_from_pem(&kdata)?;
    let certs = X509::stack_from_pem(&cdata)?;
    if certs.is_empty() {
        bail!("No certificates found in TLS .crt file");
    }
    Ok((key, certs))
}

pub fn gen_watchlist(config: &Config) -> Vec<Utf8PathBuf> {
    // We only watch user-supplied certs that are flagged to
    // reload. Acme certs are ignored.
    config.servers.iter()
        .filter_map(|s| match &s.tls.config {
            TlsConfigType::Files(TlsFilesConfig {keyfile, certfile, reload: true}) => {
                Some(vec![
                    keyfile.clone(),
                    certfile.clone(),
                ])
            }
            _ => None
        })
        .flatten()
        .collect()

}

pub struct CertStore {
    pub by_host: papaya::HashMap<String, Arc<HostCertificate>>,
    pub by_file: papaya::HashMap<Utf8PathBuf, Arc<HostCertificate>>,
    // Watched files; this may be a subset of all files as some are
    // unwatched, either by configuration or policy
    // (i.e. acme-generated).
    pub watchlist: Vec<Utf8PathBuf>,
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

impl CertStore {
    pub fn new(config: &Config) -> Result<Self> {
        info!("Loading host certificates");

        let certs = config.servers.iter()
            .filter(|s| matches!(s.tls.config, TlsConfigType::Files(_)))
            .map(|s| match &s.tls.config {
                TlsConfigType::Files(tfc) => {
                    debug!("Loading {} certs from {}, {}", s.hostname, tfc.keyfile, tfc.certfile);
                    let (key, certs) = load_certs(&tfc.keyfile, &tfc.certfile)?;

                    let cn = cn_host(certs[0].subject_name().print_ex(0)
                                     .or_err(ErrorType::InvalidCert, "No host/CN in certificate")?)?;
                    let s_host = uri_host(&s.hostname)?;
                    if s_host != cn {
                        bail!("Certificate {cn} doesn't match server host {s_host}");
                    }

                    let hostcert = HostCertificate {
                        host: cn,
                        keyfile: tfc.keyfile.clone(),
                        key,
                        certfile: tfc.certfile.clone(),
                        certs,
                    };
                    Ok(Arc::new(hostcert))
                }
                _ => unreachable!("Found filtered value")
            })
            .collect::<Result<Vec<Arc<HostCertificate>>>>()?;

        let by_host = certs.iter()
            .map(|cert| (cert.host.clone(),
                         cert.clone()))
            .collect();

        let by_file = certs.iter()
            .flat_map(|cert| {
                vec!((cert.keyfile.clone(), cert.clone()),
                     (cert.certfile.clone(), cert.clone()))
            })
            .collect();

        let watchlist = gen_watchlist(config);

        let certstore = Self {
            by_host,
            by_file,
            watchlist,
        };

        info!("Loaded {} certificates", certs.len());

        Ok(certstore)
    }

    pub fn replace(&self, newcert: Arc<HostCertificate>) -> Result<()> {
        let host = newcert.host.clone();
        info!("Replacing certificate for {host}");

        self.by_host.pin().update(host, |_old| newcert.clone());

        let by_file = self.by_file.pin();
        let keyfile = newcert.keyfile.clone();
        by_file.update(keyfile, |_old| newcert.clone());
        let certfile = newcert.keyfile.clone();
        by_file.update(certfile, |_old| newcert.clone());

        Ok(())
    }

    pub fn file_list(&self) -> Vec<Utf8PathBuf> {
        self.by_file.pin()
            .keys()
            .cloned()
            .collect()
    }
}

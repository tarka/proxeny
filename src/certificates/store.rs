use std::sync::Arc;

use anyhow::{bail, Context, Result};
use camino::Utf8PathBuf;
use http::Uri;
use tracing::{debug, info};

use crate::{
    certificates::HostCertificate,
    config::{Config, TlsConfigType, TlsFilesConfig},
};


pub fn gen_watchlist(config: &Config) -> Vec<Utf8PathBuf> {
    // We only watch user-supplied certs that are flagged to
    // reload. Acme certs are ignored.

    config.servers().iter()
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


fn uri_host(uri: &String) -> Result<String> {
    let parsed = Uri::try_from(uri)?;
    let host = parsed.host()
        .context("Failed to find host in servername '{uri}'")?;
    Ok(host.to_string())
}


// TODO: We currently use papaya to store lookup tables for multiple
// server support. However we don't actually support multiple servers
// in the config at the moment. This may change, so this is left in
// place for now.
pub struct CertStore {
    pub by_host: papaya::HashMap<String, Arc<HostCertificate>>,
    pub by_file: papaya::HashMap<Utf8PathBuf, Arc<HostCertificate>>,
    // Watched files; this may be a subset of all files as some are
    // unwatched, either by configuration or policy
    // (i.e. acme-generated).
    pub watchlist: Vec<Utf8PathBuf>,
}

impl CertStore {
    pub fn new(config: &Config) -> Result<Self> {
        info!("Loading host certificates");

        let local_certs = read_local_certs(config)?;

        let by_host = local_certs.iter()
            .map(|cert| (cert.host.clone(),
                         cert.clone()))
            .collect();

        let by_file = local_certs.iter()
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

        info!("Loaded {} certificates", local_certs.len());

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

fn read_local_certs(config: &Config) -> Result<Vec<Arc<HostCertificate>>> {
    config.servers().iter()
        // FIXME: Remove for ACME
        .filter(|s| matches!(s.tls.config, TlsConfigType::Files(_)))
        .map(|s| match &s.tls.config {
            TlsConfigType::Files(tfc) => {
                debug!("Loading {} certs from {}, {}", s.hostname, tfc.keyfile, tfc.certfile);
                let hostcert = HostCertificate::new(tfc.keyfile.clone(), tfc.certfile.clone())?;

                let server_host = uri_host(&s.hostname)?;
                if server_host != hostcert.host {
                    bail!("Certificate {} doesn't match server host {}", hostcert.host, server_host);
                }

                Ok(Arc::new(hostcert))
            }
            _ => unreachable!("ACME goes here")
        })
        .collect::<Result<Vec<Arc<HostCertificate>>>>()
}

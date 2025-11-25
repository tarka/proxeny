use std::sync::Arc;

use anyhow::{bail, Context, Result};
use camino::Utf8PathBuf;
use tracing::{debug, info};

use crate::{
    certificates::{external::ExternalProvider, HostCertificate},
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


// TODO: We currently use papaya to store lookup tables for multiple
// server support. However we don't actually support multiple servers
// in the config at the moment. This may change, so this is left in
// place for now.
pub struct CertStore {
    certs: Vec<Arc<HostCertificate>>,
    by_host: papaya::HashMap<String, Arc<HostCertificate>>,
    by_file: papaya::HashMap<Utf8PathBuf, Arc<HostCertificate>>,
}

impl CertStore {
    pub fn new(certs: Vec<Arc<HostCertificate>>) -> Result<Self> {
        info!("Loading host certificates");

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

        info!("Loaded {} certificates", certs.len());

        let certstore = Self {
            certs,
            by_host,
            by_file,
        };
        Ok(certstore)
    }

    pub fn by_host(&self, host: &String) -> Option<Arc<HostCertificate>> {
        let pmap = self.by_host.pin();
        pmap.get(host)
            .map(Arc::clone)
    }

    pub fn by_file(&self, file: &Utf8PathBuf) -> Option<Arc<HostCertificate>> {
        let pmap = self.by_file.pin();
        pmap.get(file)
            .cloned()
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

    pub fn watchlist(&self) -> Vec<Utf8PathBuf> {
        self.certs.iter()
            .filter_map(|h| if h.watch {
                Some(vec![h.keyfile.clone(), h.certfile.clone()])
            } else {
                None
            })
            .flatten()
            .collect()
    }
}


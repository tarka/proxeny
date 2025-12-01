use std::sync::Arc;

use anyhow::{anyhow, Result};
use camino::Utf8PathBuf;
use itertools::Itertools;
use tracing::info;
use tracing_log::log::warn;

use crate::{
    RunContext,
    certificates::HostCertificate,
    errors::ProxenyError,
};



// TODO: We currently use papaya to store lookup tables for multiple
// server support. However we don't actually support multiple servers
// in the config at the moment. This may change, so this is left in
// place for now.
pub struct CertStore {
    context: Arc<RunContext>,
    certs: Vec<Arc<HostCertificate>>,
    by_host: papaya::HashMap<String, Arc<HostCertificate>>,
    by_file: papaya::HashMap<Utf8PathBuf, Arc<HostCertificate>>,
}

impl CertStore {

    pub fn new(certs: Vec<Arc<HostCertificate>>, context: Arc<RunContext>) -> Result<Self> {
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
            context,
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

    pub fn file_update(&self, files: Vec<Utf8PathBuf>) -> Result<()> {
        let certs = files.iter()
            .map(|path| {
                let cert = self.by_file(path)
                 .ok_or(anyhow!("Path not found in store: {path}"))?
                    .clone();
                Ok(cert)
            })
            // 2-pass as .unique() doesn't work with Results
            .collect::<Result<Vec<Arc<HostCertificate>>>>()?
            .iter()
            .unique()
            .filter_map(|existing| {
                // Attempt to reload the relevant
                // HostCertificate. However as this can be expected
                // while the certs are being replaced externally we
                // just warn and pass for now.
                match HostCertificate::from(existing) {
                    Ok(hc) => Some(Ok(Arc::new(hc))),
                    Err(err) => {
                        if err.is::<ProxenyError>() {
                            let perr = err.downcast::<ProxenyError>()
                                .expect("Error downcasting ProxenyError after check; this shouldn't happen");
                            if matches!(perr, ProxenyError::CertificateMismatch(_, _)) {
                                warn!("Possible error on reload: {perr}. This may be transient.");
                                None
                            } else {
                                Some(Err(perr.into()))
                            }
                        } else {
                            Some(Err(err))
                        }
                    },
                }
            })
            .collect::<Result<Vec<Arc<HostCertificate>>>>()?;

        for newcert in certs {
            let host = newcert.host.clone();
            info!("Updating certificate for {host}");

            self.by_host.pin().update(host, |_old| newcert.clone());

            let keyfile = newcert.keyfile.clone();
            let certfile = newcert.certfile.clone();

            let by_file = self.by_file.pin();
            by_file.update(keyfile, |_old| newcert.clone());
            by_file.update(certfile, |_old| newcert.clone());
        }
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

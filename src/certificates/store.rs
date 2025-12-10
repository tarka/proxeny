use std::sync::Arc;

use anyhow::{anyhow, Result};
use camino::Utf8PathBuf;
use tracing::info;

use crate::{
    RunContext,
    certificates::HostCertificate,
};


// TODO: We currently use papaya to store lookup tables for multiple
// server support. However we don't actually support multiple servers
// in the config at the moment. This may change, so this is left in
// place for now.
//
// TODO: It _might_ be possible to return references rather than Arcs
// here, which would enforce the store as being the source of
// truth. But a bit fiddly for MVP version.
pub struct CertStore {
    context: Arc<RunContext>,
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

    pub fn upsert(&self, newcert: Arc<HostCertificate>) -> Result<()> {
        let host = newcert.host.clone();
        let keyfile = newcert.keyfile.clone();
        let certfile = newcert.certfile.clone();

        info!("Updating/inserting certificate for {host}");
        self.by_host.pin().update_or_insert(host, |_old| newcert.clone(), newcert.clone());

        let by_file = self.by_file.pin();
        by_file.update_or_insert(keyfile, |_old| newcert.clone(), newcert.clone());
        by_file.update_or_insert(certfile, |_old| newcert.clone(), newcert.clone());

        Ok(())
    }

    pub fn update(&self, newcert: Arc<HostCertificate>) -> Result<()> {
        let host = newcert.host.clone();
        let keyfile = newcert.keyfile.clone();
        let certfile = newcert.certfile.clone();

        info!("Updating certificate for {host}");
        self.by_host.pin().update(host, |_old| newcert.clone())
            .ok_or(anyhow!("Matching host for {} not found in cert store", newcert.host))?;

        let by_file = self.by_file.pin();
        by_file.update(keyfile, |_old| newcert.clone())
            .ok_or(anyhow!("File {} not found in cert store", newcert.keyfile))?;
        by_file.update(certfile, |_old| newcert.clone())
            .ok_or(anyhow!("File {} not found in cert store", newcert.certfile))?;

        Ok(())
    }

    pub fn watchlist(&self) -> Vec<Utf8PathBuf> {
        let by_host = self.by_host.pin();
        by_host.values()
            .filter_map(|h| if h.watch {
                Some(vec![h.keyfile.clone(), h.certfile.clone()])
            } else {
                None
            })
            .flatten()
            .collect()
    }
}

use std::sync::Arc;

use anyhow::{anyhow, Result};
use camino::Utf8PathBuf;
use itertools::Itertools;
use tracing::info;
use tracing_log::log::warn;

use crate::{
    certificates::{CertificateProvider, HostCertificate},
    errors::ProxenyError, Context,
};



// TODO: We currently use papaya to store lookup tables for multiple
// server support. However we don't actually support multiple servers
// in the config at the moment. This may change, so this is left in
// place for now.
pub struct CertStore {
    context: Arc<Context>,
    certs: Vec<Arc<HostCertificate>>,
    by_host: papaya::HashMap<String, Arc<HostCertificate>>,
    by_file: papaya::HashMap<Utf8PathBuf, Arc<HostCertificate>>,
}

impl CertStore {

    pub fn new(certs: Vec<Arc<HostCertificate>>, context: Arc<Context>) -> Result<Self> {
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
            // 2-pass as .unique() can't handle Results
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


#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;
    use crate::certificates::tests::*;

    #[test]
    fn test_cert_store_new() {
        let provider = TestProvider::new(
            "tests/data/certs/snakeoil.key",
            "tests/data/certs/snakeoil.crt",
            false
        );
        let context = Arc::new(Context::new());
        let store = CertStore::new(provider.read_certs(), context).unwrap();

        assert_eq!(store.certs.len(), 1);
        assert!(store.by_host(&provider.cert.host).is_some());
        assert!(store.by_file(&"tests/data/certs/snakeoil.key".into()).is_some());
        assert!(store.by_file(&"tests/data/certs/snakeoil.crt".into()).is_some());
    }

    #[test]
    fn test_by_host() {
        let provider = TestProvider::new(
            "tests/data/certs/snakeoil.key",
            "tests/data/certs/snakeoil.crt",
            false
        );
        let context = Arc::new(Context::new());
        let store = CertStore::new(provider.read_certs(), context).unwrap();
        let found = store.by_host(&provider.cert.host).unwrap();

        assert_eq!(found.host, provider.cert.host);
    }

    #[test]
    fn test_by_file() {
        let provider = TestProvider::new(
            "tests/data/certs/snakeoil.key",
            "tests/data/certs/snakeoil.crt",
            false
        );
        let context = Arc::new(Context::new());
        let store = CertStore::new(provider.read_certs(), context).unwrap();
        let found = store.by_file(&"tests/data/certs/snakeoil.key".into()).unwrap();

        assert_eq!(found.host, provider.cert.host);
    }

    #[test]
    fn test_watchlist() -> Result<()> {
        let hc1 = Arc::new(HostCertificate::new(
            "tests/data/certs/snakeoil.key".into(),
            "tests/data/certs/snakeoil.crt".into(),
            true
        )?);
        let hc2 = Arc::new(HostCertificate::new(
            "tests/data/certs/snakeoil-2.key".into(),
            "tests/data/certs/snakeoil-2.pem".into(),
            false
        )?);

        let context = Arc::new(Context::new());
        let certs = vec![hc1, hc2];
        let store = CertStore::new(certs, context).unwrap();
        let watchlist = store.watchlist();

        assert_eq!(watchlist.len(), 2);
        assert!(watchlist.contains(&Utf8PathBuf::from("tests/data/certs/snakeoil.key")));
        assert!(watchlist.contains(&Utf8PathBuf::from("tests/data/certs/snakeoil.crt")));
        Ok(())
    }

    #[test]
    fn test_file_update_success() -> Result<()> {
        let temp_dir = tempdir()?;
        let key_path = temp_dir.path().join("test.key");
        let cert_path = temp_dir.path().join("test.crt");
        fs::copy("tests/data/certs/snakeoil.key", &key_path)?;
        fs::copy("tests/data/certs/snakeoil.crt", &cert_path)?;

        let provider = TestProvider::new(
            key_path.to_str().unwrap(),
            cert_path.to_str().unwrap(),
            true
        );
        let context = Arc::new(Context::new());
        let store = CertStore::new(provider.read_certs(), context)?;
        let original_host = provider.cert.host.clone();

        // The original cert is snakeoil
        let first_cert = store.by_host(&original_host).unwrap();
        assert!(first_cert.certs[0].subject_name().print_ex(0).unwrap().contains("proxeny.example.com"));

        // Now update the files to snakeoil-2
        fs::copy("tests/data/certs/snakeoil-2.key", &key_path)?;
        fs::copy("tests/data/certs/snakeoil-2.pem", &cert_path)?;

        let updated_files = vec![key_path.clone().try_into()?, cert_path.clone().try_into()?];
        store.file_update(updated_files)?;

        let updated_cert_from_file = test_cert(
            key_path.to_str().unwrap(),
            cert_path.to_str().unwrap(),
            true
        );
        let new_host = updated_cert_from_file.host;

        // The store should have updated the certificate.
        let updated_cert_from_store = store.by_host(&new_host).expect("Cert not found for new host");
        assert_eq!(updated_cert_from_store.host, new_host);

        // The old entry should not exist anymore if the host has changed.
        if original_host != new_host {
            assert!(store.by_host(&original_host).is_none(), "Old host entry should be removed");
        }

        Ok(())
    }

    #[test]
    fn test_file_update_mismatch() -> Result<()> {
        let temp_dir = tempdir()?;
        let key_path = temp_dir.path().join("test.key");
        let cert_path = temp_dir.path().join("test.crt");
        fs::copy("tests/data/certs/snakeoil.key", &key_path)?;
        fs::copy("tests/data/certs/snakeoil.crt", &cert_path)?;

        let provider = TestProvider::new(
            key_path.to_str().unwrap(),
            cert_path.to_str().unwrap(),
            true
        );
        let context = Arc::new(Context::new());
        let store = CertStore::new(provider.read_certs(), context)?;
        let original_host = provider.cert.host.clone();

        let first_cert = store.by_host(&original_host).unwrap();

        // Update only the key, causing a mismatch
        fs::copy("tests/data/certs/snakeoil-2.key", &key_path)?;

        let updated_files = vec![key_path.try_into()?, cert_path.try_into()?];
        // This should not return an error, but log a warning and not update.
        store.file_update(updated_files)?;

        let cert_after_update = store.by_host(&original_host).unwrap();

        // The certificate should not have changed
        assert_eq!(Arc::as_ptr(&first_cert), Arc::as_ptr(&cert_after_update));

        Ok(())
    }
}

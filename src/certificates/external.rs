use std::sync::Arc;

use anyhow::{bail, Context, Result};
use http::Uri;
use tracing::debug;

use crate::{
    certificates::{CertificateProvider, HostCertificate},
    config::{Config, TlsConfigType},
};

fn uri_host(uri: &String) -> Result<String> {
    let parsed = Uri::try_from(uri)?;
    let host = parsed.host()
        .context("Failed to find host in servername '{uri}'")?;
    Ok(host.to_string())
}


/// Externally managed certificates
pub struct ExternalProvider {
    config: Arc<Config>,
}

impl ExternalProvider {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

impl CertificateProvider for ExternalProvider {

    fn read_certs(&self) -> Result<Vec<Arc<HostCertificate>>> {
        self.config.servers().iter()
            .filter_map(|s| match &s.tls.config {
                TlsConfigType::Files(tfc) => {
                    // Wrapper closure for `?` clarity
                    let result = (|| {
                        debug!("Loading {} certs from {}, {}", s.hostname, tfc.keyfile, tfc.certfile);
                        let hostcert = HostCertificate::new(
                            tfc.keyfile.clone(),
                            tfc.certfile.clone(),
                            tfc.reload)?;

                        let server_host = uri_host(&s.hostname)?;
                        if server_host != hostcert.host {
                            bail!("Certificate {} doesn't match server host {}", hostcert.host, server_host);
                        }
                        Ok(Arc::new(hostcert))
                    })();

                    Some(result)
                }
                _ => None
            })
            .collect::<Result<Vec<Arc<HostCertificate>>>>()
    }

}

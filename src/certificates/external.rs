use std::sync::Arc;

use anyhow::{bail, Context, Result};
use http::Uri;
use tracing_log::log::debug;

use crate::{
    RunContext,
    certificates::HostCertificate,
    config::TlsConfigType
};

fn uri_host(uri: &String) -> Result<String> {
    let parsed = Uri::try_from(uri)?;
    let host = parsed.host()
        .context("Failed to find host in servername '{uri}'")?;
    Ok(host.to_string())
}


/// Externally managed certificates
// TODO: Need a better name
pub struct ExternalProvider {
    _context: Arc<RunContext>,
    certs: Vec<Arc<HostCertificate>>,
}

impl ExternalProvider {
    pub fn new(context: Arc<RunContext>) -> Result<Self> {
        let certs = context.config.servers().iter()
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
                        if server_host != hostcert.hostname {
                            bail!("Certificate {} doesn't match server host {}", hostcert.hostname, server_host);
                        }
                        Ok(Arc::new(hostcert))
                    })();

                    Some(result)
                }
                _ => None
            })
            .collect::<Result<Vec<Arc<HostCertificate>>>>()?;

        Ok(Self {
            _context: context,
            certs,
        })
    }


    pub fn read_certs(&self) -> Vec<Arc<HostCertificate>> {
        self.certs.clone()
    }
}

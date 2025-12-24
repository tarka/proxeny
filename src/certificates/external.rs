use std::sync::Arc;

use anyhow::Result;
use tracing_log::log::debug;

use crate::{
    RunContext,
    certificates::HostCertificate, config::TlsConfig,
};

/// Externally managed certificates
// TODO: Need a better name
pub struct ExternalProvider {
    _context: Arc<RunContext>,
    certs: Vec<Arc<HostCertificate>>,
}

impl ExternalProvider {
    pub fn new(context: Arc<RunContext>) -> Result<Self> {
        let certs = context.config.vhosts.iter()
            .filter_map(|vhost| match &vhost.tls {
                TlsConfig::Files(tfc) => {
                    // Wrapper closure for `?` clarity
                    let result = (|| {
                        debug!("Loading {} certs from {}, {}", vhost.hostname, tfc.keyfile, tfc.certfile);
                        let hostcert = HostCertificate::new(
                            tfc.keyfile.clone(),
                            tfc.certfile.clone(),
                            tfc.reload)?;

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

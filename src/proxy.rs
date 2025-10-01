

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use pingora::{
    http::RequestHeader,
    listeners::tls::TlsSettings,
    prelude::HttpPeer,
    proxy::{http_proxy_service, ProxyHttp, Session},
    server::{RunArgs, Server},
};
use tracing::info;

use crate::certificates::{CertHandler, CertStore};


struct Proxeny {
    certstore: Arc<CertStore>,
}

#[async_trait]
impl ProxyHttp for Proxeny {
    type CTX = ();

    fn new_ctx(&self) -> () {
        ()
    }

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> pingora::Result<Box<HttpPeer>> {
        let peer = HttpPeer::new("192.168.42.201:5000", false, "frigate.haltcondition.net".to_string());
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(&self, _session: &mut Session, upstream_request: &mut RequestHeader, _ctx: &mut Self::CTX) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        upstream_request.insert_header("Host", "frigate.haltcondition.net")?;
        Ok(())
    }
}


pub fn run_indefinitely(certstore: Arc<CertStore>) -> Result<()> {
    info!("Starting Proxy");

    let cert_handler = CertHandler::new(certstore.clone());
    let tls_settings = TlsSettings::with_callbacks(Box::new(cert_handler))?;
    let proxeny = Proxeny { certstore: certstore.clone() };

    let mut server = Server::new(None)?;
    server.bootstrap();

    let mut proxy = http_proxy_service(&server.configuration, proxeny);
    proxy.add_tcp("0.0.0.0:8080");
    proxy.add_tls_with_settings("0.0.0.0:8443", None, tls_settings);

    server.add_service(proxy);

    server.run(RunArgs::default());

    Ok(())
}

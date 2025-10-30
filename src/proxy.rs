

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

use crate::{certificates::{CertHandler, CertStore}, config::Config};


struct Proxeny {
    config: Arc<Config>,
    certstore: Arc<CertStore>,
}

impl Proxeny {
    fn new(certstore: Arc<CertStore>, config: Arc<Config>) -> Self {
        Self {
            config,
            certstore
        }
    }
}

#[async_trait]
impl ProxyHttp for Proxeny {
    type CTX = ();

    fn new_ctx(&self) -> () {
        ()
    }

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> pingora::Result<Box<HttpPeer>> {
        info!("GOT: {:#?}", _session.req_header());
        let peer = HttpPeer::new("example.com", false, "example.com".to_string());
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(&self, _session: &mut Session, upstream_request: &mut RequestHeader, _ctx: &mut Self::CTX) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        info!("GOT: {:#?}", _session.req_header());
        upstream_request.insert_header("Host", "example.com")?;
        Ok(())
    }
}


pub fn run_indefinitely(certstore: Arc<CertStore>, config: Arc<Config>) -> Result<()> {
    info!("Starting Proxy");

    let mut server = Server::new(None)?;
    server.bootstrap();

    let proxeny = Proxeny::new(certstore.clone(), config.clone());

    let mut proxy = http_proxy_service(&server.configuration, proxeny);


    for sv in config.servers.iter() {
        let cert_handler = CertHandler::new(certstore.clone());
        let tls_settings = TlsSettings::with_callbacks(Box::new(cert_handler))?;
        let addr = format!("[::]:{}", sv.tls.port);
        proxy.add_tls_with_settings(&addr, None, tls_settings);

        // FIXME: Placeholder; this should be 301/HSTS (and later Acme HTTP-01 challenges)
        // proxy.add_tcp("[::]:8080");
    }

    server.add_service(proxy);

    server.run(RunArgs::default());

    Ok(())
}

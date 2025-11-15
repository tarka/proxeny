

use std::sync::Arc;

use async_trait::async_trait;
use http::{header::HOST, StatusCode};
use pingora::{
    listeners::tls::TlsSettings, prelude::HttpPeer, proxy::{http_proxy_service, ProxyHttp, Session}, server::{RunArgs, Server}, ErrorType, OkOrErr, OrErr
};
use tracing::{info, trace};

use crate::{certificates::{CertHandler, CertStore}, config::{Backend, Config}};


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

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> pingora::Result<Box<HttpPeer>> {
        info!("Peer: {:#?}", session.req_header());

        // RequestHeader {
        //     base: Parts {
        //         method: GET,
        //         uri: /sonarr/series/the-daily-show,
        //         version: HTTP/1.1,
        //         headers: {
        //             "host": "dvalinn.haltcondition.net:8443",
        //             "user-agent": "curl/8.16.0",
        //             "accept": "*/*",
        //         },
        //     },
        //     header_name_map: Some(
        //         {
        //             "host": CaseHeaderName(
        //                 b"Host",
        //             ),
        //             "user-agent": CaseHeaderName(
        //                 b"User-Agent",
        //             ),
        //             "accept": CaseHeaderName(
        //                 b"Accept",
        //             ),
        //         },
        //     ),
        //     raw_path_fallback: [],
        //     send_end_stream: true,
        // }

        let host = session.req_header().headers.get(HOST)
            .or_err(ErrorType::InvalidHTTPHeader, "No Host header in request")?
            .to_str()
            .or_err(ErrorType::InvalidHTTPHeader, "Invalid Host header")?;
        let path = session.req_header().uri.path();
        info!("PATH: {:#?}", path);

        // TODO: move to init
        let by_host: papaya::HashMap<String, Vec<Backend>> = self.config.servers.iter()
            .map(|s| (s.hostname.clone(),
                      s.backends.clone()))
            .collect();
        info!("BY_HOST: {by_host:#?}");

        // FIXME: There are faster ways to do this, plus caching.
        info!("FETCH HOST: {host}");
        let backends = by_host.pin().get(host)
            .or_err(ErrorType::HTTPStatus(StatusCode::NOT_FOUND.as_u16()), "Hostname not found in backends")?;


        let peer = HttpPeer::new("htpc.haltcondition.net:8989", false, "htpc.haltcondition.net".to_string());
        Ok(Box::new(peer))
    }

    // async fn upstream_request_filter(&self, _session: &mut Session, upstream_request: &mut RequestHeader, _ctx: &mut Self::CTX) -> pingora::Result<()>
    // where
    //     Self::CTX: Send + Sync,
    // {
    //     info!("REQ_FILTER: {:#?}", upstream_request);
    //     upstream_request.insert_header("Host", "example.com")?;
    //     Ok(())
    // }
}


pub fn run_indefinitely(certstore: Arc<CertStore>, config: Arc<Config>) -> anyhow::Result<()> {
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

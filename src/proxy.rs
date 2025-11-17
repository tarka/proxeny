

use std::sync::Arc;

use async_trait::async_trait;
use http::{header::HOST, StatusCode};

use path_tree::PathTree;
use pingora_core::{listeners::tls::TlsSettings, prelude::HttpPeer, server::Server, ErrorType, OkOrErr, OrErr};
use pingora_proxy::{http_proxy_service, ProxyHttp, Session};
use tracing::info;

use crate::{certificates::{handler::CertHandler, store::CertStore}, config::{Backend, Config}};

struct Match<'a> {
    backend: &'a Backend,
    path: String,
}

struct Router<'a> {
    tree: PathTree<&'a Backend>,
}

const PATHVAR: &str = "subpath";

impl<'a> Router<'a> {

    fn new(backends: &'a Vec<Backend>) -> Self {
        let mut tree = PathTree::new();

        for b in backends {
            match b.context {
                Some(ref path) => {
                    let path = if path.ends_with("/") {
                        let len = path.len();
                        path.as_str()[..len-1].to_string()
                    } else {
                        path.clone()
                    };
                    let matcher = format!("{path}:{PATHVAR}*");
                    println!("Inserting {matcher}");
                    let _id = tree.insert(&matcher, b);
                }
                None => {
                    let matcher = format!("/:{PATHVAR}*");
                    println!("Inserting {matcher}");
                    let _id = tree.insert(&matcher, b);}
            }
        }

        Router {
            tree
        }
    }

    fn lookup(&self, path: &str) -> Option<Match<'a>> {
        let (backend, matched) = self.tree.find(&path)?;
        let rest = matched.params()[0].1.to_string();
        Some(Match {
            backend,
            path: rest,
        })
    }
}


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

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> pingora_core::Result<Box<HttpPeer>> {
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
        // FIXME: Worth it? 99% of selfhost installs will server a single front-end host?
        let by_host: papaya::HashMap<String, Vec<Backend>> = self.config.servers.iter()
            .map(|s| (s.hostname.clone(),
                      s.backends.clone()))
            .collect();
        info!("BY_HOST: {by_host:#?}");

        // FIXME: There are faster ways to do this, plus caching.
        info!("FETCH HOST: {host}");
        let _backends = by_host.pin().get(host)
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

    server.run(pingora_core::server::RunArgs::default());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use http::Uri;
    use test_log::test;
    use crate::config::Backend;

    #[test]
    fn test_matchit() -> Result<()> {
        let backends = vec![
            Backend {
                context: None,
                url: Uri::from_static("http://localhost:1010")
            },
            Backend {
                context: Some("/service".to_string()),
                url: Uri::from_static("http://localhost:2020")
            },
            Backend {
                context: Some("/service/subservice/".to_string()),
                url: Uri::from_static("http://localhost:3030")
            },
            Backend {
                context: Some("/other_service/".to_string()),
                url: Uri::from_static("http://localhost:4040")
            },
        ];

        let router = Router::new(&backends);

        let matched = router.lookup("/").unwrap();
        assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
        assert_eq!("", matched.path);

        let matched = router.lookup("/base/path").unwrap();
        assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
        assert_eq!("base/path", matched.path);

        let matched = router.lookup("/service").unwrap();
        assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
        assert_eq!("", matched.path);

        let matched = router.lookup("/service/").unwrap();
        assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
        assert_eq!("/", matched.path);

        let matched = router.lookup("/service/some/path").unwrap();
        assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
        assert_eq!("/some/path", matched.path);

        let matched = router.lookup("/service/subservice").unwrap();
        assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.url);
        assert_eq!("", matched.path);

        let matched = router.lookup("/service/subservice/").unwrap();
        assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.url);
        assert_eq!("/", matched.path);

        let matched = router.lookup("/service/subservice/ss/path").unwrap();
        assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.url);
        assert_eq!("/ss/path", matched.path);

        let matched = router.lookup("/other_service/some/path").unwrap();
        assert_eq!(Uri::from_static("http://localhost:4040"), matched.backend.url);
        assert_eq!("/some/path", matched.path);

        Ok(())
    }

}

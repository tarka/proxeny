

use std::sync::Arc;

use async_trait::async_trait;
use http::{header::HOST, uri::Scheme, StatusCode};

use path_tree::PathTree;
use pingora_core::{listeners::tls::TlsSettings, prelude::HttpPeer, server::Server, ErrorType, OkOrErr, OrErr};
use pingora_proxy::{http_proxy_service, ProxyHttp, Session};
use tracing::info;

use crate::{certificates::{handler::CertHandler, store::CertStore}, config::{Backend, Config}};

struct Match<'a> {
    backend: &'a Backend,
    path: String,
}

struct Router {
    // FIXME: Backends could be Arc, but probably not worth it?
    tree: PathTree<Backend>,
}

const PATHVAR: &str = "subpath";

impl Router {

    fn new(backends: &Vec<Backend>) -> Self {
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
                    let _id = tree.insert(&matcher, b.clone());
                }
                None => {
                    let matcher = format!("/:{PATHVAR}*");
                    println!("Inserting {matcher}");
                    let _id = tree.insert(&matcher, b.clone());}
            }
        }

        Router {
            tree
        }
    }

    fn lookup(&self, path: &str) -> Option<Match<'_>> {
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
    routes_by_host: papaya::HashMap<String, Router>,
}

impl Proxeny {
    fn new(certstore: Arc<CertStore>, config: Arc<Config>) -> Self {
        let routes_by_host: papaya::HashMap<String, Router> = config.servers.iter()
            .map(|s| (s.hostname.clone(),
                      Router::new(&s.backends)))
            .collect();
        Self {
            config,
            certstore,
            routes_by_host,
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
        let host = session.req_header().headers.get(HOST)
            .or_err(ErrorType::InvalidHTTPHeader, "No Host header in request")?
            .to_str()
            .or_err(ErrorType::InvalidHTTPHeader, "Invalid Host header")?;
        let path = &session.req_header().uri.path();
        info!("Request: {host} -> {path}");

        let pinned = self.routes_by_host.pin();
        let router = pinned.get(host)
            .or_err(ErrorType::HTTPStatus(StatusCode::NOT_FOUND.as_u16()), "Hostname not found in backends")?;
        let matched = router.lookup(path)
            .or_err(ErrorType::HTTPStatus(StatusCode::NOT_FOUND.as_u16()), "Path not found in host backends")?;

        let url = &matched.backend.url;
        let tls = url.scheme() == Some(&Scheme::HTTPS);
        let host = url.host()
            .or_err(ErrorType::HTTPStatus(StatusCode::INTERNAL_SERVER_ERROR.as_u16()), "Backend host lookup failed")?;
        let port = url.port()  // TODO: Can default this? Or should be required?
            .or_err(ErrorType::HTTPStatus(StatusCode::INTERNAL_SERVER_ERROR.as_u16()), "Backend port lookup failed")?
            .as_u16();

        let peer = HttpPeer::new((host, port), tls, host.to_string());
        Ok(Box::new(peer))
    }
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

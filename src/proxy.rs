

use std::sync::Arc;

use async_trait::async_trait;
use http::{header, uri::{Authority, Builder, Scheme}, Response, StatusCode, Uri};

use path_tree::PathTree;
use pingora_core::{
    apps::http_app::ServeHttp,
    listeners::tls::TlsSettings,
    prelude::HttpPeer,
    protocols::http::ServerSession,
    services::listening::Service,
    server::Server as PingoraServer,
    ErrorType,
    OkOrErr,
    OrErr
};
use pingora_proxy::{ProxyHttp, Session};
use tracing::{debug, info};

use crate::{certificates::{handler::CertHandler, store::CertStore}, config::{Backend, Config}};

struct TlsRedirector {
    port: String,
}

impl TlsRedirector {
    pub fn new(port: u16) -> Self {
        Self {
            port: port.to_string()
        }
    }
}

const REDIRECT_BODY: &[u8] = "<html><body>301 Moved Permanently</body></html>".as_bytes();


fn rewrite_port(host: &str, newport: &str) -> String {
    let port_i = if let Some(i) = host.rfind(':') {
        i
    } else {
        return host.to_string();
    };
    if !host[port_i + 1..].parse::<u16>().is_ok() {
        // Not an int, assume not port ':'
        return host.to_string();
    }
    let host_only = &host[0..port_i];

    format!("{host_only}:{newport}")
}


#[async_trait]
impl ServeHttp for TlsRedirector {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        let host = session.get_header(header::HOST)
            .expect("Failed to get host header on HTTP service")
            .to_str()
            .expect("Failed to convert host header to str");
        // Uri::Authority doesn't allow port overrides, so mangle the string
        let new_host = rewrite_port(host, &self.port);

        let uri = session.req_header().uri.clone();
        // TODO: `host` may not be full authority (i.e. including
        // uname:pw section). Does it matter?
        let location = Builder::from(uri)
            .scheme(Scheme::HTTPS)
            .authority(new_host)
            .build()
            .expect("Failed to convert URI to HTTPS");

        debug!("Redirect to {location}");
        let body = REDIRECT_BODY.to_owned();
        Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header(header::CONTENT_TYPE, "text/html")
            .header(header::CONTENT_LENGTH, body.len())
            .header(header::LOCATION, location.to_string())
            .body(body)
            .expect("Failed to create HTTP->HTTPS redirect response")
    }
}


struct Match<'a> {
    backend: &'a Backend,
    path: String,
}

struct Router {
    tree: PathTree<Backend>,
}

const PATHVAR: &str = "subpath";

impl Router {

    fn new(backends: &Vec<Backend>) -> Self {
        let mut tree = PathTree::new();

        for b in backends {
            // FIXME: Backend could be Arc, but probably not worth it?
            let backend = b.clone();
            match b.context {
                Some(ref path) => {
                    let path = if path.ends_with("/") {
                        let len = path.len();
                        path.as_str()[..len-1].to_string()
                    } else {
                        path.clone()
                    };
                    let matcher = format!("{path}:{PATHVAR}*");
                    let _id = tree.insert(&matcher, backend);
                }
                None => {
                    let matcher = format!("/:{PATHVAR}*");
                    let _id = tree.insert(&matcher, backend);}
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
        let host = session.req_header().headers.get(header::HOST)
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

    let mut pingora_server = PingoraServer::new(None)?;
    pingora_server.bootstrap();

    for sv in config.servers.iter() {
        let tls_proxy = {
            let proxeny = Proxeny::new(certstore.clone(), config.clone());

            let mut pingora_proxy = pingora_proxy::http_proxy_service(
                &pingora_server.configuration,
                proxeny);

            let cert_handler = CertHandler::new(certstore.clone());
            let tls_settings = TlsSettings::with_callbacks(Box::new(cert_handler))?;

            // TODO: Listen on specific IP/interface
            let addr = format!("[::]:{}", sv.tls.port);
            pingora_proxy.add_tls_with_settings(&addr, None, tls_settings);
            pingora_proxy
        };

        let http_redirect = {
            let redirector = TlsRedirector::new(sv.tls.port);
            let mut service = Service::new("HTTP->HTTPS Redirector".to_string(), redirector);
            service.add_tcp("[::]:8080");  // FIXME
            service
        };

        pingora_server.add_service(tls_proxy);
        pingora_server.add_service(http_redirect);
    }


    pingora_server.run(pingora_core::server::RunArgs::default());

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use http::{uri::Builder, Uri};
    use test_log::test;
    use crate::config::Backend;

    #[test]
    fn test_uri_rewrite() -> Result<()> {
        let uri = Uri::from_static("http://example.com/a/path?param=value");
        let changed = Builder::from(uri)
            .scheme("https")
            .build()?;
        assert_eq!("https://example.com/a/path?param=value", changed.to_string());
        Ok(())
    }

    #[test]
    fn test_host_port_rewrite() -> Result<()> {
        let replaced = rewrite_port("example.com:8080", "8443");
        assert_eq!("example.com:8443", replaced);
        let replaced = rewrite_port("example.com", "8443");
        assert_eq!("example.com", replaced);
        Ok(())
    }

    #[test]
    fn test_router() -> Result<()> {
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

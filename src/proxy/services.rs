

use std::sync::Arc;

use async_trait::async_trait;
use http::{header, uri::{Builder, Scheme}, Response, StatusCode};

use pingora_core::{
    apps::http_app::ServeHttp,
    prelude::HttpPeer,
    protocols::http::ServerSession,
    ErrorType,
    OkOrErr,
    OrErr
};
use pingora_proxy::{ProxyHttp, Session};
use tracing::{debug, info};

use crate::{certificates::store::CertStore, config::Config, proxy::router::Router};


pub struct TlsRedirector {
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



pub struct Proxeny {
    config: Arc<Config>,
    certstore: Arc<CertStore>,
    routes_by_host: papaya::HashMap<String, Router>,
}

impl Proxeny {
    pub fn new(certstore: Arc<CertStore>, config: Arc<Config>) -> Self {
        let routes_by_host: papaya::HashMap<String, Router> = config.servers().iter()
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


#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use http::{uri::Builder, Uri};
    use test_log::test;

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

}

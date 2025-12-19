use std::sync::Arc;

use async_trait::async_trait;
use http::{
    HeaderValue, Response, StatusCode, Uri,
    header::{self, LOCATION, REFRESH},
    uri::{Builder, Scheme},
};

use pingora_core::{
    ErrorType, OkOrErr, OrErr, apps::http_app::ServeHttp, prelude::HttpPeer,
    protocols::http::ServerSession,
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use tracing::{debug, info};

use crate::{
    RunContext,
    certificates::{acme::AcmeRuntime, store::CertStore},
    proxy::{rewrite_port, router::Router, strip_port},
};

const REDIRECT_BODY: &[u8] = "<html><body>301 Moved Permanently</body></html>".as_bytes();
const TOKEN_NOT_FOUND: &[u8] = "<html><body>ACME token not found in request path</body></html>".as_bytes();
const ACME_HTTP01_PREFIX: &'static str = "/.well-known/acme-challenge/";

fn token_not_found() -> Response<Vec<u8>> {
    Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(TOKEN_NOT_FOUND.to_vec())
            .expect("Failed to send 404 response to token")
}

struct RequestComponents<'a> {
    host: &'a str,
    path: &'a str,
    _query: &'a str,
}

fn to_components(session: &Session) -> pingora_core::Result<RequestComponents<'_>> {
    let host_header = session.req_header().headers.get(header::HOST)
        .or_err(ErrorType::InvalidHTTPHeader, "No Host header in request")?
        .to_str()
        .or_err(ErrorType::InvalidHTTPHeader, "Invalid Host header")?;
    let host = strip_port(host_header);
    let pq = session.req_header().uri.path_and_query();
    let (path, _query) = if let Some(pq) = pq {
        (pq.path(), pq.query().unwrap_or(""))
    } else {
        ("", "")
    };
    Ok(RequestComponents{
        host, path, _query,
    })
}


pub struct CleartextHandler {
    acme: Arc<AcmeRuntime>,
    port: String,
}

impl CleartextHandler {
    pub fn new(acme: Arc<AcmeRuntime>, tls_port: u16) -> Self {
        Self {
            acme,
            port: tls_port.to_string()
        }
    }
}

impl CleartextHandler {

    async fn redirect_to_tls(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        let host = session.get_header(header::HOST)
            .expect("Failed to get host header on HTTP service")
            .to_str()
            .expect("Failed to convert host header to str");
        let path = session.req_header().uri.clone();

        // Uri::Authority doesn't allow port overrides, so mangle the string
        let new_host = rewrite_port(host, &self.port);

        // TODO: `host` may not be full authority (i.e. including
        // uname:pw section). Does it matter?
        let location = Builder::from(path)
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

    async fn acme_challenge(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        let fqdn = session.get_header(header::HOST)
            .expect("Failed to get host header on HTTP service")
            .to_str()
            .expect("Failed to convert host header to str");

        let path = session.req_header().uri.path_and_query()
            .expect("Failed to find already matched path?");

        let path_token = match path.path().strip_prefix(ACME_HTTP01_PREFIX) {
            Some(token) => token,
            None => return token_not_found(),
        };

        let key_auth = if let Some(toks) = self.acme.challenge_tokens(fqdn)
            && toks.token == path_token
        {
            toks.key_auth
        } else {
            return token_not_found()
        };

        let body = key_auth.as_bytes().to_vec();
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::CONTENT_LENGTH, body.len())
            .body(body)
            .expect("Failed to create HTTP->HTTPS redirect response")
    }
}

#[async_trait]
impl ServeHttp for CleartextHandler {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        // URI in practice == /the/path/to/resource
        let path_p = session.req_header().uri.path_and_query();
        if let Some(pq) = path_p
            && pq.path().starts_with(ACME_HTTP01_PREFIX)
        {
            info!("Received ACME challenge request: {pq}");
            self.acme_challenge(session).await
        } else {
            self.redirect_to_tls(session).await
        }
    }
}

pub struct Vicarian {
    _context: Arc<RunContext>,
    _certstore: Arc<CertStore>,
    routes_by_host: papaya::HashMap<String, Router>,
}

impl Vicarian {
    pub fn new(_certstore: Arc<CertStore>, context: Arc<RunContext>) -> Self {
        let routes_by_host: papaya::HashMap<String, Router> = context.config.servers().iter()
            .map(|s| (s.hostname.clone(),
                      Router::new(&s.backends)))
            .collect();
        Self {
            _context: context,
            _certstore,
            routes_by_host,
        }
    }
}

#[async_trait]
impl ProxyHttp for Vicarian {
    type CTX = ();

    fn new_ctx(&self) -> () {
        ()
    }

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> pingora_core::Result<Box<HttpPeer>> {
        let components = to_components(session)?;

        let pinned = self.routes_by_host.pin();
        let router = pinned.get(&components.host.to_string())
            .or_err(ErrorType::HTTPStatus(StatusCode::NOT_FOUND.as_u16()), "UP: Hostname not found in backends")?;

        let matched = router.lookup(components.path)
            .or_err(ErrorType::HTTPStatus(StatusCode::NOT_FOUND.as_u16()), "UP: Path not found in host backends")?;

        let url = &matched.backend.url;
        let tls = url.scheme() == Some(&Scheme::HTTPS);
        let host = url.host()
            .or_err(ErrorType::HTTPStatus(StatusCode::INTERNAL_SERVER_ERROR.as_u16()), "Backend host lookup failed")?;
        let port = url.port()  // TODO: Can default this? Or should be required?
            .or_err(ErrorType::HTTPStatus(StatusCode::INTERNAL_SERVER_ERROR.as_u16()), "Backend port lookup failed")?
            .as_u16();

        let peer = HttpPeer::new((host, port), tls, host.to_string());

        debug!("Using peer: {peer:?}");
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(&self, session: &mut Session,
                                     upstream_request: &mut RequestHeader,
                                     _ctx: &mut Self::CTX,)
                                     -> pingora_core::Result<()>
    {
        info!("Req: {}", session.req_header().uri);
        let components = to_components(session)?;

        let pinned = self.routes_by_host.pin();
        let router = pinned.get(&components.host.to_string())
            .or_err(ErrorType::HTTPStatus(StatusCode::NOT_FOUND.as_u16()), "URF: Hostname not found in backends")?;

        let backend = router.lookup(components.path)
            .or_err(ErrorType::HTTPStatus(StatusCode::NOT_FOUND.as_u16()), "URF: Path not found in host backends")?
            .backend;

        if let Some(context) = &backend.context
            && context != "" && context != "/"
            && !backend.url.path().starts_with(context)
        {
            debug!("Modifying {} for context {context}", upstream_request.uri);
            let upath = upstream_request.uri.path()
                .strip_prefix(context)
                .unwrap_or("/");
            let uquery = upstream_request.uri.query()
                .map(|s| format!("?{s}"))
                .unwrap_or(String::new());
            let upq = format!("{upath}{uquery}");
            let uuri = Uri::builder()
                .path_and_query(upq)
                .build()
                .or_err(ErrorType::HTTPStatus(StatusCode::INTERNAL_SERVER_ERROR.as_u16()), "Failed to rewrite path")?;
            debug!("Modified to {uuri}");
            upstream_request.set_uri(uuri);
        }

        // Let's assume we always need this for now
        if let Some(sockaddr) = session.client_addr()
            && let Some(inet) = sockaddr.as_inet()
        {
            let ip = inet.ip().to_string();
            upstream_request.insert_header("X-Forwarded-For", &ip)?;
            upstream_request.insert_header("X-Real-IP", &ip)?;
        }

        Ok(())
    }

    fn upstream_response_filter(&self, session: &mut Session,
                                upstream_response: &mut ResponseHeader,
                                _ctx: &mut Self::CTX)
                                -> pingora_core::Result<()>
    {
        let components = to_components(session)?;

        let pinned = self.routes_by_host.pin();
        let router = pinned.get(&components.host.to_string())
            .or_err(ErrorType::HTTPStatus(StatusCode::NOT_FOUND.as_u16()), "Hostname not found in backends")?;

        let backend = router.lookup(components.path)
            .or_err(ErrorType::HTTPStatus(StatusCode::NOT_FOUND.as_u16()), "Path not found in host backends")?
            .backend;

        if let Some(context) = &backend.context
            && context != "" && context != "/"
            && !backend.url.path().starts_with(context)
        {
            for headername in [LOCATION, REFRESH] {
                let header_p = upstream_response.headers.get(&headername);
                if let Some(header) = header_p {
                    let oldloc = header.to_str()
                        .or_err(ErrorType::HTTPStatus(StatusCode::INTERNAL_SERVER_ERROR.as_u16()), "Failed to rewrite location header")?;
                    let newloc = HeaderValue::from_str(&format!("{context}{oldloc}"))
                        .or_err(ErrorType::HTTPStatus(StatusCode::INTERNAL_SERVER_ERROR.as_u16()), "Failed to rewrite location header")?;

                    debug!("Modifying Location to {newloc:?}");
                    let _old = upstream_response.insert_header(&headername, newloc);
                }
            }
        }

        let via = format!("{:?} Vicarian", session.req_header().version);
        upstream_response.insert_header("Via", via)?;

        Ok(())
    }

}

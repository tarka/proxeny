use std::{iter, sync::Arc};

use async_trait::async_trait;
use http::{
    HeaderValue, Uri,
    header::{self, AUTHORIZATION, LOCATION, REFRESH, STRICT_TRANSPORT_SECURITY, VIA},
    uri::Scheme,
};
use metrics::counter;
use pingora_core::{
    ErrorType, OkOrErr, OrErr, modules::http::compression::ResponseCompression, prelude::HttpPeer,
    upstreams::peer::Peer,
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use tracing::{debug, info};

use crate::{
    RunContext,
    certificates::store::CertStore,
    config::{Backend, Vhost},
    metrics::{
        METRIC_AUTH_INVALID_TOTAL, METRIC_AUTH_VALID_TOTAL, METRIC_TLS_REQUESTS_TOTAL,
        MetricsHandler,
    },
    proxy::{
        E401, E404, E500, Handler,
        mimetypes::is_compressible,
        router::{Router, RouterBackend},
        r#static::StaticHandler,
    },
};

const YEAR_IN_SECS: u64 = 31536000;

struct RequestComponents<'a> {
    host: &'a str,
    path: &'a str,
    _query: &'a str,
}

fn to_components(session: &Session) -> pingora_core::Result<RequestComponents<'_>> {
    let host = if session.is_http2() {
        session.req_header().uri.host()
            .or_err(ErrorType::InvalidHTTPHeader, "No Host component in request URI")?

    } else {
        let host_header = session.req_header().headers.get(header::HOST)
        .or_err(ErrorType::InvalidHTTPHeader, "No Host header in request")?
        .to_str()
        .or_err(ErrorType::InvalidHTTPHeader, "Invalid Host header")?;
        strip_port(host_header)
    };

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


pub(crate) fn strip_port(host_header: &str) -> &str {
    if host_header.starts_with('[') {
        // IPv6-literal special case
        if let Some(pos) = host_header.find("]:") {
            &host_header[..pos + 1]
        } else {
            host_header
        }
    } else if let Some(i) = host_header.rfind(':') {
        &host_header[..i]
    } else {
        host_header
    }
}

pub struct Vicarian {
    _context: Arc<RunContext>,
    _certstore: Arc<CertStore>,
    routes_by_host: papaya::HashMap<String, Arc<Router>>,
}

impl Vicarian {
    pub fn new(_certstore: Arc<CertStore>, context: Arc<RunContext>) -> Self {

        let routes_by_host = context.config.vhosts.iter()
            .flat_map(|vhost| {
                let router = Arc::new(vhost_to_router(vhost));
                iter::once(&vhost.hostname)
                    .chain(vhost.aliases.iter())
                    .map(|s| s.to_lowercase())
                    .map(move |h| (h.clone(), router.clone()))
            })
            .collect::<papaya::HashMap<String, Arc<Router>>>();

        Self {
            _context: context,
            _certstore,
            routes_by_host,
        }
    }
}

fn to_module_handler(backend: &Backend) -> Option<Box<dyn Handler>> {
    // url => module:://<module_name>
    // The schema/authority correctness is checked in the config module.

    let url = &backend.url;
    let _is_module = url.scheme_str()
        .filter(|&s| s == "module")?;

    let module = url.authority()?
        .as_str();

    match module {
        "metrics" => {
            Some(Box::new(MetricsHandler::new(backend)))
        }

        "static" => {
            Some(Box::new(StaticHandler::new(backend)))
        }

        _ => {
            panic!("Unknown module {module}");
        }
    }
}

// FIXME: Refactor amd make RouterBackend::new()
fn to_router_backend(backend: &Backend) -> RouterBackend {
    RouterBackend {
        config: backend.clone(),
        handler: to_module_handler(backend),
    }
}

fn vhost_to_router(vhost: &Vhost) -> Router {
    let backends = vhost.backends.iter()
        .map(to_router_backend)
        .collect();
    Router::new(backends)
}


#[derive(Clone)]
pub struct VicarianCtx {
    backend: Arc<RouterBackend>,
}

#[async_trait]
impl ProxyHttp for Vicarian {
    type CTX = Option<VicarianCtx>;

    fn new_ctx(&self) -> Self::CTX {
        None
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> pingora_core::Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        debug!("Request: {}", session.req_header().uri);
        counter!(METRIC_TLS_REQUESTS_TOTAL).increment(1);

        let components = to_components(session)?;
        let backend = {
            let pinned = self.routes_by_host.pin();
            let host = components.host.to_string().to_lowercase();
            let router = pinned.get(&host)
                .or_err(E404, "Hostname not found in backends")?;
            router.lookup(components.path)
                .or_err(E404, "Path not found in host backends")?
                .backend
        };

        if let Some(key) = &backend.config.auth_key {
            let auth = session.req_header().headers.get(AUTHORIZATION)
                .or_err(E401, "Failed to fetch Authorization header")?
                .to_str()
                .or_err(E401, "Failed to read Authorization key")?;

            let expected = format!("Bearer {key}");
            if auth != expected {
                counter!(METRIC_AUTH_INVALID_TOTAL).increment(1);
                return Err(pingora_core::Error::explain(E401, "Invalid Authorization header"))
            }

            counter!(METRIC_AUTH_VALID_TOTAL).increment(1);
            info!("Valid auth received for {:?}", backend.config.path);
        }

        match &backend.handler {
            Some(handler) => {
                debug!("Calling custom handler for {}", backend.config.path);
                handler.handle(session).await
                    .map_err(|e| pingora_core::Error::explain(E500, format!("Failed to call handler: {e}")))?;
                Ok(true)
            }
            None => {
                *ctx = Some(VicarianCtx {
                    backend: backend.clone()
                });
                Ok(false)
            }
        }
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> pingora_core::Result<Box<HttpPeer>> {
        let backend = ctx.clone()
            .or_err(E500, "Request context not initialised; shouldn't happen?")?
 .backend;
        let url = &backend.config.url;

        let host = url.host()
            .or_err(E500, "Backend host lookup failed")?;
        let port = url.port()  // TODO: Can default this? Or should be required?
            .or_err(E500, "Backend port lookup failed")?
            .as_u16();

        let tls = url.scheme() == Some(&Scheme::HTTPS);
        let mut peer = HttpPeer::new((host, port), tls, host.to_string());
        if backend.config.trust && let Some(opts) = peer.get_mut_peer_options() {
            opts.verify_cert = false;
        }

        debug!("Using peer: {peer:?}");
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(&self, session: &mut Session,
                                     upstream_request: &mut RequestHeader,
                                     ctx: &mut Self::CTX,)
                                     -> pingora_core::Result<()>
    {
        let backend = ctx.clone()
            .or_err(E500, "Request context not initialised; shouldn't happen?")?
            .backend;

        if backend.config.path != "/"
            && ! backend.config.url.path().starts_with(&backend.config.path)
        {
            debug!("Modifying {} for context {}", upstream_request.uri, backend.config.path);
            let upath = upstream_request.uri.path()
                .strip_prefix(&backend.config.path)
                .unwrap_or("/");
            let uquery = upstream_request.uri.query()
                .map(|s| format!("?{s}"))
                .unwrap_or_default();
            let upq = format!("{upath}{uquery}");
            let uuri = Uri::builder()
                .path_and_query(upq)
                .build()
                .or_err(E500, "Failed to rewrite path")?;
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

    async fn upstream_response_filter(&self, _session: &mut Session,
                                      upstream_response: &mut ResponseHeader,
                                      ctx: &mut Self::CTX)
                                      -> pingora_core::Result<()>
    {
        let backend = ctx.clone()
            .or_err(E500, "Request context not initialised; shouldn't happen?")?
            .backend;

        if backend.config.path != "/"
            && ! backend.config.url.path().starts_with(&backend.config.path)
        {
            for headername in [LOCATION, REFRESH] {
                let header_p = upstream_response.headers.get(&headername);
                if let Some(header) = header_p {
                    let oldloc = header.to_str()
                        .or_err(E500, "Failed to rewrite location header")?;
                    let newloc = HeaderValue::from_str(&format!("{}{oldloc}", backend.config.path))
                        .or_err(E500, "Failed to rewrite location header")?;

                    debug!("Modifying Location to {newloc:?}");
                    let _old = upstream_response.insert_header(&headername, newloc);
                }
            }
        }

        Ok(())
    }

    async fn response_filter(&self, session: &mut Session,
                             upstream_response: &mut ResponseHeader,
                             _ctx: &mut Self::CTX)
                             -> pingora_core::Result<()>
    {
        if let Some(comp_mod) = session.downstream_modules_ctx.get_mut::<ResponseCompression>() {
            if is_compressible(&upstream_response.headers) {
                comp_mod.adjust_level(3);
                let req_header = session.downstream_session.req_header();
                comp_mod.request_filter(req_header);
            } else {
                comp_mod.adjust_level(0);
            }
        }

        let hsts = format!("max-age={YEAR_IN_SECS}; includeSubDomains");
        upstream_response.insert_header(STRICT_TRANSPORT_SECURITY, hsts)?;

        let via = format!("{:?} Vicarian", session.req_header().version);
        upstream_response.insert_header(VIA, via)?;

        Ok(())
    }

}

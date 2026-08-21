use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderValue, header::{STRICT_TRANSPORT_SECURITY, VIA}};
use http_body_util::BodyExt;
use pingora_core::OrErr;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use static_web_server::handler::{
    RequestHandler as SWSHandler, RequestHandlerOpts as SWSHandlerOpts,
};

use crate::{config::Backend, proxy::{E500, Handler}};

// TODO: Should be own top-level module (like metrics)?

pub struct StaticHandler {
    sws_handler: SWSHandler,
}

impl StaticHandler {
    pub fn new(backend: &Backend) -> Self {
        let static_root = backend.static_root.clone()
            .expect("No static root; should be caught in config")
            .join("index.html");
        let fallback_page = std::fs::read(&static_root)
            .unwrap_or_else(|_| Vec::new());
        let opts = Arc::new(SWSHandlerOpts{
            root_dir: backend.static_root.clone()
                .expect("No static root; should be caught in config")
                .into_std_path_buf(),
            compression: true,
            dir_listing: true,
            page_fallback: fallback_page,
            redirect_trailing_slash: true,
            ..Default::default()
        });
        Self {
            sws_handler: SWSHandler {
                opts,
            },
        }
    }
}

#[async_trait]
impl Handler for StaticHandler {
    async fn handle(&self, session: &mut Session) -> Result<()> {

        // FIXME: Check length
        let parts = session.req_header().as_owned_parts();
        let is_head = parts.method == http::Method::HEAD;

        let mut req = hyper::Request::from_parts(parts, static_web_server::body::empty());
        let resp = self.sws_handler.handle(&mut req, None).await
            .or_err(E500, "Failed to retrieve static file")?;

        let (rparts, mut body) = resp.into_parts();
        let mut header = ResponseHeader::from(rparts);
        header.insert_header(VIA, HeaderValue::from_static("1.1 Vicarian"))?;
        header.insert_header(STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000; includeSubDomains"))?;

        session.write_response_header(Box::new(header), false).await?;

        if !is_head {
            while let Some(frame) = body.frame().await {
                let data = frame.or_err(E500, "Failed to read static body")?;
                if let Some(bref) = data.data_ref() {
                    let bytes = bref.to_owned();
                    session.write_response_body(bytes.into(), false).await?;
                }
            }
        }
        session.write_response_body(Bytes::new().into(), true).await?;

        Ok(())
    }
}


mod certificates;

use std::str::FromStr;

use anyhow::Result;
use async_trait::async_trait;
use pingora::{
    http::RequestHeader,
    listeners::tls::TlsSettings,
    prelude::HttpPeer,
    proxy::{http_proxy_service, ProxyHttp, Session},
    server::Server,
};
use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

use crate::certificates::Callbacks;


const TEST_HOSTS: [&str; 2] = ["dvalinn.haltcondition.net", "adguard.haltcondition.net"];


fn init_logging(level: &Option<String>) -> anyhow::Result<()> {
    let lf = level.clone()
        .map(|s| LevelFilter::from_str(&s).expect("Invalid log string"))
        .unwrap_or(LevelFilter::INFO);

    let env_log = EnvFilter::builder()
        .with_default_directive(lf.into())
        .from_env_lossy();

    tracing_log::LogTracer::init()?;
    let fmt = tracing_subscriber::fmt()
        .with_env_filter(env_log)
        .finish();
    tracing::subscriber::set_global_default(fmt)?;

    Ok(())
}

struct Proxeny {
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


fn main() -> Result<()> {
    init_logging(&Some("info".to_string()))?;
    info!("Starting");

    let mut server = Server::new(None)?;
    server.bootstrap();

    let mut proxy = http_proxy_service(&server.configuration, Proxeny {});
    proxy.add_tcp("0.0.0.0:8080");

    let acc = Callbacks::new(Vec::from(TEST_HOSTS))?;
    let tls_settings = TlsSettings::with_callbacks(Box::new(acc))?;

    proxy.add_tls_with_settings("0.0.0.0:8443", None, tls_settings);

    server.add_service(proxy);

    server.run_forever();
}

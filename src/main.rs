
use async_trait::async_trait;
use pingora::{http::RequestHeader, prelude::HttpPeer, proxy::{http_proxy_service, ProxyHttp, Session}, server::Server, Result};


fn main() -> Result<()> {
    let mut server = Server::new(None)?;
    server.bootstrap();

    let mut proxy = http_proxy_service(&server.configuration, Proxeny);
    proxy.add_tcp("0.0.0.0:8080");

    server.add_service(proxy);

    server.run_forever();
}

struct Proxeny;

#[async_trait]
impl ProxyHttp for Proxeny {
    type CTX = ();

    fn new_ctx(&self) -> () {
        ()
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX
    ) -> Result<Box<HttpPeer>>
    {
        let peer = HttpPeer::new("192.168.42.201:5000", false, "frigate.haltcondition.net".to_string());
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        upstream_request.insert_header("Host", "frigate.haltcondition.net")?;
        Ok(())
    }

}

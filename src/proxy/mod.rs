mod cleartext;
mod mimetypes;
mod router;
mod services;
mod r#static;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use http::StatusCode;
use pingora_core::{
    ErrorType, listeners::tls::TlsSettings, server::Server as PingoraServer,
    services::listening::Service,
};
use pingora_proxy::Session;
use tracing::info;

use crate::{
    RunContext,
    certificates::{CertificateRuntime, handler::CertHandler},
    config::{AcmeChallenge, TlsAcmeConfig, TlsConfig},
    proxy::{cleartext::CleartextHandler, services::Vicarian},
};

pub const E401: pingora_core::ErrorType = ErrorType::HTTPStatus(StatusCode::UNAUTHORIZED.as_u16());
pub const E404: pingora_core::ErrorType = ErrorType::HTTPStatus(StatusCode::NOT_FOUND.as_u16());
pub const E500: pingora_core::ErrorType = ErrorType::HTTPStatus(StatusCode::INTERNAL_SERVER_ERROR.as_u16());


#[async_trait]
pub trait Handler: Send + Sync {
    async fn handle(&self, session: &mut Session) -> Result<()>;
}


pub fn run_indefinitely(cert_runtime: Arc<CertificateRuntime>, context: Arc<RunContext>) -> Result<()> {
    info!("Starting Proxy");

    let mut pingora_server = PingoraServer::new(None)?;
    pingora_server.bootstrap();

    let addrs = context.config.listen.addrs()?;

    let vicarian_service = {
        let vicarian = Vicarian::new(cert_runtime.certstore().clone(), context.clone());

        let mut pingora_proxy = pingora_proxy::http_proxy_service(
            &pingora_server.configuration,
            vicarian);

        for addr in &addrs {
            let cert_handler = CertHandler::new(cert_runtime.certstore().clone());
            let mut tls_settings = TlsSettings::with_callbacks(Box::new(cert_handler))?;
            tls_settings.enable_h2();

            let mut addr_port = *addr;
            addr_port.set_port(context.config.listen.tls_port);
            let addr_port = addr_port.to_string();
            info!("Binding to {addr_port}");
            pingora_proxy.add_tls_with_settings(&addr_port, None, tls_settings);

        }
        pingora_proxy
    };
    pingora_server.add_service(vicarian_service);

    let has_http01 = context.config.vhosts.iter()
        .any(|vh| matches!(vh.tls, TlsConfig::Acme(
            TlsAcmeConfig { challenge: AcmeChallenge::Http01, .. })));

    if has_http01 || context.config.listen.insecure_port.is_some() {
        let insecure_port = context.config.listen.insecure_port
            .unwrap_or(80);

        let redirector = CleartextHandler::new(cert_runtime.acme().clone(), context.config.listen.tls_port);
        let mut service = Service::new("HTTP->HTTPS Redirector".to_string(), redirector);

        for addr in &addrs {
            let mut addr_port = *addr;
            addr_port.set_port(insecure_port);
            let addr_port = addr_port.to_string();
            info!("Binding to {addr_port}");
            service.add_tcp(&addr_port);
        }
        pingora_server.add_service(service);
    };

    pingora_server.run(pingora_core::server::RunArgs::default());

    Ok(())
}

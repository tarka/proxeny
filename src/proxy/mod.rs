mod router;
mod services;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use pingora_core::{
    listeners::tls::TlsSettings,
    services::listening::Service,
    server::Server as PingoraServer,
};
use tracing::info;

use crate::{
    certificates::{
        acme::AcmeRuntime, handler::CertHandler, store::CertStore
    },
    proxy::services::{
        CleartextHandler, Vicarian
    }, RunContext
};


pub fn run_indefinitely(certstore: Arc<CertStore>, acme: Arc<AcmeRuntime>, context: Arc<RunContext>) -> anyhow::Result<()> {
    info!("Starting Proxy");

    let mut pingora_server = PingoraServer::new(None)?;
    pingora_server.bootstrap();

    // TODO: Currently single-server; support vhosts here in the future?

    let tls_proxy = {
        let vicarian = Vicarian::new(certstore.clone(), context.clone());

        let mut pingora_proxy = pingora_proxy::http_proxy_service(
            &pingora_server.configuration,
            vicarian);

        let cert_handler = CertHandler::new(certstore.clone());
        let tls_settings = TlsSettings::with_callbacks(Box::new(cert_handler))?;

        // TODO: Listen on specific IP/interface
        let addr = format!("{}:{}", context.config.listen.addr, context.config.listen.tls_port);
        pingora_proxy.add_tls_with_settings(&addr, None, tls_settings);
        pingora_proxy
    };
    pingora_server.add_service(tls_proxy);

    if let Some(insecure) = &context.config.vhosts[0].insecure // FIXME
        && insecure.redirect
    {
        let redirector = CleartextHandler::new(acme, context.config.listen.tls_port);
        let mut service = Service::new("HTTP->HTTPS Redirector".to_string(), redirector);
        let addr = format!("{}:{}", context.config.listen.addr, context.config.listen.insecure_port);
        service.add_tcp(&addr);
        pingora_server.add_service(service);
    };
    pingora_server.run(pingora_core::server::RunArgs::default());

    Ok(())
}

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

fn strip_port(host_header: &str) -> &str {
    if let Some(i) = host_header.rfind(':') {
        &host_header[0..i]
    } else {
        host_header
    }
}

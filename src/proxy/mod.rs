
mod router;
mod services;

use std::sync::Arc;

use pingora_core::{
    listeners::tls::TlsSettings,
    services::listening::Service,
    server::Server as PingoraServer,
};
use tracing::info;

use crate::{
    certificates::{
        handler::CertHandler,
        store::CertStore
    },
    config::Config,
    proxy::services::{
        Proxeny,
        TlsRedirector
    }
};


pub fn run_indefinitely(certstore: Arc<CertStore>, config: Arc<Config>) -> anyhow::Result<()> {
    info!("Starting Proxy");

    let mut pingora_server = PingoraServer::new(None)?;
    pingora_server.bootstrap();

    // TODO: Currently single-server; support vhosts here in the future?

    let tls_proxy = {
        let proxeny = Proxeny::new(certstore.clone(), config.clone());

        let mut pingora_proxy = pingora_proxy::http_proxy_service(
            &pingora_server.configuration,
            proxeny);

        let cert_handler = CertHandler::new(certstore.clone());
        let tls_settings = TlsSettings::with_callbacks(Box::new(cert_handler))?;

        // TODO: Listen on specific IP/interface
        let addr = format!("{}:{}", config.listen, config.tls.port);
        pingora_proxy.add_tls_with_settings(&addr, None, tls_settings);
        pingora_proxy
    };
    pingora_server.add_service(tls_proxy);


    if let Some(insecure) = &config.insecure
        && insecure.redirect
    {
        let redirector = TlsRedirector::new(config.tls.port);
        let mut service = Service::new("HTTP->HTTPS Redirector".to_string(), redirector);
        let addr = format!("{}:{}", config.listen, insecure.port);
        service.add_tcp(&addr);
        pingora_server.add_service(service);
    };
    pingora_server.run(pingora_core::server::RunArgs::default());

    Ok(())
}

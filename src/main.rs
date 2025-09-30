
use std::str::FromStr;

use anyhow::{bail, Result};
use async_trait::async_trait;
use pingora::{
    http::RequestHeader,
    listeners::{tls::TlsSettings, TlsAccept},
    prelude::HttpPeer,
    protocols::tls::TlsRef,
    proxy::{http_proxy_service, ProxyHttp, Session},
    server::Server,
    tls::{pkey::{PKey, Private}, ssl::NameType, x509::X509}
};
use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

const TEST_HOSTS: [&str; 2] = ["dvalinn.haltcondition.net", "adguard.haltcondition.net"];
const TEST_DIR: &str = "tests/data/certs/acme";


struct HostCertificate {
    key: PKey<Private>,
    certs: Vec<X509>,
}

struct Callbacks {
    certmap: papaya::HashMap<String, HostCertificate>,
}

fn load_cert_files(host: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let keyfile = std::fs::read(format!("{TEST_DIR}/{host}.key"))?;
    let certfile = std::fs::read(format!("{TEST_DIR}/{host}.crt"))?;

    Ok((keyfile, certfile))
}

fn from_files(keyfile: Vec<u8>, certfile: Vec<u8>) -> Result<HostCertificate> {
    let key = PKey::private_key_from_pem(&keyfile)?;
    let certs = X509::stack_from_pem(&certfile)?;
    if certs.is_empty() {
        bail!("No certificates found in TLS .crt file");
    }

    let hostcert = HostCertificate { key, certs };

    Ok(hostcert)
}


impl Callbacks {
    fn new(hosts: Vec<&str>) -> Result<Self> {
        info!("Loading host certificates");

        let certmap = hosts.iter()
            .map(|h| {
                let (k, c) = load_cert_files(h)?;
                let cert = from_files(k, c)?;
                Ok((h.to_string(), cert))
            })
            .collect::<Result<papaya::HashMap<_, _>>>()?;

        info!("Loaded certificates");

        Ok(Callbacks { certmap })
    }

}

#[async_trait]
impl TlsAccept for Callbacks {

    // NOTE:This is all boringssl specific as pingora doesn't have
    // support for dynamic certs with rustls.
    async fn certificate_callback(&self, ssl: &mut TlsRef) -> () {
        let host = ssl.servername(NameType::HOST_NAME)
            .expect("No servername in TLS handshake");

        info!("TLS Host is {host}; loading certs");

        //        let cert = load_cert(host).await.unwrap();
        let amap = self.certmap.pin_owned();
        let cert = amap.get(&host.to_string())
            .expect("Certificate for host not found");

        ssl.set_private_key(&cert.key)
            .expect("Failed to set private key");
        ssl.set_certificate(&cert.certs[0])
            .expect("Failed to set certificate");

        if cert.certs.len() > 1 {
            for c in cert.certs[1..].iter() {
                ssl.add_chain_cert(&c)
                    .expect("Failed to add chain certificate");
            }
        }
    }

}

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

fn main() -> Result<()> {
    init_logging(&Some("info".to_string()))?;
    info!("Starting");

    let mut server = Server::new(None)?;
    server.bootstrap();

    let mut proxy = http_proxy_service(&server.configuration, Proxeny);
    proxy.add_tcp("0.0.0.0:8080");

    let acc = Callbacks::new(Vec::from(TEST_HOSTS))?;
    let tls_settings = TlsSettings::with_callbacks(Box::new(acc))?;

    proxy.add_tls_with_settings("0.0.0.0:8443", None, tls_settings);

//    proxy.add_tls("0.0.0.0:8443", "tests/data/certs/acme/test.crt", "tests/data/certs/acme/test.key")?;

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

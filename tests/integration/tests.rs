
use reqwest::{Client, redirect};
use serial_test::serial;

use crate::util::{INSECURE_PORT, ProxyBuilder, TLS_PORT, mkcert_root};

// NOTE: We use unwrap rather than result here as it save the run
// files on failure (in Proxy::drop()).

#[tokio::test]
#[serial]
async fn test_redirect_http() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_simple")
        .run().await.unwrap();

    // Look for a redirect from the non-TLS port.
    let ready = Client::builder()
        .redirect(redirect::Policy::none())
        .build().unwrap()
        .get(format!("http://localhost:{INSECURE_PORT}/status"))
        .send().await.unwrap();

    assert_eq!(301, ready.status().as_u16());
    let loc = ready.headers().get("Location").unwrap()
        .to_str().unwrap().to_string();
    let tls = format!("https://localhost:{TLS_PORT}/status");
    assert_eq!(tls, loc);
}

#[tokio::test]
#[serial]
async fn test_dns_override() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_simple")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = mkcert_root().unwrap();
    let ready = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/status"))
        .send().await.unwrap();

    // No backend, so fails
    assert_eq!(502, ready.status().as_u16());
}

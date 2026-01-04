
use reqwest::{Client, redirect};
use serial_test::serial;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

use crate::util::{BACKEND_PORT, INSECURE_PORT, ProxyBuilder, TLS_PORT, mkcert_root, mock_server};

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
    let root_cert = mkcert_root().await.unwrap();
    let ready = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/status"))
        .send().await.unwrap();

    // No backend, so fails
    assert_eq!(502, ready.status().as_u16());
}

#[tokio::test]
#[serial]
async fn test_mocked_backend() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_simple")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = mkcert_root().await.unwrap();

    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("OK"))
        .mount(&backend_server).await;

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/status"))
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    assert!(response.text().await.unwrap().contains("OK"));
}

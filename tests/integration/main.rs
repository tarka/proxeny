#![cfg(feature = "integration_tests")]

#[path = "../utils/certs.rs"]
mod certutils;
#[path = "../utils/proxy.rs"]
mod proxyutils;
mod static_files;
mod sse;
mod websockets;

use http::header::{AUTHORIZATION, HOST};
use reqwest::{Client, redirect, header::{VIA, LOCATION, STRICT_TRANSPORT_SECURITY}};
use serial_test::serial;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

use proxyutils::{
    BACKEND_PORT, INSECURE_PORT, ProxyBuilder, TLS_PORT, mock_server,
};

use crate::certutils::TEST_CERTS;

// NOTE: We use unwrap rather than result here as we can save the run
// files on failure (see Proxy::drop()).
//
// Tests run serially currently as we use the same port across runs
// for simplicity. Once we have more tests we may need to look into
// parallelising. This is also configured for `nextest` under
// $CRATE/.config/nextest.toml

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
    let root_cert = TEST_CERTS.caroot.reqcert.clone();
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
        .with_simple_config("localhost_simple")
        .run().await.unwrap();

    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("OK"))
        .mount(&backend_server).await;

    let response = Client::builder()
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://localhost:{TLS_PORT}/status"))
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    assert!(response.text().await.unwrap().contains("OK"));
}

#[tokio::test]
#[serial]
async fn test_mixed_case_host_header() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_simple")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("OK"))
        .mount(&backend_server).await;

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http1_only()
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/status"))
        .header(HOST, "WWW.EXAMPLE.COM")
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    assert!(response.text().await.unwrap().contains("OK"));
}

#[tokio::test]
#[serial]
async fn test_vhosts() {
    let backend_server1 = mock_server(BACKEND_PORT).await.unwrap();
    let backend_server2 = mock_server(BACKEND_PORT+1).await.unwrap();

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_vhosts")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = &TEST_CERTS.caroot.reqcert;

    // www.example.com

    Mock::given(method("GET"))
        .and(path("/host"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("www"))
        .mount(&backend_server1).await;

    let www_response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert.clone())
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/host"))
        .send().await.unwrap();

    assert_eq!(200, www_response.status().as_u16());
    assert!(www_response.text().await.unwrap().contains("www"));

    // test.example.com

    Mock::given(method("GET"))
        .and(path("/host"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("test"))
        .mount(&backend_server2).await;

    let test_response = Client::builder()
        .resolve("test.example.com", example_com)
        .add_root_certificate(root_cert.clone())
        .build().unwrap()
        .get(format!("https://test.example.com:{TLS_PORT}/host"))
        .send().await.unwrap();

    assert_eq!(200, test_response.status().as_u16());
    assert!(test_response.text().await.unwrap().contains("test"));
}


#[tokio::test]
#[serial]
async fn test_invalid_cert() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_simple")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("wrong.example.com", example_com)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://wrong.example.com:{TLS_PORT}/status"))
        .send().await;

    assert!(response.is_err());
}

#[tokio::test]
#[serial]
async fn test_https_headers() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_simple")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

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

    let via = response.headers().get(VIA).unwrap()
        .to_str().unwrap();
    assert!(via.contains("Vicarian"));

    let hsts = response.headers().get(STRICT_TRANSPORT_SECURITY).unwrap()
        .to_str().unwrap();
    assert_eq!("max-age=31536000; includeSubDomains", hsts);
}


#[tokio::test]
#[serial]
async fn test_http1() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_simple")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("OK"))
        .mount(&backend_server).await;

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http1_only()
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/status"))
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());

    let via = response.headers().get(VIA).unwrap()
        .to_str().unwrap();
    assert!(via.contains("Vicarian"));

    let hsts = response.headers().get(STRICT_TRANSPORT_SECURITY).unwrap()
        .to_str().unwrap();
    assert_eq!("max-age=31536000; includeSubDomains", hsts);
}

#[tokio::test]
#[serial]
async fn test_http2() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_simple")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("OK"))
        .mount(&backend_server).await;

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/status"))
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());

    let via = response.headers().get(VIA).unwrap()
        .to_str().unwrap();
    assert!(via.contains("Vicarian"));

    let hsts = response.headers().get(STRICT_TRANSPORT_SECURITY).unwrap()
        .to_str().unwrap();
    assert_eq!("max-age=31536000; includeSubDomains", hsts);
}

#[tokio::test]
#[serial]
async fn test_wildcard() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_wildcard")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("OK"))
        .mount(&backend_server).await;

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/status"))
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());

    let via = response.headers().get(VIA).unwrap()
        .to_str().unwrap();
    assert!(via.contains("Vicarian"));

    let hsts = response.headers().get(STRICT_TRANSPORT_SECURITY).unwrap()
        .to_str().unwrap();
    assert_eq!("max-age=31536000; includeSubDomains", hsts);
}

#[tokio::test]
#[serial]
async fn test_no_wildcard() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_wildcard")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("OK"))
        .mount(&backend_server).await;

    let response = Client::builder()
        .resolve("www.not-example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build().unwrap()
        .get(format!("https://www.not-example.com:{TLS_PORT}/status"))
        .send().await;

    assert!(response.is_err());
}


#[tokio::test]
#[serial]
async fn test_metrics() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_metrics")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/metrics"))
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());

    assert!(response.text().await.unwrap().contains("vicarian_metrics_scrape_total"));
}


#[tokio::test]
#[serial]
async fn test_auth_valid() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_auth")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/metrics"))
        .header(AUTHORIZATION, "Bearer my_auth_key")
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    assert!(response.text().await.unwrap().contains("vicarian_metrics_scrape_total"));
}


#[tokio::test]
#[serial]
async fn test_auth_invalid() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_auth")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/metrics"))
        .header(AUTHORIZATION, "Bearer INVALID_KEY")
        .send().await.unwrap();

    assert_eq!(401, response.status().as_u16());

}

#[tokio::test]
#[serial]
async fn test_auth_missing_header() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_auth")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/metrics"))
        .send().await.unwrap();

    // No Authorization header: should return 401
    assert_eq!(401, response.status().as_u16());
}

#[tokio::test]
#[serial]
async fn test_auth_malformed_headers() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_auth")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let client = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build().unwrap();

    // lowercase bearer prefix: expected to fail since the code checks exact match `Bearer {key}`
    let response = client.get(format!("https://www.example.com:{TLS_PORT}/metrics"))
        .header(AUTHORIZATION, "bearer my_auth_key")
        .send().await.unwrap();
    assert_eq!(401, response.status().as_u16());

    // Basic auth: should fail
    let response = client.get(format!("https://www.example.com:{TLS_PORT}/metrics"))
        .header(AUTHORIZATION, "Basic my_auth_key")
        .send().await.unwrap();
    assert_eq!(401, response.status().as_u16());

    // Just Bearer without key: should fail
    let response = client.get(format!("https://www.example.com:{TLS_PORT}/metrics"))
        .header(AUTHORIZATION, "Bearer")
        .send().await.unwrap();
    assert_eq!(401, response.status().as_u16());

    // Bearer with double spaces: should fail
    let response = client.get(format!("https://www.example.com:{TLS_PORT}/metrics"))
        .header(AUTHORIZATION, "Bearer  my_auth_key")
        .send().await.unwrap();
    assert_eq!(401, response.status().as_u16());
}

#[tokio::test]
#[serial]
async fn test_unknown_host_header() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_simple")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/status"))
        .header(HOST, "unknown.example.com")
        .send().await.unwrap();

    // Host header doesn't match any registered vhost
    assert_eq!(404, response.status().as_u16());
}

#[tokio::test]
#[serial]
async fn test_unknown_backend_path() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_simple")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/invalid-path"))
        .send().await.unwrap();

    // The host is valid, but the backend is only configured for context "/" which should match anything.
    // Since there is no mock server running on 19090 (BACKEND_PORT),
    // it should fail to connect to backend and return 502 Bad Gateway.
    assert_eq!(502, response.status().as_u16());
}

#[tokio::test]
#[serial]
async fn test_http_to_https_redirect_preserves_path_and_query() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_simple")
        .run().await.unwrap();

    let ready = Client::builder()
        .redirect(redirect::Policy::none())
        .build().unwrap()
        .get(format!("http://localhost:{INSECURE_PORT}/foo/bar?baz=qux"))
        .send().await.unwrap();

    assert_eq!(301, ready.status().as_u16());
    let loc = ready.headers().get("Location").unwrap()
        .to_str().unwrap().to_string();
    let expected_tls = format!("https://localhost:{TLS_PORT}/foo/bar?baz=qux");
    assert_eq!(expected_tls, loc);
}

#[tokio::test]
#[serial]
async fn test_http01_not_found() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_simple")
        .run().await.unwrap();

    let response = Client::builder()
        .redirect(redirect::Policy::none())
        .build().unwrap()
        .get(format!("http://localhost:{INSECURE_PORT}/.well-known/acme-challenge/nonexistent"))
        .header(HOST, "www.example.com")
        .send().await.unwrap();

    assert_eq!(404, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.contains("ACME token not found"));
}

#[tokio::test]
#[serial]
async fn test_context_path_rewriting() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    Mock::given(method("GET"))
        .and(path("/some/path"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("rewritten"))
        .mount(&backend_server).await;

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("backend_context")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/api/some/path"))
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert_eq!("rewritten", body);
}

#[tokio::test]
#[serial]
async fn test_method_passthrough() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    Mock::given(method("POST"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("POST"))
        .mount(&backend_server).await;

    Mock::given(method("PUT"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("PUT"))
        .mount(&backend_server).await;

    Mock::given(method("DELETE"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("DELETE"))
        .mount(&backend_server).await;

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("localhost", example_com)
        .add_root_certificate(root_cert.clone())
        .build().unwrap()
        .post(format!("https://localhost:{TLS_PORT}/status"))
        .body("test-body")
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert_eq!("POST", body);

    let response = Client::builder()
        .resolve("localhost", example_com)
        .add_root_certificate(root_cert.clone())
        .build().unwrap()
        .put(format!("https://localhost:{TLS_PORT}/status"))
        .body("put-body")
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert_eq!("PUT", body);

    let response = Client::builder()
        .resolve("localhost", example_com)
        .add_root_certificate(root_cert.clone())
        .build().unwrap()
        .delete(format!("https://localhost:{TLS_PORT}/status"))
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert_eq!("DELETE", body);
}

#[tokio::test]
#[serial]
async fn test_location_header_rewriting() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    Mock::given(method("GET"))
        .and(path("/some/path"))
        .respond_with(ResponseTemplate::new(301)
                      .insert_header(LOCATION, "/new-path"))
        .mount(&backend_server).await;

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("backend_context")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .redirect(redirect::Policy::none())
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/api/some/path"))
        .send().await.unwrap();

    assert_eq!(301, response.status().as_u16());
    let loc = response.headers().get(LOCATION).unwrap()
        .to_str().unwrap();
    assert!(loc.contains("/api/"));
}

#[tokio::test]
#[serial]
async fn test_x_forwarded_headers() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(|request: &wiremock::Request| {
            let xff = request.headers.get("X-Forwarded-For")
                .map(|v| v.to_str().unwrap_or(""))
                .unwrap_or("");
            let xri = request.headers.get("X-Real-IP")
                .map(|v| v.to_str().unwrap_or(""))
                .unwrap_or("");
            ResponseTemplate::new(200)
                .set_body_string(format!("xff={xff},xri={xri}"))
        })
        .mount(&backend_server).await;

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("localhost", example_com)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://localhost:{TLS_PORT}/"))
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    println!("RESP: {body}");

    assert!(body.contains("xff=127.0.0.1")
            || body.contains("xff=::ffff:127.0.0.1"));
    assert!(body.contains("xri=127.0.0.1")
            || body.contains("xri=::ffff:127.0.0.1"));

}

fn _large_body() -> &'static str {
    "The quick brown fox jumps over the lazy dog. "
}

#[tokio::test]
#[serial]
async fn test_compression_gzip_accept_encoding() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let body = _large_body().repeat(100);
    Mock::given(method("GET"))
        .and(path("/compress"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string(body.clone()))
        .mount(&backend_server).await;

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .run().await.unwrap();

    let localhost = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("localhost", localhost)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://localhost:{TLS_PORT}/compress"))
        .header("Accept-Encoding", "gzip")
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    let content_encoding = response.headers().get("Content-Encoding")
        .map(|v| v.to_str().unwrap());
    assert_eq!(Some("gzip"), content_encoding);

    let vary = response.headers().get("Vary")
        .map(|v| v.to_str().unwrap().to_lowercase());
    assert!(vary.is_some());
    assert!(vary.unwrap().contains("accept-encoding"));
}

#[tokio::test]
#[serial]
async fn test_compression_brotli_accept_encoding() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let body = _large_body().repeat(100);
    Mock::given(method("GET"))
        .and(path("/compress"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string(body.clone()))
        .mount(&backend_server).await;

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .run().await.unwrap();

    let localhost = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("localhost", localhost)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://localhost:{TLS_PORT}/compress"))
        .header("Accept-Encoding", "br")
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    let content_encoding = response.headers().get("Content-Encoding")
        .map(|v| v.to_str().unwrap());
    assert_eq!(Some("br"), content_encoding);

    let vary = response.headers().get("Vary")
        .map(|v| v.to_str().unwrap().to_lowercase());
    assert!(vary.is_some());
    assert!(vary.unwrap().contains("accept-encoding"));
}

#[tokio::test]
#[serial]
async fn test_compression_prefers_best_encoding() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let body = _large_body().repeat(100);
    Mock::given(method("GET"))
        .and(path("/compress"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string(body.clone()))
        .mount(&backend_server).await;

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .run().await.unwrap();

    let localhost = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("localhost", localhost)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://localhost:{TLS_PORT}/compress"))
        .header("Accept-Encoding", "gzip, br, zstd")
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    let content_encoding = response.headers().get("Content-Encoding")
        .map(|v| v.to_str().unwrap());
    assert!(matches!(content_encoding, Some("gzip") | Some("br") | Some("zstd")));

    let vary = response.headers().get("Vary")
        .map(|v| v.to_str().unwrap().to_lowercase());
    assert!(vary.is_some());
    assert!(vary.unwrap().contains("accept-encoding"));
}

#[tokio::test]
#[serial]
async fn test_no_compression_without_accept_encoding() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let body = _large_body().repeat(100);
    Mock::given(method("GET"))
        .and(path("/compress"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string(body.clone()))
        .mount(&backend_server).await;

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .run().await.unwrap();

    let localhost = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("localhost", localhost)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://localhost:{TLS_PORT}/compress"))
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    let content_encoding = response.headers().get("Content-Encoding");
    assert!(content_encoding.is_none());
}

#[tokio::test]
#[serial]
async fn test_no_compression_empty_accept_encoding() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let body = _large_body().repeat(100);
    Mock::given(method("GET"))
        .and(path("/compress"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string(body.clone()))
        .mount(&backend_server).await;

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .run().await.unwrap();

    let localhost = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("localhost", localhost)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://localhost:{TLS_PORT}/compress"))
        .header("Accept-Encoding", "")
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    let content_encoding = response.headers().get("Content-Encoding");
    assert!(content_encoding.is_none());
}

#[tokio::test]
#[serial]
async fn test_compression_unsupported_encoding() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let body = _large_body().repeat(100);
    Mock::given(method("GET"))
        .and(path("/compress"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string(body.clone()))
        .mount(&backend_server).await;

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .run().await.unwrap();

    let localhost = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("localhost", localhost)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://localhost:{TLS_PORT}/compress"))
        .header("Accept-Encoding", "deflate")
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    let content_encoding = response.headers().get("Content-Encoding");
    assert!(content_encoding.is_none());
}

#[tokio::test]
#[serial]
async fn test_compression_small_body_not_compressed() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    Mock::given(method("GET"))
        .and(path("/small"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("OK"))
        .mount(&backend_server).await;

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .run().await.unwrap();

    let localhost = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("localhost", localhost)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://localhost:{TLS_PORT}/small"))
        .header("Accept-Encoding", "gzip")
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    let content_encoding = response.headers().get("Content-Encoding");
    assert!(content_encoding.is_none());
}

#[tokio::test]
#[serial]
async fn test_compression_preserves_vicarian_headers() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let body = _large_body().repeat(100);
    Mock::given(method("GET"))
        .and(path("/compress"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string(body.clone()))
        .mount(&backend_server).await;

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .run().await.unwrap();

    let localhost = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("localhost", localhost)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://localhost:{TLS_PORT}/compress"))
        .header("Accept-Encoding", "gzip")
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    assert_eq!(Some("gzip"), response.headers().get("Content-Encoding")
        .map(|v| v.to_str().unwrap()));

    let via = response.headers().get(VIA)
        .map(|v| v.to_str().unwrap());
    assert!(via.is_some());
    assert!(via.unwrap().contains("Vicarian"));

    let hsts = response.headers().get(STRICT_TRANSPORT_SECURITY)
        .map(|v| v.to_str().unwrap());
    assert_eq!(Some("max-age=31536000; includeSubDomains"), hsts);
}

#[tokio::test]
#[serial]
async fn test_compression_preserves_body_content() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let body = _large_body().repeat(100);
    Mock::given(method("GET"))
        .and(path("/compress"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string(body.clone()))
        .mount(&backend_server).await;

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .run().await.unwrap();

    let localhost = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("localhost", localhost)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://localhost:{TLS_PORT}/compress"))
        .header("Accept-Encoding", "gzip")
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    // reqwest with default-features=false does not auto-decompress,
    // so the body should be compressed and different from the original.
    let response_body = response.text().await.unwrap();
    assert_ne!(body, response_body);
    // The compressed body should be shorter than the original.
    assert!(response_body.len() < body.len());
}

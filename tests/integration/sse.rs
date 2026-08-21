use std::time::{Duration, Instant};

use http::header::{CACHE_CONTROL, CONTENT_ENCODING, CONTENT_TYPE};
use reqwest::Client;
use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wiremock::{Mock, ResponseTemplate, matchers::{method, path}};

use crate::certutils::TEST_CERTS;
use crate::proxyutils::{BACKEND_PORT, ProxyBuilder, TLS_PORT, mock_server};

const SSE_EVENTS: u32 = 3;
const SSE_EVENT_DELAY: Duration = Duration::from_millis(500);

/// Minimal HTTP/1.1 backend that answers any request with an SSE stream:
/// `SSE_EVENTS` events spaced `SSE_EVENT_DELAY` apart, sent with chunked
/// transfer encoding and no Content-Length.
async fn sse_backend(listener: TcpListener) {
    loop {
        let (mut stream, _addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => return, // listener closed
        };
        tokio::spawn(async move {
            let _ = serve_sse(&mut stream).await;
        });
    }
}

async fn serve_sse(stream: &mut TcpStream) -> std::io::Result<()> {
    // Consume the request head.
    let mut buf = [0u8; 1024];
    let mut head = Vec::new();
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..n]);
    }

    stream.write_all(b"HTTP/1.1 200 OK\r\n").await?;
    stream.write_all(b"Content-Type: text/event-stream\r\n").await?;
    stream.write_all(b"Cache-Control: no-cache\r\n").await?;
    stream.write_all(b"Transfer-Encoding: chunked\r\n").await?;
    stream.write_all(b"\r\n").await?;
    stream.flush().await?;

    for i in 0..SSE_EVENTS {
        let event = format!("data: event-{i}\n\n");
        let framed = format!("{:x}\r\n{event}\r\n", event.len());
        stream.write_all(framed.as_bytes()).await?;
        stream.flush().await?;
        tokio::time::sleep(SSE_EVENT_DELAY).await;
    }

    stream.write_all(b"0\r\n\r\n").await?;
    stream.flush().await?;
    Ok(())
}

/// Read an SSE response body chunk-by-chunk, returning the time the first
/// chunk arrived, the total stream duration, and the full body.
async fn read_sse_stream(response: reqwest::Response) -> (Duration, Duration, String) {
    let mut response = response;
    let start = Instant::now();

    let mut first_at = None;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.unwrap() {
        if first_at.is_none() {
            first_at = Some(start.elapsed());
        }
        body.extend_from_slice(&chunk);
    }

    let first_at = first_at.expect("SSE stream ended without sending any data");
    (first_at, start.elapsed(), String::from_utf8(body).unwrap())
}

async fn sse_streaming_check(http2: bool) {
    let listener = TcpListener::bind(format!("127.0.0.1:{BACKEND_PORT}")).await.unwrap();
    tokio::spawn(sse_backend(listener));

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .run().await.unwrap();

    let localhost = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let mut builder = Client::builder()
        .resolve("localhost", localhost)
        .add_root_certificate(root_cert);
    if http2 {
        builder = builder.http2_prior_knowledge();
    } else {
        builder = builder.http1_only();
    }

    let response = builder.build().unwrap()
        .get(format!("https://localhost:{TLS_PORT}/events"))
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());

    // The event-stream content type must pass through unchanged.
    let content_type = response.headers().get(CONTENT_TYPE)
        .map(|v| v.to_str().unwrap()).unwrap_or("");
    assert_eq!("text/event-stream", content_type);

    // Backend headers must pass through unchanged.
    let cache_control = response.headers().get(CACHE_CONTROL)
        .map(|v| v.to_str().unwrap()).unwrap_or("");
    assert_eq!("no-cache", cache_control);

    let (first_at, total, body) = read_sse_stream(response).await;

    let expected = (0..SSE_EVENTS)
        .map(|i| format!("data: event-{i}\n\n"))
        .collect::<String>();
    assert_eq!(expected, body);

    // The backend spaces events SSE_EVENT_DELAY apart, so the full stream
    // takes at least SSE_EVENTS * SSE_EVENT_DELAY.
    assert!(total >= SSE_EVENT_DELAY * SSE_EVENTS,
            "stream finished in {total:?}; expected at least {:?}",
            SSE_EVENT_DELAY * SSE_EVENTS);

    // If the proxy buffered the response, the first byte would only arrive
    // once the whole stream had completed.
    assert!(first_at < total / 2,
            "first event arrived after {first_at:?} of {total:?}; proxy is buffering the SSE stream");
}

#[tokio::test]
#[serial]
async fn test_sse_streaming_not_buffered() {
    sse_streaming_check(false).await;
}

#[tokio::test]
#[serial]
async fn test_sse_streaming_http2() {
    sse_streaming_check(true).await;
}

#[tokio::test]
#[serial]
async fn test_sse_not_compressed() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let body = "data: event-0\n\n".repeat(100);
    Mock::given(method("GET"))
        .and(path("/events"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_raw(body.clone(), "text/event-stream")
                      .insert_header("Cache-Control", "no-cache"))
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
        .get(format!("https://localhost:{TLS_PORT}/events"))
        .header("Accept-Encoding", "gzip, br, zstd")
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());

    // SSE streams must not be compressed: the compressor buffers events
    // and breaks real-time delivery.
    let content_encoding = response.headers().get(CONTENT_ENCODING);
    assert!(content_encoding.is_none(),
            "SSE response must not be compressed, got {content_encoding:?}");

    let body = response.text().await.unwrap();
    assert!(body.starts_with("data: event-0"));
}

#[tokio::test]
#[serial]
async fn test_sse_client_disconnect() {
    let listener = TcpListener::bind(format!("127.0.0.1:{BACKEND_PORT}")).await.unwrap();
    tokio::spawn(sse_backend(listener));

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .run().await.unwrap();

    let localhost = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let client = Client::builder()
        .resolve("localhost", localhost)
        .add_root_certificate(root_cert)
        .http1_only()
        .build().unwrap();

    // Open a stream, read the first event, then disconnect abruptly.
    let response = client
        .get(format!("https://localhost:{TLS_PORT}/events"))
        .send().await.unwrap();
    assert_eq!(200, response.status().as_u16());
    let mut response = response;
    let first = response.chunk().await.unwrap();
    assert!(first.is_some());
    drop(response);

    // The proxy must survive the aborted stream and keep serving.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let response = client
        .get(format!("https://localhost:{TLS_PORT}/events"))
        .send().await.unwrap();
    assert_eq!(200, response.status().as_u16());
    let (_first_at, _total, body) = read_sse_stream(response).await;
    assert!(body.contains("data: event-0"));
}

use anyhow::Result;
use http::{uri::Builder, Uri};
use test_log::test;

use crate::{config::Backend, proxy::{rewrite_port, router::Router, strip_port}};

#[test]
fn test_uri_rewrite() -> Result<()> {
    let uri = Uri::from_static("http://example.com/a/path?param=value");
    let changed = Builder::from(uri)
        .scheme("https")
        .build()?;
    assert_eq!("https://example.com/a/path?param=value", changed.to_string());
    Ok(())
}

#[test]
fn test_host_port_rewrite() -> Result<()> {
    let replaced = rewrite_port("example.com:8080", "8443");
    assert_eq!("example.com:8443", replaced);
    let replaced = rewrite_port("example.com", "8443");
    assert_eq!("example.com", replaced);
    Ok(())
}

#[test]
fn test_port_strip() -> Result<()> {
    let host_header = "example.com:8443";
    let host = strip_port(host_header);
    assert_eq!("example.com", host);

    Ok(())
}

#[test]
fn test_no_port_strip() -> Result<()> {
    let host_header = "example.com";
    let host = strip_port(host_header);
    assert_eq!("example.com", host);

    Ok(())
}


#[test]
fn test_router() -> Result<()> {
    let backends = vec![
        Backend {
            context: None,
            url: Uri::from_static("http://localhost:1010")
        },
        Backend {
            context: Some("/service".to_string()),
            url: Uri::from_static("http://localhost:2020")
        },
        Backend {
            context: Some("/service/subservice/".to_string()),
            url: Uri::from_static("http://localhost:3030")
        },
        Backend {
            context: Some("/other_service/".to_string()),
            url: Uri::from_static("http://localhost:4040")
        },
    ];

    let router = Router::new(&backends);

    let matched = router.lookup("/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("", matched._path);

    let matched = router.lookup("/base/path").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("base/path", matched._path);

    let matched = router.lookup("/service").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
    assert_eq!("", matched._path);

    let matched = router.lookup("/service/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
    assert_eq!("/", matched._path);

    let matched = router.lookup("/service/some/path").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
    assert_eq!("/some/path", matched._path);

    let matched = router.lookup("/service/subservice").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.url);
    assert_eq!("", matched._path);

    let matched = router.lookup("/service/subservice/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.url);
    assert_eq!("/", matched._path);

    let matched = router.lookup("/service/subservice/ss/path").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.url);
    assert_eq!("/ss/path", matched._path);

    let matched = router.lookup("/other_service/some/path").unwrap();
    assert_eq!(Uri::from_static("http://localhost:4040"), matched.backend.url);
    assert_eq!("/some/path", matched._path);

    Ok(())
}


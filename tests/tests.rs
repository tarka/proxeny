mod util;


use anyhow::Result;
use reqwest::{blocking::Client, redirect};
use serial_test::serial;
use test_log::test;

use crate::util::{ProxyBuilder, INSECURE_PORT, TLS_PORT};

#[cfg_attr(not(feature = "integration_tests"), ignore = "Integration Test")]
#[test]
#[serial]
fn test_redirect_http() -> Result<()> {
    let mut _proxy = ProxyBuilder::new()
        .with_simple_config("example_com_simple")
        .run()?;
    _proxy.keep_files();

    // Look for a redirect from the non-TLS port.
    let ready = Client::builder()
                .redirect(redirect::Policy::none())
                .build().unwrap()
                .get(format!("http://localhost:{INSECURE_PORT}/status"))
                .send()?;

    assert_eq!(301, ready.status().as_u16());
    let loc = ready.headers().get("Location").unwrap()
        .to_str()?.to_string();
    let tls = format!("https://localhost:{TLS_PORT}/status");
    assert_eq!(tls, loc);

    Ok(())
}

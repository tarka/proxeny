mod util;


use anyhow::Result;
use test_log::test;

use crate::util::Proxy;

#[cfg_attr(not(feature = "integration_tests"), ignore = "Integration Test")]
#[test]
fn test_redirect_http() -> Result<()> {
    // let mut proxy = Proxy::new()
    //     .with_simple_config("example_com_simple")
    //     .run()?;
    // proxy.keep_files();

    Ok(())
}

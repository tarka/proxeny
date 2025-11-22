mod util;


use anyhow::Result;
use test_context::test_context;
use test_log::test;

use crate::util::IntegrationTest;

#[test_context(IntegrationTest)]
#[test]
fn test_fetch_port(_ctx: &IntegrationTest) -> Result<()> {
    //    println!("Port is {}", ctx.proxy_port);
    Ok(())
}

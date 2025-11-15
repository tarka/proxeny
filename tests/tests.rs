
mod util;

use std::process::Child;

use anyhow::Result;
use test_context::{TestContext, test_context};

use crate::util::{run_proxy, stop_child, wait_port};

struct IntegrationTest {
    proxy: Child,
    proxy_port: u16,
}

impl TestContext for IntegrationTest {
    fn setup() -> Self {
        let proxy = run_proxy().expect("Failed to start proxy");
        let proxy_port = wait_port(&proxy).expect("Failed to find proxy port");
        Self {
            proxy,
            proxy_port,
        }
    }

    fn teardown(self) {
        stop_child(&self.proxy).unwrap();
    }
}

#[test_context(IntegrationTest)]
#[test_log::test]
fn test_fetch_port(ctx: &IntegrationTest) -> Result<()> {
    println!("Port is {}", ctx.proxy_port);
    Ok(())
}

use std::{net::{IpAddr, SocketAddr}, process::{Child, Command}, sync::{Arc, LazyLock, OnceLock}};
use std::thread;
use std::time::Duration;

use anyhow::{Result, bail};
use axum::extract::State;
use axum::{routing, Json, Router};
use ctor::dtor;
use nix::{sys::signal::{Signal, kill}, unistd::Pid};
use procfs::{
    process::{FDTarget, Process},
    net::{tcp as tcp_table, tcp6 as tcp6_table}
};
use test_context::TestContext;
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    Notify,
};
use tokio::task::JoinHandle;
use tokio::{fs::read_to_string, time::sleep};
use tracing_log::log::info;

static PROXY: OnceLock<Child> = OnceLock::new();

const PROXY_PORT: u16 = 8080;
const PROXY_TLS_PORT: u16 = 8443;

pub fn run_proxy() -> Result<&'static Child> {
    let child = PROXY.get_or_init(|| {
        info!("Starting proxy");
        let exe = env!("CARGO_BIN_EXE_proxeny");

        let child = Command::new(exe)
            .arg("-vv")
            .arg("-c").arg("tests/proxeny.corn")
            .spawn()
            .expect("Failed to start proxy");
        child
    });

    for _ in 0..20 { // 2 second timeout
        let ready = reqwest::blocking::get(format!("http://localhost:{PROXY_PORT}/status"));
        println!("READY: {ready:#?}");
        let ready = ready.is_ok_and(|r| r.status().as_u16() == 301);
        if ready {
            return Ok(child);
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("Failed to start proxy server")
}

#[dtor]
fn proxy_cleanup() {
    child_cleanup(PROXY.get());
}

fn child_cleanup(possible_child: Option<&Child>) {
    // Make sure the server is shut down. This is a little hacky, but
    // seems to be the only reliable method for a global processs in
    // rust tests.
    if let Some(child) = possible_child {
        let pid = Pid::from_raw(child.id().try_into().unwrap());
        kill(pid, Signal::SIGINT).unwrap();
        // Last as we don't know if stdout will work
        println!("Killed process {}", pid);
    }
}

// pub fn stop_child(child: &Child) -> Result<()> {
//     let pid = Pid::from_raw(child.id().try_into()?);
//     kill(pid, Signal::SIGINT)?;
//     Ok(())
// }

pub struct IntegrationTest {
    pub proxy: &'static Child,
}

impl TestContext for IntegrationTest {
    fn setup() -> Self {
        let proxy = run_proxy()
            .expect("Failed to get proxy process");
        Self {
            proxy: &proxy,
        }
    }

    fn teardown(self) {
    }
}


// pub struct MockBackend {
//     pub handle: JoinHandle<Result<(), std::io::Error>>,
//     pub msgs: Receiver<String>,
//     pub quit: Arc<Notify>,
// }

// impl MockBackend {
//     pub async fn new() -> Result<MockBackend> {
//         let ip: IpAddr = "0.0.0.0".parse()?;
//         let addr = SocketAddr::from((ip, 9090));

//         let quit = Arc::new(Notify::new());
//         let server_quit = quit.clone();

//         let (tx, rx) = mpsc::channel(8);
//         let tstate = TelegramState {
//             recvd_msgs: tx,
//             quit: quit.clone(),
//         };

//         let sendmessage_path = format!("/bot{}/sendmessage", BOT_TOKEN);
//         let setmycommands_path = format!("/bot{}/setMyCommands", BOT_TOKEN);
//         let getupdates_path = format!("/bot{}/getUpdates", BOT_TOKEN);
//         let route = Router::new()
//             .route(sendmessage_path.as_str(), routing::post(sendmessage))
//             .route(setmycommands_path.as_str(), routing::post(set_my_commands))
//             .route(getupdates_path.as_str(), routing::get(getupdates))
//             .with_state(tstate);

//         info!("Starting HTTP server on {}", addr);
//         let listener = TcpListener::bind(&addr).await?;
//         let httpd = axum::serve(listener, route)
//             .with_graceful_shutdown(async move {
//                 server_quit.notified().await;
//             })
//             .into_future();

//         let handle = tokio::spawn(httpd);

//         let server = TelegramServer {
//             handle,
//             msgs: rx,
//             quit,
//         };

//         Ok(server)
//     }
// }

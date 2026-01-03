#![allow(unused)]

use std::{
    fs::{File, copy, create_dir_all}, net::TcpStream, process::{
        Child,
        Command
    }
};
use std::thread;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use camino::Utf8PathBuf;
use nix::{sys::signal::{Signal, kill}, unistd::Pid};
use reqwest::{blocking::Client, redirect};
use tempfile::{TempDir, tempdir_in};
use tracing_log::log::info;

pub const INSECURE_PORT: u16 = 8080;
pub const TLS_PORT: u16 = 8443;

pub struct ProxyBuilder {
    pub dir: TempDir,
    pub config: Option<Utf8PathBuf>,
}

pub struct Proxy {
    pub dir: TempDir,
    pub config: Utf8PathBuf,
    pub process: Child,
    keep_files: bool,
}

impl ProxyBuilder {
    pub fn new() -> Self {
        create_dir_all("target/test_runs").unwrap();
        let dir = tempdir_in("target/test_runs").unwrap();
        Self {
            dir,
            config: None,
        }
    }

    pub fn with_simple_config(mut self, confname: &str) -> Self {
        let path = format!("tests/data/config/{confname}.corn");
        self.config = Some(Utf8PathBuf::from(path));
        self
    }

    pub fn run(self) -> Result<Proxy> {
        if self.config.is_none() {
            bail!("No config provided")
        }
        let process = self.run_proxy()?;
        Ok(Proxy {
            dir: self.dir,
            config: self.config.unwrap(),
            process,
            keep_files: false,
        })
    }

    fn run_proxy(&self) -> Result<Child> {
        info!("Starting Test Proxy");
        let exe = env!("CARGO_BIN_EXE_vicarian");

        let out_file = self.dir.path().join("stdout");
        let err_file = self.dir.path().join("stderr");
        let stdout = File::create(out_file)?;
        let stderr = File::create(err_file)?;

        // Checked above
        let config = self.config.as_ref().unwrap();
        let fname = config.components().last().ok_or(anyhow!("No filename"))?;
        let copied = self.dir.path().join(fname);
        copy(&config, copied).unwrap();

        let child = Command::new(exe)
            .arg("-vv")
            .arg("-c").arg(config)
            .stdout(stdout)
            .stderr(stderr)
            .spawn()?;

        for _ in 0..20 { // 2 second timeout
            let conn1 = TcpStream::connect(format!("localhost:{INSECURE_PORT}"));
            let conn2 = TcpStream::connect(format!("localhost:{TLS_PORT}"));

            if conn1.is_ok() && conn2.is_ok() {
                info!("Test Proxy Ready");
                return Ok(child);
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("Failed to start proxy server")
    }
}

impl Proxy {
    fn child_cleanup(&self) {
        let pid = Pid::from_raw(self.process.id().try_into().unwrap());
        kill(pid, Signal::SIGINT).unwrap();
        println!("Killed process {}", pid);
    }

    pub fn keep_files(&mut self) {
        self.keep_files = true;
        self.dir.disable_cleanup(true);
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.child_cleanup();
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

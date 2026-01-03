
use std::{
    fs::{File, copy},
    process::{
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

pub const PROXY_PORT: u16 = 8080;
pub const PROXY_TLS_PORT: u16 = 8443;

pub struct Proxy {
    pub dir: TempDir,
    pub config: Option<Utf8PathBuf>,
    pub process: Option<Child>,
    pub keep_files: bool,
}

impl Proxy {
    pub fn new() -> Self {
        let dir = tempdir_in("target/test_runs").unwrap();
        Self {
            dir,
            config: None,
            process: None,
            keep_files: false,
        }
    }

    pub fn with_simple_config(& mut self, confname: &str) -> &mut Self {
        let path = format!("tests/data/config/{confname}.corn");
        self.config = Some(Utf8PathBuf::from(path));
        self
    }

    pub fn run(&mut self) -> Result<&mut Self> {
        if self.config.is_none() {
            bail!("No config provided")
        }
        self.process = Some(self.run_proxy()?);
        Ok(self)
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
            // Look for a redirect from the non-TLS port.
            let ready = Client::builder()
                .redirect(redirect::Policy::none())
                .build().unwrap()
                .get(format!("http://localhost:{PROXY_PORT}/status"))
                .send()
                .is_ok_and(|r| r.status().as_u16() == 301);

            if ready {
                info!("Test Proxy Ready");
                return Ok(child);
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("Failed to start proxy server")
    }

    fn child_cleanup(&self) {
        if let Some(proc) = &self.process {
            let pid = Pid::from_raw(proc.id().try_into().unwrap());
            kill(pid, Signal::SIGINT).unwrap();
            println!("Killed process {}", pid);
        }
    }

    pub fn keep_files(&mut self) {
        self.keep_files = true;
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

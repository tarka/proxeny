use std::{net::SocketAddr, process::{Child, Command}};
use std::thread;
use std::time::Duration;

use anyhow::{Result, bail};
use nix::{sys::signal::{Signal, kill}, unistd::Pid};
use procfs::{
    process::{FDTarget, Process},
    net::{tcp as tcp_table, tcp6 as tcp6_table}
};
use tracing_log::log::info;


pub fn run_proxy() -> Result<Child> {
    let exe = env!("CARGO_BIN_EXE_proxeny");

    let child = Command::new(exe)
        .arg("-vv")
        .arg("-c").arg("proxeny.corn")
        .spawn()?;
    Ok(child)
}

pub fn stop_child(child: &Child) -> Result<()> {
    let pid = Pid::from_raw(child.id().try_into()?);
    kill(pid, Signal::SIGINT)?;
    Ok(())
}

pub fn get_proc_port(child: &Child) -> Result<Option<u16>> {
    let proc = Process::new(child.id() as i32)?;
    let inodes = proc.fd()?
        .filter_map(|fd| match fd.unwrap().target {
            FDTarget::Socket(inode) => Some(inode),
            _ => None
        })
        .collect::<Vec<u64>>();

    for inode in inodes {
        let addrs = tcp_table()?.into_iter()
            .chain(tcp6_table()?)
            .filter_map(|t| if t.inode == inode {
                Some(t.local_address)
            } else {
                None
            })
            .collect::<Vec<SocketAddr>>();

        if addrs.len() > 0 {
            info!("Found addresses {addrs:#?}");
            return Ok(Some(addrs[0].port()))
        };
    }

    Ok(None)
}

pub fn wait_port(child: &Child) -> Result<u16> {
    const WAIT_MS: u64 = 10;
    const WAIT_SECS: u64 = 10;
    const WAIT_TIMES: u64 = WAIT_SECS * 1000 / WAIT_MS;
    for _ in 0..WAIT_TIMES {
        thread::sleep(Duration::from_millis(WAIT_MS));
        if let Some(port) = get_proc_port(child)? {
            return Ok(port)
        }
    }
    bail!("Failed to find process port");
}

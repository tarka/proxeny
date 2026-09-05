mod cli;
mod hcl;

#[cfg(test)]
mod tests;

use std::net::{IpAddr, SocketAddr, SocketAddrV6};

use anyhow::{Context, Result, anyhow, bail};
use camino::{Utf8Path, Utf8PathBuf};
use http::Uri;
use itertools::Itertools;
use nix::sys::socket::SockaddrStorage;
use serde::{Deserialize, Deserializer};
use serde_default_utils::{default_bool, serde_inline_default};
use strum_macros::IntoStaticStr;
use tracing_log::log::info;


pub use cli::CliOptions;


pub const DEFAULT_CONFIG_FILE: &str = "/etc/vicarian/vicarian.corn";

// pub for tests
pub trait ValidateSanitise: Sized {
    fn validate_and_sanitise(self) -> Result<Self>;
}

fn deserialize_canonical<'de, D>(deserializer: D) -> std::result::Result<Utf8PathBuf, D::Error>
where
    D: Deserializer<'de>,
{
    let path = Utf8PathBuf::deserialize(deserializer)?;
    // Attempt to turn into full path, but use the short version otherwise.
    let cpath = path.canonicalize_utf8()
        .unwrap_or(path);
    Ok(cpath)
}

#[derive(Copy, Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeProvider {
    #[default]
    LetsEncrypt,
    // TODO:
    // ZeroSsl,
}

#[derive(Copy, Clone, Debug, Default, Deserialize, IntoStaticStr)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum AcmeProfile {
    ShortLived,
    #[default]
    TlsServer,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DnsProvider {
    #[serde(default = "default_bool::<false>")]
    pub wildcard: bool,
    pub dns_provider: zone_update::Provider,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum AcmeChallenge {
    #[serde(rename = "dns-01")]
    Dns01(DnsProvider),
    #[serde(rename = "http-01")]
    Http01,
}

#[serde_inline_default]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsAcmeConfig {
    #[serde(default)]
    pub acme_provider: AcmeProvider,
    pub challenge: AcmeChallenge,
    // TODO: Need a method to default Utf8PathBuf here.
    #[serde_inline_default("/var/lib/vicarian/acme".to_string())]
    pub directory: String,
    pub contact: String,
    #[serde(default)]
    pub profile: AcmeProfile,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFilesConfig {
    #[serde(deserialize_with = "deserialize_canonical")]
    pub keyfile: Utf8PathBuf,
    #[serde(deserialize_with = "deserialize_canonical")]
    pub certfile: Utf8PathBuf,
    #[serde(default = "default_bool::<true>")]
    pub reload: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum TlsConfig {
    Files(TlsFilesConfig),
    Acme(TlsAcmeConfig),
}

fn strip_trailing_slashes(s: String) -> String {
    if s.len() > 1 {
        s.trim_end_matches('/').to_string()
    } else {
        s
    }
}

fn default_path() -> String {
    "/".to_string()
}

#[derive(Clone, Debug, Deserialize)]
#[serde_inline_default]
#[serde(deny_unknown_fields)]
pub struct Backend {
    #[serde(alias = "context", default = "default_path")]
    pub path: String,
    #[serde(with = "http_serde::uri")]
    pub url: Uri,
    #[serde(default = "default_bool::<false>")]
    pub trust: bool,
    pub auth_key: Option<String>,
    pub static_root: Option<Utf8PathBuf>
}

fn validate_path(s: &String) -> Result<()> {
    s.starts_with('/').then_some(())
        .ok_or(anyhow!("No leading slash in context path: {s}"))?;
    (!s.is_empty()).then_some(())
        .ok_or(anyhow!("Context path cannot be empty"))?;

    Ok(())
}

impl ValidateSanitise for Backend {
    fn validate_and_sanitise(self) -> Result<Self> {
        validate_path(&self.path)?;
        let uri = &self.url;
        let scheme = uri.scheme_str()
            .ok_or(anyhow!("No scheme (`http`, `https`, or `module`) in URI {uri}"))?;
        let authority = uri.authority()
            .ok_or(anyhow!("No scheme (`http`, `https`, or `module`) in URI {uri}"))?
            .as_str();

        if scheme == "module"
            && authority == "static"
            && self.static_root.is_none()
        {
            bail!("Static backends must supply a `static_root`")
        }
        let clean = Backend {
            path: strip_trailing_slashes(self.path),
            ..self
        };

        Ok(clean)
    }
}

impl ValidateSanitise for Vec<Backend> {
    fn validate_and_sanitise(self) -> Result<Self> {
        let backends = self.into_iter()
            .map(ValidateSanitise::validate_and_sanitise)
            .collect::<Result<Vec<Backend>>>()?;

        let dup_paths = backends.iter()
            .unique_by(|b| &b.path)
            .count() != backends.len();
        if dup_paths {
            return Err(anyhow!("Duplicate paths in backend"))
        }

        Ok(backends)
    }
}

#[serde_inline_default]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vhost {
    /// This should the FQDN, especially if using ACME as it is used
    /// to calculate the domain.
    pub hostname: String,
    #[serde_inline_default(Vec::new())]
    pub aliases: Vec<String>,
    pub tls: TlsConfig,
    pub backends: Vec<Backend>,
}

impl ValidateSanitise for Vhost {
    fn validate_and_sanitise(self) -> Result<Self> {

        Ok(Self {
            backends: self.backends.validate_and_sanitise()?,
            ..self
        })
    }
}

#[serde_inline_default]
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Listen {
    addrs: Vec<String>,
    pub insecure_port: Option<u16>,
    pub tls_port: u16,
}

impl Listen {

    /// Resolve iface and hostname addresses
    pub fn addrs(&self) -> Result<Vec<SocketAddr>> {
        expand_listen_addrs(&self.addrs)
    }

}

impl Default for Listen {
    fn default() -> Self {
        Self {
            addrs: vec!["[::]".to_string()],
            insecure_port: None,
            tls_port: 443
        }
    }
}

#[serde_inline_default]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub listen: Listen,
    pub vhosts: Vec<Vhost>,
    #[serde(default = "default_bool::<false>")]
    pub dev_mode: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: Default::default(),
            vhosts: Vec::new(),
            dev_mode: true,
        }
    }
}

impl ValidateSanitise for Config {
    fn validate_and_sanitise(self) -> Result<Self> {
        let vhosts = self.vhosts.into_iter()
            .map(ValidateSanitise::validate_and_sanitise)
            .collect::<Result<Vec<Vhost>>>()?;

        Ok(Self {
            vhosts,
            ..self
        })
    }
}

impl Config {

    pub fn from_file(file: &Utf8Path) -> Result<Self> {
        info!("Loading config {file}");
        let key = std::fs::read_to_string(file)
            .context("Error loading config file {file}")?;
        let config: Config = corn::from_str(&key)?;

        let config = config.validate_and_sanitise()?;

        Ok(config)
    }

}

fn strip_brackets(before: &str) -> &str {
    before.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(before)
}

const SPECIAL_ADDRESS_DELIMITER: char = '#';
const SPECIAL_ADDRESS_INTERFACE: &str = "if";

fn to_sockaddr(addr: Option<SockaddrStorage>) -> Option<SocketAddr> {
    let in_addr = addr?;
    if let Some(sai) = in_addr.as_sockaddr_in() {
        Some(SocketAddr::new(sai.ip().into(), 0))

    } else if let Some(sai6) = in_addr.as_sockaddr_in6() {
        let ip6 = SocketAddrV6::new(sai6.ip(), 0,
                                    sai6.flowinfo(),
                                    sai6.scope_id());
        Some(ip6.into())

    } else {
        None
    }
}


pub(crate) fn expand_listen_addrs(addrs: &[String]) -> Result<Vec<SocketAddr>> {
    let ips = addrs.iter()
        .map(|addr_str| {
            if let Some((pref, body)) = addr_str.split_once(SPECIAL_ADDRESS_DELIMITER) {
                match pref {
                    SPECIAL_ADDRESS_INTERFACE => get_if_addrs(body),
                    _ => Err(anyhow!("Unexpected address prefix: {pref}"))
                }
            } else {
                let addr = strip_brackets(addr_str);
                let addr: IpAddr = addr.parse()
                    .context(format!("Parsing listening address {addr_str}"))?;
                let sock = SocketAddr::new(addr, 0);
                Ok(vec![sock])
            }
        })
        .collect::<Result<Vec<Vec<SocketAddr>>>>()?
        .into_iter()
        .flatten()
        .unique()
        .collect();

    Ok(ips)
}


fn get_if_addrs(ifname: &str) -> Result<Vec<SocketAddr>> {
    let addrs = nix::ifaddrs::getifaddrs()?;
    let ifaddrs = addrs
        .filter(|ifaddr| ifaddr.interface_name == ifname)
        .filter_map(|ifaddr| to_sockaddr(ifaddr.address))
        .collect();

    Ok(ifaddrs)
}

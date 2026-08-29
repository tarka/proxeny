
// FIXME
#![allow(unused)]

use std::{collections::HashMap};
use std::net::{IpAddr, SocketAddr, SocketAddrV6};

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use http::Uri;
use serde::Deserialize;
use serde_default_utils::default_bool;
use strum_macros::IntoStaticStr;
use tracing_log::log::info;

use crate::config::deserialize_canonical;

#[derive(Debug)]
pub struct Config {
    /// Global listen configuration. Optional; all members have defaults.
    pub listen: Listen,

    /// Named TLS certificate definitions (ACME or certificate files).
    pub tls: HashMap<String, TlsConfig>,

    /// Named virtual host definitions.
    /// Key is the label from `vhost "<domain>" { ... }`.
    pub vhosts: HashMap<String, Vhost>,
}

impl Config {
    pub fn from_file(file: &Utf8Path) -> Result<Self> {
        info!("Loading config {file}");
        let key = std::fs::read_to_string(file)
            .context("Error loading config file {file}")?;
        let raw: RawConfig = hcl::from_str(&key)?;

        // Wrap `acme` and `cert` blocks in an enum.
        let acme = raw.acme.into_iter()
            .map(|(k, v)| (k, TlsConfig::Acme(v)));
        let tls = raw.cert.into_iter()
            .map(|(k, v)| (k, TlsConfig::Cert(v)))
            .chain(acme)
            .collect::<HashMap<String, TlsConfig>>();

        let mut config = Config {
            tls,
            listen: raw.listen,
            vhosts: raw.vhost,
        };

        // The vhost hostname is the block label, i.e. the map key;
        // copy it into the struct. (The backend path is likewise the
        // key of `vhost.backend`.)
        for (hostname, vhost) in config.vhosts.iter_mut() {
            vhost.hostname = hostname.clone();
        }

//        let config = config.validate_and_sanitise()?;

        Ok(config)
    }
}

/// Rather than use struggle with serde/config mapping we use an
/// intermediate struct that better matches the HCL schema and
/// restructure during validation/transform.
#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    acme: HashMap<String, AcmeConfig>,
    #[serde(default)]
    cert: HashMap<String, FilesConfig>,
    #[serde(default)]
    listen: Listen,
    #[serde(default)]
    vhost: HashMap<String, Vhost>,
}


#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawListen {
    addrs: Vec<String>,
    insecure_port: Option<u16>,
    tls_port: u16,
}

impl Default for RawListen {
    fn default() -> Self {
        Self {
            addrs: vec!["[::]".to_string()],
            insecure_port: None,
            tls_port: 443
        }
    }
}


#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeProvider {
    #[default]
    LetsEncrypt,
    // TODO:
    // ZeroSsl,
}

#[derive(Debug, Deserialize)]
pub struct AcmeConfig {
    #[serde(default)]
    pub acme_provider: AcmeProvider,
    pub profile: AcmeProfile,
    pub contact: String,
    pub challenge: AcmeChallenge,
}

#[derive(Debug, Default, Deserialize, IntoStaticStr)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum AcmeProfile {
    #[default]
    Classic,
    ShortLived,
    TlsServer,
}

#[derive(Debug, Deserialize)]
pub struct DnsProvider {
    #[serde(default = "default_bool::<false>")]
    pub wildcard: bool,
    pub dns_provider: zone_update::Provider,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum AcmeChallenge {
    #[serde(rename = "dns-01")]
    Dns01(DnsProvider),
    #[serde(rename = "http-01")]
    Http01,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesConfig {
    #[serde(deserialize_with = "deserialize_canonical")]
    pub keyfile: Utf8PathBuf,
    #[serde(deserialize_with = "deserialize_canonical")]
    pub certfile: Utf8PathBuf,
    #[serde(default = "default_bool::<true>")]
    pub reload: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsConfig {
    Acme(AcmeConfig),
    Cert(FilesConfig),
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Listen {
    #[serde(default)]
    pub addrs: Vec<String>,
//    pub addrs: Vec<SocketAddr>,
    #[serde(default)]
    pub insecure_port: Option<u16>,
    #[serde(default)]
    pub tls_port: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vhost {
    pub tls: String,
    /// This should the FQDN, especially if using ACME as it is used
    /// to calculate the domain. Populated from the `vhost` block label.
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Key is the label from `backend "<path>" { ... }`, i.e. the path.
    #[serde(default)]
    pub backend: HashMap<String, Backend>,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Backend {
    Proxy {
        #[serde(with = "http_serde::uri")]
        url: Uri,
        #[serde(default = "default_bool::<false>")]
        trust: bool,
        #[serde(default)]
        auth_key: Option<String>,
    },
    Static {
        root: String,
        #[serde(default)]
        auth_key: Option<String>,
    },
}


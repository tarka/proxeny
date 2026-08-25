use std::collections::HashMap;

use anyhow::{Context, Result};
use camino::Utf8Path;
// use hcl::eval::{Context, Evaluate, FuncArgs, FuncDef, ParamType};
// use hcl::{Body, Value};
use serde::Deserialize;
use serde_default_utils::{default_bool, serde_inline_default};
use strum_macros::IntoStaticStr;
use tracing_log::log::info;


#[derive(Debug, Deserialize)]
pub struct Config {
    /// Named ACME certificate provider definitions.
    /// Key is the label from `acme "<name>" { ... }`.
    #[serde(default)]
    pub acme: HashMap<String, AcmeConfig>,

    /// Global listen configuration. Optional; defaults are applied.
    #[serde(default)]
    pub listen: Listen,

    /// Named virtual host definitions.
    /// Key is the label from `vhost "<domain>" { ... }`.
    #[serde(default)]
    pub vhost: HashMap<String, Vhost>,
}

impl Config {
    pub fn from_file(file: &Utf8Path) -> Result<Self> {
        info!("Loading config {file}");
        let key = std::fs::read_to_string(file)
            .context("Error loading config file {file}")?;
        let config: Config = hcl::from_str(&key)?;

//        let config = config.validate_and_sanitise()?;

        Ok(config)
    }
}


#[derive(Copy, Clone, Debug, Default, Deserialize)]
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

#[derive(Copy, Clone, Debug, Default, Deserialize, IntoStaticStr)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum AcmeProfile {
    Classic,
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
#[serde(default, deny_unknown_fields)]
pub struct Listen {
    addrs: Vec<String>,
    pub insecure_port: Option<u16>,
    pub tls_port: u16,
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
pub struct Vhost {
    /// This should the FQDN, especially if using ACME as it is used
    /// to calculate the domain.
    pub hostname: String,
    #[serde_inline_default(Vec::new())]
    pub aliases: Vec<String>,
    //pub tls: TlsConfig,
    pub backends: Vec<Backend>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Backend {
    Proxy {
        url: String,
    },
    Static {
        path: String,
    },
}


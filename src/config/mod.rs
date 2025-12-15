#[cfg(test)]
mod tests;

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use clap::{ArgAction, Parser};
use http::Uri;
use serde::{Deserialize, Deserializer};
use serde_default_utils::{default_bool, default_u16, serde_inline_default};
use tracing_log::log::info;

#[derive(Clone, Debug, Parser)]
#[command(
    name = "vicarian",
    about = "A reverse proxy.",
    version,
)]
pub struct CliOptions {
    /// Verbosity.
    ///
    /// Can be specified multiple times to increase logging.
    #[arg(short = 'v', long, action = ArgAction::Count)]
    pub verbose: u8,

    /// Config file
    ///
    /// Override the config file location
    #[arg(short = 'c', long)]
    pub config: Option<Utf8PathBuf>,
}

impl CliOptions {
    pub fn from_args() -> CliOptions {
        CliOptions::parse()
    }
}

pub const DEFAULT_CONFIG_FILE: &str = "/etc/vicarian/vicarian.corn";

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


#[derive(Copy, Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeProvider {
    LetsEncrypt,
    // TODO:
    // ZeroSsl,
}
impl Default for AcmeProvider {
    fn default() -> Self {
        Self::LetsEncrypt
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct DnsProvider {
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
pub struct TlsAcmeConfig {
    #[serde(default)]
    pub acme_provider: AcmeProvider,
    pub challenge_type: AcmeChallenge,
    // TODO: Need a method to default Utf8PathBuf here.
    #[serde_inline_default("/var/lib/vicarian/acme".to_string())]
    pub directory: String,
    pub contact: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TlsFilesConfig {
    #[serde(deserialize_with = "deserialize_canonical")]
    pub keyfile: Utf8PathBuf,
    #[serde(deserialize_with = "deserialize_canonical")]
    pub certfile: Utf8PathBuf,
    #[serde(default = "default_bool::<true>")]
    pub reload: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct TlsConfig {
    #[serde(default = "default_u16::<443>")]
    pub port: u16,
    pub config: TlsConfigType,
}


#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsConfigType {
    Files(TlsFilesConfig),
    Acme(TlsAcmeConfig),
}

#[derive(Clone, Debug, Deserialize)]
pub struct Backend {
    pub context: Option<String>,
    #[serde(with = "http_serde::uri")]
    pub url: Uri,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Insecure {
    #[serde(default = "default_u16::<80>")]
    pub port: u16,
    #[serde(default = "default_bool::<true>")]
    pub redirect: bool,
    // FIXME: HTTP-01 setup here?
}

#[serde_inline_default]
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// This should the FQDN, especially if using ACME as it is used
    /// to calculate the domain.
    pub hostname: String,
    #[serde_inline_default("[::]".to_string())]
    pub listen: String,
    pub insecure: Option<Insecure>,
    pub tls: TlsConfig,
    pub backends: Vec<Backend>,
    #[serde(default = "default_bool::<false>")]
    pub dev_mode: bool,
}

pub type Server = Config;

impl Config {
    pub fn servers(&self) -> Vec<&Server> {
        // TODO: We don't currently support multiple servers in the
        // config, however some components do (see
        // config/store.rs). This may change, so we fake it here.
        vec![self]
    }

    pub fn from_file(file: &Utf8Path) -> Result<Self> {
        info!("Loading config {file}");
        let key = std::fs::read_to_string(&file)?;
        let config = corn::from_str(&key)?;
        Ok(config)
    }

    pub fn empty() -> Self {
        Self {
            hostname: String::new(),
            listen: String::new(),
            insecure: None,
            tls: TlsConfig {
                port: 0,
                config: TlsConfigType::Files(TlsFilesConfig {
                    keyfile: Utf8PathBuf::new(),
                    certfile: Utf8PathBuf::new(),
                    reload: false,
                }),
            },
            backends: Vec::new(),
            dev_mode: true,
        }
    }
}

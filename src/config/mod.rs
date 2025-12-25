#[cfg(test)]
mod tests;

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use clap::{ArgAction, Parser};
use http::Uri;
use serde::{Deserialize, Deserializer};
use serde_default_utils::{default_bool, serde_inline_default};
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
    pub challenge: AcmeChallenge,
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
pub enum TlsConfig {
    Files(TlsFilesConfig),
    Acme(TlsAcmeConfig),
}

#[derive(Clone, Debug, Deserialize)]
pub struct Backend {
    pub context: Option<String>,
    #[serde(with = "http_serde::uri")]
    pub url: Uri,
    #[serde(default = "default_bool::<false>")]
    pub trust: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Insecure {
    #[serde(default = "default_bool::<true>")]
    pub redirect: bool,
    // FIXME: HTTP-01 setup here?
}

#[serde_inline_default]
#[derive(Clone, Debug, Deserialize)]
pub struct Vhost {
    /// This should the FQDN, especially if using ACME as it is used
    /// to calculate the domain.
    pub hostname: String,
    #[serde_inline_default(Vec::new())]
    pub aliases: Vec<String>,
    #[serde_inline_default("[::]".to_string())]
    pub listen: String,
    pub insecure: Option<Insecure>,
    pub tls: TlsConfig,
    pub backends: Vec<Backend>,
}

#[serde_inline_default]
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Listen {
    pub addr: String,
    pub insecure_port: u16,
    pub tls_port: u16,
}

impl Default for Listen {
    fn default() -> Self {
        Self {
            addr: "[::]".to_string(),
            insecure_port: 80,
            tls_port: 443
        }
    }
}

#[serde_inline_default]
#[derive(Clone, Debug, Deserialize)]
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

impl Config {

    pub fn from_file(file: &Utf8Path) -> Result<Self> {
        info!("Loading config {file}");
        let key = std::fs::read_to_string(&file)?;
        let config = corn::from_str(&key)?;
        Ok(config)
    }

}

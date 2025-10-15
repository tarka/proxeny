
use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use clap::{ArgAction, Parser};
use http::Uri;
use serde::{Deserialize, Deserializer};
use serde_default_utils::default_bool;

#[derive(Clone, Debug, Parser)]
#[command(
    name = "proxeny",
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

pub const DEFAULT_CONFIG_FILE: &str = "/etc/proxeny/proxeny.corn";

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


#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeProvider {
    LetsEncrypt,
    ZeroSsl,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeChallenge {
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "http-01")]
    Http01,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsProvider {
    DnSimple(DnSimpleConfig),
    Gandi(),
}

#[derive(Debug, Deserialize)]
pub struct DnSimpleConfig {
    pub key: String,
    pub account_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct TlsAcmeConfig {
    pub provider: AcmeProvider,
    pub challenge_type: AcmeChallenge,
    pub contact: String,
    pub dns_provider: DnsProvider,
}

#[derive(Debug, Deserialize)]
pub struct TlsFilesConfig {
    #[serde(deserialize_with = "deserialize_canonical")]
    pub keyfile: Utf8PathBuf,
    #[serde(deserialize_with = "deserialize_canonical")]
    pub certfile: Utf8PathBuf,
    #[serde(default = "default_bool::<true>")]
    pub reload: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsConfigType {
    Files(TlsFilesConfig),
    Acme(TlsAcmeConfig),
}

#[derive(Debug, Deserialize)]
pub struct Backend {
    pub context: Option<String>,
    #[serde(with = "http_serde::uri")]
    pub url: Uri,
}

#[derive(Debug, Deserialize)]
pub struct Server {
    pub hostname: String,
    pub tls: TlsConfigType,
    pub backends: Vec<Backend>,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub servers: Vec<Server>,
}

impl Config {

    pub fn tls_files(&self) -> Vec<&TlsFilesConfig> {
        self.servers.iter()
            .filter_map(|s| match &s.tls {
                TlsConfigType::Files(tfc) => Some(tfc),
                _ => None
            })
            .collect()
    }

}

pub fn read_config(file: &Utf8Path) -> Result<Config> {
    println!("loading {file}");
    let key = std::fs::read_to_string(&file)?;
    let config = corn::from_str(&key)?;
    Ok(config)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_config() -> Result<()> {
        let file = Utf8PathBuf::from("examples/proxeny.corn");
        let config = read_config(&file)?;
        assert_eq!(2, config.servers.len());
        assert_eq!("gateway.example.com", config.servers[0].hostname);
        assert_eq!("files.example.com", config.servers[1].hostname);

        assert!(matches!(&config.servers[0].tls, TlsConfigType::Files(
            TlsFilesConfig {
                keyfile: _,  // FIXME: Match Utf8PathBuf?
                certfile: _,
                reload: true,
            })));

        assert!(matches!(config.servers[1].tls, TlsConfigType::Acme(
            TlsAcmeConfig {
                provider: AcmeProvider::LetsEncrypt,
                challenge_type: AcmeChallenge::Dns01,
                contact: _,  // FIXME: Match String?
                dns_provider: DnsProvider::DnSimple(_),
            },
        )));

        assert_eq!(None, config.servers[0].backends[0].context);
        assert_eq!("/paperless", config.servers[1].backends[0].context.as_ref().unwrap());

        Ok(())
    }

    #[test]
    fn test_no_optionals() -> Result<()> {
        let file = Utf8PathBuf::from("tests/data/config/no-optionals.corn");
        let config = read_config(&file)?;
        assert_eq!(2, config.servers.len());
        assert_eq!("host01.example.com", config.servers[0].hostname);
        assert_eq!("host02.example.com", config.servers[1].hostname);

        assert!(matches!(&config.servers[0].tls, TlsConfigType::Files(
            TlsFilesConfig {
                keyfile: _,
                certfile: _,
                reload: true,
            })));

        Ok(())
    }

    #[test]
    fn test_extract_files() -> Result<()> {
        let file = Utf8PathBuf::from("tests/data/config/no-optionals.corn");
        let config = read_config(&file)?;

        let files = config.tls_files();
        assert_eq!(2, files.len());
        assert_eq!(Utf8PathBuf::from("/etc/ssl/certs/host01.example.com.key"), files[0].keyfile);
        assert_eq!(Utf8PathBuf::from("/etc/ssl/certs/host01.example.com.crt"), files[0].certfile);
        assert!(files[0].reload);
        assert_eq!(Utf8PathBuf::from("/etc/ssl/certs/host02.example.com.key"), files[1].keyfile);
        assert_eq!(Utf8PathBuf::from("/etc/ssl/certs/host02.example.com.crt"), files[1].certfile);
        assert!(files[1].reload);

        Ok(())
    }


}

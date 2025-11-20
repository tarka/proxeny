
use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use clap::{ArgAction, Parser};
use http::Uri;
use serde::{Deserialize, Deserializer};
use serde_default_utils::{default_bool, default_u16, serde_inline_default};
use tracing_log::log::info;
use zone_update::{
    gandi, dnsimple, dnsmadeeasy, porkbun,
};

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


#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeProvider {
    LetsEncrypt,
    ZeroSsl,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeChallenge {
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "http-01")]
    Http01,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsProvider {
    Gandi(gandi::Auth),
    Dnsimple(dnsimple::Auth),
    DnsMadeEasy(dnsmadeeasy::Auth),
    PorkBun(porkbun::Auth),
}

#[derive(Clone, Debug, Deserialize)]
pub struct TlsAcmeConfig {
    pub provider: AcmeProvider,
    pub challenge_type: AcmeChallenge,
    pub contact: String,
    pub dns_provider: DnsProvider,
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
    #[serde(default = "default_u16::<80>")]
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
    pub port: u16,
    #[serde(default = "default_bool::<true>")]
    pub redirect: bool,
    // FIXME: HTTP-01 setup here?
}

#[serde_inline_default]
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub hostname: String,
    #[serde_inline_default("[::]".to_string())]
    pub listen: String,
    pub insecure: Option<Insecure>,
    pub tls: TlsConfig,
    pub backends: Vec<Backend>,
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

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_config() -> Result<()> {
        let file = Utf8PathBuf::from("examples/proxeny.corn");
        let config = Config::from_file(&file)?;
        assert_eq!("files.example.com", config.hostname);

        assert_eq!(8443, config.tls.port);
        assert!(matches!(&config.tls.config, TlsConfigType::Files(
            TlsFilesConfig {
                keyfile: _,  // FIXME: Match Utf8PathBuf?
                certfile: _,
                reload: true,
            })));

        // assert!(matches!(config.servers[1].tls.config, TlsConfigType::Acme(
        //     TlsAcmeConfig {
        //         provider: AcmeProvider::LetsEncrypt,
        //         challenge_type: AcmeChallenge::Dns01,
        //         contact: _,  // FIXME: Match String?
        //         dns_provider: DnsProvider::Dnsimple(_),
        //     }),
        // ));

//        assert_eq!(None, config.servers[0].backends[0].context);
        assert_eq!("/paperless", config.backends[0].context.as_ref().unwrap());

//        assert!(config.servers[0].is_tls());


        Ok(())
    }

    #[test]
    fn test_no_optionals() -> Result<()> {
        let file = Utf8PathBuf::from("tests/data/config/no-optionals.corn");
        let config = Config::from_file(&file)?;
        assert_eq!("host01.example.com", config.hostname);

        assert!(matches!(&config.tls.config, TlsConfigType::Files(
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
        let config = Config::from_file(&file)?;


        let files = if let TlsConfigType::Files(tfc) = config.tls.config {
            tfc
        } else {
            panic!("Expected TLS files");
        };
        assert_eq!(Utf8PathBuf::from("/etc/ssl/certs/host01.example.com.key"), files.keyfile);
        assert_eq!(Utf8PathBuf::from("/etc/ssl/certs/host01.example.com.crt"), files.certfile);
        assert!(files.reload);

        Ok(())
    }


}

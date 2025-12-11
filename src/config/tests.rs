
use super::*;

#[test]
fn test_simple_example_config() -> Result<()> {
    let file = Utf8PathBuf::from("examples/vicarian.corn");
    let config = Config::from_file(&file)?;
    assert_eq!("files.example.com", config.hostname);

    assert_eq!(8443, config.tls.port);
    assert!(matches!(&config.tls.config, TlsConfigType::Files(
        TlsFilesConfig {
            keyfile: _,  // FIXME: Match Utf8PathBuf?
            certfile: _,
            reload: true,
        })));

    assert_eq!("/paperless", config.backends[0].context.as_ref().unwrap());

    Ok(())
}

#[test]
fn test_acme_example_config() -> Result<()> {
    let file = Utf8PathBuf::from("examples/vicarian-dns01.corn");
    let config = Config::from_file(&file)?;
    assert_eq!("files.example.com", config.hostname);

    assert_eq!(8443, config.tls.port);
    assert!(matches!(&config.tls.config, TlsConfigType::Acme(
        TlsAcmeConfig {
            contact: _,
            acme_provider: AcmeProvider::LetsEncrypt,
            directory: _,
            challenge_type: AcmeChallenge::Dns01(DnsProvider {
                domain: _,
                dns_provider: zone_update::Provider::PorkBun(_)
            }),

        })));

    assert_eq!("/paperless", config.backends[0].context.as_ref().unwrap());

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

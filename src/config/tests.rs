use super::*;

#[test]
fn test_tls_files_example_config() -> Result<()> {
    let file = Utf8PathBuf::from("examples/vicarian-tls-files.corn");
    let config = Config::from_file(&file)?;
    assert_eq!("files.example.com", config.vhosts[0].hostname);

    assert_eq!(8443, config.listen.tls_port);
    assert!(matches!(&config.vhosts[0].tls, TlsConfig::Files(
        TlsFilesConfig {
            keyfile: _,  // FIXME: Match Utf8PathBuf?
            certfile: _,
            reload: true,
        })));

    assert_eq!("/", config.vhosts[0].backends[0].context.as_ref().unwrap());

    Ok(())
}

#[test]
fn test_dns01_example_config() -> Result<()> {
    let file = Utf8PathBuf::from("examples/vicarian-dns01.corn");
    let config = Config::from_file(&file)?;
    assert_eq!("files.example.com", config.vhosts[0].hostname);

    assert_eq!(443, config.listen.tls_port);
    assert!(matches!(&config.vhosts[0].tls, TlsConfig::Acme(
        TlsAcmeConfig {
            contact: _,
            acme_provider: AcmeProvider::LetsEncrypt,
            directory: _,
            challenge: AcmeChallenge::Dns01(DnsProvider {
                dns_provider: zone_update::Provider::PorkBun(_)
            }),
            profile: AcmeProfile::TlsServer,
        })));

    assert_eq!("/", config.vhosts[0].backends[0].context.as_ref().unwrap());

    Ok(())
}

#[test]
fn test_http01_example_config() -> Result<()> {
    let file = Utf8PathBuf::from("examples/vicarian-http01.corn");
    let config = Config::from_file(&file)?;
    assert_eq!("www.example.com", config.vhosts[0].hostname);

    assert_eq!(443, config.listen.tls_port);
    assert!(matches!(&config.vhosts[0].tls, TlsConfig::Acme(
        TlsAcmeConfig {
            contact: _,
            acme_provider: AcmeProvider::LetsEncrypt,
            directory: _,
            challenge: AcmeChallenge::Http01,
            profile: AcmeProfile::ShortLived,
        })));

    assert_eq!("/copyparty", config.vhosts[0].backends[1].context.as_ref().unwrap());

    Ok(())
}

#[test]
fn test_no_optionals() -> Result<()> {
    let file = Utf8PathBuf::from("tests/data/config/no-optionals.corn");
    let config = Config::from_file(&file)?;
    assert_eq!("host01.example.com", config.vhosts[0].hostname);

    assert_eq!(443, config.listen.tls_port);
    assert!(matches!(&config.vhosts[0].tls, TlsConfig::Files(
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


    let files = if let TlsConfig::Files(tfc) = &config.vhosts[0].tls {
        tfc
    } else {
        panic!("Expected TLS files");
    };
    assert_eq!(Utf8PathBuf::from("/etc/ssl/certs/host01.example.com.key"), files.keyfile);
    assert_eq!(Utf8PathBuf::from("/etc/ssl/certs/host01.example.com.crt"), files.certfile);
    assert!(files.reload);

    Ok(())
}

#[test]
#[ignore]
fn test_dns01_dev_config() -> Result<()> {
    let file = Utf8PathBuf::from("vicarian.corn");
    // This is the file I use for local dev, ignore if it's not there.
    if ! file.exists() {
        return Ok(())
    }

    let config = Config::from_file(&file)?;
    //assert_eq!("www.vicarian.org", config.vhosts[0].hostname);
    //assert_eq!("staging.vicarian.org", config.vhosts[0].aliases[0]);

    assert_eq!(443, config.listen.tls_port);
    assert!(matches!(&config.vhosts[0].tls, TlsConfig::Acme(
        TlsAcmeConfig {
            contact: _,
            acme_provider: AcmeProvider::LetsEncrypt,
            directory: _,
            challenge: AcmeChallenge::Dns01(DnsProvider {
                dns_provider: zone_update::Provider::PorkBun(_)
            }),
            profile: AcmeProfile::TlsServer,
        })));

    assert_eq!("/", config.vhosts[0].backends[0].context.as_ref().unwrap());

    Ok(())
}

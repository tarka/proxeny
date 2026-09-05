use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};

use crate::config::hcl::{ProxyBackend, StaticBackend};

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

    assert_eq!("/", config.vhosts[0].backends[0].path);

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
                wildcard: false,
                dns_provider: zone_update::Provider::PorkBun(_)
            }),
            profile: AcmeProfile::Classic,
        })));

    assert_eq!("/", config.vhosts[0].backends[0].path);

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

    assert_eq!("/copyparty", config.vhosts[0].backends[1].path);

    Ok(())
}

#[test]
fn test_wildcard_example_config() -> Result<()> {
    unsafe {
        std::env::set_var("DNS_KEY", "my-key");
        std::env::set_var("DNS_SECRET", "my-secret");
    }
    let file = Utf8PathBuf::from("examples/vicarian-wildcard-tls.corn");
    let config = Config::from_file(&file)?;
    assert_eq!("files.example.com", config.vhosts[0].hostname);

    Ok(())
}

#[test]
fn test_tls_example_interface() -> Result<()> {
    let file = Utf8PathBuf::from("examples/vicarian-listen-interface.corn");
    let config = Config::from_file(&file)?;
    assert_eq!("files.example.com", config.vhosts[0].hostname);

    assert_eq!(443, config.listen.tls_port);
    assert!(matches!(&config.vhosts[0].tls, TlsConfig::Files(
        TlsFilesConfig {
            keyfile: _,  // FIXME: Match Utf8PathBuf?
            certfile: _,
            reload: true,
        })));

    assert_eq!("/", config.vhosts[0].backends[0].path);

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
fn test_no_leading_slash() -> Result<()> {
    let file = Utf8PathBuf::from("tests/data/config/no-leading-slash.corn");
    let result = Config::from_file(&file);
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_module_backend() -> Result<()> {
    let file = Utf8PathBuf::from("tests/data/config/module-backend.corn");
    let config = Config::from_file(&file)?;

    let url = &config.vhosts[0].backends[0].url;
    assert_eq!("module", url.scheme_str().unwrap());
    assert_eq!("metrics", url.authority().unwrap());

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
fn test_get_if_addr() -> Result<()> {
    let ifname = "lo";

    let v4: SocketAddr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into();
    let v6: SocketAddr = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0).into();

    let addrs = get_if_addrs(ifname)?;
    assert_eq!(2, addrs.len());

    assert!(addrs.contains(&v4));
    assert!(addrs.contains(&v6));

    Ok(())
}

#[test]
fn test_get_if_expansion() -> Result<()> {
    let addrs = vec!["if#lo".to_string()];

    let v4: SocketAddr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into();
    let v6: SocketAddr = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0).into();

    let ips = expand_listen_addrs(&addrs)?;

    assert_eq!(2, ips.len());

    assert!(ips.contains(&v4));
    assert!(ips.contains(&v6));

    Ok(())
}

#[test]
fn test_get_mixed_if_expansion() -> Result<()> {
    let addrs = vec![
        "if#lo".to_string(),
        "10.1.1.1".to_string(),
        "[fc00::1]".to_string(),
    ];

    let v4: SocketAddr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into();
    let v6: SocketAddr = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0).into();
    let ten: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(10,1,1,1), 0).into();
    let fc00: SocketAddr = SocketAddrV6::new( Ipv6Addr::new(0xfc00,0,0,0,0,0,0,1), 0, 0, 0).into();

    let ips = expand_listen_addrs(&addrs)?;
    assert_eq!(4, ips.len());

    assert!(ips.contains(&v4));
    assert!(ips.contains(&v6));
    assert!(ips.contains(&ten));
    assert!(ips.contains(&fc00));

    Ok(())
}

#[test]
fn test_collapse_dups() -> Result<()> {
    let addrs = vec![
        "if#lo".to_string(),
        "10.1.1.1".to_string(),
        "::1".to_string(),
    ];

    let v4: SocketAddr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into();
    let v6: SocketAddr = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0).into();
    let ten: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(10,1,1,1), 0).into();

    let ips = expand_listen_addrs(&addrs)?;
    assert_eq!(3, ips.len());

    assert!(ips.contains(&v4));
    assert!(ips.contains(&v6));
    assert!(ips.contains(&ten));

    Ok(())
}

#[test]
fn test_get_invalid_prefix() -> Result<()> {
    let addrs = vec![
        "if#lo".to_string(),
        "10.1.1.1".to_string(),
        "typo#eth0".to_string(),
        "[fc00::1]".to_string(),
    ];
    let result = expand_listen_addrs(&addrs);
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_strip_brackets() {
    assert_eq!("192.168.1.1", strip_brackets("192.168.1.1"));
    assert_eq!("::1", strip_brackets("[::1]"));
    assert_eq!("2001:db8::1", strip_brackets("[2001:db8::1]"));
    assert_eq!("[invalid", strip_brackets("[invalid"));
}

#[test]
fn test_uri_both_scheme_and_authority() {
    let uri: Uri = "https://example.com/api".parse().unwrap();
    assert_eq!(Some("https"), uri.scheme_str());
    assert_eq!(Some("example.com"), uri.authority().map(|a| a.as_str()));
    assert_eq!("/api", uri.path());
}

#[test]
fn test_uri_no_scheme_no_authority() {
    let uri: Uri = "/api/v1".parse().unwrap();
    assert!(uri.scheme().is_none());
    assert!(uri.authority().is_none());
    assert_eq!("/api/v1", uri.path());
}

#[test]
fn test_uri_no_scheme_with_authority() {
    let uri: Uri = "//example.com/api".parse().unwrap();
    assert!(uri.scheme().is_none());
    assert!(uri.authority().is_none());
    assert_eq!("//example.com/api", uri.path());
}

#[test]
fn test_uri_with_scheme_no_authority() {
    let result: Result<Uri, _> = "unix:///var/run/socket.sock".parse();
    assert!(result.is_err());
}

#[test]
fn test_hcl_vicarian_full_example() -> Result<()> {
    let config = hcl::Config::from_file("examples/vicarian-full.hcl".into())?;

    // `listen` block
    assert_eq!(443, config.listen.tls_port);
    assert_eq!(Some(80), config.listen.insecure_port);

    // Two `acme` blocks and one `cert` block, merged into one map.
    assert_eq!(3, config.tls.len());

    // `acme "le-porkbun"` — dns-01 with a porkbun provider.
    let le_porkbun = config.tls.get("le-porkbun")
        .ok_or_else(|| anyhow!("missing tls definition le-porkbun"))?;
    assert!(matches!(le_porkbun, hcl::TlsConfig::Acme(hcl::AcmeConfig {
        acme_provider: hcl::AcmeProvider::LetsEncrypt,
        profile: AcmeProfile::ShortLived,
        contact,
        challenge: hcl::AcmeChallenge::Dns01(hcl::DnsProvider {
            wildcard: true,
            dns_provider: zone_update::Provider::PorkBun(_),
        }),
    }) if contact == "admin@haltcondition.net"));

    // `acme "le-http01"` — http-01, defaults for provider and profile.
    let le_http01 = config.tls.get("le-http01")
        .ok_or_else(|| anyhow!("missing tls definition le-http01"))?;
    assert!(matches!(le_http01, hcl::TlsConfig::Acme(hcl::AcmeConfig {
        acme_provider: hcl::AcmeProvider::LetsEncrypt,
        profile: AcmeProfile::Classic,
        contact: _,
        challenge: hcl::AcmeChallenge::Http01,
    })));

    // `cert "snakeoil"` — static key/cert files.
    let snakeoil = config.tls.get("snakeoil")
        .ok_or_else(|| anyhow!("missing tls definition snakeoil"))?;
    let hcl::TlsConfig::Cert(files) = snakeoil else {
        bail!("snakeoil should be a cert (files) definition")
    };
    // Paths are canonicalised when they exist, so only check the suffix.
    assert!(files.keyfile.ends_with("ssl-cert-snakeoil.pem"));
    assert!(files.certfile.ends_with("ssl-cert-snakeoil.key"));
    assert!(files.reload);

    // `vhost` blocks; hostname is populated from the block label.
    assert_eq!(2, config.vhosts.len());

    let hc = config.vhosts.get("haltcondition.net")
        .ok_or_else(|| anyhow!("missing vhost haltcondition.net"))?;
    assert_eq!("haltcondition.net", hc.hostname);
    assert_eq!("le-porkbun", hc.tls);
    assert_eq!(vec!["www.haltcondition.net".to_string()], hc.aliases);
    assert_eq!(3, hc.backend.len());
    let hcl::Backend { backend_type: hcl::BackendType::Proxy(ProxyBackend { url, trust }), auth_key } = hc.backend.get("/").unwrap() else {
        bail!("expected proxy backend /")
    };
    assert_eq!("http", url.scheme_str().unwrap());
    assert_eq!("192.168.20.27:9191", url.authority().unwrap().as_str());
    assert!(!trust);
    assert!(auth_key.is_none());

    let hcl::Backend { backend_type: hcl::BackendType::Static(StaticBackend { root } ), auth_key } = hc.backend.get("/html").unwrap() else {
        bail!("expected static backend /html")
    };
    assert_eq!("/var/www/haltcondition.net", root);
    assert!(auth_key.is_none());

    let hcl::Backend { backend_type: hcl::BackendType::Metrics, auth_key: Some(keyval) } = hc.backend.get("/metrics").unwrap() else {
        bail!("expected static backend /metrics")
    };
    assert_eq!(keyval, "my-secret-key");

    let vo = config.vhosts.get("vicarian.org")
        .ok_or_else(|| anyhow!("missing vhost vicarian.org"))?;
    assert_eq!("vicarian.org", vo.hostname);
    assert_eq!("le-http01", vo.tls);
    assert_eq!(vec!["www.vicarian.org".to_string()], vo.aliases);
    assert_eq!(3, vo.backend.len());

    let hcl::Backend { backend_type: hcl::BackendType::Proxy(ProxyBackend { url, .. }), auth_key: _ } = vo.backend.get("/").unwrap() else {
        bail!("expected proxy backend /")
    };
    assert_eq!("http", url.scheme_str().unwrap());
    assert_eq!("192.168.20.27:9192", url.authority().unwrap().as_str());

    let hcl::Backend { backend_type: hcl::BackendType::Static(StaticBackend { root, .. }), auth_key: _ } = vo.backend.get("/html").unwrap() else {
        bail!("expected static backend /html")
    };
    assert_eq!("/var/www/vicarian.org", root);

    let hcl::Backend { backend_type: hcl::BackendType::Proxy(ProxyBackend { url, trust }), auth_key: _ } = vo.backend.get("/trusted").unwrap() else {
        bail!("expected proxy backend /")
    };
    assert_eq!("https", url.scheme_str().unwrap());
    assert!(trust);
    Ok(())
}

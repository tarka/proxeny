// Optional; otherwise defaults as below
listen {
    addrs = [
        // Default; this covers IPv4 & IPv6
        "[::]"
    ]
    insecure_port = 80    // Default
    tls_port = 443        // Default
}

// A definition of an ACME DNS-01 provider; there can be multiple of these
// and be reused in multiple vhosts.
acme "le-porkbun" {
    acme_provider = "letsencrypt"    // Default
    // Optional; 'classic' (default), 'tlsserver', or 'shortlived'.
    // See https://letsencrypt.org/docs/profiles/
    profile = "shortlived"
    contact = "admin@haltcondition.net"  // Required
    challenge {
        type = "dns-01"
        wildcard = true   // Default is false
        dns_provider {
            // This is a DNS provider defined in the `Provider` enum
            // in the zone-update crate.
            // See https://github.com/tarka/zone-update/blob/main/docs/PROVIDERS.md
            name = "porkbun"

            // env() fetches data from environment variables.
            key = env("PORKBUN_KEY")
            secret = env("PORKBUN_SECRET")
        }
    }
}

acme "le-http01" {
    contact = "admin@haltcondition.net"
    profile = "classic"
    challenge {
        type = "http-01"
        // HTTP-01 does not require any additional information.
    }
}

cert "snakeoil" {
    keyfile = "/etc/ssl/certs/ssl-cert-snakeoil.pem"
    certfile = "/etc/ssl/private/ssl-cert-snakeoil.key"
    reload = true // Optiona; defaults to true
}


vhost "haltcondition.net" {
    // Optional
    aliases = [
        "www.haltcondition.net",
    ]

    // Required; inserts the definition defined above
    tls = "le-porkbun"

    backend "/" {
        // The backend type; "proxy", "static", or "metrics".
        // See below for other examples.
        type = "proxy"
        // Required for type = "proxy"
        url = "http://192.168.20.27:9191"
    }

    backend "/html" {
        type = "static"
        // Required for type = "static"
        root = "/var/www/haltcondition.net"
    }

    backend "/metrics" {
        auth_key = "my-secret-key"
        type = "metrics"
    }
}


vhost "vicarian.org" {
    // Optional
    aliases = [
        "www.vicarian.org",
    ]

    // Required; inserts the definition defined above
    tls = "le-http01"

    backend "/" {
        type = "proxy"
        url = "http://192.168.20.27:9192"
    }

    backend "/trusted" {
        type = "proxy"
        url = "https://127.0.0.1:4443"
        // `trust` bypasses TLS cert checks, allowing backends with self-signed certificates.
        trust = true
    }

    backend "/html" {
        type = "static"
        root = "/var/www/vicarian.org"
    }
}

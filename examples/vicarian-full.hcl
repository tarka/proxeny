
// A definition of an ACME DNS-01 provider; there can be multiple of these
// and be reused in multiple vhosts.
acme "le-porkbun" {
    acme_provider = "letsencrypt"    // Default
    profile = "shortlived"           // 'classic' (default), 'tlsserver', or 'shortlived'
    contact = "admin@haltcondition.net"  // Required
    challenge {
        type = "dns-01"
        wildcard = true   // Default is false
        dns_provider {
            // This is a DNS provider defined in the `Provider` enum
            // in the zone-update crate.
            name = "porkbun"

            // env() fetches data from environment variables
            // key = env("PORKBUN_KEY")
            // secret = env("PORKBUN_SECRET")
            key = "PORKBUN_KEY"
            secret = "PORKBUN_SECRET"
        }
    }
}


acme "le-http01" {
    contact = "admin@haltcondition.net"
    challenge {
        type = "http-01"
        // This type does not require any additional information.
    }
    profile = "classic" // Default
}

cert "snakeoil" {
    keyfile = "/etc/ssl/certs/ssl-cert-snakeoil.pem"
    certfile = "/etc/ssl/private/ssl-cert-snakeoil.key"
    reload = true
}

// Optional; otherwise defaults as below
listen {
    addrs = [ "[::]" ]    // Default
    insecure_port = 80    // Default
    tls_port = 443        // Default
}

vhost "haltcondition.net" {
    // Required; inserts the definition defined above
    tls = "le-porkbun"

    // Optional
    aliases = [
        "www.haltcondition.net",
    ]

    backend "/" {
        type = "proxy"    // Default
        // Required for type = proxy
        url = "http://192.168.20.27:9191"
    }

    backend "/html" {
        type = "static"
        root = "/var/www/haltcondition.net"
    }

    backend "/metrics" {
        auth_key = "my-secret-key"
        type = "metrics"
    }
}


vhost "vicarian.org" {
    // Required; inserts the definition defined above
    tls = "le-http01"

    // Optional
    aliases = [
        "www.vicarian.org",
    ]

    backend "/" {
        type = "proxy"    // Default
        url = "http://192.168.20.27:9192"
    }

    backend "/html" {
        type = "static"
        root = "/var/www/vicarian.org"
    }
}

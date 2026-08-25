

// A definition of an ACME DNS-01 provider; there can be multiple of these
// and be reused in multiple vhosts.
acme "le-porkbun" {
    acme_provider = "letsencrypt"    // Default
    profile = "shortlived"
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
    profile = "tlsserver"  // Default
}

// Optional; otherwise defaults as below
listen {
    addrs = [ "[::]" ]    // Default
    insecure_port = 80    // Default
    tls_port = 443        // Default
}

vhost "haltcondition.net" {
    // Required; inserts the definition defined above
    acme = "le-porkbun"

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
        path = "/var/www/haltcondition.net"
    }
}


vhost "vicarian.org" {
    // Required; inserts the definition defined above
    acme = "le-http01"

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
        path = "/var/www/vicarian.org"
    }
}

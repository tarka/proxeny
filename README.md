# Vicarian

[Vicarian](https://vicarian.org/) is a TLS-first reverse proxy server with
built-in ACME support. It is currently targeted at self-hosting and SOHO
installations; in particular it supports provisioning TLS certificates
behind-the-firewall via ACME DNS-01 and the
[zone-update](https://github.com/tarka/zone-update/) library.

Vicarian aims to have sensible defaults without additional configuration.

## Project Status

[![Crates.io](https://img.shields.io/crates/v/vicarian)](https://crates.io/crates/vicarian)
[![GitHub CI](https://github.com/tarka/vicarian/actions/workflows/tests.yml/badge.svg)](https://github.com/tarka/vicarian/actions)
[![License](https://img.shields.io/crates/l/vicarian)](https://github.com/tarka/vicarian/blob/master/README.md#License)

This software should be consider pre-alpha; the feature-set is
[MVP](https://en.wikipedia.org/wiki/Minimum_viable_product) and is still in
active development. It should not be considered production-ready and no warranty
is expressed or implied. It is very-much a work-in-progress and virtually every
part of it subject to change without notice.

Only Linux is currently supported (x86_64 and Arm64). Testing for other
platforms is welcome.

## Features

### Current features

- **TLS-first**: Port-80/HTTP can be enabled, but will always redirect to the
  configured TLS server. The exception to this is when the HTTP-01 ACME is
  enabled; Vicarian will serve any challenge responses directly.
- **Native ACME Support**: Vicarian has first-class support for
  ACME/LetsEncrypt, including DNS-01. LetEncrypt [certificate
  profiles](https://letsencrypt.org/docs/profiles/) are supported; `tlsserver`
  is the default.
- **Multiple DNS Providers**: Multiple DNS providers are supported for DNS-01
  via the [zone-update](https://github.com/tarka/zone-update/)
  sibling-project. See that project for a list of supported
  providers. (Contributions of provider support are very welcome.)
- **Dynamic Certificate Loading**: Where TLS certificates are maintained
  externally Vicarian will dynamically reload certificates when they are
  updated.
- **Simple backend routing**: Traffic can be routed to multiple backend services
  based on URL paths.
- **Basic path rewriting**: This may work with some simple apps that don't
  support contexts natively, but is likely to fail with more complex apps that
  have hardcoded paths.
- **Virtual hosts**: Hosting of multiple domains and domain aliases is
  supported, along with certificate generation for host aliases.
- **Bearer authorization**: Basic `Authorization: Bearer <key>` support for
  protecting backend services.
- **Separated secrets**: ACME DNS requires DNS-provider secrets to be
  configured. These can be placed in a separate secure file using systemd
  [EnvironmentFile](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#EnvironmentFile=)
  and [corn](https://cornlang.dev) environment injection (see
  [vicarian-dns01.corn](examples/vicarian-dns01.corn) for an example).
- **Wildcards**: Wildcard ACME certificate generation.
- **Prometheus Metrics**: Built-in support for exporting Prometheus metrics.
  See [METRICS.md](METRICS.md) for configuration and visualization details.
- **Static Files**: Built-in support for static-file serving, utilising embedded
  [static-web-server](https://static-web-server.net/).

### To-dos

- Access & error logs
- [Happy Eyeballs](https://en.wikipedia.org/wiki/Happy_Eyeballs) support
- Docker images.

### Possible Future Features

The following may be implemented at some point depending on interest and
resources.

- TLS-ALPN-01 ACME support.
- Other ACME providers (e.g. ZeroSSL)
- HTTP3/Quic support.
- [h2c](https://httpwg.org/specs/rfc7540.html#versioning) backend support
  (avoids a lot of proxy security corner-cases, but there's not much support in
  backend server software).
- Basic [12-factor](https://12factor.net/config)-style
  configuration. This should be relatively easy due to
  [corn's](https://cornlang.dev/) support for environment injection; however
  there is a [known issue](https://github.com/corn-config/corn/issues/49)
  limiting this currently.

### Probably-not features

Vicarian is very opinionated and tries to do the sensible thing by
default. Ideally if a particular header or setting was usually required by, say,
`nginx` then it should be the default. e.g. `X-Forwarded-For` and
[HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security)
are always set. Consequently there are no plans to add a large number of
features and settings.

Other notable non-features:

- Load-balancing, round-robin, complex rewrite rules, etc.
- Advanced connection tuning

## Installation

### Release Binaries

Tarballs are available on the [Github release page](https://github.com/tarka/vicarian/releases). 
These contain binaries, documentation, example configuration files, and an example
systemd configuration:

```
├── bin
│   └── vicarian
├── CONFIGURATION.md
├── etc
│   ├── systemd
│   │   └── system
│   │       └── vicarian.service
│   └── vicarian
│       ├── examples
│       │   ├── vicarian-dns01.corn
│       │   ├── vicarian-http01.corn
│       │   └── vicarian-tls-files.corn
│       ├── secrets
│       └── vicarian.corn
├── LICENSE
└── README.md
```

### Packages

Debian & Ubuntu packages are available from
[vicarian.org](https://vicarian.org/debian/):

    # 1. Download the repository key:
    curl -fsSL https://vicarian.org/debian/vicarian-repo.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/vicarian-repo-archive-keyring.gpg

    # 2. Add the APT source
    echo "deb [signed-by=/etc/apt/keyrings/vicarian-repo-archive-keyring.gpg] https://vicarian.org/debian stable main" | sudo tee /etc/apt/sources.list.d/vicarian.list

    # 3. Install Vicarian
    sudo apt update && sudo apt install vicarian

### Install from crates.io

```bash
cargo install vicarian
```

The binary will be available at
`~/.crates/bin/vicarian`. [cargo-binstall](https://github.com/cargo-bins/cargo-binstall)
is also supported.

## Running

### Systemd Service

An example `systemd` service in provided in `systemd/vicarian.service`. The
systemd service sets the `CAP_NET_BIND_SERVICE` flag which allows binding to
ports 80/443 without root.

## Configuration

Vicarian currently uses the [corn](https://cornlang.dev/) configuration
language. The default configuration file is located at
`/etc/vicarian/vicarian.corn`, but can be changed with the `--config` flag.

### Basic Configuration Structure

The full configuration structure is documented in
[CONFIGURATION.md](CONFIGURATION.md), and additional examples are available in
the `examples` directory, but a basic working configuration with HTTP-based
Let's Encrypt TLS would look like:

```corn
{
    listen = {
        addrs = [
            "[::]"  // Default; this covers IPv4 & IPv6
        ]
        insecure_port = 80 // Disabled by default, this will redirect to HTTPS
        tls_port = 443 // Default
    }

    vhosts = [
        {
            hostname = "example.com"

            tls = {
                acme = {
                    contact = "admin@example.com"
                    challenge.type = "http-01"
                }
            }

            backends = [
                {
                    context = "/"
                    url = "http://localhost:8080"
                }
                {
                    context = "/app2"
                    url = "https://localhost:8443"
                    trust = true
                }
                {
                    context = "/metrics"
                    url = "module://metrics"
                    // Optional. Env variables can be referenced.
                    auth_key = $env_SECRET_KEY
                }
            ]
        }
    ]
}
```


## Contributing

Contributions, bug reports, fixes, etc. are welcome.

Additionally, a useful contributions would be to add additional DNS provider
APIs to the [zone-update](https://github.com/tarka/zone-update/) project.

### Code of Conduct

The project follows the Rust Code of Conduct; [this can be found online](https://www.rust-lang.org/conduct.html).

### Tech stack

As well as the usual dependencies Vicarian also uses:

- [Pingora](https://github.com/cloudflare/pingora) for HTTP/TLS proxying.
- [instant-acme](https://github.com/djc/instant-acme) for ACME/LetEncrypt support.
- [static-web-server](https://static-web-server.net/) for static file support.
- [corn](https://cornlang.dev) for configuration.

### AI Contribution Policy

This project will not accept runtime code generated by AI/LLMs.

## Security Notes

- Vicarian binds to ports 80 and 443 by default, requiring appropriate permissions
- The systemd service uses `CAP_NET_BIND_SERVICE` to bind to privileged ports without full root privileges
- Private keys are stored in PEM format and should be properly secured
- When using ACME with DNS-01 challenges, ensure DNS provider API credentials are stored securely

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

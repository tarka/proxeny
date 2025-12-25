# Vicarian Configuration Documentation

Vicarian's configuration is defined in a [Corn](https://cornlang.dev) file, by
default in `/etc/vicarian/vicarian.corn`. This file defines how the proxy should
behave, including TLS settings, backend services, and routing.

## Basic Structure

A minimal Vicarian configuration file would look something like this (note: it
could be made smaller, but some defaults have been left in for clarity):

```corn
{
    listen = {
        addr = "[::]"  // This covers IPv4 & IPv6
        insecure_port = 80 // Default
        tls_port = 443 // Default
    }

    vhosts = [
        {
            hostname = "example.com"

            insecure = {
                redirect = true
            }

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
            ]
        }
    ]
}
```

## Configuration Fields

### listen
- **Type**: Object
- **Optional**: Yes (uses default values if not specified)
- **Description**: Network listening configuration for the proxy.
- **Fields**:
  - addr: The IP address to bind the server to (default: `"[::]"`)
  - insecure_port: The HTTP port to listen on (default: 80)
  - tls_port: The HTTPS port to listen on (default: 443)

### vhosts
- **Type**: Array of objects
- **Required**: Yes
- **Description**: List of virtual hosts (domains) that this server will handle.

### hostname (within vhost)
- **Type**: String
- **Required**: Yes (within each vhost)
- **Description**: The primary hostname for this virtual host. Used for TLS certificate generation when using ACME.
- **Example**: `hostname = "example.com"`

### aliases (within vhost)
- **Type**: Array of strings
- **Default**: Empty array
- **Description**: Additional domain names that should be handled by this virtual host.
- **Example**: `aliases = ["www.example.com", "api.example.com"]`

### listen (within vhost)
- **Type**: String
- **Default**: `"[::]"`
- **Description**: The IP address to bind this specific virtual host to. Overrides the global listen.addr if specified.
- **Examples**:
  - `listen = "[::]"` (all interfaces)
  - `listen = "127.0.0.1"` (IPv4 localhost)

### insecure (within vhost)
- **Type**: Object
- **Optional**: Yes (if TLS is configured with ACME)
- **Description**: Configuration for HTTP (non-TLS) connections for this virtual host.
- **Fields**:
  - redirect: Whether to redirect HTTP requests to HTTPS (default: true)

### tls (within vhost)
- **Type**: Object
- **Required**: Yes (within each vhost)
- **Description**: TLS configuration for HTTPS connections for this virtual host.
- **Fields**:
  - acme: Configuration for ACME certificate provisioning
  - files: Configuration for using existing certificate files

### backends (within vhost)
- **Type**: Array of objects
- **Required**: Yes (within each vhost)
- **Description**: List of backend services that this virtual host will proxy requests to.
- **Fields**:
  - context: The URL path prefix this backend handles (default: "/")
  - url: The backend service URL
  - trust: Whether to skip certificate verification for TLS backends (default: false)

## TLS Configuration

### TLS with Certificate Files

```corn
tls = {
  files = {
    keyfile = "/path/to/private.key"
    certfile = "/path/to/certificate.crt"
    reload = true
  }
}
```

### TLS with ACME HTTP provisioning

```corn
tls = {
  acme = {
    contact = "admin@example.com"
    challenge.type = "http-01"
  }
}
```

### TLS with ACME DNS provisioning

```corn
tls = {
  acme = {
    acme_provider = "letsencrypt"  // Default & only supported provider ATM
    contact = "admin@example.com"
    challenge = {
      type = "dns-01"  // or "http-01"
      dns_provider = {
        name = "porkbun"
        key = $env_PORKBUN_KEY
        secret = $env_PORKBUN_SECRET
      }
    }
  }
}
```

## Backend Configuration

Each backend entry has the following fields:

### context
- **Type**: String
- **Default**: "/"
- **Description**: The URL path prefix that this backend will handle. For example, if `context = "/api"`, requests to `/api/endpoint` will be forwarded to the backend.

### url
- **Type**: String (URI)
- **Required**: Yes
- **Description**: The URL of the backend service to proxy requests to.

### trust
- **Type**: Boolean
- **Default**: false
- **Description**: Set to true if the backend uses a self-signed certificate or certificate that can't be verified by the system's CA store.


## Additional Configuration Options

### dev_mode
- **Type**: Boolean
- **Default**: false
- **Description**: Enables development mode with relaxed security settings. This should not be used in production environments.

## Environment Variables

Configuration supports environment variable substitution using the `$env_VARIABLE_NAME` syntax. This allows sensitive information like API keys to be kept out of configuration files.

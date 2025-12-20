# Vicarian Configuration Documentation

Vicarian's configuration is defined in a [Corn](https://cornlang.dev) file, by
default in `/etc/vicarian/vicarian.corn`. This file defines how the proxy should
behave, including TLS settings, backend services, and routing.

## Basic Structure

A typical vicarian configuration file includes the following top-level fields:

```corn
{
  hostname = "example.com"
  listen = "[::]"
  
  // Vicarian does not enable non-TLS by default
  insecure = {
    port = 80  // Default
    redirect = true  // Redirect to TLS
  }
  
  tls = {
    port = 443  // Default
    config = {
      // Or `files` for existing certificates.
      acme = {
        acme_provider = "letsencrypt"
        contact = "admin@example.com"
        challenge.type = "http-01" // `dns-01` is also supported, see below
      }
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
```

## Configuration Fields

### hostname
- **Type**: String
- **Required**: Yes
- **Description**: The primary hostname for this server. Used for TLS certificate generation when using ACME.
- **Example**: `hostname = "example.com"`

### listen
- **Type**: String
- **Default**: `"[::]"`
- **Description**: The IP address to bind the server to. Uses IPv6 notation to handle both IPv4 and IPv6 connections.
- **Examples**: 
  - `listen = "[::]"` (all interfaces)
  - `listen = "127.0.0.1"` (IPv4 localhost)

### aliases
- **Type**: Array of strings
- **Default**: Empty array
- **Description**: Additional domain names that should be handled by this server.
- **Example**: `aliases = ["www.example.com", "api.example.com"]`

### insecure
- **Type**: Object
- **Optional**: Yes (if TLS is configured with ACME)
- **Description**: Configuration for HTTP (non-TLS) connections.
- **Fields**:
  - port: The HTTP port to listen on (default: 80)
  - redirect: Whether to redirect HTTP requests to HTTPS (default: true)

### tls
- **Type**: Object
- **Required**: Yes
- **Description**: TLS configuration for HTTPS connections.
- **Fields**:
  - port: The HTTPS port to listen on (default: 443)
  - config: Configuration for the TLS certificate (either "files" or "acme")

### backends
- **Type**: Array of objects
- **Required**: Yes
- **Description**: List of backend services that vicarian will proxy requests to.
- **Fields**:
  - context: The URL path prefix this backend handles (default: "/")
  - url: The backend service URL
  - trust: Whether to skip certificate verification for TLS backends (default: false)

## TLS Configuration

### TLS with Certificate Files

```corn
tls = {
  port = 443
  config = {
    files = {
      keyfile = "/path/to/private.key"
      certfile = "/path/to/certificate.crt"
      reload = true
    }
  }
}
```

### TLS with ACME HTTP provisioning

```corn
tls = {
  port = 443
  config = {
    acme = {
      acme_provider = "letsencrypt"
      contact = "admin@example.com"
      challenge.type = "http-01"
    }
  }
}
```

### TLS with ACME DNS provisioning

```corn
tls = {
  port = 443
  config = {
    acme = {
      acme_provider = "letsencrypt"
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

## Example Configurations

See the example configuration files in the `examples/` directory for full working examples:
- `vicarian-tls-files.corn`: TLS with certificate files
- `vicarian-http01.corn`: ACME with HTTP-01 challenge
- `vicarian-dns01.corn`: ACME with DNS-01 challenge

## Environment Variables

Configuration supports environment variable substitution using the `$env_VARIABLE_NAME` syntax. This allows sensitive information like API keys to be kept out of configuration files.

# caddy-token

Caddy token based authentication. Supports static tokens from files, signed API keys, JWT tokens, and client certificate authentication.

## Quick Start

```caddyfile
{
    order token first
}

:3000 {
    token {
        jwt {
            issuer https://dex.issuer.lan
            group admin
        }
    }
  
    reverse_proxy https://some.service.internal {
        header_up Host {http.reverse_proxy.upstream.hostport}
    }
}
```

## Development

Read [Extending Caddy](https://caddyserver.com/docs/extending-caddy) to get an overview
of what interfaces you need to implement.

# building

You first need to build a new caddy executable with this plugin. The easiest way is to do this with xcaddy.

Install xcaddy:

```shell
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

After xcaddy installation you can build caddy with this plugin by executing:

```shell
xcaddy build v2.8.4 --with github.com/loafoe/caddy-token
```
# Configuration

The `token` directive supports multiple authentication methods and configuration options.

## Directive Syntax

```caddyfile
token {
    file <token_file>
    jwt {
        issuer <issuer_url>
        verify <true|false>
        group <group_name>
    }
    signed {
        key <signing_key>
        scope <scope_name>
    }
    client_ca {
        debug <true|false>
        default_org <organization_name>
    }
    injectOrgHeader <true|false>
    allowUpstreamAuth <true|false>
    tenantOrgClaim <claim_name>
}
```

## Directives Reference

### `file`
Specifies a file containing static API tokens.

**Syntax:** `file <path_to_token_file>`

**Example:**
```caddyfile
token {
    file /etc/caddy/tokens.txt
}
```

### `jwt`
Configures JWT token validation using an OIDC issuer.

**Sub-directives:**
- `issuer <url>` - OIDC issuer URL for token validation
- `verify <true|false>` - Enable/disable token verification (default: true)
- `group <name>` - Required group claim (can be specified multiple times)

**Example:**
```caddyfile
token {
    jwt {
        issuer https://auth.example.com
        verify true
        group admin
        group developers
    }
}
```

### `signed`
Configures signed API key validation.

**Sub-directives:**
- `key <signing_key>` - The signing key for API key validation
- `scope <name>` - Required scope (can be specified multiple times)

**Example:**
```caddyfile
token {
    signed {
        key "your-signing-key-here"
        scope read
        scope write
    }
}
```

### `client_ca`
Enables client certificate authentication.

**Sub-directives:**
- `debug <true|false>` - Enable debug logging for client CA operations
- `default_org <organization_name>` - Organization name to set in X-Scope-OrgID header (default: "anonymous")

**Example:**
```caddyfile
token {
    client_ca {
        debug true
        default_org "my-organization"
    }
}
```

### `injectOrgHeader`
Controls whether to inject the `X-Scope-OrgID` header based on token claims.

**Syntax:** `injectOrgHeader <true|false>`
**Default:** `true`

**Example:**
```caddyfile
token {
    injectOrgHeader false
}
```

### `allowUpstreamAuth`
Allows upstream services to set authentication headers.

**Syntax:** `allowUpstreamAuth <true|false>`
**Default:** `false`

**Example:**
```caddyfile
token {
    allowUpstreamAuth true
}
```

### `tenantOrgClaim`
Specifies which JWT claim to use for tenant organization mapping.

**Syntax:** `tenantOrgClaim <claim_name>`
**Options:** `ort` (observability read tenants), `owt` (observability write tenants)

**Example:**
```caddyfile
token {
    tenantOrgClaim ort
}
```

## Complete Configuration Examples

### Static Token File Authentication
```caddyfile
{
    order token first
}

:8080 {
    token {
        file /etc/caddy/api-tokens.txt
        injectOrgHeader true
    }
    
    respond "Authenticated with static token"
}
```

### JWT with OIDC Provider
```caddyfile
{
    order token first
}

:8080 {
    token {
        jwt {
            issuer https://auth.example.com
            verify true
            group admin
        }
        tenantOrgClaim ort
        injectOrgHeader true
    }
    
    reverse_proxy backend:3000
}
```

### Signed API Keys
```caddyfile
{
    order token first
}

:8080 {
    token {
        signed {
            key "your-secret-signing-key"
            scope api:read
            scope api:write
        }
    }
    
    reverse_proxy api-server:8000
}
```

### Client Certificate Authentication
```caddyfile
{
    order token first
}

:8080 {
    token {
        client_ca {
            debug true
            default_org "secure-clients"
        }
        allowUpstreamAuth false
    }
    
    reverse_proxy secure-service:9000
}
```

### Combined Authentication Methods
```caddyfile
{
    order token first
}

:8080 {
    token {
        file /etc/caddy/tokens.txt
        jwt {
            issuer https://sso.company.com
            group employees
        }
        signed {
            key "api-signing-key"
            scope service:access
        }
        client_ca {
            debug false
            default_org "combined-clients"
        }
        injectOrgHeader true
        allowUpstreamAuth false
        tenantOrgClaim ort
    }
    
    reverse_proxy internal-service:5000
}
```

## Authentication Flow

The plugin checks for authentication in the following order:

1. **Upstream Authentication** - When `allowUpstreamAuth` is enabled, allows upstream `X-Scope-OrgID` headers

2. **Client Certificate Authentication** - When `client_ca` is configured, checks for TLS client certificates and sets `X-Scope-OrgID` to the configured `default_org` value

3. **API Key Authentication** - Checks for API keys in:
   - `X-Api-Key` header
   - Basic Auth password field
   - `Authorization: Bearer <token>` header

4. **JWT Token Authentication** - Validates JWT tokens from:
   - `X-Id-Token` header
   - Verifies against configured OIDC issuer

# license

License is Apache 2.0

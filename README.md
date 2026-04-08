# caddy-token

Caddy token based authentication. Supports static tokens from files, signed API keys, JWT tokens, client certificate authentication, and SPIFFE JWT SVIDs.

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

### `spiffe`
Configures SPIFFE JWT SVID authentication. Supports multiple trust domains with per-domain organization extraction.

**Sub-directives:**
- `workload_socket <socket_path>` - SPIFFE Workload API socket path for fetching JWT bundles (e.g., `unix:///run/spire/sockets/agent.sock`). When set, `jwks_url` is not required. Respects `SPIFFE_ENDPOINT_SOCKET` environment variable.
- `trust_domain <domain> { ... }` - Configure a SPIFFE trust domain (can be specified multiple times)
  - `jwks_url <url>` - JWKS endpoint URL for JWT verification (required unless `workload_socket` is set)
  - `audience <audience>` - Required audience claim value
  - `org <organization>` - Static organization name for this trust domain
  - `org_from_path <true|false>` - Extract organization from SPIFFE ID path
  - `org_path_index <index>` - Path segment index to use as organization (0-indexed)
  - `org_claim <claim_name>` - Extract organization from a JWT claim
- `allowed_ids <pattern>` - SPIFFE ID pattern to allow (supports `*` and `**` wildcards, can be specified multiple times)
- `default_org <organization>` - Default organization when extraction fails (default: "anonymous")
- `debug <true|false>` - Enable debug logging

**Organization Extraction Priority:**
1. Static `org` value (if configured)
2. JWT claim via `org_claim` (if configured and claim exists)
3. Path segment via `org_from_path` and `org_path_index` (if configured)
4. `default_org` fallback

**Example with JWKS URL:**
```caddyfile
token {
    spiffe {
        trust_domain example.org {
            jwks_url https://spire.example.org/.well-known/jwks.json
            audience myapi
            org_from_path true
            org_path_index 1
        }
        allowed_ids spiffe://example.org/tenant/*/service/*
        default_org anonymous
    }
}
```

**Example with Workload API (Kubernetes/SPIRE):**
```caddyfile
token {
    spiffe {
        workload_socket unix:///run/spire/sockets/agent.sock
        trust_domain example.org {
            audience myapi
            org_from_path true
            org_path_index 1
        }
        allowed_ids spiffe://example.org/tenant/*/service/*
        default_org anonymous
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

### SPIFFE JWT SVID Authentication
```caddyfile
{
    order token first
}

:8080 {
    token {
        spiffe {
            trust_domain example.org {
                jwks_url https://spire.example.org/.well-known/jwks.json
                audience myapi
                org_from_path true
                org_path_index 1
            }
            allowed_ids spiffe://example.org/tenant/*/service/*
            default_org anonymous
        }
        injectOrgHeader true
    }
    
    reverse_proxy backend:3000
}
```

### SPIFFE with Multiple Trust Domains
```caddyfile
{
    order token first
}

:8080 {
    token {
        spiffe {
            trust_domain prod.example.org {
                jwks_url https://spire-prod.example.org/keys
                audience prod-api
                org production
            }
            trust_domain staging.example.org {
                jwks_url https://spire-staging.example.org/keys
                audience staging-api
                org staging
            }
            trust_domain partners.example.org {
                jwks_url https://spire-partners.example.org/keys
                audience partner-api
                org_claim partner_id
            }
            default_org anonymous
        }
    }
    
    reverse_proxy backend:3000
}
```

### SPIFFE with Kubernetes/SPIRE Workload API
```caddyfile
{
    order token first
}

:8080 {
    token {
        spiffe {
            # Connect to SPIRE Agent socket (mounted as volume in K8s)
            workload_socket unix:///run/spire/sockets/agent.sock
            trust_domain cluster.local {
                audience myapi
                org_from_path true
                org_path_index 1  # e.g., spiffe://cluster.local/ns/{namespace}/sa/...
            }
            allowed_ids spiffe://cluster.local/ns/*/sa/*
            default_org anonymous
        }
        injectOrgHeader true
    }
    
    reverse_proxy backend:3000
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

## SPIFFE Integration

[SPIFFE](https://spiffe.io/) (Secure Production Identity Framework For Everyone) provides a standard for service identity in distributed systems. This plugin supports SPIFFE JWT SVIDs for workload authentication.

### How It Works

1. Workloads present JWT SVIDs in the `Authorization: Bearer <token>` header
2. The plugin extracts the SPIFFE ID from the JWT's `sub` claim (e.g., `spiffe://cluster.local/ns/prod/sa/api`)
3. JWT signature is verified against keys from either:
   - **Workload API**: Fetches JWT bundles directly from SPIRE Agent (recommended for Kubernetes)
   - **JWKS URL**: Fetches keys from an HTTP endpoint
4. The `X-Scope-OrgID` header is set based on the trust domain configuration

### Kubernetes Deployment with SPIRE

To use SPIFFE authentication in Kubernetes with SPIRE:

#### 1. Prerequisites

- SPIRE Server deployed in your cluster
- SPIRE Agent running as a DaemonSet
- Workloads registered with SPIRE (via ClusterSPIFFEID or manual registration)

#### 2. Mount the SPIRE Agent Socket

Add the SPIRE Agent socket volume to your Caddy deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: caddy-gateway
spec:
  template:
    spec:
      containers:
        - name: caddy
          image: your-caddy-image:latest
          volumeMounts:
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
              readOnly: true
      volumes:
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/sockets
            type: Directory
```

#### 3. Register the Caddy Workload

Create a ClusterSPIFFEID for your Caddy deployment:

```yaml
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: caddy-gateway
spec:
  spiffeIDTemplate: "spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}"
  podSelector:
    matchLabels:
      app: caddy-gateway
  namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: gateway
```

#### 4. Configure Caddy

```caddyfile
{
    order token first
}

:8080 {
    token {
        spiffe {
            workload_socket unix:///run/spire/sockets/agent.sock
            trust_domain cluster.local {
                audience myapi
                org_from_path true
                org_path_index 1  # Extract namespace as org
            }
            allowed_ids spiffe://cluster.local/ns/*/sa/*
            default_org anonymous
        }
    }
    
    reverse_proxy backend:3000
}
```

### SPIFFE ID Patterns

The `allowed_ids` directive supports glob patterns:

| Pattern | Matches |
|---------|---------|
| `spiffe://example.org/service/api` | Exact match only |
| `spiffe://example.org/service/*` | Any single segment: `/service/api`, `/service/web` |
| `spiffe://example.org/ns/**` | Any path under `/ns/`: `/ns/prod/sa/api`, `/ns/dev/sa/web/v2` |
| `spiffe://*/service/*` | Any trust domain with `/service/{name}` path |

### Organization Extraction from SPIFFE ID

For a SPIFFE ID like `spiffe://cluster.local/ns/production/sa/api-service`:

| Configuration | Extracted Org |
|---------------|---------------|
| `org production` | `production` (static) |
| `org_from_path true`, `org_path_index 0` | `ns` |
| `org_from_path true`, `org_path_index 1` | `production` |
| `org_from_path true`, `org_path_index 2` | `sa` |
| `org_from_path true`, `org_path_index 3` | `api-service` |
| `org_claim tenant` | Value of `tenant` claim in JWT |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SPIFFE_ENDPOINT_SOCKET` | Default Workload API socket path (used if `workload_socket` not configured) |

## Authentication Flow

The plugin checks for authentication in the following order:

1. **Upstream Authentication** - When `allowUpstreamAuth` is enabled, allows upstream `X-Scope-OrgID` headers

2. **Client Certificate Authentication** - When `client_ca` is configured, checks for TLS client certificates and sets `X-Scope-OrgID` to the configured `default_org` value

3. **SPIFFE JWT SVID Authentication** - When `spiffe` is configured, validates Bearer tokens as SPIFFE JWT SVIDs:
   - Extracts trust domain from the `sub` claim (SPIFFE ID)
   - Verifies signature against the trust domain's JWKS
   - Validates audience claim
   - Matches SPIFFE ID against allowed patterns
   - Sets `X-Scope-OrgID` based on trust domain configuration

4. **API Key Authentication** - Checks for API keys in:
   - `X-Api-Key` header
   - Basic Auth password field
   - `Authorization: Bearer <token>` header

5. **JWT Token Authentication** - Validates JWT tokens from:
   - `X-Id-Token` header
   - Verifies against configured OIDC issuer

# caddy-token-gen CLI tool

A companion CLI tool is available to generate static tokens for use with this plugin.

## install

```shell
go install github.com/loafoe/caddy-token/cmd/caddy-token-gen@latest
```

## usage

```shell
caddy-token-gen g -e client-test -r us-east -p fake -o fake
```

# license

License is Apache 2.0

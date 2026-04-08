package token

import (
	"path/filepath"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(&Middleware{})
	httpcaddyfile.RegisterHandlerDirective("token", parseCaddyfile)
}

// UnmarshalCaddyfile sets up caddy-token from Caddyfile tokens. Syntax:
//
//	token {
//	  file <token_file>
//	  jwt {
//	    issuer <issuer_url>
//	    group <value>
//	    ...
//	  }
//	  signed {
//	    key <key>
//	    scope <value>
//	  }
//	  client_ca {
//	    debug <true|false>
//	    default_org <organization_name>
//	  }
//	  spiffe {
//	    workload_socket <socket_path>  # e.g., unix:///run/spire/sockets/agent.sock
//	    trust_domain <domain> {
//	      jwks_url <url>               # required if workload_socket not set
//	      audience <audience>
//	      org <static_org>
//	      org_from_path <true|false>
//	      org_path_index <index>
//	      org_claim <claim_name>
//	    }
//	    allowed_ids <pattern>
//	    default_org <org>
//	    debug <true|false>
//	  }
//	  injectOrgHeader true
//	  allowUpstreamAuth true
//	  tenantOrgClaim ort
//	  debug false
//	}

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	m.InjectOrgHeader = true // default
	m.Verify = true
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "file":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if m.TokenFile != "" {
					return d.Err("Issuer already set")
				}
				filePath := d.Val()
				absPath, err := filepath.Abs(filePath)
				if err != nil {
					return d.Errf("error resolving path: %w", err)
				}
				m.TokenFile = absPath
			case "jwt":
				for nesting := d.Nesting(); d.NextBlock(nesting); {
					switch d.Val() {
					case "verify":
						if !d.NextArg() {

							return d.ArgErr()
						}
						if enable := d.Val(); enable == "false" {
							m.Verify = false
						}
					case "issuer":
						if !d.NextArg() {
							return d.ArgErr()
						}
						m.Issuer = d.Val()
					case "group":
						if !d.NextArg() {
							return d.ArgErr()
						}
						group := d.Val()
						m.Groups = append(m.Groups, group)
					default:
						return d.Errf("unrecognized subdirective '%s'", d.Val())
					}
				}
			case "signed":
				for nesting := d.Nesting(); d.NextBlock(nesting); {
					switch d.Val() {
					case "key":
						if !d.NextArg() {
							return d.ArgErr()
						}
						m.SigningKey = d.Val()
					case "scope":
						if !d.NextArg() {
							return d.ArgErr()
						}
						scope := d.Val()
						m.Scopes = append(m.Scopes, scope)
					default:
						return d.Errf("unrecognized subdirective '%s'", d.Val())
					}
				}
			case "debug":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if debug := d.Val(); debug == "true" {
					m.Debug = true
				} else if debug == "false" {
					m.Debug = false
				} else {
					return d.Errf("debug must be 'true' or 'false', got '%s'", debug)
				}
			case "client_ca":
				m.ClientCA = true          // Set to true when directive is present
				m.DefaultOrg = "anonymous" // Set default value
				for nesting := d.Nesting(); d.NextBlock(nesting); {
					switch d.Val() {
					case "debug":
						if !d.NextArg() {
							return d.ArgErr()
						}
						if debug := d.Val(); debug == "true" {
							m.Debug = true
						} else if debug == "false" {
							m.Debug = false
						} else {
							return d.Errf("debug must be 'true' or 'false', got '%s'", debug)
						}
					case "default_org":
						if !d.NextArg() {
							return d.ArgErr()
						}
						m.DefaultOrg = d.Val()
					default:
						return d.Errf("unrecognized subdirective '%s'", d.Val())
					}
				}
			case "spiffe":
				if m.Spiffe == nil {
					m.Spiffe = &SpiffeConfig{DefaultOrg: "anonymous"}
				}
				for nesting := d.Nesting(); d.NextBlock(nesting); {
					switch d.Val() {
					case "trust_domain":
						if !d.NextArg() {
							return d.ArgErr()
						}
						td := SpiffeTrustDomain{Domain: d.Val()}
						for nesting := d.Nesting(); d.NextBlock(nesting); {
							switch d.Val() {
							case "jwks_url":
								if !d.NextArg() {
									return d.ArgErr()
								}
								td.JWKSURL = d.Val()
							case "audience":
								if !d.NextArg() {
									return d.ArgErr()
								}
								td.Audience = d.Val()
							case "org":
								if !d.NextArg() {
									return d.ArgErr()
								}
								td.Org = d.Val()
							case "org_from_path":
								if !d.NextArg() {
									return d.ArgErr()
								}
								if val := d.Val(); val == "true" {
									td.OrgFromPath = true
								} else if val != "false" {
									return d.Errf("org_from_path must be 'true' or 'false', got '%s'", val)
								}
							case "org_path_index":
								if !d.NextArg() {
									return d.ArgErr()
								}
								idx, err := strconv.Atoi(d.Val())
								if err != nil {
									return d.Errf("org_path_index must be an integer, got '%s'", d.Val())
								}
								td.OrgPathIndex = idx
							case "org_claim":
								if !d.NextArg() {
									return d.ArgErr()
								}
								td.OrgClaim = d.Val()
							default:
								return d.Errf("unrecognized trust_domain subdirective '%s'", d.Val())
							}
						}
						// jwks_url is required unless workload_socket will be configured
						// We defer this validation to after the full spiffe block is parsed
						m.Spiffe.TrustDomains = append(m.Spiffe.TrustDomains, td)
					case "allowed_ids":
						if !d.NextArg() {
							return d.ArgErr()
						}
						m.Spiffe.AllowedIDs = append(m.Spiffe.AllowedIDs, d.Val())
					case "default_org":
						if !d.NextArg() {
							return d.ArgErr()
						}
						m.Spiffe.DefaultOrg = d.Val()
					case "debug":
						if !d.NextArg() {
							return d.ArgErr()
						}
						if debug := d.Val(); debug == "true" {
							m.Spiffe.Debug = true
						} else if debug != "false" {
							return d.Errf("debug must be 'true' or 'false', got '%s'", debug)
						}
					case "workload_socket":
						if !d.NextArg() {
							return d.ArgErr()
						}
						m.Spiffe.WorkloadSocket = d.Val()
					default:
						return d.Errf("unrecognized spiffe subdirective '%s'", d.Val())
					}
				}
				// Validate: each trust_domain needs jwks_url unless workload_socket is set
				if m.Spiffe.WorkloadSocket == "" {
					for _, td := range m.Spiffe.TrustDomains {
						if td.JWKSURL == "" {
							return d.Errf("trust_domain %s requires jwks_url (or configure workload_socket)", td.Domain)
						}
					}
				}
			case "injectOrgHeader":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if enable := d.Val(); enable == "false" {
					m.InjectOrgHeader = false
				}
			case "allowUpstreamAuth":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if enable := d.Val(); enable == "true" {
					m.AllowUpstreamAuth = true
				}
			case "tenantOrgClaim":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.TenantOrgClaim = d.Val()
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

// parseCaddyfile will unmarshal tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := &Middleware{}
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

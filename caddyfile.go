package token

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"path/filepath"
)

func init() {
	caddy.RegisterModule(&Middleware{})
	httpcaddyfile.RegisterHandlerDirective("token", parseCaddyfile)
}

// UnmarshalCaddyfile sets up caddy-token from Caddyfile tokens. Syntax:
//
//			token {
//			  file <token_file>
//			  issuer <issuer_url>
//		      injectOrgHeader true
//	          tenantOrgClaim ort
//			}
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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
			case "issuer":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Issuer = d.Val()
			case "injectOrgHeader":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if enable := d.Val(); enable == "false" {
					m.injectOrgHeader = false
				}
			case "tenantOrgClaim":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.tenantOrgClaim = d.Val()
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
package token

import (
	"bufio"
	"encoding/json"
	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"net/http"
	"os"
	"strings"
)

const (
	scopeIDHeader = "X-Scope-OrgID-Test"
	tokenHeader   = "X-API-Key"
)

type Key struct {
	Version      string `json:"v"`
	Token        string `json:"t"`
	Organization string `json:"o"`
	Environment  string `json:"e"`
	Region       string `json:"r"`
	Project      string `json:"p"`
}

type Middleware struct {
	logger    *zap.Logger
	TokenFile string
	tokens    map[string]Key
}

func (m *Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.token",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// UnmarshalCaddyfile sets up Lessor from Caddyfile tokens. Syntax:
// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
//	token [<token_file>] {
//	    file <token_file>
//	}
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			m.TokenFile = d.Val()
		}
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "file":
				if m.TokenFile != "" {
					return d.Err("Issuer already set")
				}
				m.TokenFile = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := &Middleware{}
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	err := m.checkTokenAndInjectHeaders(r)
	if err != nil {
		return err
	}
	return next.ServeHTTP(w, r)
}

func (m *Middleware) Validate() error {
	return nil
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	tokens, err := readTokenFile(m.TokenFile)
	if err != nil {
		return err
	}
	m.tokens = tokens
	m.logger = ctx.Logger() // g.logger is a *zap.Logger
	return nil
}

func (m *Middleware) checkTokenAndInjectHeaders(r *http.Request) error {
	tokenValue := r.Header.Get(tokenHeader)
	if tokenValue == "" {
		return caddyhttp.Error(http.StatusUnauthorized, nil)
	}
	token, ok := m.tokens[tokenValue]
	if !ok {
		return caddyhttp.Error(http.StatusForbidden, nil)
	}
	r.Header.Set(scopeIDHeader, token.Organization)
	return nil
}

// readTokenFile reads a static token file and returns a map of tokens
func readTokenFile(filename string) (map[string]Key, error) {
	tokens := make(map[string]Key)

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var decoded Key
		trimmedLine := strings.TrimSpace(scanner.Text())
		err := json.Unmarshal([]byte(trimmedLine), &decoded)
		if err != nil {
			return nil, err
		}
		tokens[trimmedLine] = decoded
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return tokens, nil
}

func init() {
	caddy.RegisterModule(&Middleware{})
	httpcaddyfile.RegisterHandlerDirective("token", parseCaddyfile)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
	_ caddy.Module                = (*Middleware)(nil)
)

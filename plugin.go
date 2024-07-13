package token

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"net/http"
	"os"
	"strings"
)

const (
	Prefix         = "lst_"
	scopeIDHeader  = "X-Scope-OrgID-Test"
	apiKeyHeader   = "X-API-Key"
	tokenKeyHeader = "X-Id-Token"
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
	Issuer    string
	verifier  *oidc.IDTokenVerifier
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
//		token {
//		    file <token_file>
//	        issuer <issuer_url>
//		}
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
				m.TokenFile = d.Val()
			case "issuer":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Issuer = d.Val()
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
	m.logger = ctx.Logger() // g.logger is a *zap.Logger
	if m.Issuer != "" {
		provider, err := oidc.NewProvider(ctx, m.Issuer)
		if err != nil {
			m.logger.Error("error provisioning issuer", zap.String("issuer", m.Issuer), zap.Error(err))
			return fmt.Errorf("erorr provisioning issuer '%s': %w", m.Issuer, err)
		}
		m.verifier = provider.Verifier(&oidc.Config{
			SkipClientIDCheck: true,
		})
		m.logger.Info("verifier setup", zap.String("issuer", m.Issuer))
	}
	if m.TokenFile != "" {
		tokens, err := m.readTokenFile(m.TokenFile)
		if err != nil {
			return err
		}
		m.tokens = tokens
	}
	if m.verifier == nil && len(m.tokens) == 0 {
		return fmt.Errorf("no tokens or issuer provided")
	}
	return nil
}

func (m *Middleware) checkTokenAndInjectHeaders(r *http.Request) error {
	apiKey := r.Header.Get(apiKeyHeader)
	if apiKey != "" { // Token flow
		token, ok := m.tokens[apiKey]
		if !ok {
			return caddyhttp.Error(http.StatusForbidden, nil)
		}
		r.Header.Set(scopeIDHeader, token.Organization)
		return nil
	}
	idToken := r.Header.Get(tokenKeyHeader)
	if m.verifier != nil && idToken != "" { // OIDC flow
		_, err := m.verifier.Verify(r.Context(), idToken)
		if err != nil {
			return caddyhttp.Error(http.StatusUnauthorized, err)
		}
		type DexClaims struct {
			ManagingOrganization string `json:"mid,omitempty"`
			jwt.RegisteredClaims
		}

		token, err := jwt.ParseWithClaims(idToken, &DexClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(""), jwt.ErrTokenUnverifiable // We already verified
		})
		if !errors.Is(err, jwt.ErrTokenUnverifiable) {
			return caddyhttp.Error(http.StatusUnauthorized, err)
		}
		// Verified
		claims, ok := token.Claims.(*DexClaims)
		if !ok {
			m.logger.Error("invalid claims detected", zap.Error(err))
			err := fmt.Errorf("invalid claims detected: %w", err)
			return caddyhttp.Error(http.StatusUnauthorized, err)
		}
		if len(claims.ManagingOrganization) == 0 {
			r.Header.Set(scopeIDHeader, claims.ManagingOrganization)
		} else {
			m.logger.Info("fallback fake tenant")
			r.Header.Set(scopeIDHeader, "fake") // Default to fake
		}
		return nil
	}
	// No valid token found
	return caddyhttp.Error(http.StatusUnauthorized, nil)
}

// readTokenFile reads a static token file and returns a map of tokens
func (m *Middleware) readTokenFile(filename string) (map[string]Key, error) {
	tokens := make(map[string]Key)

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("opening file %s: %w", filename, err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var decoded Key
		trimmedLine := strings.TrimSpace(scanner.Text())
		prefixRemoved := strings.TrimPrefix(trimmedLine, Prefix)
		decodedString, err := base64.StdEncoding.DecodeString(prefixRemoved)
		err = json.Unmarshal([]byte(decodedString), &decoded)
		if err != nil {
			return nil, fmt.Errorf("unmarshal token: %w '%s'", err, decodedString)
		}
		tokens[trimmedLine] = decoded
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner: %w", err)
	}
	m.logger.Info("loaded tokens", zap.Int("count", len(tokens)))
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

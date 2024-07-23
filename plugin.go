package token

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/avast/retry-go/v4"
	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/fsnotify/fsnotify"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	Prefix         = "lst_"
	scopeIDHeader  = "X-Scope-OrgID-Test"
	apiKeyHeader   = "X-Api-Key"
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
	watcher   *fsnotify.Watcher
}

func (m *Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.token",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// UnmarshalCaddyfile sets up casdy-token from Caddyfile tokens. Syntax:
//
//	token {
//	  file <token_file>
//	  issuer <issuer_url>
//	}
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
	var err error

	m.logger = ctx.Logger() // g.logger is a *zap.Logger
	// Create new watcher.
	m.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("error creating watcher: %w", err)
	}
	//defer watcher.Close()

	if m.Issuer != "" {
		provider, err := oidc.NewProvider(ctx, m.Issuer)
		if err != nil {
			m.logger.Info("error provisioning issuer", zap.String("issuer", m.Issuer), zap.Error(err))
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
		err = m.watcher.Add(m.TokenFile)
		if err != nil {
			return fmt.Errorf("error watching token file: %w", err)
		}
		m.tokens = tokens
	}
	if m.verifier == nil && len(m.tokens) == 0 {
		return fmt.Errorf("no tokens or issuer provided")
	}
	m.logger.Info("provisioned caddy-token middleware",
		zap.String("issuer", m.Issuer),
		zap.String("tokenFile", m.TokenFile),
		zap.Int64("apiKeyCount", int64(len(m.tokens))))
	// start watching tokenFile
	if m.TokenFile != "" {
		m.logger.Info("starting watcher for token file", zap.String("tokenFile", m.TokenFile))
		// Start listening for events
		go func() {
			for {
				select {
				case event, ok := <-m.watcher.Events:
					if !ok {
						return
					}
					if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove) {
						tokens := make(map[string]Key)
						err = retry.Do(func() error {
							tokens, err = m.readTokenFile(m.TokenFile)
							return err
						}, retry.Attempts(5), retry.Delay(1))
						if err != nil {
							m.logger.Error("error reloading token file", zap.Error(err))
						} else {
							m.tokens = tokens
							m.logger.Info("reloaded token file", zap.Int("apiKeyCount", len(m.tokens)))
						}
					}
					if event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove) { // Re-add
						_ = m.watcher.Remove(m.TokenFile)
						err = retry.Do(func() error {
							return m.watcher.Add(m.TokenFile)
						}, retry.Attempts(5), retry.Delay(1))
						if err != nil {
							m.logger.Error("error re-adding watcher", zap.Error(err))
						}
					}
				case err, ok := <-m.watcher.Errors:
					if !ok {
						return
					}
					m.logger.Error("watcher error", zap.Error(err))
				}
			}
		}()
	} else {
		m.logger.Info("no token file to watch")
	}
	return nil
}

func (m *Middleware) checkTokenAndInjectHeaders(r *http.Request) error {
	// Read API key from header
	apiKey := r.Header.Get(apiKeyHeader)
	// Try to extract token from Basic Auth
	username, password, ok := r.BasicAuth()
	if ok && username == "otlp" && password != "" {
		apiKey = password
	}
	if apiKey != "" { // API Key flow
		token, ok := m.tokens[apiKey]
		if !ok {
			m.logger.Info("invalid token detected",
				zap.String("apiKey", apiKey),
				zap.Int64("count", int64(len(m.tokens))))
			return caddyhttp.Error(http.StatusForbidden, nil)
		}
		r.Header.Set(scopeIDHeader, token.Organization)
		return nil
	}
	idToken := r.Header.Get(tokenKeyHeader)
	if m.verifier != nil && idToken != "" { // OIDC flow
		_, err := m.verifier.Verify(r.Context(), idToken)
		if err != nil {
			m.logger.Info("invalid token detected", zap.Error(err))
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
			m.logger.Info("invalid claims detected", zap.Error(err))
			err := fmt.Errorf("invalid claims detected: %w", err)
			return caddyhttp.Error(http.StatusUnauthorized, err)
		}
		// TODO: configurable header injection
		if len(claims.ManagingOrganization) > 0 {
			r.Header.Set(scopeIDHeader, claims.ManagingOrganization)
		} else {
			m.logger.Debug("fallback fake tenant")
			r.Header.Set(scopeIDHeader, "fake") // Default to fake
		}
		return nil
	}
	// No valid token found
	m.logger.Error("no valid token found")
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
		if len(trimmedLine) == 0 { // Skip empty lines
			continue
		}
		prefixRemoved := strings.TrimPrefix(trimmedLine, Prefix)
		decodedString, err := base64.StdEncoding.DecodeString(prefixRemoved)
		if err != nil {
			return nil, fmt.Errorf("decode token: %w", err)
		}
		err = json.Unmarshal([]byte(decodedString), &decoded)
		if err != nil {
			return nil, fmt.Errorf("unmarshal token: %w '%s'", err, decodedString)
		}
		tokens[trimmedLine] = decoded
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner: %w", err)
	}
	m.logger.Info("loaded tokens", zap.Int("apiKeyCount", len(tokens)))
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

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
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/fsnotify/fsnotify"
	"github.com/golang-jwt/jwt/v5"
	"github.com/loafoe/caddy-token/keys"
	"go.uber.org/zap"
	"net/http"
	"os"
	"strings"
)

const (
	scopeIDHeader    = "X-Scope-OrgID"
	apiKeyHeader     = "X-Api-Key"
	tokenKeyHeader   = "X-Id-Token"
	grafanaOrgHeader = "X-Grafana-Org-Id"
)

type Middleware struct {
	logger            *zap.Logger
	TokenFile         string
	tokens            map[string]keys.Key
	Issuer            string
	InjectOrgHeader   bool
	AllowUpstreamAuth bool
	verifier          *oidc.IDTokenVerifier
	watcher           *fsnotify.Watcher
	TenantOrgClaim    string
	SigningKey        string
}

func (m *Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.token",
		New: func() caddy.Module { return new(Middleware) },
	}
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
	if m.verifier == nil && len(m.tokens) == 0 && m.SigningKey == "" {
		return fmt.Errorf("no tokens or issuer provided")
	}
	m.logger.Info("provisioned caddy-token middleware",
		zap.String("issuer", m.Issuer),
		zap.String("tokenFile", m.TokenFile),
		zap.Int64("apiKeyCount", int64(len(m.tokens))),
		zap.String("TenantOrgClaim", m.TenantOrgClaim),
		zap.Bool("HasSigningKey", m.SigningKey != ""),
		zap.Bool("AllowUpstreamAuth", m.AllowUpstreamAuth))
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
						tokens := make(map[string]keys.Key)
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
	grafanaOrgId := r.Header.Get(grafanaOrgHeader)
	idToken := r.Header.Get(tokenKeyHeader)
	apiKey := r.Header.Get(apiKeyHeader)
	// Check for upstream auth
	upstreamAuth := r.Header.Get(scopeIDHeader)
	if grafanaOrgId != "" {
		m.logger.Info("Grafana Org context detected", zap.String("value", grafanaOrgId))
	}
	if upstreamAuth != "" {
		m.logger.Info("upstream X-Scope-OrgID detected", zap.String("value", upstreamAuth))
		if m.AllowUpstreamAuth {
			// TODO: double check if we have a user token
			return nil
		}
		m.logger.Info("ignoring upstream X-Scope-OrgID", zap.Bool("AllowUpstreamAuth", m.AllowUpstreamAuth))
	}
	// Check if API key is there in header
	// Try to extract token from Basic Auth
	username, password, ok := r.BasicAuth()
	if ok && username == "otlp" && password != "" {
		apiKey = password
	}
	if apiKey != "" { // API Key flow
		// Check v2 API keys first
		if ok, token, _ := keys.VerifyAPIKey(apiKey, m.SigningKey); ok {
			r.Header.Set(scopeIDHeader, token.Organization)
			return nil
		}
		token, ok := m.tokens[apiKey]
		if !ok {
			m.logger.Info("invalid token detected",
				zap.String("apiKey", apiKey),
				zap.Int64("count", int64(len(m.tokens))))
			return caddyhttp.Error(http.StatusForbidden, nil)
		}
		if m.InjectOrgHeader {
			r.Header.Set(scopeIDHeader, token.Organization)
		}
		return nil
	}
	if m.verifier != nil && idToken != "" { // OIDC flow
		_, err := m.verifier.Verify(r.Context(), idToken)
		if err != nil {
			m.logger.Info("invalid token detected", zap.Error(err))
			return caddyhttp.Error(http.StatusUnauthorized, err)
		}
		type DexClaims struct {
			ManagingOrganization      string   `json:"mid,omitempty"`
			ObservabilityReadTenants  []string `json:"ort,omitempty"`
			ObservabilityWriteTenants []string `json:"owt,omitempty"`
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
		// Inject X-Scope-OrgID header
		if m.InjectOrgHeader {
			switch m.TenantOrgClaim {
			case "ort":
				if len(claims.ObservabilityReadTenants) > 0 {
					m.logger.Info("ort X-Scope-OrgID", zap.String("value", strings.Join(claims.ObservabilityReadTenants, "|")))
					r.Header.Set(scopeIDHeader, strings.Join(claims.ObservabilityReadTenants, "|"))
				}
			case "owt":
				if len(claims.ObservabilityWriteTenants) > 0 {
					m.logger.Info("owt X-Scope-OrgID", zap.String("value", strings.Join(claims.ObservabilityWriteTenants, "|")))
					r.Header.Set(scopeIDHeader, strings.Join(claims.ObservabilityWriteTenants, "|"))
				}
			default:
				m.logger.Info("default X-Scope-OrgID", zap.String("value", claims.ManagingOrganization))
				r.Header.Set(scopeIDHeader, claims.ManagingOrganization)
			}
		} else {
			m.logger.Info("not injecting X-Scope-OrgID header")
		}
		return nil
	}
	// No valid token found
	m.logger.Error("no valid token found")
	return caddyhttp.Error(http.StatusUnauthorized, nil)
}

// readTokenFile reads a static token file and returns a map of tokens
func (m *Middleware) readTokenFile(filename string) (map[string]keys.Key, error) {
	tokens := make(map[string]keys.Key)

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("opening file %s: %w", filename, err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var decoded keys.Key
		trimmedLine := strings.TrimSpace(scanner.Text())
		if len(trimmedLine) == 0 { // Skip empty lines
			continue
		}
		prefixRemoved := strings.TrimPrefix(trimmedLine, keys.Prefix)
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

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
	_ caddy.Module                = (*Middleware)(nil)
)

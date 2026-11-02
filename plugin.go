package token

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/avast/retry-go/v4"
	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/fsnotify/fsnotify"
	"github.com/golang-jwt/jwt/v5"
	"github.com/loafoe/caddy-token/keys"
	"go.uber.org/zap"
)

const (
	scopeIDHeader    = "X-Scope-OrgID"
	apiKeyHeader     = "X-Api-Key"
	tokenKeyHeader   = "X-Id-Token"
	grafanaOrgHeader = "X-Grafana-Org-Id"
	authHeader       = "Authorization"
)

type Middleware struct {
	logger            *zap.Logger
	TokenFile         string
	tokens            map[string]keys.Key
	Issuer            string
	InjectOrgHeader   bool
	AllowUpstreamAuth bool
	Verify            bool
	verifier          *oidc.IDTokenVerifier
	watcher           *fsnotify.Watcher
	TenantOrgClaim    string
	JWTMappings       []JWTGroupMapping
	SigningKey        string
	Scopes            []string
	ClientCA          bool
	Debug             bool
	DefaultOrg        string
	Spiffe            *SpiffeConfig
	spiffeValidator   *SpiffeValidator
	Metrics           bool
	metrics           *tenantMetrics
}

func (m *Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.token",
		New: func() caddy.Module { return new(Middleware) },
	}
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	err := m.CheckTokenAndInjectHeaders(r)
	if err != nil {
		return err
	}
	if m.metrics != nil {
		if tenant := r.Header.Get(scopeIDHeader); tenant != "" {
			return m.recordTenantActivity(w, r, tenant, next)
		}
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

	if err := validateJWTMappings(m.JWTMappings); err != nil {
		return err
	}

	if m.Issuer != "" {
		provider, err := oidc.NewProvider(ctx, m.Issuer)
		if err != nil {
			m.logger.Info("error provisioning issuer", zap.String("issuer", m.Issuer), zap.Error(err))
			return fmt.Errorf("erorr provisioning issuer '%s': %w", m.Issuer, err)
		}
		m.verifier = provider.Verifier(&oidc.Config{
			SkipClientIDCheck: true,
		})
		if !m.Verify {
			m.logger.Warn("jwt 'verify false' no longer disables signature verification; tokens with invalid signatures are always rejected",
				zap.String("issuer", m.Issuer))
		}
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
	if m.Spiffe != nil && len(m.Spiffe.TrustDomains) > 0 {
		socketPath := m.Spiffe.GetWorkloadSocket()
		// Count trust domains with/without JWKS URLs
		jwksCount := 0
		workloadCount := 0
		for _, td := range m.Spiffe.TrustDomains {
			if td.JWKSURL != "" {
				jwksCount++
			} else {
				workloadCount++
			}
		}

		if socketPath != "" || jwksCount > 0 {
			// Use hybrid source: JWKS for domains with URLs, Workload API for others
			var err error
			m.spiffeValidator, err = NewSpiffeValidatorWithWorkloadAPI(ctx, m.Spiffe, m.logger)
			if err != nil {
				return fmt.Errorf("creating SPIFFE validator: %w", err)
			}
			m.logger.Info("SPIFFE validator configured",
				zap.String("socket", socketPath),
				zap.Int("trustDomains", len(m.Spiffe.TrustDomains)),
				zap.Int("jwksDomains", jwksCount),
				zap.Int("workloadDomains", workloadCount),
				zap.Int("allowedIDs", len(m.Spiffe.AllowedIDs)))
		} else {
			// No socket and no JWKS URLs - this is a configuration error
			return fmt.Errorf("SPIFFE configured but no workload socket or JWKS URLs provided")
		}
	}
	if m.verifier == nil && len(m.tokens) == 0 && m.SigningKey == "" && !m.ClientCA && m.spiffeValidator == nil {
		return fmt.Errorf("no tokens, issuer, client CA, or SPIFFE config provided")
	}
	if m.Metrics {
		m.metrics = initTenantMetrics(ctx)
	}
	m.logger.Info("provisioned caddy-token middleware",
		zap.String("issuer", m.Issuer),
		zap.String("tokenFile", m.TokenFile),
		zap.Int64("apiKeyCount", int64(len(m.tokens))),
		zap.String("TenantOrgClaim", m.TenantOrgClaim),
		zap.Bool("HasSigningKey", m.SigningKey != ""),
		zap.Bool("AllowUpstreamAuth", m.AllowUpstreamAuth),
		zap.Bool("HasSpiffe", m.spiffeValidator != nil))
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

// JWTGroupMapping associates a set of required group claims with an
// organization to resolve for the jwt auth flow. Each `jwt { ... }` block
// in the Caddyfile contributes one mapping, so multiple blocks sharing the
// same issuer can route different group memberships to different orgs. A
// mapping with no Groups configured matches any token unconditionally.
type JWTGroupMapping struct {
	Groups   []string
	Org      string
	OrgClaim string
}

// orgClaimIndexPattern matches an OrgClaim using array-index syntax, e.g.
// "groups[0]", referencing an element of an array-valued claim.
var orgClaimIndexPattern = regexp.MustCompile(`^(.+)\[(\d+)\]$`)

// ErrOrgClaimNoAccess is returned when OrgClaim uses array-index syntax
// (e.g. "groups[0]") but the referenced claim has no usable value at that
// index - the claim is absent, isn't an array, or the array is shorter
// than the index requires (including empty). This is treated as an
// explicit denial rather than a fallthrough to another org source: an
// empty groups claim means the subject has no org/tenant membership to
// authorize against.
var ErrOrgClaimNoAccess = errors.New("org_claim array index has no value: access denied")

// matchJWTMapping returns the first mapping whose required Groups are all
// present in have, and whether one was found. A mapping with no Groups
// configured matches unconditionally. An empty mappings list (no jwt
// blocks configure group/org restrictions) also matches unconditionally,
// preserving the behavior of a bare `jwt { issuer ... }` block.
func matchJWTMapping(mappings []JWTGroupMapping, have []string) (JWTGroupMapping, bool) {
	if len(mappings) == 0 {
		return JWTGroupMapping{}, true
	}
	for _, mapping := range mappings {
		if jwtGroupsSatisfied(mapping.Groups, have) {
			return mapping, true
		}
	}
	return JWTGroupMapping{}, false
}

// jwtGroupsSatisfied reports whether every group in required is present in
// have. An empty required list matches unconditionally.
func jwtGroupsSatisfied(required, have []string) bool {
	for _, g := range required {
		if !slices.Contains(have, g) {
			return false
		}
	}
	return true
}

// validateJWTMappings rejects configurations where the same group name is
// required by two or more jwt blocks that resolve to different orgs. Since
// matchJWTMapping picks the first satisfied block in declaration order, a
// token holding that group would silently get whichever org happens to be
// declared first - this is almost certainly a config mistake rather than
// intent, so it's rejected outright instead of resolved implicitly.
//
// A mapping with no Groups (a catch-all) is exempt: pairing a catch-all
// with specific-group blocks is the deliberate fallback pattern documented
// for `jwt`, not a conflict.
func validateJWTMappings(mappings []JWTGroupMapping) error {
	type seenMapping struct {
		mapping JWTGroupMapping
		block   int
	}
	seenByGroup := make(map[string]seenMapping)

	for i, mapping := range mappings {
		for _, group := range mapping.Groups {
			prior, ok := seenByGroup[group]
			if !ok {
				seenByGroup[group] = seenMapping{mapping: mapping, block: i + 1}
				continue
			}
			if prior.mapping.Org == mapping.Org && prior.mapping.OrgClaim == mapping.OrgClaim {
				continue // identical org resolution: redundant, not ambiguous
			}
			return fmt.Errorf(
				"ambiguous jwt org mapping: group %q resolves to %s in jwt block %d, but to %s in jwt block %d; "+
					"a group may only be mapped to one org across all jwt blocks - remove or reconcile one of these blocks",
				group, describeJWTOrgSource(prior.mapping), prior.block, describeJWTOrgSource(mapping), i+1)
		}
	}
	return nil
}

// describeJWTOrgSource renders how a JWTGroupMapping resolves its org, for
// use in validateJWTMappings error messages.
func describeJWTOrgSource(m JWTGroupMapping) string {
	switch {
	case m.Org != "":
		return fmt.Sprintf("org %q", m.Org)
	case m.OrgClaim != "":
		return fmt.Sprintf("org_claim %q", m.OrgClaim)
	default:
		return "no org (falls back to tenantOrgClaim)"
	}
}

// resolveOrgFromClaim extracts an organization from a static org value or
// a named claim. A static org always takes precedence over orgClaim,
// mirroring SpiffeTrustDomain.ExtractOrg.
//
// orgClaim may name a plain string claim ("department") or, for array
// claims, an indexed element ("groups[0]"). The second return value
// reports whether an org was resolved, so callers can fall back to another
// org source (e.g. legacy TenantOrgClaim) when neither org nor orgClaim is
// configured, or a plain string claim is absent/empty. A non-nil error
// instead means array-index extraction found no usable value and access
// must be denied outright (see ErrOrgClaimNoAccess).
func resolveOrgFromClaim(org, orgClaim string, claims map[string]any) (string, bool, error) {
	if org != "" {
		return org, true, nil
	}
	if orgClaim == "" {
		return "", false, nil
	}

	claimName := orgClaim
	index := -1
	if match := orgClaimIndexPattern.FindStringSubmatch(orgClaim); match != nil {
		claimName = match[1]
		idx, err := strconv.Atoi(match[2])
		if err != nil {
			return "", false, nil
		}
		index = idx
	}

	val, ok := claims[claimName]
	if !ok {
		if index >= 0 {
			return "", false, ErrOrgClaimNoAccess
		}
		return "", false, nil
	}

	if index >= 0 {
		items, ok := toStringSlice(val)
		if !ok || index >= len(items) || items[index] == "" {
			return "", false, ErrOrgClaimNoAccess
		}
		return items[index], true, nil
	}

	if str, ok := val.(string); ok && str != "" {
		return str, true, nil
	}
	return "", false, nil
}

// toStringSlice converts a JSON-decoded array claim into a []string. It
// reports false if val isn't an array or contains a non-string element.
func toStringSlice(val any) ([]string, bool) {
	arr, ok := val.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		s, ok := v.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func (m *Middleware) CheckTokenAndInjectHeaders(r *http.Request) error {
	grafanaOrgId := r.Header.Get(grafanaOrgHeader)
	idToken := r.Header.Get(tokenKeyHeader)
	apiKey := r.Header.Get(apiKeyHeader)
	// Check for upstream auth
	upstreamAuth := r.Header.Get(scopeIDHeader)
	if grafanaOrgId != "" && m.Debug {
		m.logger.Info("Grafana Org context detected", zap.String("value", grafanaOrgId))
	}
	if upstreamAuth != "" {
		if m.Debug {
			m.logger.Info("upstream X-Scope-OrgID detected", zap.String("value", upstreamAuth))
		}
		if m.AllowUpstreamAuth {
			return nil
		}
		if m.Debug {
			m.logger.Info("ignoring upstream X-Scope-OrgID", zap.Bool("AllowUpstreamAuth", m.AllowUpstreamAuth))
		}
	}

	// Strip any client-supplied tenant headers before authenticating. Unless
	// AllowUpstreamAuth is enabled (handled above), these headers must never be
	// trusted: leaving them in place would let a caller spoof a tenant on any
	// success path that does not explicitly overwrite X-Scope-OrgID (e.g.
	// InjectOrgHeader=false, or a JWT/SPIFFE org that resolves to empty).
	r.Header.Del(scopeIDHeader)
	r.Header.Del(grafanaOrgHeader)

	// Check for client certificate authentication first. We require a verified
	// chain (r.TLS.VerifiedChains), not merely a presented certificate: a bare
	// PeerCertificates entry can be any self-signed cert. Verified chains are
	// only populated when the TLS listener is configured with
	// require_and_verify against a trusted client CA.
	if m.ClientCA && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && len(r.TLS.VerifiedChains) > 0 {
		if m.Debug {
			m.logger.Info("client certificate detected",
				zap.Int("certCount", len(r.TLS.PeerCertificates)),
				zap.String("subject", r.TLS.PeerCertificates[0].Subject.String()))
		}
		// Set the default organization header
		r.Header.Set(scopeIDHeader, m.DefaultOrg)
		if m.Debug {
			m.logger.Info("client certificate authenticated", zap.String("defaultOrg", m.DefaultOrg))
		}
		return nil
	}

	// Check for SPIFFE JWT SVID in Authorization header
	if m.spiffeValidator != nil {
		authHeader := r.Header.Get(authHeader)
		if authHeader != "" {
			parts := strings.Split(authHeader, " ")
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
				result, err := m.spiffeValidator.ValidateJWT(r.Context(), parts[1])
				if err == nil {
					// Valid SPIFFE JWT
					if m.InjectOrgHeader && result.Org != "" {
						r.Header.Set(scopeIDHeader, result.Org)
					}
					if m.Debug {
						m.logger.Debug("SPIFFE JWT authenticated",
							zap.String("spiffeID", result.SpiffeID.String()),
							zap.String("org", result.Org))
					}
					return nil
				}
				// If SPIFFE validation failed but we have other auth methods, continue
				// Otherwise, if SPIFFE is the only method, return the error
				if m.verifier == nil && len(m.tokens) == 0 && m.SigningKey == "" {
					if m.Debug {
						m.logger.Error("SPIFFE JWT validation failed", zap.Error(err))
					}
					return caddyhttp.Error(http.StatusUnauthorized, err)
				}
				// Log but continue to try other auth methods
				if m.Debug {
					m.logger.Debug("SPIFFE JWT validation failed, trying other auth methods", zap.Error(err))
				}
			}
		}
	}

	// Check if API key is there in header
	// Try to extract token from Basic Auth
	_, password, ok := r.BasicAuth()
	if ok && password != "" {
		apiKey = password
	}
	// Also support bearer token
	if apiKey == "" {
		authHeader := r.Header.Get(authHeader)
		if authHeader != "" {
			parts := strings.Split(authHeader, " ")
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
				apiKey = parts[1]
			}
		}
	}
	if apiKey != "" { // API Key flow
		// Check v2 API keys first
		if ok, token, _ := keys.VerifyAPIKey(apiKey, m.SigningKey); ok {
			r.Header.Set(scopeIDHeader, token.Organization)
			return nil
		}
		token, ok := m.tokens[apiKey]
		if !ok {
			if m.Debug {
				m.logger.Error("invalid token detected",
					zap.String("apiKey", "..."+LastNChars(6, apiKey)),
					zap.Int64("count", int64(len(m.tokens))),
					zap.String("remoteAddr", r.RemoteAddr))
			}
			return caddyhttp.Error(http.StatusForbidden, nil)
		}

		// Check scopes
		if len(m.Scopes) > 0 {
			for _, scope := range m.Scopes {
				if !slices.Contains(token.Scopes, scope) {
					m.logger.Error("missing required scope",
						zap.String("scope", scope),
						zap.String("remoteAddr", r.RemoteAddr))
					return caddyhttp.Error(http.StatusForbidden, nil)
				}
			}
		}

		if m.InjectOrgHeader {
			r.Header.Set(scopeIDHeader, token.Organization)
		}
		return nil
	}
	if m.verifier != nil && idToken != "" { // OIDC flow
		_, err := m.verifier.Verify(r.Context(), idToken)
		if err != nil {
			// Fail closed: a token whose signature cannot be verified is
			// rejected regardless of the `verify` setting. Authorizing on
			// claims from an unverified JWT would let anyone forge group and
			// tenant membership. The `verify false` option only suppresses
			// issuer/expiry strictness within the verifier, not the signature
			// check itself.
			m.logger.Error("invalid token detected",
				zap.Error(err),
				zap.String("remoteAddr", r.RemoteAddr))
			return caddyhttp.Error(http.StatusUnauthorized, err)
		}
		type DexClaims struct {
			ObservabilityReadTenants  []string `json:"ort,omitempty"`
			ObservabilityWriteTenants []string `json:"owt,omitempty"`
			Groups                    []string `json:"groups,omitempty"`
			jwt.RegisteredClaims
		}
		token, err := jwt.ParseWithClaims(idToken, &DexClaims{}, func(token *jwt.Token) (any, error) {
			return []byte(""), jwt.ErrTokenUnverifiable // We already verified
		})
		if !errors.Is(err, jwt.ErrTokenUnverifiable) {
			return caddyhttp.Error(http.StatusUnauthorized, err)
		}
		// Verified
		claims, ok := token.Claims.(*DexClaims)
		if !ok {
			err := fmt.Errorf("invalid claims detected: %w", err)
			m.logger.Error("invalid claims detected", zap.Error(err))
			return caddyhttp.Error(http.StatusUnauthorized, err)
		}

		// Resolve the jwt mapping (if any) whose required groups are all
		// present in the token. Each `jwt { ... }` block contributes one
		// mapping, so multiple blocks can route different group
		// memberships to different orgs using the same issuer.
		mapping, matched := matchJWTMapping(m.JWTMappings, claims.Groups)
		if !matched {
			m.logger.Error("no jwt mapping matched token groups", zap.Strings("groups", claims.Groups))
			return caddyhttp.Error(http.StatusUnauthorized, nil)
		}

		// Inject X-Scope-OrgID header
		if m.InjectOrgHeader {
			rawClaims := jwt.MapClaims{}
			_, _, _ = jwt.NewParser().ParseUnverified(idToken, rawClaims) // signature already verified above

			org, ok, orgErr := resolveOrgFromClaim(mapping.Org, mapping.OrgClaim, rawClaims)
			if orgErr != nil {
				if m.Debug {
					m.logger.Error("jwt org_claim denied access", zap.Error(orgErr))
				}
				return caddyhttp.Error(http.StatusUnauthorized, orgErr)
			}
			if ok {
				if m.Debug {
					m.logger.Info("jwt org X-Scope-OrgID", zap.String("value", org))
				}
				r.Header.Set(scopeIDHeader, org)
			} else {
				switch m.TenantOrgClaim {
				case "ort":
					if len(claims.ObservabilityReadTenants) > 0 {
						if m.Debug {
							m.logger.Info("ort X-Scope-OrgID", zap.String("value", strings.Join(claims.ObservabilityReadTenants, "|")))
						}
						r.Header.Set(scopeIDHeader, strings.Join(claims.ObservabilityReadTenants, "|"))
					}
				case "owt":
					if len(claims.ObservabilityWriteTenants) > 0 {
						if m.Debug {
							m.logger.Info("owt X-Scope-OrgID", zap.String("value", strings.Join(claims.ObservabilityWriteTenants, "|")))
						}
						r.Header.Set(scopeIDHeader, strings.Join(claims.ObservabilityWriteTenants, "|"))
					}
				default:
					if m.Debug {
						m.logger.Info("not injecting X-Scope-OrgID header")
					}
				}
			}
		} else {
			if m.Debug {
				m.logger.Info("not injecting X-Scope-OrgID header")
			}
		}
		return nil
	}
	// No valid token found
	if m.Debug {
		m.logger.Error("no valid token found")
	}
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

// LastNChars returns the last n characters of a string.
func LastNChars(n int, s string) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
	_ caddy.Module                = (*Middleware)(nil)
)

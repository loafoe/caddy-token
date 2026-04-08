package token

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.uber.org/zap"
)

const (
	// DefaultWorkloadSocketPath is the default SPIFFE Workload API socket path
	DefaultWorkloadSocketPath = "unix:///tmp/spire-agent/public/api.sock"
	// K8sWorkloadSocketPath is the common socket path in Kubernetes deployments
	K8sWorkloadSocketPath = "unix:///run/spire/sockets/agent.sock"
	// EnvSpiffeEndpointSocket is the environment variable for the socket path
	EnvSpiffeEndpointSocket = "SPIFFE_ENDPOINT_SOCKET"
)

// SpiffeTrustDomain configures a single SPIFFE trust domain
type SpiffeTrustDomain struct {
	Domain   string `json:"domain"`
	JWKSURL  string `json:"jwks_url"`
	Audience string `json:"audience"`

	// Org extraction (mutually exclusive)
	Org          string `json:"org,omitempty"`            // Static org
	OrgFromPath  bool   `json:"org_from_path,omitempty"`  // Extract from SPIFFE ID path
	OrgPathIndex int    `json:"org_path_index,omitempty"` // Which path segment (0-indexed)
	OrgClaim     string `json:"org_claim,omitempty"`      // Extract from JWT claim
}

// SpiffeConfig holds the complete SPIFFE configuration
type SpiffeConfig struct {
	TrustDomains   []SpiffeTrustDomain `json:"trust_domains,omitempty"`
	AllowedIDs     []string            `json:"allowed_ids,omitempty"`
	DefaultOrg     string              `json:"default_org,omitempty"`
	WorkloadSocket string              `json:"workload_socket,omitempty"` // SPIFFE Workload API socket path
	Debug          bool                `json:"debug,omitempty"`
}

// GetWorkloadSocket returns the workload socket path, checking environment variable and defaults
func (c *SpiffeConfig) GetWorkloadSocket() string {
	if c.WorkloadSocket != "" {
		return c.WorkloadSocket
	}
	if envSocket := os.Getenv(EnvSpiffeEndpointSocket); envSocket != "" {
		return envSocket
	}
	return ""
}

// SpiffeID represents a parsed SPIFFE ID
type SpiffeID struct {
	TrustDomain string
	Path        string
}

// String returns the full SPIFFE ID as a string
func (s SpiffeID) String() string {
	return fmt.Sprintf("spiffe://%s%s", s.TrustDomain, s.Path)
}

// PathSegments returns the path split into segments (without leading empty string)
func (s SpiffeID) PathSegments() []string {
	trimmed := strings.TrimPrefix(s.Path, "/")
	if trimmed == "" {
		return []string{}
	}
	return strings.Split(trimmed, "/")
}

// ParseSpiffeID parses a SPIFFE ID string into its components
func ParseSpiffeID(id string) (SpiffeID, error) {
	if !strings.HasPrefix(id, "spiffe://") {
		return SpiffeID{}, fmt.Errorf("invalid SPIFFE ID: must start with spiffe://")
	}

	u, err := url.Parse(id)
	if err != nil {
		return SpiffeID{}, fmt.Errorf("invalid SPIFFE ID URL: %w", err)
	}

	if u.Scheme != "spiffe" {
		return SpiffeID{}, fmt.Errorf("invalid SPIFFE ID scheme: %s", u.Scheme)
	}

	if u.Host == "" {
		return SpiffeID{}, fmt.Errorf("invalid SPIFFE ID: missing trust domain")
	}

	return SpiffeID{
		TrustDomain: u.Host,
		Path:        u.Path,
	}, nil
}

// MatchSpiffeID checks if a SPIFFE ID matches any of the allowed patterns
// Patterns support glob-style wildcards: * matches any single path segment
func MatchSpiffeID(id string, patterns []string) bool {
	if len(patterns) == 0 {
		return true // No patterns means allow all
	}

	parsed, err := ParseSpiffeID(id)
	if err != nil {
		return false
	}

	for _, pattern := range patterns {
		if matchPattern(parsed, pattern) {
			return true
		}
	}
	return false
}

// matchPattern checks if a SPIFFE ID matches a single pattern
func matchPattern(id SpiffeID, pattern string) bool {
	patternID, err := ParseSpiffeID(pattern)
	if err != nil {
		return false
	}

	// Trust domain must match exactly or pattern uses *
	if patternID.TrustDomain != "*" && patternID.TrustDomain != id.TrustDomain {
		return false
	}

	// Match path segments
	patternSegments := patternID.PathSegments()
	idSegments := id.PathSegments()

	return matchPathSegments(idSegments, patternSegments)
}

// matchPathSegments matches path segments with glob support
func matchPathSegments(segments, pattern []string) bool {
	si, pi := 0, 0

	for pi < len(pattern) {
		if pattern[pi] == "**" {
			// ** matches zero or more segments
			if pi == len(pattern)-1 {
				return true // ** at end matches everything
			}
			// Try matching ** with different numbers of segments
			for si <= len(segments) {
				if matchPathSegments(segments[si:], pattern[pi+1:]) {
					return true
				}
				si++
			}
			return false
		}

		if si >= len(segments) {
			return false // No more segments to match
		}

		if pattern[pi] != "*" && pattern[pi] != segments[si] {
			return false // Segment doesn't match
		}

		si++
		pi++
	}

	return si == len(segments) // All segments must be consumed
}

// ExtractOrg extracts the organization from a SPIFFE ID based on trust domain config
func (td *SpiffeTrustDomain) ExtractOrg(spiffeID SpiffeID, claims map[string]any, defaultOrg string) string {
	// Static org takes precedence
	if td.Org != "" {
		return td.Org
	}

	// Extract from JWT claim
	if td.OrgClaim != "" {
		if val, ok := claims[td.OrgClaim]; ok {
			if str, ok := val.(string); ok && str != "" {
				return str
			}
		}
	}

	// Extract from path
	if td.OrgFromPath {
		segments := spiffeID.PathSegments()
		if td.OrgPathIndex >= 0 && td.OrgPathIndex < len(segments) {
			return segments[td.OrgPathIndex]
		}
	}

	return defaultOrg
}

// keySource provides signing keys for JWT verification
type keySource interface {
	getKey(ctx context.Context, trustDomain, keyID string, forceRefresh bool) (crypto.PublicKey, error)
	close() error
}

// jwksCache holds cached JWKS data fetched from HTTP endpoints
type jwksCache struct {
	mu        sync.RWMutex
	keysets   map[string]*cachedJWKS
	client    *http.Client
	cacheTTL  time.Duration
	logger    *zap.Logger
	domainMap map[string]*SpiffeTrustDomain
}

type cachedJWKS struct {
	jwks      *jose.JSONWebKeySet
	fetchedAt time.Time
}

// newJWKSCache creates a new JWKS cache
func newJWKSCache(logger *zap.Logger, domainMap map[string]*SpiffeTrustDomain) *jwksCache {
	return &jwksCache{
		keysets: make(map[string]*cachedJWKS),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		cacheTTL:  5 * time.Minute,
		logger:    logger,
		domainMap: domainMap,
	}
}

func (c *jwksCache) close() error {
	return nil
}

// getKey retrieves a key from the JWKS for the given trust domain
func (c *jwksCache) getKey(ctx context.Context, trustDomain, keyID string, forceRefresh bool) (crypto.PublicKey, error) {
	td, ok := c.domainMap[trustDomain]
	if !ok {
		return nil, fmt.Errorf("unknown trust domain: %s", trustDomain)
	}
	if td.JWKSURL == "" {
		return nil, fmt.Errorf("no JWKS URL configured for trust domain: %s", trustDomain)
	}

	c.mu.RLock()
	cached, exists := c.keysets[td.JWKSURL]
	c.mu.RUnlock()

	needsFetch := !exists || forceRefresh || time.Since(cached.fetchedAt) > c.cacheTTL

	if needsFetch {
		if err := c.fetchJWKS(ctx, td.JWKSURL); err != nil {
			// If we have a cached version, use it even if expired
			if exists {
				c.logger.Warn("failed to refresh JWKS, using cached version",
					zap.String("url", td.JWKSURL),
					zap.Error(err))
			} else {
				return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
			}
		}
	}

	c.mu.RLock()
	cached = c.keysets[td.JWKSURL]
	c.mu.RUnlock()

	if cached == nil || cached.jwks == nil {
		return nil, fmt.Errorf("no JWKS available for %s", td.JWKSURL)
	}

	keys := cached.jwks.Key(keyID)
	if len(keys) == 0 {
		// Key not found, try refreshing if we haven't just done so
		if !needsFetch {
			return c.getKey(ctx, trustDomain, keyID, true)
		}
		return nil, fmt.Errorf("key %s not found in JWKS", keyID)
	}

	pubKey, ok := keys[0].Key.(crypto.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key %s is not a public key", keyID)
	}

	return pubKey, nil
}

// fetchJWKS fetches and caches a JWKS from the given URL
func (c *jwksCache) fetchJWKS(ctx context.Context, jwksURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetching JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("decoding JWKS: %w", err)
	}

	c.mu.Lock()
	c.keysets[jwksURL] = &cachedJWKS{
		jwks:      &jwks,
		fetchedAt: time.Now(),
	}
	c.mu.Unlock()

	c.logger.Debug("fetched JWKS", zap.String("url", jwksURL), zap.Int("keyCount", len(jwks.Keys)))
	return nil
}

// workloadBundleSource fetches JWT bundles from the SPIFFE Workload API
type workloadBundleSource struct {
	mu         sync.RWMutex
	client     *workloadapi.Client
	bundles    *jwtbundle.Set
	logger     *zap.Logger
	socketPath string
	cancel     context.CancelFunc
}

// newWorkloadBundleSource creates a new workload bundle source
func newWorkloadBundleSource(ctx context.Context, socketPath string, logger *zap.Logger) (*workloadBundleSource, error) {
	ctx, cancel := context.WithCancel(ctx)

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(socketPath))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("creating workload API client: %w", err)
	}

	source := &workloadBundleSource{
		client:     client,
		logger:     logger,
		socketPath: socketPath,
		cancel:     cancel,
	}

	// Fetch initial bundles
	bundles, err := client.FetchJWTBundles(ctx)
	if err != nil {
		_ = client.Close()
		cancel()
		return nil, fmt.Errorf("fetching initial JWT bundles: %w", err)
	}
	source.bundles = bundles

	logger.Info("connected to SPIFFE Workload API",
		zap.String("socket", socketPath),
		zap.Int("bundleCount", bundles.Len()))

	// Start watching for bundle updates in background
	go source.watchBundles(ctx)

	return source, nil
}

func (s *workloadBundleSource) watchBundles(ctx context.Context) {
	err := s.client.WatchJWTBundles(ctx, &bundleWatcher{source: s})
	if err != nil && ctx.Err() == nil {
		s.logger.Error("JWT bundle watcher stopped", zap.Error(err))
	}
}

type bundleWatcher struct {
	source *workloadBundleSource
}

func (w *bundleWatcher) OnJWTBundlesUpdate(bundles *jwtbundle.Set) {
	w.source.mu.Lock()
	w.source.bundles = bundles
	w.source.mu.Unlock()
	w.source.logger.Debug("JWT bundles updated", zap.Int("bundleCount", bundles.Len()))
}

func (w *bundleWatcher) OnJWTBundlesWatchError(err error) {
	w.source.logger.Warn("JWT bundle watch error", zap.Error(err))
}

func (s *workloadBundleSource) close() error {
	s.cancel()
	return s.client.Close()
}

func (s *workloadBundleSource) getKey(ctx context.Context, trustDomain, keyID string, forceRefresh bool) (crypto.PublicKey, error) {
	if forceRefresh {
		// Fetch fresh bundles
		bundles, err := s.client.FetchJWTBundles(ctx)
		if err != nil {
			s.logger.Warn("failed to refresh JWT bundles", zap.Error(err))
		} else {
			s.mu.Lock()
			s.bundles = bundles
			s.mu.Unlock()
		}
	}

	s.mu.RLock()
	bundles := s.bundles
	s.mu.RUnlock()

	if bundles == nil {
		return nil, fmt.Errorf("no JWT bundles available")
	}

	bundle, err := bundles.GetJWTBundleForTrustDomain(trustDomainFromString(trustDomain))
	if err != nil {
		return nil, fmt.Errorf("no bundle for trust domain %s: %w", trustDomain, err)
	}

	key, ok := bundle.FindJWTAuthority(keyID)
	if !ok {
		// Key not found, try refreshing
		if !forceRefresh {
			return s.getKey(ctx, trustDomain, keyID, true)
		}
		return nil, fmt.Errorf("key %s not found in bundle for trust domain %s", keyID, trustDomain)
	}

	return key, nil
}

// trustDomainFromString creates a spiffeid.TrustDomain from a string
func trustDomainFromString(td string) spiffeid.TrustDomain {
	trustDomain, err := spiffeid.TrustDomainFromString(td)
	if err != nil {
		// This shouldn't happen with valid trust domain strings
		return spiffeid.TrustDomain{}
	}
	return trustDomain
}

// SpiffeValidator handles SPIFFE JWT SVID validation
type SpiffeValidator struct {
	config    *SpiffeConfig
	keySource keySource
	logger    *zap.Logger
	domainMap map[string]*SpiffeTrustDomain
}

// NewSpiffeValidator creates a new SPIFFE validator
func NewSpiffeValidator(config *SpiffeConfig, logger *zap.Logger) *SpiffeValidator {
	domainMap := make(map[string]*SpiffeTrustDomain)
	for i := range config.TrustDomains {
		td := &config.TrustDomains[i]
		domainMap[td.Domain] = td
	}

	return &SpiffeValidator{
		config:    config,
		keySource: newJWKSCache(logger, domainMap), // Default to JWKS cache
		logger:    logger,
		domainMap: domainMap,
	}
}

// NewSpiffeValidatorWithWorkloadAPI creates a SPIFFE validator using the Workload API
func NewSpiffeValidatorWithWorkloadAPI(ctx context.Context, config *SpiffeConfig, logger *zap.Logger) (*SpiffeValidator, error) {
	domainMap := make(map[string]*SpiffeTrustDomain)
	for i := range config.TrustDomains {
		td := &config.TrustDomains[i]
		domainMap[td.Domain] = td
	}

	socketPath := config.GetWorkloadSocket()
	if socketPath == "" {
		return nil, fmt.Errorf("no workload socket configured")
	}

	source, err := newWorkloadBundleSource(ctx, socketPath, logger)
	if err != nil {
		return nil, fmt.Errorf("creating workload bundle source: %w", err)
	}

	return &SpiffeValidator{
		config:    config,
		keySource: source,
		logger:    logger,
		domainMap: domainMap,
	}, nil
}

// Close releases resources used by the validator
func (v *SpiffeValidator) Close() error {
	if v.keySource != nil {
		return v.keySource.close()
	}
	return nil
}

// SpiffeValidationResult contains the result of SPIFFE JWT validation
type SpiffeValidationResult struct {
	SpiffeID    SpiffeID
	TrustDomain *SpiffeTrustDomain
	Claims      map[string]any
	Org         string
}

// ValidateJWT validates a SPIFFE JWT SVID and returns the validation result
func (v *SpiffeValidator) ValidateJWT(ctx context.Context, tokenString string) (*SpiffeValidationResult, error) {
	// Parse without verification first to get the header and claims
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parsing JWT: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	// Extract SPIFFE ID from sub claim
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return nil, fmt.Errorf("missing or invalid sub claim")
	}

	spiffeID, err := ParseSpiffeID(sub)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID in sub claim: %w", err)
	}

	// Find trust domain config
	td, ok := v.domainMap[spiffeID.TrustDomain]
	if !ok {
		return nil, fmt.Errorf("unknown trust domain: %s", spiffeID.TrustDomain)
	}

	// Get key ID from header
	keyID, _ := token.Header["kid"].(string)
	if keyID == "" {
		return nil, fmt.Errorf("missing kid in JWT header")
	}

	// Get signing key
	key, err := v.keySource.getKey(ctx, spiffeID.TrustDomain, keyID, false)
	if err != nil {
		return nil, fmt.Errorf("getting signing key: %w", err)
	}

	// Verify signature
	verifiedToken, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("verifying JWT signature: %w", err)
	}

	if !verifiedToken.Valid {
		return nil, fmt.Errorf("invalid JWT")
	}

	// Validate audience
	if td.Audience != "" {
		aud, err := claims.GetAudience()
		if err != nil {
			return nil, fmt.Errorf("getting audience: %w", err)
		}
		found := false
		for _, a := range aud {
			if a == td.Audience {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("audience mismatch: expected %s", td.Audience)
		}
	}

	// Check allowed IDs
	if !MatchSpiffeID(sub, v.config.AllowedIDs) {
		return nil, fmt.Errorf("SPIFFE ID not in allowed list: %s", sub)
	}

	// Extract org
	claimsMap := make(map[string]any)
	for k, v := range claims {
		claimsMap[k] = v
	}

	org := td.ExtractOrg(spiffeID, claimsMap, v.config.DefaultOrg)

	if v.config.Debug {
		v.logger.Info("SPIFFE JWT validated",
			zap.String("spiffeID", sub),
			zap.String("trustDomain", spiffeID.TrustDomain),
			zap.String("org", org))
	}

	return &SpiffeValidationResult{
		SpiffeID:    spiffeID,
		TrustDomain: td,
		Claims:      claimsMap,
		Org:         org,
	}, nil
}

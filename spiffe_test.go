package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestParseSpiffeID(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantDomain  string
		wantPath    string
		expectError bool
	}{
		{
			name:       "valid SPIFFE ID with path",
			input:      "spiffe://example.org/service/api",
			wantDomain: "example.org",
			wantPath:   "/service/api",
		},
		{
			name:       "valid SPIFFE ID without path",
			input:      "spiffe://example.org",
			wantDomain: "example.org",
			wantPath:   "",
		},
		{
			name:       "valid SPIFFE ID with complex path",
			input:      "spiffe://prod.example.org/tenant/acme/service/api/v2",
			wantDomain: "prod.example.org",
			wantPath:   "/tenant/acme/service/api/v2",
		},
		{
			name:        "invalid - missing scheme",
			input:       "example.org/service/api",
			expectError: true,
		},
		{
			name:        "invalid - wrong scheme",
			input:       "https://example.org/service/api",
			expectError: true,
		},
		{
			name:        "invalid - missing trust domain",
			input:       "spiffe:///service/api",
			expectError: true,
		},
		{
			name:        "invalid - empty string",
			input:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSpiffeID(tt.input)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantDomain, result.TrustDomain)
			assert.Equal(t, tt.wantPath, result.Path)
		})
	}
}

func TestSpiffeID_PathSegments(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected []string
	}{
		{
			name:     "multiple segments",
			path:     "/tenant/acme/service/api",
			expected: []string{"tenant", "acme", "service", "api"},
		},
		{
			name:     "single segment",
			path:     "/service",
			expected: []string{"service"},
		},
		{
			name:     "empty path",
			path:     "",
			expected: []string{},
		},
		{
			name:     "root path",
			path:     "/",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := SpiffeID{TrustDomain: "example.org", Path: tt.path}
			result := id.PathSegments()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchSpiffeID(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		patterns []string
		expected bool
	}{
		{
			name:     "empty patterns allows all",
			id:       "spiffe://example.org/service/api",
			patterns: []string{},
			expected: true,
		},
		{
			name:     "exact match",
			id:       "spiffe://example.org/service/api",
			patterns: []string{"spiffe://example.org/service/api"},
			expected: true,
		},
		{
			name:     "wildcard single segment",
			id:       "spiffe://example.org/tenant/acme/service/api",
			patterns: []string{"spiffe://example.org/tenant/*/service/api"},
			expected: true,
		},
		{
			name:     "wildcard multiple positions",
			id:       "spiffe://example.org/tenant/acme/service/api",
			patterns: []string{"spiffe://example.org/*/acme/*/api"},
			expected: true,
		},
		{
			name:     "double wildcard at end",
			id:       "spiffe://example.org/tenant/acme/service/api/v2",
			patterns: []string{"spiffe://example.org/tenant/**"},
			expected: true,
		},
		{
			name:     "double wildcard matches zero segments",
			id:       "spiffe://example.org/tenant",
			patterns: []string{"spiffe://example.org/tenant/**"},
			expected: true,
		},
		{
			name:     "no match - wrong trust domain",
			id:       "spiffe://other.org/service/api",
			patterns: []string{"spiffe://example.org/service/api"},
			expected: false,
		},
		{
			name:     "no match - path mismatch",
			id:       "spiffe://example.org/service/other",
			patterns: []string{"spiffe://example.org/service/api"},
			expected: false,
		},
		{
			name:     "no match - shorter path",
			id:       "spiffe://example.org/service",
			patterns: []string{"spiffe://example.org/service/api"},
			expected: false,
		},
		{
			name:     "multiple patterns - first matches",
			id:       "spiffe://example.org/service/api",
			patterns: []string{"spiffe://example.org/service/*", "spiffe://other.org/*"},
			expected: true,
		},
		{
			name:     "multiple patterns - second matches",
			id:       "spiffe://other.org/api",
			patterns: []string{"spiffe://example.org/*", "spiffe://other.org/*"},
			expected: true,
		},
		{
			name:     "invalid SPIFFE ID",
			id:       "not-a-spiffe-id",
			patterns: []string{"spiffe://example.org/*"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchSpiffeID(tt.id, tt.patterns)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSpiffeTrustDomain_ExtractOrg(t *testing.T) {
	spiffeID := SpiffeID{
		TrustDomain: "example.org",
		Path:        "/tenant/acme/service/api",
	}

	tests := []struct {
		name       string
		td         SpiffeTrustDomain
		claims     map[string]any
		defaultOrg string
		expected   string
	}{
		{
			name: "static org",
			td: SpiffeTrustDomain{
				Org: "static-org",
			},
			claims:     map[string]any{},
			defaultOrg: "default",
			expected:   "static-org",
		},
		{
			name: "org from claim",
			td: SpiffeTrustDomain{
				OrgClaim: "tenant_id",
			},
			claims:     map[string]any{"tenant_id": "claim-org"},
			defaultOrg: "default",
			expected:   "claim-org",
		},
		{
			name: "org from path index 0",
			td: SpiffeTrustDomain{
				OrgFromPath:  true,
				OrgPathIndex: 0,
			},
			claims:     map[string]any{},
			defaultOrg: "default",
			expected:   "tenant",
		},
		{
			name: "org from path index 1",
			td: SpiffeTrustDomain{
				OrgFromPath:  true,
				OrgPathIndex: 1,
			},
			claims:     map[string]any{},
			defaultOrg: "default",
			expected:   "acme",
		},
		{
			name: "org from path - index out of range",
			td: SpiffeTrustDomain{
				OrgFromPath:  true,
				OrgPathIndex: 10,
			},
			claims:     map[string]any{},
			defaultOrg: "default",
			expected:   "default",
		},
		{
			name: "static org takes precedence over claim",
			td: SpiffeTrustDomain{
				Org:      "static-org",
				OrgClaim: "tenant_id",
			},
			claims:     map[string]any{"tenant_id": "claim-org"},
			defaultOrg: "default",
			expected:   "static-org",
		},
		{
			name: "claim takes precedence over path",
			td: SpiffeTrustDomain{
				OrgClaim:     "tenant_id",
				OrgFromPath:  true,
				OrgPathIndex: 1,
			},
			claims:     map[string]any{"tenant_id": "claim-org"},
			defaultOrg: "default",
			expected:   "claim-org",
		},
		{
			name: "missing claim falls back to path",
			td: SpiffeTrustDomain{
				OrgClaim:     "missing_claim",
				OrgFromPath:  true,
				OrgPathIndex: 1,
			},
			claims:     map[string]any{},
			defaultOrg: "default",
			expected:   "acme",
		},
		{
			name:       "no extraction config uses default",
			td:         SpiffeTrustDomain{},
			claims:     map[string]any{},
			defaultOrg: "default",
			expected:   "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.td.ExtractOrg(spiffeID, tt.claims, tt.defaultOrg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSpiffeValidator_ValidateJWT(t *testing.T) {
	// Generate RSA key for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWKS server
	jwk := jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     "test-key-1",
		Algorithm: "RS256",
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	logger := zaptest.NewLogger(t)

	tests := []struct {
		name        string
		config      *SpiffeConfig
		claims      jwt.MapClaims
		expectError bool
		expectedOrg string
	}{
		{
			name: "valid JWT with static org",
			config: &SpiffeConfig{
				TrustDomains: []SpiffeTrustDomain{
					{
						Domain:   "example.org",
						JWKSURL:  server.URL,
						Audience: "test-audience",
						Org:      "static-org",
					},
				},
				DefaultOrg: "default",
			},
			claims: jwt.MapClaims{
				"sub": "spiffe://example.org/service/api",
				"aud": []string{"test-audience"},
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			},
			expectError: false,
			expectedOrg: "static-org",
		},
		{
			name: "valid JWT with org from path",
			config: &SpiffeConfig{
				TrustDomains: []SpiffeTrustDomain{
					{
						Domain:       "example.org",
						JWKSURL:      server.URL,
						Audience:     "test-audience",
						OrgFromPath:  true,
						OrgPathIndex: 1,
					},
				},
				DefaultOrg: "default",
			},
			claims: jwt.MapClaims{
				"sub": "spiffe://example.org/tenant/acme/service/api",
				"aud": []string{"test-audience"},
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			},
			expectError: false,
			expectedOrg: "acme",
		},
		{
			name: "valid JWT with org from claim",
			config: &SpiffeConfig{
				TrustDomains: []SpiffeTrustDomain{
					{
						Domain:   "example.org",
						JWKSURL:  server.URL,
						Audience: "test-audience",
						OrgClaim: "tenant_id",
					},
				},
				DefaultOrg: "default",
			},
			claims: jwt.MapClaims{
				"sub":       "spiffe://example.org/service/api",
				"aud":       []string{"test-audience"},
				"exp":       time.Now().Add(time.Hour).Unix(),
				"iat":       time.Now().Unix(),
				"tenant_id": "claim-org",
			},
			expectError: false,
			expectedOrg: "claim-org",
		},
		{
			name: "unknown trust domain",
			config: &SpiffeConfig{
				TrustDomains: []SpiffeTrustDomain{
					{
						Domain:   "example.org",
						JWKSURL:  server.URL,
						Audience: "test-audience",
					},
				},
			},
			claims: jwt.MapClaims{
				"sub": "spiffe://unknown.org/service/api",
				"aud": []string{"test-audience"},
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			},
			expectError: true,
		},
		{
			name: "wrong audience",
			config: &SpiffeConfig{
				TrustDomains: []SpiffeTrustDomain{
					{
						Domain:   "example.org",
						JWKSURL:  server.URL,
						Audience: "expected-audience",
					},
				},
			},
			claims: jwt.MapClaims{
				"sub": "spiffe://example.org/service/api",
				"aud": []string{"wrong-audience"},
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			},
			expectError: true,
		},
		{
			name: "SPIFFE ID not in allowed list",
			config: &SpiffeConfig{
				TrustDomains: []SpiffeTrustDomain{
					{
						Domain:   "example.org",
						JWKSURL:  server.URL,
						Audience: "test-audience",
					},
				},
				AllowedIDs: []string{"spiffe://example.org/allowed/*"},
			},
			claims: jwt.MapClaims{
				"sub": "spiffe://example.org/notallowed/api",
				"aud": []string{"test-audience"},
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			},
			expectError: true,
		},
		{
			name: "expired JWT",
			config: &SpiffeConfig{
				TrustDomains: []SpiffeTrustDomain{
					{
						Domain:   "example.org",
						JWKSURL:  server.URL,
						Audience: "test-audience",
					},
				},
			},
			claims: jwt.MapClaims{
				"sub": "spiffe://example.org/service/api",
				"aud": []string{"test-audience"},
				"exp": time.Now().Add(-time.Hour).Unix(),
				"iat": time.Now().Add(-2 * time.Hour).Unix(),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewSpiffeValidator(tt.config, logger)

			// Create signed JWT
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, tt.claims)
			token.Header["kid"] = "test-key-1"
			tokenString, err := token.SignedString(privateKey)
			require.NoError(t, err)

			result, err := validator.ValidateJWT(context.Background(), tokenString)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedOrg, result.Org)
		})
	}
}

func TestSpiffeValidator_MultiTrustDomain(t *testing.T) {
	// Generate RSA keys for each trust domain
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWKS servers
	jwks1 := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &privateKey1.PublicKey, KeyID: "key-1", Algorithm: "RS256", Use: "sig"},
		},
	}
	jwks2 := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &privateKey2.PublicKey, KeyID: "key-2", Algorithm: "RS256", Use: "sig"},
		},
	}

	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks1)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks2)
	}))
	defer server2.Close()

	logger := zaptest.NewLogger(t)

	config := &SpiffeConfig{
		TrustDomains: []SpiffeTrustDomain{
			{
				Domain:   "prod.example.org",
				JWKSURL:  server1.URL,
				Audience: "prod-api",
				Org:      "production",
			},
			{
				Domain:   "staging.example.org",
				JWKSURL:  server2.URL,
				Audience: "staging-api",
				Org:      "staging",
			},
		},
		DefaultOrg: "default",
	}

	validator := NewSpiffeValidator(config, logger)

	// Test token from first trust domain
	t.Run("token from first trust domain", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "spiffe://prod.example.org/service/api",
			"aud": []string{"prod-api"},
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "key-1"
		tokenString, err := token.SignedString(privateKey1)
		require.NoError(t, err)

		result, err := validator.ValidateJWT(context.Background(), tokenString)
		require.NoError(t, err)
		assert.Equal(t, "production", result.Org)
		assert.Equal(t, "prod.example.org", result.SpiffeID.TrustDomain)
	})

	// Test token from second trust domain
	t.Run("token from second trust domain", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "spiffe://staging.example.org/service/api",
			"aud": []string{"staging-api"},
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "key-2"
		tokenString, err := token.SignedString(privateKey2)
		require.NoError(t, err)

		result, err := validator.ValidateJWT(context.Background(), tokenString)
		require.NoError(t, err)
		assert.Equal(t, "staging", result.Org)
		assert.Equal(t, "staging.example.org", result.SpiffeID.TrustDomain)
	})

	// Test cross-signed token (wrong key for trust domain) should fail
	t.Run("cross-signed token fails", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "spiffe://prod.example.org/service/api",
			"aud": []string{"prod-api"},
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "key-2" // Wrong key ID for prod trust domain
		tokenString, err := token.SignedString(privateKey2)
		require.NoError(t, err)

		_, err = validator.ValidateJWT(context.Background(), tokenString)
		assert.Error(t, err)
	})
}

// TestHybridKeySource tests the hybrid key source that combines JWKS and Workload API
func TestHybridKeySource(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Generate test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWKS server
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &privateKey.PublicKey,
				KeyID:     "jwks-key-1",
				Algorithm: "RS256",
				Use:       "sig",
			},
		},
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	// Create config with one JWKS domain and one without (would use Workload API)
	domainMap := map[string]*SpiffeTrustDomain{
		"jwks.example.org": {
			Domain:  "jwks.example.org",
			JWKSURL: jwksServer.URL,
		},
		"workload.example.org": {
			Domain: "workload.example.org",
			// No JWKS URL - would use Workload API
		},
	}

	config := &SpiffeConfig{
		TrustDomains: []SpiffeTrustDomain{
			{Domain: "jwks.example.org", JWKSURL: jwksServer.URL},
			{Domain: "workload.example.org"},
		},
		// No workload socket configured
	}

	// Create hybrid source without workload socket
	source, err := newHybridKeySource(context.Background(), config, domainMap, logger)
	require.NoError(t, err)
	defer func() { _ = source.close() }()

	// Test JWKS domain works
	t.Run("JWKS domain returns key", func(t *testing.T) {
		key, err := source.getKey(context.Background(), "jwks.example.org", "jwks-key-1", false)
		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	// Test non-JWKS domain without workload socket fails gracefully
	t.Run("non-JWKS domain without workload socket fails", func(t *testing.T) {
		_, err := source.getKey(context.Background(), "workload.example.org", "any-key", false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "workload API not available")
	})

	// Test unknown domain fails
	t.Run("unknown domain fails", func(t *testing.T) {
		_, err := source.getKey(context.Background(), "unknown.example.org", "any-key", false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown trust domain")
	})
}

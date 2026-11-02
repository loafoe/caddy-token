package token

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/loafoe/caddy-token/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestCheckTokenAndInjectHeaders_ClientCertificate(t *testing.T) {
	tests := []struct {
		name           string
		clientCA       bool
		debug          bool
		defaultOrg     string
		hasTLS         bool
		hasCerts       bool
		verifiedChain  bool
		expectedHeader string
		expectError    bool
	}{
		{
			name:           "client cert with default org",
			clientCA:       true,
			debug:          false,
			defaultOrg:     "anonymous",
			hasTLS:         true,
			hasCerts:       true,
			verifiedChain:  true,
			expectedHeader: "anonymous",
			expectError:    false,
		},
		{
			name:           "client cert with custom org",
			clientCA:       true,
			debug:          true,
			defaultOrg:     "my-organization",
			hasTLS:         true,
			hasCerts:       true,
			verifiedChain:  true,
			expectedHeader: "my-organization",
			expectError:    false,
		},
		{
			name:           "client cert presented but chain not verified",
			clientCA:       true,
			debug:          false,
			defaultOrg:     "anonymous",
			hasTLS:         true,
			hasCerts:       true,
			verifiedChain:  false,
			expectedHeader: "",
			expectError:    true, // Unverified cert must not authenticate
		},
		{
			name:           "client cert disabled",
			clientCA:       false,
			debug:          false,
			defaultOrg:     "anonymous",
			hasTLS:         true,
			hasCerts:       true,
			verifiedChain:  true,
			expectedHeader: "",
			expectError:    true, // Should fail with no valid token
		},
		{
			name:           "no TLS connection",
			clientCA:       true,
			debug:          false,
			defaultOrg:     "anonymous",
			hasTLS:         false,
			hasCerts:       false,
			expectedHeader: "",
			expectError:    true, // Should fail with no valid token
		},
		{
			name:           "TLS but no client certs",
			clientCA:       true,
			debug:          false,
			defaultOrg:     "anonymous",
			hasTLS:         true,
			hasCerts:       false,
			expectedHeader: "",
			expectError:    true, // Should fail with no valid token
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup middleware
			m := &Middleware{
				logger:     zaptest.NewLogger(t),
				ClientCA:   tt.clientCA,
				Debug:      tt.debug,
				DefaultOrg: tt.defaultOrg,
			}

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)

			// Setup TLS if needed
			if tt.hasTLS {
				req.TLS = &tls.ConnectionState{}
				if tt.hasCerts {
					// Create a dummy certificate
					cert := &x509.Certificate{
						Subject: pkix.Name{
							CommonName: "test-client",
						},
					}
					req.TLS.PeerCertificates = []*x509.Certificate{cert}
					if tt.verifiedChain {
						// A verified chain is what TLS termination populates when
						// the client cert chains to a trusted CA.
						req.TLS.VerifiedChains = [][]*x509.Certificate{{cert}}
					}
				}
			}

			// Call the function
			err := m.CheckTokenAndInjectHeaders(req)

			// Check results
			if tt.expectError {
				assert.Error(t, err)
				if caddyErr, ok := err.(caddyhttp.HandlerError); ok {
					assert.Equal(t, http.StatusUnauthorized, caddyErr.StatusCode)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedHeader, req.Header.Get("X-Scope-OrgID"))
			}
		})
	}
}

func TestCheckTokenAndInjectHeaders_UpstreamAuth(t *testing.T) {
	tests := []struct {
		name              string
		allowUpstreamAuth bool
		upstreamOrgID     string
		expectError       bool
		expectedHeader    string
	}{
		{
			name:              "upstream auth allowed",
			allowUpstreamAuth: true,
			upstreamOrgID:     "upstream-org",
			expectError:       false,
			expectedHeader:    "upstream-org",
		},
		{
			name:              "upstream auth not allowed",
			allowUpstreamAuth: false,
			upstreamOrgID:     "upstream-org",
			expectError:       true,
			expectedHeader:    "",
		},
		{
			name:              "no upstream auth header",
			allowUpstreamAuth: true,
			upstreamOrgID:     "",
			expectError:       true,
			expectedHeader:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup middleware
			m := &Middleware{
				logger:            zaptest.NewLogger(t),
				AllowUpstreamAuth: tt.allowUpstreamAuth,
			}

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.upstreamOrgID != "" {
				req.Header.Set("X-Scope-OrgID", tt.upstreamOrgID)
			}

			// Call the function
			err := m.CheckTokenAndInjectHeaders(req)

			// Check results
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedHeader, req.Header.Get("X-Scope-OrgID"))
			}
		})
	}
}

func TestCheckTokenAndInjectHeaders_APIKey(t *testing.T) {
	// Generate test tokens
	oneHourFromNow := time.Now().Add(time.Hour)
	testToken, _, err := keys.GenerateAPIKey("1", "test-key", "test-org", "test-user", "test-email", "test-name", []string{"read", "write"}, oneHourFromNow)
	require.NoError(t, err)

	v2Token, _, err := keys.GenerateAPIKey("2", "signing-key", "v2-org", "v2-user", "v2-email", "v2-name", []string{"api:read"}, oneHourFromNow)
	require.NoError(t, err)

	// Create tokens map for v1 tokens
	tokens := make(map[string]keys.Key)
	prefixRemoved := testToken[len(keys.Prefix):]
	decodedString, err := base64.StdEncoding.DecodeString(prefixRemoved)
	require.NoError(t, err)
	var decoded keys.Key
	err = json.Unmarshal([]byte(decodedString), &decoded)
	require.NoError(t, err)
	tokens[testToken] = decoded

	tests := []struct {
		name           string
		headerName     string
		headerValue    string
		basicAuth      bool
		bearerToken    bool
		signingKey     string
		requiredScopes []string
		expectedOrg    string
		injectHeader   bool
		expectError    bool
	}{
		{
			name:         "valid v1 token in X-Api-Key header",
			headerName:   "X-Api-Key",
			headerValue:  testToken,
			expectedOrg:  "test-org",
			injectHeader: true,
			expectError:  false,
		},
		{
			name:         "valid v2 token in X-Api-Key header",
			headerName:   "X-Api-Key",
			headerValue:  v2Token,
			signingKey:   "signing-key",
			expectedOrg:  "v2-org",
			injectHeader: false,
			expectError:  false,
		},
		{
			name:        "valid token in basic auth",
			headerValue: testToken,
			basicAuth:   true,
			expectedOrg: "test-org",
			expectError: false,
		},
		{
			name:         "valid token as bearer token",
			headerValue:  testToken,
			bearerToken:  true,
			expectedOrg:  "test-org",
			injectHeader: true,
			expectError:  false,
		},
		{
			name:        "invalid token",
			headerName:  "X-Api-Key",
			headerValue: "invalid-token",
			expectError: true,
		},
		{
			name:           "valid token but missing required scope",
			headerName:     "X-Api-Key",
			headerValue:    testToken,
			requiredScopes: []string{"admin"},
			expectError:    true,
		},
		{
			name:           "valid token with matching scope",
			headerName:     "X-Api-Key",
			headerValue:    testToken,
			requiredScopes: []string{"read"},
			expectedOrg:    "test-org",
			injectHeader:   true,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup middleware
			m := &Middleware{
				logger:          zaptest.NewLogger(t),
				tokens:          tokens,
				SigningKey:      tt.signingKey,
				Scopes:          tt.requiredScopes,
				InjectOrgHeader: tt.injectHeader,
			}

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)

			// Set authentication header
			if tt.headerName != "" {
				req.Header.Set(tt.headerName, tt.headerValue)
			}
			if tt.basicAuth {
				req.SetBasicAuth("user", tt.headerValue)
			}
			if tt.bearerToken {
				req.Header.Set("Authorization", "Bearer "+tt.headerValue)
			}

			// Call the function
			err := m.CheckTokenAndInjectHeaders(req)

			// Check results
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.injectHeader && tt.expectedOrg != "" {
					assert.Equal(t, tt.expectedOrg, req.Header.Get("X-Scope-OrgID"))
				}
			}
		})
	}
}

func TestCheckTokenAndInjectHeaders_JWT(t *testing.T) {
	// Create a test JWT token
	claims := jwt.MapClaims{
		"iss":    "test-issuer",
		"sub":    "test-subject",
		"aud":    "test-audience",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"groups": []string{"admin", "users"},
		"ort":    []string{"tenant1", "tenant2"},
		"owt":    []string{"tenant3"},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	tests := []struct {
		name        string
		token       string
		hasVerifier bool
		expectError bool
	}{
		{
			name:        "no verifier configured",
			token:       tokenString,
			hasVerifier: false,
			expectError: true,
		},
		{
			name:        "no JWT token provided",
			token:       "",
			hasVerifier: false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup middleware
			m := &Middleware{
				logger: zaptest.NewLogger(t),
			}

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.token != "" {
				req.Header.Set("X-Id-Token", tt.token)
			}

			// Call the function
			err := m.CheckTokenAndInjectHeaders(req)

			// Check results
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckTokenAndInjectHeaders_NoValidToken(t *testing.T) {
	// Setup middleware with no authentication methods
	m := &Middleware{
		logger: zaptest.NewLogger(t),
	}

	// Create test request with no authentication
	req := httptest.NewRequest("GET", "/test", nil)

	// Call the function
	err := m.CheckTokenAndInjectHeaders(req)

	// Should return unauthorized error
	assert.Error(t, err)
	if caddyErr, ok := err.(caddyhttp.HandlerError); ok {
		assert.Equal(t, http.StatusUnauthorized, caddyErr.StatusCode)
	}
}

func TestCheckTokenAndInjectHeaders_AuthenticationPriority(t *testing.T) {
	// This test verifies that client certificate authentication takes priority
	oneHourFromNow := time.Now().Add(time.Hour)
	testToken, _, err := keys.GenerateAPIKey("1", "test-key", "api-org", "test-user", "test-email", "test-name", []string{"read"}, oneHourFromNow)
	require.NoError(t, err)

	// Create tokens map
	tokens := make(map[string]keys.Key)
	prefixRemoved := testToken[len(keys.Prefix):]
	decodedString, err := base64.StdEncoding.DecodeString(prefixRemoved)
	require.NoError(t, err)
	var decoded keys.Key
	err = json.Unmarshal([]byte(decodedString), &decoded)
	require.NoError(t, err)
	tokens[testToken] = decoded

	// Setup middleware with both client cert and API key support
	m := &Middleware{
		logger:          zaptest.NewLogger(t),
		ClientCA:        true,
		DefaultOrg:      "cert-org",
		tokens:          tokens,
		InjectOrgHeader: true,
	}

	// Create test request with both client cert and API key
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Api-Key", testToken)

	// Add client certificate
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "test-client",
		},
	}
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}

	// Call the function
	err = m.CheckTokenAndInjectHeaders(req)

	// Should succeed and use client cert org (higher priority)
	assert.NoError(t, err)
	assert.Equal(t, "cert-org", req.Header.Get("X-Scope-OrgID"))
}

func TestResolveOrgFromClaim(t *testing.T) {
	tests := []struct {
		name        string
		org         string
		orgClaim    string
		claims      map[string]any
		expected    string
		expectedOK  bool
		expectedErr error
	}{
		{
			name:       "static org",
			org:        "static-org",
			claims:     map[string]any{},
			expected:   "static-org",
			expectedOK: true,
		},
		{
			name:       "org from claim",
			orgClaim:   "tenant_id",
			claims:     map[string]any{"tenant_id": "claim-org"},
			expected:   "claim-org",
			expectedOK: true,
		},
		{
			name:       "static org takes precedence over claim",
			org:        "static-org",
			orgClaim:   "tenant_id",
			claims:     map[string]any{"tenant_id": "claim-org"},
			expected:   "static-org",
			expectedOK: true,
		},
		{
			name:       "missing claim is not resolved",
			orgClaim:   "tenant_id",
			claims:     map[string]any{},
			expected:   "",
			expectedOK: false,
		},
		{
			name:       "non-string claim value is not resolved",
			orgClaim:   "tenant_id",
			claims:     map[string]any{"tenant_id": 42},
			expected:   "",
			expectedOK: false,
		},
		{
			name:       "empty string claim value is not resolved",
			orgClaim:   "tenant_id",
			claims:     map[string]any{"tenant_id": ""},
			expected:   "",
			expectedOK: false,
		},
		{
			name:       "no extraction config is not resolved",
			claims:     map[string]any{"tenant_id": "claim-org"},
			expected:   "",
			expectedOK: false,
		},
		{
			name:       "array index selects first element",
			orgClaim:   "groups[0]",
			claims:     map[string]any{"groups": []any{"acme", "other"}},
			expected:   "acme",
			expectedOK: true,
		},
		{
			name:       "array index selects second element",
			orgClaim:   "groups[1]",
			claims:     map[string]any{"groups": []any{"acme", "other"}},
			expected:   "other",
			expectedOK: true,
		},
		{
			name:        "static org takes precedence over array index claim",
			org:         "static-org",
			orgClaim:    "groups[0]",
			claims:      map[string]any{"groups": []any{}},
			expected:    "static-org",
			expectedOK:  true,
			expectedErr: nil,
		},
		{
			name:        "empty array denies access",
			orgClaim:    "groups[0]",
			claims:      map[string]any{"groups": []any{}},
			expectedErr: ErrOrgClaimNoAccess,
		},
		{
			name:        "index out of range denies access",
			orgClaim:    "groups[2]",
			claims:      map[string]any{"groups": []any{"acme", "other"}},
			expectedErr: ErrOrgClaimNoAccess,
		},
		{
			name:        "missing array claim denies access",
			orgClaim:    "groups[0]",
			claims:      map[string]any{},
			expectedErr: ErrOrgClaimNoAccess,
		},
		{
			name:        "non-array claim with index syntax denies access",
			orgClaim:    "groups[0]",
			claims:      map[string]any{"groups": "not-an-array"},
			expectedErr: ErrOrgClaimNoAccess,
		},
		{
			name:        "empty string element at index denies access",
			orgClaim:    "groups[0]",
			claims:      map[string]any{"groups": []any{""}},
			expectedErr: ErrOrgClaimNoAccess,
		},
		{
			name:        "non-string element at index denies access",
			orgClaim:    "groups[0]",
			claims:      map[string]any{"groups": []any{42}},
			expectedErr: ErrOrgClaimNoAccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			org, ok, err := resolveOrgFromClaim(tt.org, tt.orgClaim, tt.claims)
			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, tt.expectedErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, org)
			assert.Equal(t, tt.expectedOK, ok)
		})
	}
}

func TestMatchJWTMapping(t *testing.T) {
	tests := []struct {
		name            string
		mappings        []JWTGroupMapping
		have            []string
		expectedMatched bool
		expectedMapping JWTGroupMapping
	}{
		{
			name:            "no mappings matches unconditionally",
			mappings:        nil,
			have:            []string{"anything"},
			expectedMatched: true,
			expectedMapping: JWTGroupMapping{},
		},
		{
			name:            "single mapping with no groups matches unconditionally",
			mappings:        []JWTGroupMapping{{Org: "default-org"}},
			have:            nil,
			expectedMatched: true,
			expectedMapping: JWTGroupMapping{Org: "default-org"},
		},
		{
			name:            "single mapping requires all groups present",
			mappings:        []JWTGroupMapping{{Groups: []string{"admin", "test"}, Org: "admin-org"}},
			have:            []string{"admin", "test", "extra"},
			expectedMatched: true,
			expectedMapping: JWTGroupMapping{Groups: []string{"admin", "test"}, Org: "admin-org"},
		},
		{
			name:            "single mapping fails when a required group is missing",
			mappings:        []JWTGroupMapping{{Groups: []string{"admin", "test"}, Org: "admin-org"}},
			have:            []string{"admin"},
			expectedMatched: false,
		},
		{
			name: "first matching mapping wins over a later catch-all",
			mappings: []JWTGroupMapping{
				{Groups: []string{"admin"}, Org: "admin-org"},
				{Org: "default-org"},
			},
			have:            []string{"admin"},
			expectedMatched: true,
			expectedMapping: JWTGroupMapping{Groups: []string{"admin"}, Org: "admin-org"},
		},
		{
			name: "falls through to a later mapping when an earlier one doesn't match",
			mappings: []JWTGroupMapping{
				{Groups: []string{"admin"}, Org: "admin-org"},
				{Groups: []string{"viewer"}, Org: "viewer-org"},
			},
			have:            []string{"viewer"},
			expectedMatched: true,
			expectedMapping: JWTGroupMapping{Groups: []string{"viewer"}, Org: "viewer-org"},
		},
		{
			name: "no mapping matches when none of the group requirements are satisfied",
			mappings: []JWTGroupMapping{
				{Groups: []string{"admin"}, Org: "admin-org"},
				{Groups: []string{"viewer"}, Org: "viewer-org"},
			},
			have:            []string{"guest"},
			expectedMatched: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapping, matched := matchJWTMapping(tt.mappings, tt.have)
			assert.Equal(t, tt.expectedMatched, matched)
			if tt.expectedMatched {
				assert.Equal(t, tt.expectedMapping, mapping)
			}
		})
	}
}

func TestValidateJWTMappings(t *testing.T) {
	tests := []struct {
		name        string
		mappings    []JWTGroupMapping
		expectError bool
		errContains []string
	}{
		{
			name:     "no mappings",
			mappings: nil,
		},
		{
			name: "single mapping",
			mappings: []JWTGroupMapping{
				{Groups: []string{"admin"}, Org: "admin-org"},
			},
		},
		{
			name: "disjoint groups map to different orgs",
			mappings: []JWTGroupMapping{
				{Groups: []string{"admin"}, Org: "admin-org"},
				{Groups: []string{"viewer"}, Org: "viewer-org"},
			},
		},
		{
			name: "catch-all alongside a specific group is not a conflict",
			mappings: []JWTGroupMapping{
				{Groups: []string{"admin"}, Org: "admin-org"},
				{Org: "default-org"},
			},
		},
		{
			name: "identical mapping repeated is redundant but not ambiguous",
			mappings: []JWTGroupMapping{
				{Groups: []string{"admin"}, Org: "admin-org"},
				{Groups: []string{"admin", "extra"}, Org: "admin-org"},
			},
		},
		{
			name: "same group maps to two different static orgs",
			mappings: []JWTGroupMapping{
				{Groups: []string{"admin"}, Org: "platform"},
				{Groups: []string{"admin"}, Org: "security"},
			},
			expectError: true,
			errContains: []string{`"admin"`, `org "platform"`, `org "security"`, "jwt block 1", "jwt block 2"},
		},
		{
			name: "same group maps to an org and an org_claim",
			mappings: []JWTGroupMapping{
				{Groups: []string{"admin"}, Org: "platform"},
				{Groups: []string{"admin", "extra"}, OrgClaim: "department"},
			},
			expectError: true,
			errContains: []string{`"admin"`, `org "platform"`, `org_claim "department"`},
		},
		{
			name: "same group maps to an explicit org and to no org at all",
			mappings: []JWTGroupMapping{
				{Groups: []string{"admin"}, Org: "platform"},
				{Groups: []string{"admin"}},
			},
			expectError: true,
			errContains: []string{`"admin"`, `org "platform"`, "no org"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateJWTMappings(tt.mappings)
			if !tt.expectError {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			for _, substr := range tt.errContains {
				assert.Contains(t, err.Error(), substr)
			}
		})
	}
}

func TestProvision_AmbiguousJWTMappingsRejected(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	m := &Middleware{
		JWTMappings: []JWTGroupMapping{
			{Groups: []string{"admin"}, Org: "platform"},
			{Groups: []string{"admin"}, Org: "security"},
		},
	}

	err := m.Provision(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ambiguous jwt org mapping")
	assert.Contains(t, err.Error(), `"admin"`)
	assert.Contains(t, err.Error(), `org "platform"`)
	assert.Contains(t, err.Error(), `org "security"`)
}

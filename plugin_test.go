package token

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
			expectedHeader: "my-organization",
			expectError:    false,
		},
		{
			name:           "client cert disabled",
			clientCA:       false,
			debug:          false,
			defaultOrg:     "anonymous",
			hasTLS:         true,
			hasCerts:       true,
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
	}

	// Call the function
	err = m.CheckTokenAndInjectHeaders(req)

	// Should succeed and use client cert org (higher priority)
	assert.NoError(t, err)
	assert.Equal(t, "cert-org", req.Header.Get("X-Scope-OrgID"))
}

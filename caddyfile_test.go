package token_test

import (
	"bytes"
	"fmt"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/loafoe/caddy-token"
	"github.com/loafoe/caddy-token/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestCaddyfileTokenV2(t *testing.T) {
	oneHourFromNow := time.Now().Add(time.Hour)
	v2Token, signature, err := keys.GenerateAPIKey("2", "test", "test", "test", "test", "test", []string{"test"}, oneHourFromNow)
	if err != nil {
		t.Fatalf("Failed to generate v2 token: %v", err)
	}

	// Admin API must be exposed on port 2999 to match what caddytest.Tester does
	config := `
	{
		skip_install_trust
		admin 127.0.0.1:2999
        order token first
	}

	http://127.0.0.1:12344 {
		bind 127.0.0.1

		token {
			tenantOrgClaim ort
			allowUpstreamAuth true
            signed {
			  key test
			}
	    }
	    respond 200
	}
	`

	tester := caddytest.NewTester(t)
	tester.InitServer(config, "caddyfile")

	assert.NotEmpty(t, v2Token)
	assert.NotEmpty(t, signature)

	tester.AssertGetResponse("http://127.0.0.1:12344", 401, "")
	tester.AssertPostResponseBody("http://127.0.0.1:12344", []string{"X-Api-Key: " + v2Token, "Content-Type: application/json"}, bytes.NewBuffer([]byte("[]")), 200, "")
}

func TestCaddyfileToken(t *testing.T) {
	oneHourFromNow := time.Now().Add(time.Hour)
	testToken, _, err := keys.GenerateAPIKey("1", "test", "test", "test", "test", "test", []string{"test"}, oneHourFromNow)
	if err != nil {
		t.Fatalf("Failed to generate v1 token: %v", err)
	}

	tmpFile, err := os.CreateTemp("", "testfile-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	// Ensure the file is cleaned up after the test
	defer func(name string) {
		err := os.Remove(name)
		if err != nil {
			t.Fatalf("Failed to remove temp file: %v", err)
		}
	}(tmpFile.Name())

	// Write content to the temporary file
	content := []byte(testToken)
	if _, err := tmpFile.Write(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	// Close the file
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	// Admin API must be exposed on port 2999 to match what caddytest.Tester does
	config := fmt.Sprintf(`
	{
		skip_install_trust
		admin 127.0.0.1:2999
        order token first
	}

	http://127.0.0.1:12344 {
		bind 127.0.0.1

		token {
			file %s
			tenantOrgClaim ort
			allowUpstreamAuth true
	    }
	    respond 200
	}
	`, tmpFile.Name())

	tester := caddytest.NewTester(t)
	tester.InitServer(config, "caddyfile")

	tester.AssertPostResponseBody("http://127.0.0.1:12344", []string{"X-Api-Key: " + testToken, "Content-Type: application/json"}, bytes.NewBuffer([]byte("[]")), 200, "")
}

func TestCaddyfileTokenV2WithEnvSecret(t *testing.T) {
	password := keys.GenerateRandomString(32)
	_ = os.Setenv("SIGNING_KEY", password)
	oneHourFromNow := time.Now().Add(time.Hour)

	v2Token, signature, err := keys.GenerateAPIKey("2", password, "test", "test", "test", "test", []string{"test"}, oneHourFromNow)
	if err != nil {
		t.Fatalf("Failed to generate v2 token: %v", err)
	}

	// Admin API must be exposed on port 2999 to match what caddytest.Tester does
	config := `
	{
		skip_install_trust
		admin 127.0.0.1:2999
        order token first
	}

	http://127.0.0.1:12344 {
		bind 127.0.0.1

		token {
			tenantOrgClaim ort
			allowUpstreamAuth true
            signed {
				key {$SIGNING_KEY}
			}
	    }
	    respond 200
	}
	`

	tester := caddytest.NewTester(t)
	tester.InitServer(config, "caddyfile")

	assert.NotEmpty(t, v2Token)
	assert.NotEmpty(t, signature)

	tester.AssertPostResponseBody("http://127.0.0.1:12344", []string{"X-Api-Key: " + v2Token, "Content-Type: application/json"}, bytes.NewBuffer([]byte("[]")), 200, "")
}

func TestCaddyfileJWTClaims(t *testing.T) {
	started := make(chan bool)
	go runMockServer(started)

	// Admin API must be exposed on port 2999 to match what caddytest.Tester does
	config := `
	{
		skip_install_trust
		admin 127.0.0.1:2999
        order token first
	}

	http://127.0.0.1:12344 {
		bind 127.0.0.1

		route /* {
		  token {
            tenantOrgClaim ort
            allowUpstreamAuth true
            jwt {
                issuer http://127.0.0.1:12000
                verify false
                group admin
                group test
            }
          }
	      respond 200
       }
	}
	`

	tester := caddytest.NewTester(t)
	tester.InitServer(config, "caddyfile")

	<-started

	accessToken, err := getToken()
	if err != nil {
		t.Fatalf("Failed to get access token: %v", err)
	}

	tester.AssertPostResponseBody("http://127.0.0.1:12344", []string{"X-Id-Token: " + accessToken, "Content-Type: application/json"}, bytes.NewBuffer([]byte("[]")), 200, "")
}

func TestCaddyfileClientCA(t *testing.T) {
	// Admin API must be exposed on port 2999 to match what caddytest.Tester does
	config := `
	{
		skip_install_trust
		admin 127.0.0.1:2999
        order token first
	}

	http://127.0.0.1:12344 {
		bind 127.0.0.1

		token {
			client_ca {
				debug true
				default_org "test-org"
			}
			allowUpstreamAuth false
	    }
	    respond 200
	}
	`

	tester := caddytest.NewTester(t)
	tester.InitServer(config, "caddyfile")

	// Test that requests without client certificates are rejected
	tester.AssertGetResponse("http://127.0.0.1:12344", 401, "")
}

func TestCaddyfileClientCADefaults(t *testing.T) {
	// Test client_ca directive with default values
	config := `
	{
		skip_install_trust
		admin 127.0.0.1:2999
        order token first
	}

	http://127.0.0.1:12344 {
		bind 127.0.0.1

		token {
			client_ca {
				debug false
			}
			allowUpstreamAuth false
	    }
	    respond 200
	}
	`

	tester := caddytest.NewTester(t)
	tester.InitServer(config, "caddyfile")

	// Test that requests without client certificates are rejected
	tester.AssertGetResponse("http://127.0.0.1:12344", 401, "")
}

func TestCaddyfileClientCAMinimal(t *testing.T) {
	// Test client_ca directive with minimal configuration
	config := `
	{
		skip_install_trust
		admin 127.0.0.1:2999
        order token first
	}

	http://127.0.0.1:12344 {
		bind 127.0.0.1

		token {
			client_ca {
			}
			allowUpstreamAuth false
	    }
	    respond 200
	}
	`

	tester := caddytest.NewTester(t)
	tester.InitServer(config, "caddyfile")

	// Test that requests without client certificates are rejected
	tester.AssertGetResponse("http://127.0.0.1:12344", 401, "")
}

func TestSpiffeDirectiveParsing(t *testing.T) {
	tests := []struct {
		name                  string
		config                string
		expectError           bool
		expectedTrustDomains  int
		expectedAllowedIDs    int
		expectedDefaultOrg    string
		expectedDebug         bool
		checkTrustDomain      func(t *testing.T, m *token.Middleware)
	}{
		{
			name: "spiffe with single trust domain",
			config: `token {
				spiffe {
					trust_domain example.org {
						jwks_url https://spire.example.org/keys
						audience myapi
						org production
					}
				}
			}`,
			expectedTrustDomains: 1,
			expectedAllowedIDs:   0,
			expectedDefaultOrg:   "anonymous",
			checkTrustDomain: func(t *testing.T, m *token.Middleware) {
				td := m.Spiffe.TrustDomains[0]
				assert.Equal(t, "example.org", td.Domain)
				assert.Equal(t, "https://spire.example.org/keys", td.JWKSURL)
				assert.Equal(t, "myapi", td.Audience)
				assert.Equal(t, "production", td.Org)
			},
		},
		{
			name: "spiffe with multiple trust domains",
			config: `token {
				spiffe {
					trust_domain prod.example.org {
						jwks_url https://spire-prod.example.org/keys
						audience prod-api
						org production
					}
					trust_domain staging.example.org {
						jwks_url https://spire-staging.example.org/keys
						audience staging-api
						org staging
					}
					default_org fallback
				}
			}`,
			expectedTrustDomains: 2,
			expectedDefaultOrg:   "fallback",
			checkTrustDomain: func(t *testing.T, m *token.Middleware) {
				assert.Equal(t, "prod.example.org", m.Spiffe.TrustDomains[0].Domain)
				assert.Equal(t, "production", m.Spiffe.TrustDomains[0].Org)
				assert.Equal(t, "staging.example.org", m.Spiffe.TrustDomains[1].Domain)
				assert.Equal(t, "staging", m.Spiffe.TrustDomains[1].Org)
			},
		},
		{
			name: "spiffe with org_from_path",
			config: `token {
				spiffe {
					trust_domain example.org {
						jwks_url https://spire.example.org/keys
						audience myapi
						org_from_path true
						org_path_index 1
					}
				}
			}`,
			expectedTrustDomains: 1,
			checkTrustDomain: func(t *testing.T, m *token.Middleware) {
				td := m.Spiffe.TrustDomains[0]
				assert.True(t, td.OrgFromPath)
				assert.Equal(t, 1, td.OrgPathIndex)
			},
		},
		{
			name: "spiffe with org_claim",
			config: `token {
				spiffe {
					trust_domain example.org {
						jwks_url https://spire.example.org/keys
						audience myapi
						org_claim tenant_id
					}
				}
			}`,
			expectedTrustDomains: 1,
			checkTrustDomain: func(t *testing.T, m *token.Middleware) {
				td := m.Spiffe.TrustDomains[0]
				assert.Equal(t, "tenant_id", td.OrgClaim)
			},
		},
		{
			name: "spiffe with allowed_ids",
			config: `token {
				spiffe {
					trust_domain example.org {
						jwks_url https://spire.example.org/keys
						audience myapi
					}
					allowed_ids spiffe://example.org/tenant/*
					allowed_ids spiffe://example.org/service/**
				}
			}`,
			expectedTrustDomains: 1,
			expectedAllowedIDs:   2,
			checkTrustDomain: func(t *testing.T, m *token.Middleware) {
				assert.Contains(t, m.Spiffe.AllowedIDs, "spiffe://example.org/tenant/*")
				assert.Contains(t, m.Spiffe.AllowedIDs, "spiffe://example.org/service/**")
			},
		},
		{
			name: "spiffe with debug",
			config: `token {
				spiffe {
					trust_domain example.org {
						jwks_url https://spire.example.org/keys
					}
					debug true
				}
			}`,
			expectedTrustDomains: 1,
			expectedDebug:        true,
		},
		{
			name: "spiffe with workload_socket",
			config: `token {
				spiffe {
					workload_socket unix:///run/spire/sockets/agent.sock
					trust_domain example.org {
						audience myapi
						org production
					}
				}
			}`,
			expectedTrustDomains: 1,
			checkTrustDomain: func(t *testing.T, m *token.Middleware) {
				assert.Equal(t, "unix:///run/spire/sockets/agent.sock", m.Spiffe.WorkloadSocket)
				assert.Equal(t, "", m.Spiffe.TrustDomains[0].JWKSURL) // No JWKS URL needed
				assert.Equal(t, "production", m.Spiffe.TrustDomains[0].Org)
			},
		},
		{
			name: "spiffe with workload_socket and multiple trust domains",
			config: `token {
				spiffe {
					workload_socket unix:///run/spire/sockets/agent.sock
					trust_domain prod.example.org {
						audience prod-api
						org production
					}
					trust_domain staging.example.org {
						audience staging-api
						org_from_path true
						org_path_index 1
					}
					default_org fallback
				}
			}`,
			expectedTrustDomains: 2,
			expectedDefaultOrg:   "fallback",
			checkTrustDomain: func(t *testing.T, m *token.Middleware) {
				assert.Equal(t, "unix:///run/spire/sockets/agent.sock", m.Spiffe.WorkloadSocket)
				assert.Equal(t, "production", m.Spiffe.TrustDomains[0].Org)
				assert.True(t, m.Spiffe.TrustDomains[1].OrgFromPath)
			},
		},
		{
			name: "spiffe missing jwks_url",
			config: `token {
				spiffe {
					trust_domain example.org {
						audience myapi
					}
				}
			}`,
			expectError: true,
		},
		{
			name: "spiffe invalid org_path_index",
			config: `token {
				spiffe {
					trust_domain example.org {
						jwks_url https://spire.example.org/keys
						org_path_index notanumber
					}
				}
			}`,
			expectError: true,
		},
		{
			name: "spiffe invalid debug value",
			config: `token {
				spiffe {
					trust_domain example.org {
						jwks_url https://spire.example.org/keys
					}
					debug invalid
				}
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.config)
			m := &token.Middleware{}

			err := m.UnmarshalCaddyfile(d)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, m.Spiffe, "Spiffe config should not be nil")

			if tt.expectedTrustDomains > 0 {
				assert.Len(t, m.Spiffe.TrustDomains, tt.expectedTrustDomains)
			}
			if tt.expectedAllowedIDs > 0 {
				assert.Len(t, m.Spiffe.AllowedIDs, tt.expectedAllowedIDs)
			}
			if tt.expectedDefaultOrg != "" {
				assert.Equal(t, tt.expectedDefaultOrg, m.Spiffe.DefaultOrg)
			}
			if tt.expectedDebug {
				assert.True(t, m.Spiffe.Debug)
			}
			if tt.checkTrustDomain != nil {
				tt.checkTrustDomain(t, m)
			}
		})
	}
}

func TestClientCADirectiveParsing(t *testing.T) {
	tests := []struct {
		name           string
		config         string
		expectedCA     bool
		expectedDebug  bool
		expectedOrg    string
		expectError    bool
	}{
		{
			name: "client_ca with all options",
			config: `token {
				client_ca {
					debug true
					default_org "custom-org"
				}
			}`,
			expectedCA:    true,
			expectedDebug: true,
			expectedOrg:   "custom-org",
			expectError:   false,
		},
		{
			name: "client_ca with debug false",
			config: `token {
				client_ca {
					debug false
					default_org "test-org"
				}
			}`,
			expectedCA:    true,
			expectedDebug: false,
			expectedOrg:   "test-org",
			expectError:   false,
		},
		{
			name: "client_ca with defaults",
			config: `token {
				client_ca {
				}
			}`,
			expectedCA:    true,
			expectedDebug: false,
			expectedOrg:   "anonymous",
			expectError:   false,
		},
		{
			name: "client_ca with only debug",
			config: `token {
				client_ca {
					debug true
				}
			}`,
			expectedCA:    true,
			expectedDebug: true,
			expectedOrg:   "anonymous",
			expectError:   false,
		},
		{
			name: "invalid debug value",
			config: `token {
				client_ca {
					debug invalid
				}
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.config)
			m := &token.Middleware{}
			
			err := m.UnmarshalCaddyfile(d)
			
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedCA, m.ClientCA, "ClientCA field")
				assert.Equal(t, tt.expectedDebug, m.Debug, "Debug field")
				assert.Equal(t, tt.expectedOrg, m.DefaultOrg, "DefaultOrg field")
			}
		})
	}
}

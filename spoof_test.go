package token

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/loafoe/caddy-token/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestSpoofedScopeOrgIDStripped ensures a client-supplied X-Scope-OrgID is not
// passed through to upstream when AllowUpstreamAuth is false, even on success
// paths that do not overwrite the header (e.g. InjectOrgHeader=false).
func TestSpoofedScopeOrgIDStripped(t *testing.T) {
	oneHourFromNow := time.Now().Add(time.Hour)
	testToken, _, err := keys.GenerateAPIKey("1", "test-key", "real-org", "u", "e", "n", []string{"read"}, oneHourFromNow)
	require.NoError(t, err)

	tokens := make(map[string]keys.Key)
	prefixRemoved := testToken[len(keys.Prefix):]
	decodedString, err := base64.StdEncoding.DecodeString(prefixRemoved)
	require.NoError(t, err)
	var decoded keys.Key
	require.NoError(t, json.Unmarshal(decodedString, &decoded))
	tokens[testToken] = decoded

	// InjectOrgHeader=false: the success path returns without setting the header,
	// so a spoofed value must have been stripped beforehand.
	m := &Middleware{
		logger:          zaptest.NewLogger(t),
		tokens:          tokens,
		InjectOrgHeader: false,
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Api-Key", testToken)
	req.Header.Set("X-Scope-OrgID", "victim-tenant")
	req.Header.Set("X-Grafana-Org-Id", "victim-grafana")

	require.NoError(t, m.CheckTokenAndInjectHeaders(req))

	assert.NotEqual(t, "victim-tenant", req.Header.Get("X-Scope-OrgID"),
		"spoofed X-Scope-OrgID must not survive")
	assert.Empty(t, req.Header.Get("X-Grafana-Org-Id"),
		"client X-Grafana-Org-Id must be stripped")
}

// TestUpstreamAuthAllowedPreservesHeader ensures that when AllowUpstreamAuth is
// explicitly enabled, the upstream-supplied header is honored (backward compat).
func TestUpstreamAuthAllowedPreservesHeader(t *testing.T) {
	m := &Middleware{
		logger:            zaptest.NewLogger(t),
		AllowUpstreamAuth: true,
	}
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Scope-OrgID", "upstream-org")

	require.NoError(t, m.CheckTokenAndInjectHeaders(req))
	assert.Equal(t, "upstream-org", req.Header.Get("X-Scope-OrgID"))
}

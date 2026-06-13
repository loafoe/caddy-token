package keys_test

import (
	"testing"
	"time"

	"github.com/loafoe/caddy-token/keys"
	"github.com/stretchr/testify/assert"
)

// TestVerifyAPIKeyRejectsExpired ensures that a token whose Expires timestamp
// is in the past is rejected by VerifyAPIKey for both v2 and v3 formats.
func TestVerifyAPIKeyRejectsExpired(t *testing.T) {
	password := keys.GenerateRandomString(32)
	past := time.Now().Add(-1 * time.Hour)

	for _, version := range []string{"2", "3"} {
		token, _, err := keys.GenerateAPIKey(version, password, "org", "env", "region", "project", []string{"scope"}, past)
		if !assert.NoError(t, err) {
			continue
		}
		ok, _, err := keys.VerifyAPIKey(token, password)
		assert.False(t, ok, "expired v%s token must not verify", version)
		assert.Error(t, err, "expired v%s token must return an error", version)
	}
}

// TestVerifyAPIKeyAcceptsUnexpired ensures a token with a future expiry verifies.
func TestVerifyAPIKeyAcceptsUnexpired(t *testing.T) {
	password := keys.GenerateRandomString(32)
	future := time.Now().Add(1 * time.Hour)

	for _, version := range []string{"2", "3"} {
		token, _, err := keys.GenerateAPIKey(version, password, "org", "env", "region", "project", []string{"scope"}, future)
		if !assert.NoError(t, err) {
			continue
		}
		ok, _, err := keys.VerifyAPIKey(token, password)
		assert.True(t, ok, "unexpired v%s token must verify", version)
		assert.NoError(t, err, "unexpired v%s token must not error", version)
	}
}

// TestVerifyAPIKeyNeverExpires ensures a token with Expires==0 (no expiry set)
// continues to verify, preserving backward compatibility with non-expiring keys.
func TestVerifyAPIKeyNeverExpires(t *testing.T) {
	password := keys.GenerateRandomString(32)

	for _, version := range []string{"2", "3"} {
		token, _, err := keys.GenerateDeterministicAPIKey(version, password,
			keys.WithToken("abcdefghijklmnopqr123456"),
			keys.WithOrganization("org"),
			keys.WithRegion("region"),
			keys.WithExpires(0))
		if !assert.NoError(t, err) {
			continue
		}
		ok, _, err := keys.VerifyAPIKey(token, password)
		assert.True(t, ok, "v%s token with no expiry must verify", version)
		assert.NoError(t, err)
	}
}

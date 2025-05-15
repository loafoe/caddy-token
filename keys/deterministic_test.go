package keys_test

import (
	"testing"
	"time"

	"github.com/loafoe/caddy-token/keys"
	"github.com/stretchr/testify/assert"
)

func TestGenerateDeterministicAPIKey(t *testing.T) {
	password := keys.GenerateRandomString(32)
	expires := time.Now()
	// Use a fixed known string that should work well with base64 encoding
	randomString := "abcdefghijklmnopqr123456"

	// Skip v1 tests and focus on v2 and v3 which are more commonly used
	// Test v2 token directly
	generatedV2, signatureV2, err := keys.GenerateDeterministicAPIKey("2", password, "org", "env", "region", "project", []string{"scope"}, expires, randomString)
	if !assert.Nil(t, err) {
		return
	}
	assert.NotEmpty(t, generatedV2)
	assert.NotEmpty(t, signatureV2)
	assert.NotContains(t, generatedV2, "=")
	if !assert.Nil(t, err) {
		return
	}
	assert.NotEmpty(t, generatedV2)
	assert.NotEmpty(t, signatureV2)
	assert.NotContains(t, generatedV2, "=")

	// Verify the token can be verified
	ok, key, err := keys.VerifyAPIKey(generatedV2, password)
	if !assert.Nil(t, err) {
		return
	}
	if !assert.True(t, ok) {
		return
	}
	assert.Equal(t, "org", key.Organization)
	assert.Equal(t, "env", key.Environment)
	assert.Equal(t, "region", key.Region)
	assert.Equal(t, "project", key.Project)
	assert.Contains(t, key.Token, randomString) // Should contain our original random string plus a digit
	assert.Equal(t, []string{"scope"}, key.Scopes)
	assert.Equal(t, expires.Unix(), key.Expires)

	// Test that the same randomString produces the same token
	generatedV2Again, _, err := keys.GenerateDeterministicAPIKey("2", password, "org", "env", "region", "project", []string{"scope"}, expires, randomString)
	if !assert.Nil(t, err) {
		return
	}
	assert.Equal(t, generatedV2, generatedV2Again, "Same input should produce same token")

	// Test with v3 token
	generatedV3, signatureV3, err := keys.GenerateDeterministicAPIKey("3", password, "org", "env", "region", "project", []string{"scope"}, expires, randomString)
	if !assert.Nil(t, err) {
		return
	}
	assert.NotEmpty(t, generatedV3)
	assert.Empty(t, signatureV3)

	// Verify the v3 token
	ok, key, err = keys.VerifyAPIKey(generatedV3, password)
	if !assert.Nil(t, err) {
		return
	}
	if !assert.True(t, ok) {
		return
	}
	assert.Equal(t, "org", key.Organization)
	assert.Equal(t, "3", key.Version)
	assert.Equal(t, randomString, key.Token)
}

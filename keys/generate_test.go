package keys_test

import (
	"github.com/loafoe/caddy-token/keys"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestGenerateAPIKeyV2(t *testing.T) {
	password := keys.GenerateRandomString(32)
	expires := time.Now()
	generated, signature, err := keys.GenerateAPIKey("2", password, "org", "env", "region", "project", []string{"scope"}, expires)
	if !assert.Nil(t, err) {
		return
	}
	ok, key, err := keys.VerifyAPIKey(generated, password)
	if !assert.Nil(t, err) {
		return
	}
	if !assert.True(t, ok) {
		return
	}
	assert.NotEmpty(t, signature)
	assert.Equal(t, "org", key.Organization)
	assert.Equal(t, "env", key.Environment)
	assert.Equal(t, "region", key.Region)
	assert.Equal(t, "project", key.Project)
	assert.Equal(t, []string{"scope"}, key.Scopes)
	assert.Equal(t, expires.Unix(), key.Expires)
}

func TestGenerateAPIKeyV3(t *testing.T) {
	password := keys.GenerateRandomString(32)
	expires := time.Now()
	generated, signature, err := keys.GenerateAPIKey("3", password, "org", "env", "region", "project", []string{"scope"}, expires)
	if !assert.Nil(t, err) {
		return
	}
	ok, key, err := keys.VerifyAPIKey(generated, password)
	if !assert.Nil(t, err) {
		return
	}
	if !assert.True(t, ok) {
		return
	}
	assert.Empty(t, signature)
	assert.Equal(t, "org", key.Organization)
	assert.Equal(t, "3", key.Version)
}

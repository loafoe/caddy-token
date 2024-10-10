package keys_test

import (
	"github.com/loafoe/caddy-token/keys"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateAPIKey(t *testing.T) {
	password := keys.GenerateRandomString(32)
	generated, signature, err := keys.GenerateAPIKey("2", password, "org", "env", "region", "project", []string{"scope"})
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
}

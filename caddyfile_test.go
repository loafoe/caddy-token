package token_test

import (
	"bytes"
	"fmt"
	"github.com/loafoe/caddy-token/keys"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestCaddyfileTokenV2(t *testing.T) {
	v2Token, signature, err := keys.GenerateAPIKey("2", "test", "test", "test", "test", "test", []string{"test"})
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
	testToken, _, err := keys.GenerateAPIKey("1", "test", "test", "test", "test", "test", []string{"test"})
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

	v2Token, signature, err := keys.GenerateAPIKey("2", password, "test", "test", "test", "test", []string{"test"})
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

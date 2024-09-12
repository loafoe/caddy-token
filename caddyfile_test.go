package token

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestCaddyfileToken(t *testing.T) {
	testToken := "lst_eyJ2IjoiIiwidCI6IndWUk5TNkVRbjhVNGhTcDZETzQ4TG1OY0YiLCJvIjoidGVzdCIsImUiOiJ0ZXN0IiwiciI6InRlc3QiLCJwIjoidGVzdCJ9"

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
		admin localhost:2999
		http_port 12344
        order token first
	}

	:12344 {
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

	tester.AssertGetResponse("http://localhost:12344", 401, "")
	tester.AssertPostResponseBody("http://localhost:12344", []string{"X-Api-Key: " + testToken}, bytes.NewBuffer([]byte("foo")), 200, "")
}

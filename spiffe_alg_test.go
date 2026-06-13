package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestSpiffeValidator_AlgConfusionRejected verifies that a token forged with
// the HMAC algorithm, using the trust domain's RSA public key bytes as the HMAC
// secret, is rejected. This is the classic RS256->HS256 key-confusion attack;
// it must fail because the validator pins the expected signature algorithm.
func TestSpiffeValidator_AlgConfusionRejected(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwk := jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     "test-key-1",
		Algorithm: "RS256",
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	config := &SpiffeConfig{
		TrustDomains: []SpiffeTrustDomain{
			{Domain: "example.org", JWKSURL: server.URL, Audience: "test-audience", Org: "static-org"},
		},
		DefaultOrg: "default",
	}
	validator := NewSpiffeValidator(config, zaptest.NewLogger(t))

	// The attacker's "secret" is the server's public key, marshaled the way a
	// naive HS256 verifier would feed it in.
	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"sub": "spiffe://example.org/service/api",
		"aud": []string{"test-audience"},
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	forged.Header["kid"] = "test-key-1"
	forgedString, err := forged.SignedString(pubDER)
	require.NoError(t, err)

	_, err = validator.ValidateJWT(context.Background(), forgedString)
	assert.Error(t, err, "HMAC-forged token using the RSA public key must be rejected")
}

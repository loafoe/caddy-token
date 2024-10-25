package keys

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const Prefix = "lst_"

// GenerateSignature signs the API key with the given password using HMAC-SHA256
func GenerateSignature(payload, password string) string {
	h := hmac.New(sha256.New, []byte(password))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifySignature verifies the provided API key with the stored signature
func VerifySignature(payload, providedSignature, password string) bool {
	expectedSignature := GenerateSignature(payload, password)
	return hmac.Equal([]byte(expectedSignature), []byte(providedSignature))
}

func VerifyAPIKey(apiKey, password string) (bool, *Key, error) {
	var key Key
	prefixRemoved := strings.TrimPrefix(apiKey, Prefix)
	split := strings.Split(prefixRemoved, ".")
	if len(split) != 2 {
		return false, nil, fmt.Errorf("invalid token format")
	}
	payload := split[0]
	signature := split[1]
	if !VerifySignature(payload, signature, password) {
		return false, nil, fmt.Errorf("signature mismatch")
	}
	decodedString, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return false, nil, fmt.Errorf("decode token: %w", err)
	}

	err = json.Unmarshal([]byte(decodedString), &key)
	if err != nil {
		return false, nil, fmt.Errorf("unmarshal token: %w '%s'", err, decodedString)
	}
	return true, &key, nil
}

func GenerateAPIKey(version, key, org, env, region, project string, scopes []string, expiresAt time.Time) (string, string, error) {
	randomCount := 12
	bail := 4
	var newToken Key
	newToken.Organization = org
	newToken.Environment = env
	newToken.Region = region
	newToken.Project = project
	newToken.Scopes = scopes
	newToken.Expires = expiresAt.Unix()
	for {
		if bail <= 0 {
			return "", "", fmt.Errorf("failed to generate a valid token")
		}
		newToken.Token = GenerateRandomString(randomCount)
		switch version {
		case "1":
			newToken.Version = "1"
			marshalled, _ := json.Marshal(newToken)
			key := base64.StdEncoding.EncodeToString(marshalled)
			if strings.HasSuffix(key, "=") {
				randomCount = randomCount + 1
				bail = bail - 1
				continue
			}
			// We have a good-looking newToken, return it
			return fmt.Sprintf("%s%s", Prefix, key), "", nil
		case "2":
			newToken.Version = "2"
			if key == "" {
				return "", "", fmt.Errorf("please provide a key for token version 2")
			}
			marshalled, _ := json.Marshal(newToken)
			payload := base64.StdEncoding.EncodeToString(marshalled)
			if strings.HasSuffix(payload, "=") {
				randomCount = randomCount + 1
				bail = bail - 1
				continue
			}
			signature := GenerateSignature(payload, key)
			return fmt.Sprintf("%s%s.%s", Prefix, payload, signature), signature, nil
		default:
			return "", "", fmt.Errorf("invalid token version: %s", version)
		}
	}
}

// GenerateRandomString generates a random alphanumeric string of length n.
func GenerateRandomString(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[num.Int64()]
	}
	return string(b)
}

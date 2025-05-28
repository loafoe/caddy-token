package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

	// Check for empty inputs
	if apiKey == "" {
		return false, nil, fmt.Errorf("empty API key")
	}
	if password == "" {
		return false, nil, fmt.Errorf("empty password")
	}

	prefixRemoved := strings.TrimPrefix(apiKey, Prefix)
	var version string
	split := strings.Split(prefixRemoved, ".")
	if len(split) != 2 {
		version = "3" // Assume version 3
	} else {
		version = "2"
	}
	switch version {
	case "2":
		if len(split) < 2 {
			return false, nil, fmt.Errorf("invalid format for version 2 token: missing signature part")
		}

		payload := split[0]
		signature := split[1]

		decodedString, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return false, nil, fmt.Errorf("decode token: %w", err)
		}
		err = json.Unmarshal([]byte(decodedString), &key)
		if err != nil {
			return false, nil, fmt.Errorf("unmarshal token: %w '%s'", err, decodedString)
		}
		if !VerifySignature(payload, signature, password) {
			return false, &key, fmt.Errorf("signature mismatch")
		}
		return true, &key, nil
	case "3":
		if len(split) == 0 || split[0] == "" {
			return false, nil, fmt.Errorf("invalid format for version 3 token: missing payload")
		}

		decodedString, err := hex.DecodeString(split[0])
		if err != nil {
			return false, nil, fmt.Errorf("decode token: %w", err)
		}
		decrypted, err := decrypt(decodedString, []byte(password))
		if err != nil {
			return false, nil, fmt.Errorf("decrypt token: %w", err)
		}

		// Check if decrypted data is valid JSON
		if len(decrypted) == 0 {
			return false, nil, fmt.Errorf("empty decrypted token data")
		}

		err = json.Unmarshal([]byte(decrypted), &key)
		if err != nil {
			return false, nil, fmt.Errorf("unmarshal token: %w '%s'", err, decrypted)
		}
		return true, &key, nil
	default:
		return false, nil, fmt.Errorf("invalid token version: %s", version)
	}

}

// GenerateDeterministicAPIKey generates an API key with a given random string value.
// Instead of regenerating the random string when encountering base64 padding,
// it appends digits to the random string until the padding is gone.
func GenerateDeterministicAPIKey(version string, signingKey string, opts ...OptionFunc) (string, string, error) {
	// Create a key request object
	kr := &keyRequest{
		k:          Key{Version: version},
		signingKey: signingKey,
	}

	// Apply all options to the key request
	for _, opt := range opts {
		if err := opt(kr); err != nil {
			return "", "", err
		}
	}

	// We need to retrieve the token from the Key structure
	token := kr.k.Token

	// Check key length for version 3
	if version == "3" && len(kr.signingKey) < 16 {
		return "", "", fmt.Errorf("key must be at least 16 characters long for token version 3")
	}

	switch version {
	case "1":
		kr.k.Version = "1"

		// Keep adding digits (0-9) to grow the token until the padding is gone
		var finalKey string
		var found bool

		// Start with the original token
		growingToken := token
		// Try up to 10 additions (since we have 10 digits)
		for attempt := 0; attempt < 10 && !found; attempt++ {
			// Add each digit 0-9 in sequence
			for _, digit := range []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"} {
				// Add the current digit to our growing token
				growingToken += digit

				// Try with the new token
				modifiedToken := kr.k
				modifiedToken.Token = growingToken
				marshalledData, _ := json.Marshal(modifiedToken)
				finalKey = base64.StdEncoding.EncodeToString(marshalledData)

				if !strings.HasSuffix(finalKey, "=") {
					found = true
					break
				}
			}
		}

		if !found {
			// If no digit combination works, error out instead of trimming padding
			return "", "", fmt.Errorf("could not generate a token without padding for version 1")
		}

		// Return the token
		return fmt.Sprintf("%s%s", Prefix, finalKey), "", nil

	case "2":
		kr.k.Version = "2"
		if kr.signingKey == "" {
			return "", "", fmt.Errorf("please provide a key for token version 2")
		}

		// Keep adding digits (0-9) to grow the token until the padding is gone
		var payload string
		var found bool

		// Start with the original token
		growingToken := token
		// Try up to 10 additions (since we have 10 digits)
		for attempt := 0; attempt < 10 && !found; attempt++ {
			// Add each digit 0-9 in sequence
			for _, digit := range []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"} {
				// Add the current digit to our growing token
				growingToken += digit

				// Try with the new token
				modifiedToken := kr.k
				modifiedToken.Token = growingToken
				marshalledData, _ := json.Marshal(modifiedToken)
				payload = base64.StdEncoding.EncodeToString(marshalledData)

				if !strings.HasSuffix(payload, "=") {
					found = true
					break
				}
			}
		}

		if !found {
			// If no digit combination works, error out instead of trimming padding
			return "", "", fmt.Errorf("could not generate a token without padding for version 2")
		}

		signature := GenerateSignature(payload, kr.signingKey)
		return fmt.Sprintf("%s%s.%s", Prefix, payload, signature), signature, nil

	case "3":
		kr.k.Version = "3"
		kr.k.Token = token

		if kr.signingKey == "" {
			return "", "", fmt.Errorf("please provide a key for token version 3")
		}

		marshalled, _ := json.Marshal(kr.k)
		ciphertext, err := encrypt(marshalled, []byte(kr.signingKey))
		if err != nil {
			return "", "", fmt.Errorf("encrypt error: %w", err)
		}
		encoded := hex.EncodeToString(ciphertext)
		return fmt.Sprintf("%s%s", Prefix, encoded), "", nil

	default:
		return "", "", fmt.Errorf("invalid token version: %s", version)
	}
}

func GenerateAPIKey(version, key, org, env, region, project string, scopes []string, expiresAt time.Time) (string, string, error) {
	// Start with a sufficiently long random string to avoid padding issues
	randomCount := 16

	if version == "3" && len(key) < 16 {
		return "", "", fmt.Errorf("key must be at least 16 characters long for token version 3")
	}

	// Generate a random string and use the deterministic function
	randomString := GenerateRandomString(randomCount)
	return GenerateDeterministicAPIKey(version, "",
		WithSigningKey(key),
		WithToken(randomString),
		WithOrganization(org),
		WithEnvironment(env),
		WithRegion(region),
		WithProject(project),
		WithScopes(scopes),
		WithExpires(expiresAt.Unix()))
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

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM - Galois/Counter Mode - cipher
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a nonce. Nonce must be unique for each message
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the plaintext and append the message authentication code (MAC)
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	// Check if key is valid
	if len(key) == 0 {
		return nil, fmt.Errorf("empty encryption key")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM - Galois/Counter Mode - cipher
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Get the nonce size
	nonceSize := aesGCM.NonceSize()

	// Check if ciphertext is long enough to contain a nonce
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: expected at least %d bytes for nonce, got %d", nonceSize, len(ciphertext))
	}

	// Extract the nonce
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Check if remaining ciphertext is valid (must be at least 16 bytes for GCM tag)
	if len(ciphertext) < 16 {
		return nil, fmt.Errorf("ciphertext too short after nonce extraction: expected at least 16 bytes for GCM tag, got %d", len(ciphertext))
	}

	// Decrypt and verify the message
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

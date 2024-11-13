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
	case "3":
		decodedString, err := hex.DecodeString(split[0])
		if err != nil {
			return false, nil, fmt.Errorf("decode token: %w", err)
		}
		decrypted, err := decrypt(decodedString, []byte(password))
		if err != nil {
			return false, nil, fmt.Errorf("decrypt token: %w", err)
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
	if version == "3" && len(key) < 16 {
		return "", "", fmt.Errorf("key must be at least 16 characters long for token version 3")
	}
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
		case "3":
			newToken.Version = "3"
			if key == "" {
				return "", "", fmt.Errorf("please provide a key for token version 3")
			}
			marshalled, _ := json.Marshal(newToken)
			ciphertext, err := encrypt(marshalled, []byte(key))
			if err != nil {
				return "", "", fmt.Errorf("encrypt error: %w", err)
			}
			encoded := hex.EncodeToString(ciphertext)
			return fmt.Sprintf("%s%s", Prefix, encoded), "", nil
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

	// Extract the nonce

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt and verify the message
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

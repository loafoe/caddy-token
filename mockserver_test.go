package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

// TokenResponse represents the structure of the JSON body
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
}

func init() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	publicKey = &privateKey.PublicKey
}

func getToken() (string, error) {
	// Create a new GET request
	resp, err := http.Get("http://127.0.0.1:12000/token")
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error: received non-200 status code: %d\n", resp.StatusCode)
		return "", fmt.Errorf("non-200 status code: %d", resp.StatusCode)
	}
	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return "", err
	}

	// Decode the JSON response
	var tokenResponse TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		fmt.Printf("Error decoding JSON response: %v\n", err)
		return "", err
	}
	return tokenResponse.AccessToken, nil
}

func runMockServer(started chan bool) {

	http.HandleFunc("/.well-known/openid-configuration", discoveryHandler)
	http.HandleFunc("/token", tokenHandler)
	http.HandleFunc("/userinfo", userinfoHandler)
	http.HandleFunc("/jwks", jwksHandler)
	go func() {
		time.Sleep(1 * time.Second)
		started <- true
	}()

	_ = http.ListenAndServe("127.0.0.1:12000", nil)
}

func discoveryHandler(w http.ResponseWriter, r *http.Request) {
	discovery := map[string]interface{}{
		"issuer":                 "http://127.0.0.1:12000",
		"authorization_endpoint": "http://127.0.0.1:12000/authorize",
		"token_endpoint":         "http://127.0.0.1:12000/token",
		"userinfo_endpoint":      "http://127.0.0.1:12000/userinfo",
		"jwks_uri":               "http://127.0.0.1:12000/jwks",
	}
	_ = json.NewEncoder(w).Encode(discovery)
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":    "1234567890",
		"name":   "John Doe",
		"email":  "john.doe@example.com",
		"exp":    time.Now().Add(time.Hour * 1).Unix(),
		"groups": []string{"admin", "test"},
	})

	// Sign the token with the private key
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Return the token in the response
	response := map[string]interface{}{
		"access_token": tokenString,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     tokenString,
	}
	_ = json.NewEncoder(w).Encode(response)
}

func userinfoHandler(w http.ResponseWriter, r *http.Request) {
	userinfo := map[string]interface{}{
		"sub":    "1234567890",
		"name":   "John Doe",
		"email":  "john.doe@example.com",
		"groups": []string{"admin", "test"},
	}
	_ = json.NewEncoder(w).Encode(userinfo)
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	jwks := map[string]interface{}{
		"keys": []interface{}{
			map[string]interface{}{
				"kty": "RSA",
				"kid": "1",
				"use": "sig",
				"alg": "RS256",
				"n":   encodeBase64URL(publicKey.N.Bytes()),
				"e":   encodeBase64URL(big.NewInt(int64(publicKey.E)).Bytes()),
			},
		},
	}
	_ = json.NewEncoder(w).Encode(jwks)
}

func encodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

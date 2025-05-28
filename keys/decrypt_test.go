package keys

import (
	"testing"
)

func TestDecryptErrors(t *testing.T) {
	tests := []struct {
		name       string
		ciphertext []byte
		key        []byte
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "empty key",
			ciphertext: []byte("some data"),
			key:        []byte{},
			wantErr:    true,
			errMsg:     "empty encryption key",
		},
		{
			name:       "invalid key",
			ciphertext: []byte("some data"),
			key:        []byte("123"), // Too short for AES
			wantErr:    true,
			errMsg:     "crypto/aes",
		},
		{
			name:       "empty ciphertext",
			ciphertext: []byte{},
			key:        []byte("0123456789abcdef"), // 16 bytes key
			wantErr:    true,
			errMsg:     "ciphertext too short",
		},
		{
			name:       "ciphertext too short",
			ciphertext: []byte{1, 2, 3, 4}, // Too short to contain nonce + data
			key:        []byte("0123456789abcdef"),
			wantErr:    true,
			errMsg:     "ciphertext too short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decrypt(tt.ciphertext, tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" {
				if containsError(err.Error(), tt.errMsg) == false {
					t.Errorf("decrypt() error = %v, expected to contain %v", err, tt.errMsg)
				}
			}
		})
	}
}

// Helper function to check if an error message contains a specific string
func containsError(errStr, expected string) bool {
	return len(errStr) >= len(expected) && errStr[:len(expected)] == expected
}

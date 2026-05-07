package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func GenerateCodeVerifier() (string, error) {
	// PKCE requires a high-entropy one-time secret per authorization attempt.
	random := make([]byte, 64) // 64 bytes -> ~86 base64url characters (valid PKCE range: 43-128)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate code verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

func GenerateCodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func GenerateRandomURLSafe(size int) (string, error) {
	random := make([]byte, size)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate random URL-safe value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

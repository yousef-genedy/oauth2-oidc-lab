package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

var pendingAuthorizations = struct {
	mu      sync.Mutex
	entries map[string]string
}{
	entries: make(map[string]string),
}

func generateState() (string, error) {
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(random), nil
}

func storeStateVerifier(state, verifier string) {
	pendingAuthorizations.mu.Lock()
	pendingAuthorizations.entries[state] = verifier
	pendingAuthorizations.mu.Unlock()
}

func consumeCodeVerifier(state string) (string, bool) {
	pendingAuthorizations.mu.Lock()
	verifier, ok := pendingAuthorizations.entries[state]
	if ok {
		delete(pendingAuthorizations.entries, state)
	}
	pendingAuthorizations.mu.Unlock()
	return verifier, ok
}

func buildAuthorizationURL(state, codeChallenge string) (string, error) {
	u, err := url.Parse(authorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("parse authorization endpoint: %w", err)
	}

	query := u.Query()
	query.Set("response_type", "code")
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", "openid profile email")
	query.Set("state", state)
	query.Set("code_challenge", codeChallenge)
	query.Set("code_challenge_method", "S256")
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func decodeJWT(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode JWT header: %w", err)
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT claims: %w", err)
	}

	var header any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("unmarshal JWT header: %w", err)
	}

	var claims any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal JWT claims: %w", err)
	}

	return map[string]any{
		"header": header,
		"claims": claims,
	}, nil
}

func readBearerToken(authorizationHeader string) (string, error) {
	if authorizationHeader == "" {
		return "", errors.New("missing Authorization header")
	}
	if !strings.HasPrefix(strings.ToLower(authorizationHeader), "bearer ") {
		return "", errors.New("Authorization header must start with Bearer")
	}

	token := strings.TrimSpace(authorizationHeader[len("Bearer "):])
	if token == "" {
		return "", errors.New("missing bearer token")
	}
	return token, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("failed to write JSON response: %v", err)
	}
}

func logStep(title string, payload any) {
	log.Printf("\n========== %s ==========", title)
	if payload == nil {
		return
	}

	formatted, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		log.Printf("%+v", payload)
		return
	}
	log.Printf("%s", formatted)
}

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

func handleHome(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("OAuth 2.0 + OIDC Authorization Code Flow with PKCE (Go)\n\nRoutes:\n- GET /login    Start flow and redirect to Keycloak\n- GET /callback Handle authorization response and token exchange\n- GET /profile  Decode bearer token (header + claims)\n"))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := generateState()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	verifier, err := generateCodeVerifier()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	challenge := generateCodeChallenge(verifier)

	// Store state + verifier in memory so callback can validate CSRF and redeem code safely.
	// The verifier is secret and must not be sent on /login.
	storeStateVerifier(state, verifier)

	authURL, err := buildAuthorizationURL(state, challenge)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	logStep("LOGIN - Authorization URL", map[string]any{
		"state":          state,
		"code_verifier":  verifier,
		"code_challenge": challenge,
		"authorization":  authURL,
	})

	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	logStep("CALLBACK - Query Parameters", query)

	if callbackErr := query.Get("error"); callbackErr != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"message":           "authorization server returned an error",
			"error":             callbackErr,
			"error_description": query.Get("error_description"),
		})
		return
	}

	code := query.Get("code")
	state := query.Get("state")
	if code == "" || state == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"message":  "missing required callback parameters",
			"expected": []string{"code", "state"},
		})
		return
	}

	verifier, ok := consumeCodeVerifier(state)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"message": "state validation failed",
			"details": "unknown or already consumed state",
		})
		return
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	// PKCE verification happens here: Keycloak hashes this verifier and compares it
	// with the code_challenge sent earlier during /login.
	form.Set("code_verifier", verifier)

	logStep("TOKEN REQUEST - Payload", map[string]any{
		"endpoint": tokenEndpoint,
		"body": map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"redirect_uri":  redirectURI,
			"client_id":     clientID,
			"code_verifier": verifier,
		},
		"encoded": form.Encode(),
	})

	tokenReq, err := http.NewRequest(http.MethodPost, tokenEndpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("create token request: %v", err)})
		return
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("token request failed: %v", err)})
		return
	}
	defer tokenResp.Body.Close()

	rawTokenBody, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("read token response: %v", err)})
		return
	}
	logStep("TOKEN RESPONSE - Raw JSON", json.RawMessage(rawTokenBody))

	if tokenResp.StatusCode < 200 || tokenResp.StatusCode >= 300 {
		writeJSON(w, tokenResp.StatusCode, map[string]any{
			"message": "token endpoint returned an error",
			"status":  tokenResp.StatusCode,
			"body":    json.RawMessage(rawTokenBody),
		})
		return
	}

	var tokens tokenResponse
	if err := json.Unmarshal(rawTokenBody, &tokens); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("decode token response: %v", err)})
		return
	}

	decodedAccess, err := decodeJWT(tokens.AccessToken)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("decode access token: %v", err)})
		return
	}
	decodedID, err := decodeJWT(tokens.IDToken)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("decode id token: %v", err)})
		return
	}
	logStep("DECODED ACCESS TOKEN", decodedAccess)
	logStep("DECODED ID TOKEN", decodedID)

	userinfoReq, err := http.NewRequest(http.MethodGet, userInfoEndpoint, nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("create userinfo request: %v", err)})
		return
	}
	userinfoReq.Header.Set("Authorization", "Bearer "+tokens.AccessToken)

	userinfoResp, err := http.DefaultClient.Do(userinfoReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("userinfo request failed: %v", err)})
		return
	}
	defer userinfoResp.Body.Close()

	userinfoBody, err := io.ReadAll(userinfoResp.Body)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("read userinfo response: %v", err)})
		return
	}
	logStep("USERINFO RESPONSE", map[string]any{
		"status": userinfoResp.StatusCode,
		"body":   json.RawMessage(userinfoBody),
	})

	response := map[string]any{
		"message": "Authorization Code + PKCE flow completed",
		"callback": map[string]string{
			"code":  code,
			"state": state,
		},
		"token_response_raw": json.RawMessage(rawTokenBody),
		"tokens": map[string]any{
			"access_token":  tokens.AccessToken,
			"id_token":      tokens.IDToken,
			"refresh_token": tokens.RefreshToken,
			"token_type":    tokens.TokenType,
			"expires_in":    tokens.ExpiresIn,
			"scope":         tokens.Scope,
		},
		"decoded_tokens": map[string]any{
			"access_token": decodedAccess,
			"id_token":     decodedID,
		},
		"userinfo_raw": json.RawMessage(userinfoBody),
	}

	writeJSON(w, http.StatusOK, response)
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	token, err := readBearerToken(r.Header.Get("Authorization"))
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": err.Error(),
			"usage": "Send Authorization: Bearer <access_token>",
		})
		return
	}

	decoded, err := decodeJWT(token)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("invalid bearer token: %v", err)})
		return
	}

	logStep("PROFILE - Decoded Bearer Token", decoded)
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Decoded bearer token payload (decode only; signature not validated)",
		"decoded": decoded,
	})
}

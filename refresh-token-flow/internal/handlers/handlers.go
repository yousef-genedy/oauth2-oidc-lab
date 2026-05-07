package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"refresh-token-flow/internal/config"
	"refresh-token-flow/internal/jwtutil"
	"refresh-token-flow/internal/oauth"
	"refresh-token-flow/internal/pkce"
	"refresh-token-flow/internal/session"
	"refresh-token-flow/internal/tokenutil"
	"strings"
	"time"
)

type Handler struct {
	cfg         *config.Config
	store       *session.Store
	oauthClient *oauth.Client
}

func New(cfg *config.Config, store *session.Store, oauthClient *oauth.Client) *Handler {
	return &Handler{
		cfg:         cfg,
		store:       store,
		oauthClient: oauthClient,
	}
}

func (h *Handler) Home(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(
		"OAuth 2.0 + OIDC Refresh Token Flow (Go)\n\n" +
			"Routes:\n" +
			"- GET /login         Start Authorization Code + PKCE\n" +
			"- GET /callback      Exchange code for tokens and inspect JWTs\n" +
			"- GET /profile       Call UserInfo; auto-refresh and retry if token expired\n" +
			"- GET /token-status  Check access token lifetime/expiration\n",
	))
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	state, err := pkce.GenerateRandomURLSafe(24)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	nonce, err := pkce.GenerateRandomURLSafe(24)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	verifier, err := pkce.GenerateCodeVerifier()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	challenge := pkce.GenerateCodeChallenge(verifier)

	h.store.SavePendingAuthorization(state, nonce, verifier)

	authURL, err := h.authorizationURL(state, nonce, challenge)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	logStep("LOGIN - Authorization Request", map[string]any{
		"state":                 state,
		"nonce":                 nonce,
		"code_verifier":         verifier,
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
		"authorization_url":     authURL,
	})

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	logStep("CALLBACK - Query Parameters", map[string]any{
		"raw_query": r.URL.RawQuery,
		"params":    query,
	})

	if callbackError := query.Get("error"); callbackError != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"message":           "authorization server returned an error",
			"error":             callbackError,
			"error_description": query.Get("error_description"),
		})
		return
	}

	code := query.Get("code")
	state := query.Get("state")
	if code == "" || state == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"message":  "missing callback parameters",
			"expected": []string{"code", "state"},
		})
		return
	}

	pending, ok := h.store.ConsumePendingAuthorization(state)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"message": "state validation failed",
			"details": "unknown, expired, or already consumed state",
		})
		return
	}

	logStep("CALLBACK - State Validation", map[string]any{
		"state":   state,
		"status":  "valid",
		"created": pending.CreatedAt.Format(time.RFC3339),
	})

	logStep("TOKEN REQUEST - Authorization Code Exchange", map[string]any{
		"endpoint": h.cfg.TokenEndpoint,
		"body": map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"redirect_uri":  h.cfg.RedirectURI,
			"client_id":     h.cfg.ClientID,
			"code_verifier": pending.CodeVerifier,
		},
	})

	tokenResp, rawTokenResp, err := h.oauthClient.ExchangeAuthorizationCode(r.Context(), code, pending.CodeVerifier)
	if err != nil {
		h.writeTokenExchangeError(w, "authorization_code exchange failed", rawTokenResp, err)
		return
	}

	logStep("TOKEN RESPONSE - Raw JSON", rawJSONOrString(rawTokenResp))
	stored := tokenutil.NewTokenSet(tokenResp, time.Now().UTC())
	h.store.SaveTokenSet(stored)

	decodedAccess, err := jwtutil.DecodeJWT(tokenResp.AccessToken)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": fmt.Sprintf("decode access token: %v", err)})
		return
	}

	decodedID, err := jwtutil.DecodeJWT(tokenResp.IDToken)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": fmt.Sprintf("decode id token: %v", err)})
		return
	}

	nonceInIDToken, hasNonce := jwtutil.StringClaim(decodedID.Claims, "nonce")
	nonceStatus := "nonce claim missing"
	if hasNonce {
		if nonceInIDToken != pending.Nonce {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"message":         "nonce validation failed",
				"expected_nonce":  pending.Nonce,
				"received_nonce":  nonceInIDToken,
				"security_reason": "nonce binds the ID token to the original auth request to prevent replay/injection",
			})
			return
		}
		nonceStatus = "nonce validated"
	}

	logStep("JWT INSPECTION - Access Token", decodedAccess)
	logStep("JWT INSPECTION - ID Token", decodedID)
	logStep("REFRESH TOKEN INFO", map[string]any{
		"present":               tokenResp.RefreshToken != "",
		"refresh_token_preview": previewToken(tokenResp.RefreshToken),
		"note":                  "Refresh tokens are sensitive bearer credentials. Keep them server-side and never expose them to front-end clients.",
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Authorization Code + PKCE completed. Tokens stored in memory for lifecycle demo.",
		"callback": map[string]string{
			"code":  code,
			"state": state,
		},
		"nonce_check":                 nonceStatus,
		"token_response_raw":          rawJSONOrString(rawTokenResp),
		"access_token_expires_at":     stored.AccessTokenExpiresAt.Format(time.RFC3339),
		"access_token_expires_in":     tokenResp.ExpiresIn,
		"decoded_access_token":        decodedAccess,
		"decoded_id_token":            decodedID,
		"refresh_token_present":       tokenResp.RefreshToken != "",
		"refresh_token_preview":       previewToken(tokenResp.RefreshToken),
		"learning_note_access_token":  "Access tokens are intentionally short-lived to reduce the impact window if leaked.",
		"learning_note_refresh_token": "Refresh tokens enable silent session continuity without forcing the user to re-authenticate frequently.",
	})
}

func (h *Handler) Profile(w http.ResponseWriter, r *http.Request) {
	current, ok := h.store.CurrentTokenSet()
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"message": "no active in-memory session",
			"usage":   "Run GET /login first, complete callback, then call GET /profile",
		})
		return
	}

	now := time.Now().UTC()
	logStep("PROFILE - Attempt UserInfo With Current Access Token", map[string]any{
		"access_token_expiration": current.AccessTokenExpiresAt.Format(time.RFC3339),
		"seconds_remaining":       tokenutil.SecondsRemaining(current.AccessTokenExpiresAt, now),
		"expired_by_local_clock":  tokenutil.IsExpired(current.AccessTokenExpiresAt, now),
	})

	status, body, err := h.oauthClient.CallUserInfo(r.Context(), current.AccessToken)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": fmt.Sprintf("userinfo request failed: %v", err)})
		return
	}

	logStep("PROFILE - UserInfo Response (Initial Attempt)", map[string]any{
		"status": status,
		"body":   rawJSONOrString(body),
	})

	if status >= 200 && status < 300 {
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "userinfo call succeeded with current access token",
			"profile": rawJSONOrString(body),
			"token_status": map[string]any{
				"access_token_expires_at": current.AccessTokenExpiresAt.Format(time.RFC3339),
				"seconds_remaining":       tokenutil.SecondsRemaining(current.AccessTokenExpiresAt, now),
				"expired":                 tokenutil.IsExpired(current.AccessTokenExpiresAt, now),
			},
		})
		return
	}

	if status != http.StatusUnauthorized {
		writeJSON(w, status, map[string]any{
			"message": "userinfo failed and was not treated as refreshable",
			"status":  status,
			"body":    rawJSONOrString(body),
		})
		return
	}

	logStep("PROFILE - Access Token Rejected, Starting Refresh Flow", map[string]any{
		"reason": "received HTTP 401 from userinfo endpoint",
	})

	refreshedTokens, rotated, err := h.refreshAccessToken(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"message": "access token expired and refresh failed",
			"error":   err.Error(),
		})
		return
	}

	retryStatus, retryBody, err := h.oauthClient.CallUserInfo(r.Context(), refreshedTokens.AccessToken)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": fmt.Sprintf("userinfo retry failed: %v", err)})
		return
	}

	logStep("PROFILE - UserInfo Response (After Refresh Retry)", map[string]any{
		"status": retryStatus,
		"body":   rawJSONOrString(retryBody),
	})

	if retryStatus < 200 || retryStatus >= 300 {
		writeJSON(w, retryStatus, map[string]any{
			"message": "refresh succeeded but userinfo retry still failed",
			"status":  retryStatus,
			"body":    rawJSONOrString(retryBody),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "userinfo succeeded after refresh (silent session continuity)",
		"profile": rawJSONOrString(retryBody),
		"refresh": map[string]any{
			"triggered":              true,
			"rotation_occurred":      rotated,
			"new_access_expires_at":  refreshedTokens.AccessTokenExpiresAt.Format(time.RFC3339),
			"new_refresh_token_hint": previewToken(refreshedTokens.RefreshToken),
		},
	})
}

func (h *Handler) TokenStatus(w http.ResponseWriter, _ *http.Request) {
	current, ok := h.store.CurrentTokenSet()
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"has_tokens": false,
			"message":    "no tokens in memory yet. Complete /login then /callback first.",
		})
		return
	}

	now := time.Now().UTC()
	secondsRemaining := tokenutil.SecondsRemaining(current.AccessTokenExpiresAt, now)
	expired := tokenutil.IsExpired(current.AccessTokenExpiresAt, now)

	logStep("TOKEN STATUS", map[string]any{
		"expires_at":         current.AccessTokenExpiresAt.Format(time.RFC3339),
		"seconds_remaining":  secondsRemaining,
		"expired":            expired,
		"obtained_at":        current.ObtainedAt.Format(time.RFC3339),
		"refresh_token_hint": previewToken(current.RefreshToken),
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"has_tokens":              true,
		"access_token_expires_at": current.AccessTokenExpiresAt.Format(time.RFC3339),
		"seconds_remaining":       secondsRemaining,
		"expired":                 expired,
		"obtained_at":             current.ObtainedAt.Format(time.RFC3339),
		"refresh_token_preview":   previewToken(current.RefreshToken),
	})
}

func (h *Handler) authorizationURL(state, nonce, codeChallenge string) (string, error) {
	u, err := url.Parse(h.cfg.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("parse authorization endpoint: %w", err)
	}

	query := u.Query()
	query.Set("response_type", "code")
	query.Set("client_id", h.cfg.ClientID)
	query.Set("redirect_uri", h.cfg.RedirectURI)
	query.Set("scope", h.cfg.Scope)
	query.Set("state", state)
	query.Set("nonce", nonce)
	query.Set("code_challenge", codeChallenge)
	query.Set("code_challenge_method", "S256")
	u.RawQuery = query.Encode()

	return u.String(), nil
}

func (h *Handler) writeTokenExchangeError(w http.ResponseWriter, message string, raw []byte, err error) {
	status := http.StatusBadGateway
	response := map[string]any{
		"message": message,
		"error":   err.Error(),
	}

	if len(raw) > 0 {
		response["token_response_raw"] = rawJSONOrString(raw)
	}

	if tokenErr, ok := err.(*oauth.TokenEndpointError); ok {
		status = tokenErr.StatusCode
		response["status"] = tokenErr.StatusCode
		response["token_response_raw"] = rawJSONOrString(tokenErr.Body)
	}

	logStep("TOKEN EXCHANGE - Failed", response)
	writeJSON(w, status, response)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
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

func rawJSONOrString(body []byte) any {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return ""
	}

	var parsed any
	if err := json.Unmarshal(body, &parsed); err == nil {
		return parsed
	}
	return trimmed
}

func previewToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return "(empty)"
	}

	if len(token) <= 20 {
		return token
	}
	return token[:10] + "..." + token[len(token)-10:]
}

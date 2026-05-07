package handlers

import (
	"context"
	"fmt"
	"net/http"
	"refresh-token-flow/internal/models"
	"refresh-token-flow/internal/oauth"
	"refresh-token-flow/internal/tokenutil"
	"time"
)

func (h *Handler) refreshAccessToken(ctx context.Context) (models.TokenSet, bool, error) {
	current, ok := h.store.CurrentTokenSet()
	if !ok {
		return models.TokenSet{}, false, fmt.Errorf("no token set in memory")
	}
	if current.RefreshToken == "" {
		return models.TokenSet{}, false, fmt.Errorf("no refresh token available")
	}

	// Access tokens are intentionally short-lived to limit blast radius if leaked.
	// Refresh tokens provide continuity but are more sensitive and must be protected.
	logStep("REFRESH REQUEST - Payload", map[string]any{
		"endpoint": h.cfg.TokenEndpoint,
		"body": map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": current.RefreshToken,
			"client_id":     h.cfg.ClientID,
		},
		"learning_note": "PKCE protected the initial code exchange, then refresh token keeps the session alive without re-login.",
	})

	tokenResp, raw, err := h.oauthClient.ExchangeRefreshToken(ctx, current.RefreshToken)
	if err != nil {
		if tokenErr, ok := err.(*oauth.TokenEndpointError); ok {
			logStep("REFRESH RESPONSE - Failed", map[string]any{
				"status": tokenErr.StatusCode,
				"body":   rawJSONOrString(tokenErr.Body),
			})
			if tokenErr.StatusCode == http.StatusBadRequest {
				return models.TokenSet{}, false, fmt.Errorf("refresh failed (possibly reused/rotated/expired refresh token): %w", err)
			}
			return models.TokenSet{}, false, err
		}
		return models.TokenSet{}, false, err
	}

	logStep("REFRESH RESPONSE - Raw JSON", rawJSONOrString(raw))

	newTokens := tokenutil.NewTokenSet(tokenResp, time.Now().UTC())
	if newTokens.RefreshToken == "" {
		newTokens.RefreshToken = current.RefreshToken
	}

	rotationOccurred := newTokens.RefreshToken != current.RefreshToken
	h.store.SaveTokenSet(newTokens)

	logStep("REFRESH TOKEN ROTATION", map[string]any{
		"old_refresh_token":  previewToken(current.RefreshToken),
		"new_refresh_token":  previewToken(newTokens.RefreshToken),
		"rotation_occurred":  rotationOccurred,
		"security_note":      "Rotation reduces replay risk: once used, the old refresh token should no longer be valid.",
		"new_access_expires": newTokens.AccessTokenExpiresAt.Format(time.RFC3339),
	})

	return newTokens, rotationOccurred, nil
}

package tokenutil

import (
	"refresh-token-flow/internal/models"
	"time"
)

func NewTokenSet(resp models.TokenResponse, now time.Time) models.TokenSet {
	return models.TokenSet{
		AccessToken:          resp.AccessToken,
		IDToken:              resp.IDToken,
		RefreshToken:         resp.RefreshToken,
		TokenType:            resp.TokenType,
		ExpiresIn:            resp.ExpiresIn,
		Scope:                resp.Scope,
		ObtainedAt:           now,
		AccessTokenExpiresAt: now.Add(time.Duration(resp.ExpiresIn) * time.Second),
	}
}

func IsExpired(expiration time.Time, now time.Time) bool {
	return !expiration.After(now)
}

func SecondsRemaining(expiration time.Time, now time.Time) int64 {
	return int64(expiration.Sub(now).Seconds())
}

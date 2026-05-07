package models

import "time"

type PendingAuthorization struct {
	State        string
	Nonce        string
	CodeVerifier string
	CreatedAt    time.Time
}

type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Scope            string `json:"scope"`
}

type TokenSet struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
	Scope        string

	ObtainedAt           time.Time
	AccessTokenExpiresAt time.Time
}

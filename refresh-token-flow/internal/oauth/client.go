package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"refresh-token-flow/internal/models"
	"time"
)

type Client struct {
	HTTPClient       *http.Client
	TokenEndpoint    string
	UserInfoEndpoint string
	ClientID         string
	RedirectURI      string
}

type TokenEndpointError struct {
	StatusCode int
	Body       []byte
}

func (e *TokenEndpointError) Error() string {
	return fmt.Sprintf("token endpoint returned status %d", e.StatusCode)
}

func NewClient(tokenEndpoint, userInfoEndpoint, clientID, redirectURI string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	return &Client{
		HTTPClient:       httpClient,
		TokenEndpoint:    tokenEndpoint,
		UserInfoEndpoint: userInfoEndpoint,
		ClientID:         clientID,
		RedirectURI:      redirectURI,
	}
}

func (c *Client) ExchangeAuthorizationCode(ctx context.Context, code, codeVerifier string) (models.TokenResponse, []byte, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.RedirectURI)
	form.Set("client_id", c.ClientID)
	form.Set("code_verifier", codeVerifier)
	return c.exchangeTokens(ctx, form)
}

func (c *Client) ExchangeRefreshToken(ctx context.Context, refreshToken string) (models.TokenResponse, []byte, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", c.ClientID)
	return c.exchangeTokens(ctx, form)
}

func (c *Client) exchangeTokens(ctx context.Context, form url.Values) (models.TokenResponse, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenEndpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return models.TokenResponse{}, nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return models.TokenResponse{}, nil, fmt.Errorf("send token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.TokenResponse{}, nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return models.TokenResponse{}, body, &TokenEndpointError{
			StatusCode: resp.StatusCode,
			Body:       body,
		}
	}

	var parsed models.TokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return models.TokenResponse{}, body, fmt.Errorf("unmarshal token response: %w", err)
	}

	return parsed, body, nil
}

func (c *Client) CallUserInfo(ctx context.Context, accessToken string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.UserInfoEndpoint, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("send userinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("read userinfo response: %w", err)
	}

	return resp.StatusCode, body, nil
}

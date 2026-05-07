package jwtutil

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type DecodedToken struct {
	Header           map[string]any `json:"header"`
	Claims           map[string]any `json:"claims"`
	ExpUnix          *int64         `json:"exp_unix,omitempty"`
	ExpiresAtRFC3339 *string        `json:"expires_at,omitempty"`
}

func DecodeJWT(token string) (DecodedToken, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return DecodedToken{}, fmt.Errorf("invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return DecodedToken{}, fmt.Errorf("decode JWT header: %w", err)
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return DecodedToken{}, fmt.Errorf("decode JWT claims: %w", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return DecodedToken{}, fmt.Errorf("unmarshal JWT header: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return DecodedToken{}, fmt.Errorf("unmarshal JWT claims: %w", err)
	}

	decoded := DecodedToken{
		Header: header,
		Claims: claims,
	}

	if expUnix, ok := Int64Claim(claims, "exp"); ok {
		exp := expUnix
		expAt := time.Unix(expUnix, 0).UTC().Format(time.RFC3339)
		decoded.ExpUnix = &exp
		decoded.ExpiresAtRFC3339 = &expAt
	}

	return decoded, nil
}

func StringClaim(claims map[string]any, key string) (string, bool) {
	raw, ok := claims[key]
	if !ok {
		return "", false
	}

	value, ok := raw.(string)
	if !ok {
		return "", false
	}
	return value, true
}

func Int64Claim(claims map[string]any, key string) (int64, bool) {
	raw, ok := claims[key]
	if !ok {
		return 0, false
	}

	switch value := raw.(type) {
	case float64:
		return int64(value), true
	case float32:
		return int64(value), true
	case int64:
		return value, true
	case int:
		return int64(value), true
	case json.Number:
		num, err := value.Int64()
		if err != nil {
			return 0, false
		}
		return num, true
	default:
		return 0, false
	}
}

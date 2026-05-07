package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	ServerAddr      string
	KeycloakBaseURL string
	Realm           string
	ClientID        string
	RedirectURI     string
	Scope           string

	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	JWKSEndpoint          string
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	cfg := &Config{
		ServerAddr:      envOrDefault("SERVER_ADDR", ":3000"),
		KeycloakBaseURL: envOrDefault("KEYCLOAK_BASE_URL", "http://127.0.0.1:8080"),
		Realm:           envOrDefault("REALM", "oauth-poc"),
		ClientID:        envOrDefault("CLIENT_ID", "oauth-refresh-client"),
		RedirectURI:     envOrDefault("REDIRECT_URI", "http://localhost:3000/callback"),
		Scope:           envOrDefault("SCOPE", "openid profile email"),
	}

	if cfg.ServerAddr == "" || cfg.KeycloakBaseURL == "" || cfg.Realm == "" || cfg.ClientID == "" || cfg.RedirectURI == "" {
		return nil, fmt.Errorf("one or more required settings are empty")
	}

	base := strings.TrimRight(cfg.KeycloakBaseURL, "/")
	oidcBase := fmt.Sprintf("%s/realms/%s/protocol/openid-connect", base, cfg.Realm)
	cfg.AuthorizationEndpoint = oidcBase + "/auth"
	cfg.TokenEndpoint = oidcBase + "/token"
	cfg.UserInfoEndpoint = oidcBase + "/userinfo"
	cfg.JWKSEndpoint = oidcBase + "/certs"

	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

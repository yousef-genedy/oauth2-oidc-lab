package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

var (
	serverAddr            string
	keycloakBaseURL       string
	realm                 string
	clientID              string
	redirectURI           string
	authorizationEndpoint string
	tokenEndpoint         string
	userInfoEndpoint      string
	jwksEndpoint          string
)

func loadConfig() error {
	if err := godotenv.Load(); err != nil {
		return fmt.Errorf("load .env: %w", err)
	}

	var err error
	serverAddr, err = requiredEnv("SERVER_ADDR")
	if err != nil {
		return err
	}
	keycloakBaseURL, err = requiredEnv("KEYCLOAK_BASE_URL")
	if err != nil {
		return err
	}
	realm, err = requiredEnv("REALM")
	if err != nil {
		return err
	}
	clientID, err = requiredEnv("CLIENT_ID")
	if err != nil {
		return err
	}
	redirectURI, err = requiredEnv("REDIRECT_URI")
	if err != nil {
		return err
	}

	base := strings.TrimRight(keycloakBaseURL, "/")
	oidcBase := fmt.Sprintf("%s/realms/%s/protocol/openid-connect", base, realm)
	authorizationEndpoint = oidcBase + "/auth"
	tokenEndpoint = oidcBase + "/token"
	userInfoEndpoint = oidcBase + "/userinfo"
	jwksEndpoint = oidcBase + "/certs"

	return nil
}

func requiredEnv(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("missing required env var: %s", name)
	}
	return value, nil
}

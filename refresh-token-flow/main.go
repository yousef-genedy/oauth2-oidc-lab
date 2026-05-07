package main

import (
	"log"
	"net/http"
	"time"

	"refresh-token-flow/internal/config"
	"refresh-token-flow/internal/handlers"
	"refresh-token-flow/internal/oauth"
	"refresh-token-flow/internal/routes"
	"refresh-token-flow/internal/session"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	store := session.NewStore()
	oauthClient := oauth.NewClient(
		cfg.TokenEndpoint,
		cfg.UserInfoEndpoint,
		cfg.ClientID,
		cfg.RedirectURI,
		&http.Client{Timeout: 15 * time.Second},
	)

	handler := handlers.New(cfg, store, oauthClient)
	mux := http.NewServeMux()
	routes.Register(mux, handler)

	log.Printf("Server running at http://localhost%s", cfg.ServerAddr)
	log.Printf("Start flow at GET /login")
	log.Printf("Configured endpoints:")
	log.Printf("  Authorization: %s", cfg.AuthorizationEndpoint)
	log.Printf("  Token:         %s", cfg.TokenEndpoint)
	log.Printf("  UserInfo:      %s", cfg.UserInfoEndpoint)
	log.Printf("  JWKS:          %s", cfg.JWKSEndpoint)

	if err := http.ListenAndServe(cfg.ServerAddr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

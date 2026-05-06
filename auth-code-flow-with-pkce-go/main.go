package main

import (
	"log"
	"net/http"
)

func main() {
	if err := loadConfig(); err != nil {
		log.Fatalf("config error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHome)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/callback", handleCallback)
	mux.HandleFunc("/profile", handleProfile)

	log.Printf("Server running at http://localhost%s", serverAddr)
	log.Printf("Start flow at GET /login")
	log.Printf("Configured endpoints:")
	log.Printf("  Authorization: %s", authorizationEndpoint)
	log.Printf("  Token:         %s", tokenEndpoint)
	log.Printf("  UserInfo:      %s", userInfoEndpoint)
	log.Printf("  JWKS:          %s", jwksEndpoint)

	if err := http.ListenAndServe(serverAddr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

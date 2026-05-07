package routes

import (
	"net/http"
	"refresh-token-flow/internal/handlers"
)

func Register(mux *http.ServeMux, h *handlers.Handler) {
	mux.HandleFunc("/", h.Home)
	mux.HandleFunc("/login", h.Login)
	mux.HandleFunc("/callback", h.Callback)
	mux.HandleFunc("/profile", h.Profile)
	mux.HandleFunc("/token-status", h.TokenStatus)
}

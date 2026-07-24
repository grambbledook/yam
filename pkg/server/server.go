package server

import (
	"net/http"
	"yam/pkg/handler"
)

func NewMux() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", handler.HandleHealth)
	mux.HandleFunc("GET /authorize", handler.HandleAuthorize)
	mux.HandleFunc("POST /token", handler.HandleToken)
	mux.HandleFunc("POST /introspect", handler.HandleIntrospect)
	mux.HandleFunc("POST /revoke", handler.HandleRevoke)

	return mux
}

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"yam/pkg/config"
	"yam/pkg/handler"

	"net/http"
)

func main() {
	cfg := config.DefaultConfig()

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", handler.HandleHealth)
	mux.HandleFunc("GET /authorize", handler.HandleAuthorize)
	mux.HandleFunc("POST /token", handler.HandleToken)
	mux.HandleFunc("POST /introspect", handler.HandleIntrospect)
	mux.HandleFunc("POST /revoke", handler.HandleRevoke)

	http.ListenAndServe(cfg.Port, mux)
	srv := &http.Server{Addr: ":" + cfg.Port, Handler: mux}
	go func() {
		log.Printf("Server starting on: %s\n", srv.Addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal("ListenAndServ:", err.Error())
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err.Error())
	}

	log.Println("Server exiting")
}

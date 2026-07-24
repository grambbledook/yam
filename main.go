package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"yam/pkg/config"
	"yam/pkg/server"

	"net/http"
)

func main() {
	cfg := config.Load()

	mux := server.NewMux()

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

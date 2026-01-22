package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vue-project-backend/internal/api"
	"vue-project-backend/internal/config"
	"vue-project-backend/internal/db"
	"vue-project-backend/internal/store"
)

func main() {
	cfg := config.Load()

	connection, err := db.Open(cfg)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	defer func() {
		if closeErr := connection.Close(); closeErr != nil {
			log.Printf("database close failed: %v", closeErr)
		}
	}()

	userStore := store.NewUserStore(connection)
	serverStore := store.NewServerStore(connection)
	l4Store := store.NewL4Store(connection)
	handler := api.NewRouter(cfg, userStore, serverStore, l4Store)

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("backend listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

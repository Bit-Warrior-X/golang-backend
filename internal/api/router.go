package api

import (
	"net/http"

	"vue-project-backend/internal/config"
	"vue-project-backend/internal/store"
)

func NewRouter(cfg config.Config, users store.UserStore, servers store.ServerStore) http.Handler {
	mux := http.NewServeMux()

	registerRoutes(mux, users, servers)

	handler := withCORS(cfg, mux)
	handler = withRequestLogging(handler)

	return handler
}

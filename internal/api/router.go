package api

import (
	"net/http"

	"vue-project-backend/internal/config"
	"vue-project-backend/internal/store"
)

func NewRouter(cfg config.Config, users store.UserStore, servers store.ServerStore, l4 store.L4Store) http.Handler {
	mux := http.NewServeMux()

	registerRoutes(mux, users, servers, l4)

	handler := withCORS(cfg, mux)
	handler = withRequestLogging(handler)

	return handler
}

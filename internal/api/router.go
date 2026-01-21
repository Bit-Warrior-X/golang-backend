package api

import (
	"net/http"

	"vue-project-backend/internal/config"
	"vue-project-backend/internal/store"
)

func NewRouter(cfg config.Config, users store.UserStore) http.Handler {
	mux := http.NewServeMux()

	registerRoutes(mux, users)

	handler := withCORS(cfg, mux)
	handler = withRequestLogging(handler)

	return handler
}

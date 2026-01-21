package api

import (
	"net/http"

	"vue-project-backend/internal/config"
)

func NewRouter(cfg config.Config) http.Handler {
	mux := http.NewServeMux()

	registerRoutes(mux)

	handler := withCORS(cfg, mux)
	handler = withRequestLogging(handler)

	return handler
}

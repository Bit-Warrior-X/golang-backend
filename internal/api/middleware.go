package api

import (
	"log"
	"net/http"
	"strings"
	"time"

	"vue-project-backend/internal/config"
)

type corsConfig struct {
	allowAll bool
	allowed  map[string]struct{}
}

func withCORS(cfg config.Config, next http.Handler) http.Handler {
	cors := corsConfig{
		allowAll: cfg.AllowAllCORS,
		allowed:  map[string]struct{}{},
	}

	if !cors.allowAll {
		for _, origin := range cfg.AllowedOrigins {
			cors.allowed[origin] = struct{}{}
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := origin != "" && cors.isAllowed(origin)
		if allowed {
			if cors.allowAll {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
			requestedHeaders := r.Header.Get("Access-Control-Request-Headers")
			if requestedHeaders != "" {
				w.Header().Set("Access-Control-Allow-Headers", requestedHeaders)
				w.Header().Add("Vary", "Access-Control-Request-Headers")
			} else {
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		}

		if r.Method == http.MethodOptions {
			if !allowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (c corsConfig) isAllowed(origin string) bool {
	if c.allowAll {
		return true
	}
	if origin == "" {
		return false
	}
	_, ok := c.allowed[origin]
	return ok
}

func withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start).Truncate(time.Millisecond)
		path := r.URL.Path
		if strings.TrimSpace(path) == "" {
			path = "/"
		}
		log.Printf("%s %s (%s)", r.Method, path, duration)
	})
}

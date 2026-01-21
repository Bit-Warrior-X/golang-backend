package config

import (
	"os"
	"strings"
)

type Config struct {
	Port           string
	AllowedOrigins []string
	AllowAllCORS   bool
}

func Load() Config {
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}

	origins := strings.TrimSpace(os.Getenv("ALLOWED_ORIGINS"))
	if origins == "" {
		return Config{
			Port:         port,
			AllowAllCORS: true,
		}
	}

	parsed := splitAndTrim(origins)
	return Config{
		Port:           port,
		AllowedOrigins: parsed,
		AllowAllCORS:   false,
	}
}

func splitAndTrim(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

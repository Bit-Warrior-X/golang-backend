package api

import (
	"log"
	"strings"
)

// logDeployLicenseClientf logs outbound calls from the API to deploy_license (never log secrets).
func logDeployLicenseClientf(format string, args ...any) {
	log.Printf("[deploy_license_client] "+format, args...)
}

// oneLineLogPreview collapses whitespace and truncates for safe single-line logs.
func oneLineLogPreview(s string, max int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return "…"
	}
	return s[:max-3] + "…"
}

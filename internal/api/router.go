package api

import (
	"net/http"

	"vue-project-backend/internal/config"
	"vue-project-backend/internal/store"
)

func NewRouter(
	cfg config.Config,
	users store.UserStore,
	servers store.ServerStore,
	l4 store.L4Store,
	wafWhitelist store.WafWhitelistStore,
	wafBlacklist store.WafBlacklistStore,
	wafGeo store.WafGeoStore,
	wafAntiCc store.WafAntiCcStore,
	wafAntiHeader store.WafAntiHeaderStore,
) http.Handler {
	mux := http.NewServeMux()

	registerRoutes(mux, users, servers, l4, wafWhitelist, wafBlacklist, wafGeo, wafAntiCc, wafAntiHeader)

	handler := withCORS(cfg, mux)
	handler = withRequestLogging(handler)

	return handler
}

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
	l4LiveAttack store.L4LiveAttackStore,
	securityEvents store.SecurityEventStore,
	serverTrafficStats store.ServerTrafficStatsStore,
	wafWhitelist store.WafWhitelistStore,
	wafBlacklist store.WafBlacklistStore,
	wafGeo store.WafGeoStore,
	wafAntiCc store.WafAntiCcStore,
	wafAntiHeader store.WafAntiHeaderStore,
	wafInterval store.WafIntervalStore,
	wafSecond store.WafSecondStore,
	wafResponse store.WafResponseStore,
	wafUserAgent store.WafUserAgentStore,
	upstreamServers store.UpstreamServerStore,
	blacklist store.BlacklistStore,
) http.Handler {
	mux := http.NewServeMux()

	registerRoutes(mux, users, servers, l4, l4LiveAttack, securityEvents, serverTrafficStats, wafWhitelist, wafBlacklist, wafGeo, wafAntiCc, wafAntiHeader, wafInterval, wafSecond, wafResponse, wafUserAgent, upstreamServers, blacklist)

	handler := withCORS(cfg, mux)
	handler = withRequestLogging(handler)

	return handler
}

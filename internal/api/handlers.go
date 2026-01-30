package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"vue-project-backend/internal/store"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string    `json:"token"`
	User  userShape `json:"user"`
}

type userShape struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
	Name  string `json:"name"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

func registerRoutes(
	mux *http.ServeMux,
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
) {
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/v1/health", healthHandler)
	mux.HandleFunc("/api/v1/status", statusHandler)
	mux.HandleFunc("/dashboard/summary", dashboardSummaryHandler(users, servers, blacklist, l4LiveAttack, serverTrafficStats))
	mux.HandleFunc("/api/v1/dashboard/summary", dashboardSummaryHandler(users, servers, blacklist, l4LiveAttack, serverTrafficStats))
	mux.HandleFunc("/dashboard/security-events", dashboardSecurityEventsHandler(securityEvents))
	mux.HandleFunc("/api/v1/dashboard/security-events", dashboardSecurityEventsHandler(securityEvents))
	mux.HandleFunc("/dashboard/bandwidth", dashboardBandwidthHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/dashboard/bandwidth", dashboardBandwidthHandler(serverTrafficStats))
	mux.HandleFunc("/dashboard/request-response", dashboardRequestResponseHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/dashboard/request-response", dashboardRequestResponseHandler(serverTrafficStats))
	mux.HandleFunc("/dashboard/status-codes", dashboardStatusCodesHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/dashboard/status-codes", dashboardStatusCodesHandler(serverTrafficStats))
	mux.HandleFunc("/auth/login", loginHandler(users))
	mux.HandleFunc("/servers", serversHandler(servers))
	mux.HandleFunc("/servers/blacklist", serverBlacklistHandler(blacklist))
	mux.HandleFunc("/servers/blacklist/", serverBlacklistHandler(blacklist))
	mux.HandleFunc("/servers/", serverDetailHandler(servers, l4, wafWhitelist, wafBlacklist, wafGeo, wafAntiCc, wafAntiHeader, wafInterval, wafSecond, wafResponse, wafUserAgent, upstreamServers))
	mux.HandleFunc("/users", usersHandler(users))
	mux.HandleFunc("/users/", userHandler(users))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": "v1",
	})
}

type dashboardSummaryResponse struct {
	TotalUsers   int64 `json:"totalUsers"`
	TotalServers int64 `json:"totalServers"`
	ActiveServers int64 `json:"activeServers"`
	BlockedIps   int64 `json:"blockedIps"`
	L4AttacksThisMonth int64 `json:"l4AttacksThisMonth"`
	L4AttacksPreviousMonth int64 `json:"l4AttacksPreviousMonth"`
	L7ThreatsThisMonth int64 `json:"l7ThreatsThisMonth"`
	L7ThreatsPreviousMonth int64 `json:"l7ThreatsPreviousMonth"`
}

func dashboardSummaryHandler(users store.UserStore, servers store.ServerStore, blacklist store.BlacklistStore, l4LiveAttack store.L4LiveAttackStore, trafficStats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		totalUsers, err := users.Count(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load users total")
			return
		}

		totalServers, err := servers.Count(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load servers total")
			return
		}

		activeServers, err := servers.CountByStatus(r.Context(), "Normal")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load active servers")
			return
		}

		blockedIps, err := blacklist.Count(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load blocked ips")
			return
		}

		now := time.Now()
		startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		startOfNextMonth := startOfMonth.AddDate(0, 1, 0)
		startOfPreviousMonth := startOfMonth.AddDate(0, -1, 0)

		l4ThisMonth, err := l4LiveAttack.CountBetween(r.Context(), startOfMonth, startOfNextMonth)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l4 attacks this month")
			return
		}

		l4PreviousMonth, err := l4LiveAttack.CountBetween(r.Context(), startOfPreviousMonth, startOfMonth)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l4 attacks previous month")
			return
		}

		l7ThisMonth, err := trafficStats.SumBlockedRequests(r.Context(), startOfMonth, startOfNextMonth)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l7 threats this month")
			return
		}

		l7PreviousMonth, err := trafficStats.SumBlockedRequests(r.Context(), startOfPreviousMonth, startOfMonth)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l7 threats previous month")
			return
		}

		writeJSON(w, http.StatusOK, dashboardSummaryResponse{
			TotalUsers:   totalUsers,
			TotalServers: totalServers,
			ActiveServers: activeServers,
			BlockedIps:   blockedIps,
			L4AttacksThisMonth: l4ThisMonth,
			L4AttacksPreviousMonth: l4PreviousMonth,
			L7ThreatsThisMonth: l7ThisMonth,
			L7ThreatsPreviousMonth: l7PreviousMonth,
		})
	}
}

func dashboardSecurityEventsHandler(securityEvents store.SecurityEventStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		limit := 5
		if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
			if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
				limit = parsed
			}
		}

		events, err := securityEvents.ListRecent(r.Context(), limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load security events")
			return
		}

		writeJSON(w, http.StatusOK, events)
	}
}

type bandwidthPoint struct {
	Timestamp string `json:"timestamp"`
	Bandwidth int64  `json:"bandwidth"`
}

type bandwidthSeries struct {
	ServerID int64           `json:"serverId"`
	Points   []bandwidthPoint `json:"points"`
}

func dashboardBandwidthHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		rangeValue := parseBandwidthRange(r.URL.Query().Get("range"))

		var serverID int64
		if rawServerID := strings.TrimSpace(r.URL.Query().Get("serverId")); rawServerID != "" {
			parsed, err := strconv.ParseInt(rawServerID, 10, 64)
			if err != nil || parsed < 0 {
				writeError(w, http.StatusBadRequest, "invalid serverId")
				return
			}
			serverID = parsed
		}

		end := time.Now()
		start := end.Add(-rangeValue)

		points, err := stats.ListBandwidth(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load bandwidth stats")
			return
		}

		grouped := make(map[int64][]bandwidthPoint)
		for _, point := range points {
			grouped[point.ServerID] = append(grouped[point.ServerID], bandwidthPoint{
				Timestamp: point.Timestamp,
				Bandwidth: point.Bandwidth,
			})
		}

		serverIDs := make([]int64, 0, len(grouped))
		for id := range grouped {
			serverIDs = append(serverIDs, id)
		}
		sort.Slice(serverIDs, func(i, j int) bool { return serverIDs[i] < serverIDs[j] })

		series := make([]bandwidthSeries, 0, len(serverIDs))
		for _, id := range serverIDs {
			series = append(series, bandwidthSeries{
				ServerID: id,
				Points:   grouped[id],
			})
		}

		writeJSON(w, http.StatusOK, series)
	}
}

func dashboardRequestResponseHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		rangeValue := parseTrafficRange(r.URL.Query().Get("range"))
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		end := time.Now()
		start := end.Add(-rangeValue)

		points, err := stats.ListRequestResponse(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load request response stats")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func dashboardStatusCodesHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		rangeValue := parseTrafficRange(r.URL.Query().Get("range"))
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		end := time.Now()
		start := end.Add(-rangeValue)

		points, err := stats.ListStatusCodes(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load status code stats")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func parseBandwidthRange(value string) time.Duration {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1h":
		return time.Hour
	case "2h":
		return 2 * time.Hour
	case "4h":
		return 4 * time.Hour
	case "8h":
		return 8 * time.Hour
	case "12h":
		return 12 * time.Hour
	case "24h":
		return 24 * time.Hour
	default:
		return 30 * time.Minute
	}
}

func parseTrafficRange(value string) time.Duration {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" {
		return 30 * time.Minute
	}
	if parsed, err := strconv.ParseInt(trimmed, 10, 64); err == nil && parsed > 0 {
		return time.Duration(parsed) * time.Millisecond
	}
	if strings.HasSuffix(trimmed, "m") {
		if minutes, err := strconv.ParseInt(strings.TrimSuffix(trimmed, "m"), 10, 64); err == nil && minutes > 0 {
			return time.Duration(minutes) * time.Minute
		}
	}
	if strings.HasSuffix(trimmed, "h") {
		if hours, err := strconv.ParseInt(strings.TrimSuffix(trimmed, "h"), 10, 64); err == nil && hours > 0 {
			return time.Duration(hours) * time.Hour
		}
	}
	return 30 * time.Minute
}

func parseServerIDParam(value string) (int64, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || parsed < 0 {
		return 0, err
	}
	return parsed, nil
}

func loginHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var payload loginRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		email := strings.ToLower(strings.TrimSpace(payload.Email))
		password := strings.TrimSpace(payload.Password)
		if email == "" || password == "" {
			writeError(w, http.StatusBadRequest, "email and password are required")
			return
		}

		user, err := users.FindByCredentials(r.Context(), email, password)
		if err != nil {
			if store.IsNotFound(err) {
				writeJSON(w, http.StatusUnauthorized, errorResponse{
					Error:   "unauthorized",
					Message: "Invalid email or password. Please try again.",
				})
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to authenticate")
			return
		}

		if strings.EqualFold(user.Status, "Block") {
			writeJSON(w, http.StatusForbidden, errorResponse{
				Error:   "forbidden",
				Message: "Your account is blocked. Please contact an administrator.",
			})
			return
		}

		if strings.EqualFold(user.Status, "Waiting") {
			writeJSON(w, http.StatusForbidden, errorResponse{
				Error:   "forbidden",
				Message: "Please wait while admin accept your login.",
			})
			return
		}

		writeJSON(w, http.StatusOK, loginResponse{
			Token: "mock-token",
			User:  userShape{ID: user.ID, Email: user.Email, Role: user.Role, Name: user.Name},
		})
	}
}

func serversHandler(servers store.ServerStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			list, err := servers.ListWithUsers(r.Context())
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load servers")
				return
			}
			writeJSON(w, http.StatusOK, list)
		case http.MethodPost:
			var payload serverCreatePayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			created, err := servers.Create(r.Context(), store.ServerInput{
				Name:        strings.TrimSpace(payload.Name),
				IP:          strings.TrimSpace(payload.IP),
				Status:      strings.TrimSpace(payload.Status),
				LicenseType: strings.TrimSpace(payload.LicenseType),
				LicenseFile: strings.TrimSpace(payload.LicenseFile),
				Version:     strings.TrimSpace(payload.Version),
				SSHUser:     strings.TrimSpace(payload.SSHUser),
				SSHPassword: strings.TrimSpace(payload.SSHPassword),
				SSHPort:     strings.TrimSpace(payload.SSHPort),
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to create server")
				return
			}
			if err := servers.UpdateServerUsers(r.Context(), created.ID, payload.UserIDs); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to assign server users")
				return
			}
			view, err := servers.GetView(r.Context(), created.ID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load server")
				return
			}
			writeJSON(w, http.StatusCreated, view)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

type serverUsersPayload struct {
	UserIDs []int64 `json:"userIds"`
}

type serverCreatePayload struct {
	Name        string  `json:"name"`
	IP          string  `json:"ip"`
	Status      string  `json:"status"`
	LicenseType string  `json:"licenseType"`
	LicenseFile string  `json:"licenseFile"`
	Version     string  `json:"version"`
	SSHUser     string  `json:"sshUser"`
	SSHPassword string  `json:"sshPassword"`
	SSHPort     string  `json:"sshPort"`
	UserIDs     []int64 `json:"userIds"`
}

type serverUpdatePayload struct {
	Name        string `json:"name"`
	IP          string `json:"ip"`
	Status      string `json:"status"`
	LicenseType string `json:"licenseType"`
	LicenseFile string `json:"licenseFile"`
	Version     string `json:"version"`
	SSHUser     string `json:"sshUser"`
	SSHPassword string `json:"sshPassword"`
	SSHPort     string `json:"sshPort"`
}

type wafWhitelistPayload struct {
	IPs         string `json:"ips"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	Description string `json:"description"`
}

type wafWhitelistBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type wafBlacklistPayload struct {
	IPs         string `json:"ips"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	Behavior    string `json:"behavior"`
	Description string `json:"description"`
}

type wafBlacklistBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type wafGeoPayload struct {
	Country   string `json:"country"`
	URL       string `json:"url"`
	Behavior  string `json:"behavior"`
	Operation string `json:"operation"`
	Status    string `json:"status"`
}

type wafGeoBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type wafAntiCcPayload struct {
	URL       string `json:"url"`
	Method    string `json:"method"`
	Threshold int    `json:"threshold"`
	Window    int    `json:"window"`
	Action    string `json:"action"`
	Behavior  string `json:"behavior"`
	Status    string `json:"status"`
}

type wafAntiCcBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type wafAntiHeaderPayload struct {
	URL       string `json:"url"`
	Header    string `json:"header"`
	Value     string `json:"value"`
	BlockMode string `json:"blockMode"`
	Behavior  string `json:"behavior"`
	Status    string `json:"status"`
}

type wafAntiHeaderBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type wafIntervalPayload struct {
	URL          string `json:"url"`
	Time         int    `json:"time"`
	RequestCount int    `json:"requestCount"`
	Behavior     string `json:"behavior"`
	Status       string `json:"status"`
}

type wafIntervalBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type wafSecondPayload struct {
	URL          string `json:"url"`
	RequestCount int    `json:"requestCount"`
	Burst        int    `json:"burst"`
	Behavior     string `json:"behavior"`
	Status       string `json:"status"`
}

type wafSecondBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type wafResponsePayload struct {
	URL           string `json:"url"`
	ResponseCode  string `json:"responseCode"`
	Time          int    `json:"time"`
	ResponseCount int    `json:"responseCount"`
	Behavior      string `json:"behavior"`
	Status        string `json:"status"`
}

type wafResponseBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type wafUserAgentPayload struct {
	URL       string `json:"url"`
	UserAgent string `json:"userAgent"`
	Match     string `json:"match"`
	Behavior  string `json:"behavior"`
	Status    string `json:"status"`
}

type wafUserAgentBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type upstreamServerPayload struct {
	Address     string `json:"address"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

type upstreamServerBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type serverBlacklistPayload struct {
	ServerID    int64  `json:"serverId"`
	IPAddress   string `json:"ipAddress"`
	Geolocation string `json:"geolocation"`
	Reason      string `json:"reason"`
	Server      string `json:"server"`
	TTL         string `json:"ttl"`
	TriggerRule string `json:"triggerRule"`
}

func serverBlacklistHandler(blacklist store.BlacklistStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/servers/blacklist")
		if path == "" || path == "/" {
			switch r.Method {
			case http.MethodGet:
				var serverID int64
				rawServerID := strings.TrimSpace(r.URL.Query().Get("serverId"))
				if rawServerID != "" {
					parsed, ok := parsePositiveInt(rawServerID)
					if !ok {
						writeError(w, http.StatusBadRequest, "invalid serverId")
						return
					}
					serverID = parsed
				}
				list, err := blacklist.List(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load blacklist entries")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				var payload serverBlacklistPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				if payload.ServerID == 0 {
					writeError(w, http.StatusBadRequest, "serverId is required")
					return
				}
				ipAddress := strings.TrimSpace(payload.IPAddress)
				if ipAddress == "" {
					writeError(w, http.StatusBadRequest, "ipAddress is required")
					return
				}
				geolocation := strings.TrimSpace(payload.Geolocation)
				if geolocation == "" {
					geolocation = "Manual"
				}
				reason := strings.TrimSpace(payload.Reason)
				if reason == "" {
					reason = "Manual block"
				}
				ttl := strings.TrimSpace(payload.TTL)
				triggerRule := strings.TrimSpace(payload.TriggerRule)
				serverName := strings.TrimSpace(payload.Server)

				created, err := blacklist.Create(r.Context(), payload.ServerID, store.BlacklistInput{
					IPAddress:   ipAddress,
					Geolocation: geolocation,
					Reason:      reason,
					Server:      serverName,
					TTL:         ttl,
					TriggerRule: triggerRule,
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create blacklist entry")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodDelete:
				var serverID int64
				rawServerID := strings.TrimSpace(r.URL.Query().Get("serverId"))
				if rawServerID != "" {
					parsed, ok := parsePositiveInt(rawServerID)
					if !ok {
						writeError(w, http.StatusBadRequest, "invalid serverId")
						return
					}
					serverID = parsed
				}
				if err := blacklist.DeleteAll(r.Context(), serverID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to flush blacklist entries")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if !strings.HasPrefix(path, "/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		rawID := strings.TrimPrefix(path, "/")
		if rawID == "" || strings.Contains(rawID, "/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		entryID, ok := parsePositiveInt(rawID)
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if r.Method != http.MethodDelete {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if err := blacklist.Delete(r.Context(), entryID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to delete blacklist entry")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func serverDetailHandler(
	servers store.ServerStore,
	l4 store.L4Store,
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
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/access-log/stream") {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/access-log/stream")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			streamAccessLog(w, r, servers, serverID)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/users") {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/users")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			if r.Method != http.MethodPut {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			var payload serverUsersPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			if err := servers.UpdateServerUsers(r.Context(), serverID, payload.UserIDs); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to update server users")
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/l4") {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/l4")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			switch r.Method {
			case http.MethodGet:
				config, err := l4.GetByServerID(r.Context(), serverID)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "l4 config not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to load l4 config")
					return
				}
				writeJSON(w, http.StatusOK, config)
			case http.MethodPut:
				var payload store.L4Config
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				if err := l4.UpdateByServerID(r.Context(), serverID, payload); err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "l4 config not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update l4 config")
					return
				}
				updated, err := l4.GetByServerID(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load l4 config")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/whitelist") {
			serverID, ruleID, isBatch, ok := parseWafWhitelistPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafWhitelist.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load whitelist rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafWhitelistBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafWhitelist.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafWhitelistPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafWhitelist.Create(r.Context(), serverID, store.WafWhitelistInput{
					IPs:         strings.TrimSpace(payload.IPs),
					URL:         strings.TrimSpace(payload.URL),
					Method:      strings.TrimSpace(payload.Method),
					Description: strings.TrimSpace(payload.Description),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create whitelist rule")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafWhitelistPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafWhitelist.Update(r.Context(), serverID, ruleID, store.WafWhitelistInput{
					IPs:         strings.TrimSpace(payload.IPs),
					URL:         strings.TrimSpace(payload.URL),
					Method:      strings.TrimSpace(payload.Method),
					Description: strings.TrimSpace(payload.Description),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "whitelist rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update whitelist rule")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafWhitelist.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete whitelist rule")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/blacklist") {
			serverID, ruleID, isBatch, ok := parseWafBlacklistPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafBlacklist.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load blacklist rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafBlacklistBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafBlacklist.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafBlacklistPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafBlacklist.Create(r.Context(), serverID, store.WafBlacklistInput{
					IPs:         strings.TrimSpace(payload.IPs),
					URL:         strings.TrimSpace(payload.URL),
					Method:      strings.TrimSpace(payload.Method),
					Behavior:    strings.TrimSpace(payload.Behavior),
					Description: strings.TrimSpace(payload.Description),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create blacklist rule")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafBlacklistPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafBlacklist.Update(r.Context(), serverID, ruleID, store.WafBlacklistInput{
					IPs:         strings.TrimSpace(payload.IPs),
					URL:         strings.TrimSpace(payload.URL),
					Method:      strings.TrimSpace(payload.Method),
					Behavior:    strings.TrimSpace(payload.Behavior),
					Description: strings.TrimSpace(payload.Description),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "blacklist rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update blacklist rule")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafBlacklist.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete blacklist rule")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/geolocation") {
			serverID, ruleID, isBatch, ok := parseWafGeoPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafGeo.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load geo rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafGeoBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafGeo.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafGeoPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafGeo.Create(r.Context(), serverID, store.WafGeoInput{
					Country:   strings.TrimSpace(payload.Country),
					URL:       strings.TrimSpace(payload.URL),
					Behavior:  strings.TrimSpace(payload.Behavior),
					Operation: strings.TrimSpace(payload.Operation),
					Status:    strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create geo rule")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafGeoPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafGeo.Update(r.Context(), serverID, ruleID, store.WafGeoInput{
					Country:   strings.TrimSpace(payload.Country),
					URL:       strings.TrimSpace(payload.URL),
					Behavior:  strings.TrimSpace(payload.Behavior),
					Operation: strings.TrimSpace(payload.Operation),
					Status:    strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "geo rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update geo rule")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafGeo.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete geo rule")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/anti-cc") {
			serverID, ruleID, isBatch, ok := parseWafAntiCcPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafAntiCc.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load anti-cc rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafAntiCcBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafAntiCc.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafAntiCcPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafAntiCc.Create(r.Context(), serverID, store.WafAntiCcInput{
					URL:       strings.TrimSpace(payload.URL),
					Method:    strings.TrimSpace(payload.Method),
					Threshold: payload.Threshold,
					Window:    payload.Window,
					Action:    strings.TrimSpace(payload.Action),
					Behavior:  strings.TrimSpace(payload.Behavior),
					Status:    strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create anti-cc rule")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafAntiCcPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafAntiCc.Update(r.Context(), serverID, ruleID, store.WafAntiCcInput{
					URL:       strings.TrimSpace(payload.URL),
					Method:    strings.TrimSpace(payload.Method),
					Threshold: payload.Threshold,
					Window:    payload.Window,
					Action:    strings.TrimSpace(payload.Action),
					Behavior:  strings.TrimSpace(payload.Behavior),
					Status:    strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "anti-cc rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update anti-cc rule")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafAntiCc.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete anti-cc rule")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/anti-header") {
			serverID, ruleID, isBatch, ok := parseWafAntiHeaderPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafAntiHeader.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load anti-header rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafAntiHeaderBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafAntiHeader.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafAntiHeaderPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafAntiHeader.Create(r.Context(), serverID, store.WafAntiHeaderInput{
					URL:       strings.TrimSpace(payload.URL),
					Header:    strings.TrimSpace(payload.Header),
					Value:     strings.TrimSpace(payload.Value),
					BlockMode: strings.TrimSpace(payload.BlockMode),
					Behavior:  strings.TrimSpace(payload.Behavior),
					Status:    strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create anti-header rule")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafAntiHeaderPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafAntiHeader.Update(r.Context(), serverID, ruleID, store.WafAntiHeaderInput{
					URL:       strings.TrimSpace(payload.URL),
					Header:    strings.TrimSpace(payload.Header),
					Value:     strings.TrimSpace(payload.Value),
					BlockMode: strings.TrimSpace(payload.BlockMode),
					Behavior:  strings.TrimSpace(payload.Behavior),
					Status:    strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "anti-header rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update anti-header rule")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafAntiHeader.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete anti-header rule")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/interval-freq-limit") {
			serverID, ruleID, isBatch, ok := parseWafIntervalPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafInterval.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load interval rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafIntervalBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafInterval.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafIntervalPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafInterval.Create(r.Context(), serverID, store.WafIntervalInput{
					URL:          strings.TrimSpace(payload.URL),
					TimeSeconds:  payload.Time,
					RequestCount: payload.RequestCount,
					Behavior:     strings.TrimSpace(payload.Behavior),
					Status:       strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create interval rule")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafIntervalPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafInterval.Update(r.Context(), serverID, ruleID, store.WafIntervalInput{
					URL:          strings.TrimSpace(payload.URL),
					TimeSeconds:  payload.Time,
					RequestCount: payload.RequestCount,
					Behavior:     strings.TrimSpace(payload.Behavior),
					Status:       strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "interval rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update interval rule")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafInterval.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete interval rule")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/second-freq-limit") {
			serverID, ruleID, isBatch, ok := parseWafSecondPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafSecond.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load second freq rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafSecondBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafSecond.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafSecondPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafSecond.Create(r.Context(), serverID, store.WafSecondInput{
					URL:          strings.TrimSpace(payload.URL),
					RequestCount: payload.RequestCount,
					Burst:        payload.Burst,
					Behavior:     strings.TrimSpace(payload.Behavior),
					Status:       strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create second freq rule")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafSecondPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafSecond.Update(r.Context(), serverID, ruleID, store.WafSecondInput{
					URL:          strings.TrimSpace(payload.URL),
					RequestCount: payload.RequestCount,
					Burst:        payload.Burst,
					Behavior:     strings.TrimSpace(payload.Behavior),
					Status:       strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "second freq rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update second freq rule")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafSecond.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete second freq rule")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/response-freq") {
			serverID, ruleID, isBatch, ok := parseWafResponsePath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafResponse.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load response freq rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafResponseBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafResponse.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafResponsePayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafResponse.Create(r.Context(), serverID, store.WafResponseInput{
					URL:           strings.TrimSpace(payload.URL),
					ResponseCode:  strings.TrimSpace(payload.ResponseCode),
					TimeSeconds:   payload.Time,
					ResponseCount: payload.ResponseCount,
					Behavior:      strings.TrimSpace(payload.Behavior),
					Status:        strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create response freq rule")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafResponsePayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafResponse.Update(r.Context(), serverID, ruleID, store.WafResponseInput{
					URL:           strings.TrimSpace(payload.URL),
					ResponseCode:  strings.TrimSpace(payload.ResponseCode),
					TimeSeconds:   payload.Time,
					ResponseCount: payload.ResponseCount,
					Behavior:      strings.TrimSpace(payload.Behavior),
					Status:        strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "response freq rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update response freq rule")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafResponse.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete response freq rule")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/user-agent") {
			serverID, ruleID, isBatch, ok := parseWafUserAgentPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafUserAgent.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load user agent rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafUserAgentBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafUserAgent.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafUserAgentPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafUserAgent.Create(r.Context(), serverID, store.WafUserAgentInput{
					URL:       strings.TrimSpace(payload.URL),
					UserAgent: strings.TrimSpace(payload.UserAgent),
					Match:     strings.TrimSpace(payload.Match),
					Behavior:  strings.TrimSpace(payload.Behavior),
					Status:    strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create user agent rule")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafUserAgentPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafUserAgent.Update(r.Context(), serverID, ruleID, store.WafUserAgentInput{
					URL:       strings.TrimSpace(payload.URL),
					UserAgent: strings.TrimSpace(payload.UserAgent),
					Match:     strings.TrimSpace(payload.Match),
					Behavior:  strings.TrimSpace(payload.Behavior),
					Status:    strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "user agent rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update user agent rule")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafUserAgent.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete user agent rule")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/upstream-servers") {
			serverID, upstreamID, isBatch, ok := parseUpstreamPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if upstreamID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := upstreamServers.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load upstream servers")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload upstreamServerBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := upstreamServers.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete upstream servers")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload upstreamServerPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := upstreamServers.Create(r.Context(), serverID, store.UpstreamServerInput{
					Address:     strings.TrimSpace(payload.Address),
					Description: strings.TrimSpace(payload.Description),
					Status:      strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create upstream server")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if upstreamID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload upstreamServerPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := upstreamServers.Update(r.Context(), serverID, upstreamID, store.UpstreamServerInput{
					Address:     strings.TrimSpace(payload.Address),
					Description: strings.TrimSpace(payload.Description),
					Status:      strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "upstream server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update upstream server")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if upstreamID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := upstreamServers.Delete(r.Context(), serverID, upstreamID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete upstream server")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		serverID, ok := parseID(r.URL.Path, "/servers/")
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		switch r.Method {
		case http.MethodPut:
			var payload serverUpdatePayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			if err := servers.Update(r.Context(), serverID, store.ServerInput{
				Name:        strings.TrimSpace(payload.Name),
				IP:          strings.TrimSpace(payload.IP),
				Status:      strings.TrimSpace(payload.Status),
				LicenseType: strings.TrimSpace(payload.LicenseType),
				LicenseFile: strings.TrimSpace(payload.LicenseFile),
				Version:     strings.TrimSpace(payload.Version),
				SSHUser:     strings.TrimSpace(payload.SSHUser),
				SSHPassword: strings.TrimSpace(payload.SSHPassword),
				SSHPort:     strings.TrimSpace(payload.SSHPort),
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to update server")
				return
			}
			view, err := servers.GetView(r.Context(), serverID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load server")
				return
			}
			writeJSON(w, http.StatusOK, view)
		case http.MethodDelete:
			if err := servers.Delete(r.Context(), serverID); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to delete server")
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func parseWafWhitelistPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "whitelist" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseWafBlacklistPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "blacklist" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseWafGeoPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "geolocation" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseWafAntiCcPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "anti-cc" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseWafAntiHeaderPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "anti-header" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseWafIntervalPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "interval-freq-limit" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseWafSecondPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "second-freq-limit" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseWafResponsePath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "response-freq" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseWafUserAgentPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "user-agent" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseUpstreamPath(path string) (serverID int64, upstreamID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return 0, 0, false, false
	}
	if parts[1] != "upstream-servers" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 2 {
		return serverID, 0, false, true
	}
	if len(parts) == 3 && parts[2] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 3 {
		upstreamID, ok = parsePositiveInt(parts[2])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, upstreamID, false, true
	}
	return 0, 0, false, false
}

func usersHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			list, err := users.List(r.Context())
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load users")
				return
			}
			writeJSON(w, http.StatusOK, list)
		case http.MethodPost:
			var payload store.UserInput
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			payload = payload.Normalize()
			if payload.Name == "" || payload.Email == "" {
				writeError(w, http.StatusBadRequest, "name and email are required")
				return
			}
			if !strings.EqualFold(payload.Role, "User") {
				payload.ServerIDs = nil
			}
			created, err := users.Create(r.Context(), payload)
			if err != nil {
				if store.IsDuplicateEmail(err) {
					writeError(w, http.StatusConflict, "email already exists")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to create user")
				return
			}
			if err := users.UpdateUserServers(r.Context(), created.ID, payload.ServerIDs); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to assign servers")
				return
			}
			created.ServerIDs = payload.ServerIDs
			writeJSON(w, http.StatusCreated, created)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func userHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseID(r.URL.Path, "/users/")
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}

		switch r.Method {
		case http.MethodPut, http.MethodPatch:
			var payload store.UserInput
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			payload = payload.Normalize()
			if payload.Name == "" || payload.Email == "" {
				writeError(w, http.StatusBadRequest, "name and email are required")
				return
			}
			if !strings.EqualFold(payload.Role, "User") {
				payload.ServerIDs = nil
			}
			updated, err := users.Update(r.Context(), id, payload)
			if err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "user not found")
					return
				}
				if store.IsDuplicateEmail(err) {
					writeError(w, http.StatusConflict, "email already exists")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to update user")
				return
			}
			if err := users.UpdateUserServers(r.Context(), id, payload.ServerIDs); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to assign servers")
				return
			}
			updated.ServerIDs = payload.ServerIDs
			writeJSON(w, http.StatusOK, updated)
		case http.MethodDelete:
			if err := users.Delete(r.Context(), id); err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "user not found")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to delete user")
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

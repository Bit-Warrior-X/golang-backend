package api

import (
	"encoding/json"
	"net/http"
	"strings"

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
	wafWhitelist store.WafWhitelistStore,
	wafBlacklist store.WafBlacklistStore,
	wafGeo store.WafGeoStore,
	wafAntiCc store.WafAntiCcStore,
	wafAntiHeader store.WafAntiHeaderStore,
) {
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/v1/health", healthHandler)
	mux.HandleFunc("/api/v1/status", statusHandler)
	mux.HandleFunc("/auth/login", loginHandler(users))
	mux.HandleFunc("/servers", serversHandler(servers))
	mux.HandleFunc("/servers/", serverDetailHandler(servers, l4, wafWhitelist, wafBlacklist, wafGeo, wafAntiCc, wafAntiHeader))
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

func serverDetailHandler(
	servers store.ServerStore,
	l4 store.L4Store,
	wafWhitelist store.WafWhitelistStore,
	wafBlacklist store.WafBlacklistStore,
	wafGeo store.WafGeoStore,
	wafAntiCc store.WafAntiCcStore,
	wafAntiHeader store.WafAntiHeaderStore,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

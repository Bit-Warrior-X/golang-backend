package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"vue-project-backend/internal/data"
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
	Email string `json:"email"`
	Role  string `json:"role"`
	Name  string `json:"name"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

func registerRoutes(mux *http.ServeMux, users store.UserStore) {
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/v1/health", healthHandler)
	mux.HandleFunc("/api/v1/status", statusHandler)
	mux.HandleFunc("/auth/login", loginHandler(users))
	mux.HandleFunc("/servers", serversHandler)
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
			User:  userShape{Email: user.Email, Role: user.Role, Name: user.Name},
		})
	}
}

func serversHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, data.ServerList())
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
			created, err := users.Create(r.Context(), payload)
			if err != nil {
				if store.IsDuplicateEmail(err) {
					writeError(w, http.StatusConflict, "email already exists")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to create user")
				return
			}
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

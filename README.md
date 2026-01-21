# vue-project-backend

Go backend for the Vue project. Provides simple auth and server APIs that
match the frontend expectations.

## Requirements

- Go 1.22+

## Run locally

```sh
cd /home/vue-project-backend
go run ./cmd/server
```

The server listens on `:8080` by default.

## Environment

- `PORT` (default: `8080`)
- `ALLOWED_ORIGINS` (comma-separated list of allowed origins; if unset, allows all)

Example:

```sh
PORT=8080 ALLOWED_ORIGINS=http://localhost:5173 go run ./cmd/server
```

## Endpoints

- `POST /auth/login`
  - body: `{ "email": "...", "password": "..." }`
  - response: `{ "token": "mock-token", "user": { "email": "..." } }`
- `GET /servers`
- `GET /health`
- `GET /api/v1/health`
- `GET /api/v1/status`

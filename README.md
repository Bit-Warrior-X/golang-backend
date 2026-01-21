
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
- `DB_USER` (default: `root`)
- `DB_PASSWORD` (default: empty)
- `DB_HOST` (default: `127.0.0.1`)
- `DB_PORT` (default: `3306`)
- `DB_NAME` (default: `cdnproxy`)
- `DB_DSN` (optional full MySQL DSN; overrides individual DB settings)
- `CONFIG_FILE` (optional; defaults to `config.json`)

Example:

```sh
PORT=8080 ALLOWED_ORIGINS=http://localhost:5173 go run ./cmd/server
```

## Config file

Backend can read `config.json` by default (or `CONFIG_FILE` if set). Env vars
override config file values.

## Database schema

```sql
CREATE DATABASE IF NOT EXISTS cdnproxy;

CREATE TABLE IF NOT EXISTS users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(50) NOT NULL,
  status VARCHAR(50) NOT NULL,
  server_id_list TEXT
);
```

## Endpoints

- `POST /auth/login`
  - body: `{ "email": "...", "password": "..." }`
  - response: `{ "token": "mock-token", "user": { "email": "..." } }`
- `GET /servers`
- `GET /users`
- `POST /users`
- `PUT /users/:id`
- `PATCH /users/:id`
- `DELETE /users/:id`
- `GET /health`
- `GET /api/v1/health`
- `GET /api/v1/status`


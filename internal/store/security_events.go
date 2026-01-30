package store

import (
	"context"
	"database/sql"
)

type SecurityEvent struct {
	ID          int64  `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

type SecurityEventStore interface {
	ListRecent(ctx context.Context, limit int) ([]SecurityEvent, error)
}

type securityEventStore struct {
	db *sql.DB
}

func NewSecurityEventStore(db *sql.DB) SecurityEventStore {
	return &securityEventStore{db: db}
}

func (store *securityEventStore) ListRecent(ctx context.Context, limit int) ([]SecurityEvent, error) {
	if limit <= 0 {
		limit = 5
	}
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, title, description, created_at, updated_at
		FROM security_events
		ORDER BY created_at DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []SecurityEvent
	for rows.Next() {
		var item SecurityEvent
		var createdAt sql.NullTime
		var updatedAt sql.NullTime
		if err := rows.Scan(&item.ID, &item.Title, &item.Description, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		item.CreatedAt = formatTimestamp(createdAt)
		item.UpdatedAt = formatTimestamp(updatedAt)
		events = append(events, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

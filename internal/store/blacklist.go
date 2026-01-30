package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

type BlacklistEntry struct {
	ID         int64  `json:"id"`
	ServerID   int64  `json:"serverId"`
	IPAddress  string `json:"ipAddress"`
	Geolocation string `json:"geolocation"`
	Reason     string `json:"reason"`
	Server     string `json:"server"`
	TTL        string `json:"ttl"`
	TriggerRule string `json:"triggerRule"`
	CreatedAt  string `json:"createdAt"`
	ExpireAt   string `json:"expireAt"`
	UpdatedAt  string `json:"updatedAt"`
}

type BlacklistInput struct {
	IPAddress  string
	Geolocation string
	Reason     string
	Server     string
	TTL        string
	TriggerRule string
}

type BlacklistStore interface {
	List(ctx context.Context, serverID int64) ([]BlacklistEntry, error)
	Count(ctx context.Context) (int64, error)
	Create(ctx context.Context, serverID int64, input BlacklistInput) (BlacklistEntry, error)
	Delete(ctx context.Context, entryID int64) error
	DeleteAll(ctx context.Context, serverID int64) error
}

type blacklistStore struct {
	db *sql.DB
}

func NewBlacklistStore(db *sql.DB) BlacklistStore {
	return &blacklistStore{db: db}
}

func (store *blacklistStore) List(ctx context.Context, serverID int64) ([]BlacklistEntry, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT b.id,
		       b.server_id,
		       b.ip_address,
		       b.geolocation,
		       b.reason,
		       b.server,
		       b.ttl,
		       b.trigger_rule,
		       b.created_at,
		       b.expire_at,
		       b.updated_at,
		       s.name
		FROM blacklist b
		LEFT JOIN servers s ON b.server_id = s.id
		WHERE (? = 0 OR b.server_id = ?)
		ORDER BY b.id DESC`,
		serverID,
		serverID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []BlacklistEntry
	for rows.Next() {
		var entry BlacklistEntry
		var serverText sql.NullString
		var ttl sql.NullString
		var triggerRule sql.NullString
		var createdAt sql.NullTime
		var expireAt sql.NullTime
		var updatedAt sql.NullTime
		var serverName sql.NullString
		if err := rows.Scan(
			&entry.ID,
			&entry.ServerID,
			&entry.IPAddress,
			&entry.Geolocation,
			&entry.Reason,
			&serverText,
			&ttl,
			&triggerRule,
			&createdAt,
			&expireAt,
			&updatedAt,
			&serverName,
		); err != nil {
			return nil, err
		}

		entry.Server = strings.TrimSpace(nullStringValue(serverText))
		if entry.Server == "" {
			entry.Server = nullStringValue(serverName)
		}
		entry.TTL = nullStringValue(ttl)
		entry.TriggerRule = nullStringValue(triggerRule)
		entry.CreatedAt = formatTimestamp(createdAt)
		entry.ExpireAt = formatTimestamp(expireAt)
		entry.UpdatedAt = formatTimestamp(updatedAt)
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func (store *blacklistStore) Count(ctx context.Context) (int64, error) {
	var total int64
	row := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM blacklist`)
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (store *blacklistStore) Create(ctx context.Context, serverID int64, input BlacklistInput) (BlacklistEntry, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO blacklist (server_id, ip_address, geolocation, reason, server, ttl, trigger_rule)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		serverID,
		input.IPAddress,
		input.Geolocation,
		input.Reason,
		nullableServerString(input.Server),
		nullableServerString(input.TTL),
		nullableServerString(input.TriggerRule),
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return BlacklistEntry{}, errNotFound
		}
		return BlacklistEntry{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return BlacklistEntry{}, err
	}

	now := time.Now().UTC()
	return BlacklistEntry{
		ID:          id,
		ServerID:    serverID,
		IPAddress:   input.IPAddress,
		Geolocation: input.Geolocation,
		Reason:      input.Reason,
		Server:      strings.TrimSpace(input.Server),
		TTL:         input.TTL,
		TriggerRule: input.TriggerRule,
		CreatedAt:   now.Format(time.RFC3339),
		ExpireAt:    now.Format(time.RFC3339),
		UpdatedAt:   now.Format(time.RFC3339),
	}, nil
}

func (store *blacklistStore) Delete(ctx context.Context, entryID int64) error {
	_, err := store.db.ExecContext(ctx, `DELETE FROM blacklist WHERE id = ?`, entryID)
	return err
}

func (store *blacklistStore) DeleteAll(ctx context.Context, serverID int64) error {
	if serverID == 0 {
		_, err := store.db.ExecContext(ctx, `DELETE FROM blacklist`)
		return err
	}
	_, err := store.db.ExecContext(ctx, `DELETE FROM blacklist WHERE server_id = ?`, serverID)
	return err
}

func formatTimestamp(value sql.NullTime) string {
	if !value.Valid {
		return ""
	}
	return value.Time.UTC().Format(time.RFC3339)
}

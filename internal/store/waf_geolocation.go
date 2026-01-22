package store

import (
	"context"
	"database/sql"
	"strings"
)

type WafGeoRule struct {
	ID        int64  `json:"id"`
	ServerID  int64  `json:"serverId"`
	Country   string `json:"country"`
	URL       string `json:"url"`
	Behavior  string `json:"behavior"`
	Operation string `json:"operation"`
	Status    string `json:"status"`
}

type WafGeoInput struct {
	Country   string
	URL       string
	Behavior  string
	Operation string
	Status    string
}

type WafGeoStore interface {
	ListByServer(ctx context.Context, serverID int64) ([]WafGeoRule, error)
	Create(ctx context.Context, serverID int64, input WafGeoInput) (WafGeoRule, error)
	Update(ctx context.Context, serverID, ruleID int64, input WafGeoInput) (WafGeoRule, error)
	Delete(ctx context.Context, serverID, ruleID int64) error
	DeleteBatch(ctx context.Context, serverID int64, ruleIDs []int64) error
}

type wafGeoStore struct {
	db *sql.DB
}

func NewWafGeoStore(db *sql.DB) WafGeoStore {
	return &wafGeoStore{db: db}
}

func (store *wafGeoStore) ListByServer(ctx context.Context, serverID int64) ([]WafGeoRule, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, server_id, country, url, behavior, operation, status
		FROM waf_geolocation
		WHERE server_id = ?
		ORDER BY id DESC`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WafGeoRule
	for rows.Next() {
		var rule WafGeoRule
		if err := rows.Scan(
			&rule.ID,
			&rule.ServerID,
			&rule.Country,
			&rule.URL,
			&rule.Behavior,
			&rule.Operation,
			&rule.Status,
		); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func (store *wafGeoStore) Create(ctx context.Context, serverID int64, input WafGeoInput) (WafGeoRule, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO waf_geolocation (server_id, country, url, behavior, operation, status)
		VALUES (?, ?, ?, ?, ?, ?)`,
		serverID,
		input.Country,
		input.URL,
		input.Behavior,
		input.Operation,
		input.Status,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafGeoRule{}, errNotFound
		}
		return WafGeoRule{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return WafGeoRule{}, err
	}

	return WafGeoRule{
		ID:        id,
		ServerID:  serverID,
		Country:   input.Country,
		URL:       input.URL,
		Behavior:  input.Behavior,
		Operation: input.Operation,
		Status:    input.Status,
	}, nil
}

func (store *wafGeoStore) Update(ctx context.Context, serverID, ruleID int64, input WafGeoInput) (WafGeoRule, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE waf_geolocation
		SET country = ?, url = ?, behavior = ?, operation = ?, status = ?
		WHERE id = ? AND server_id = ?`,
		input.Country,
		input.URL,
		input.Behavior,
		input.Operation,
		input.Status,
		ruleID,
		serverID,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafGeoRule{}, errNotFound
		}
		return WafGeoRule{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return WafGeoRule{}, err
	}
	if affected == 0 {
		return WafGeoRule{}, errNotFound
	}

	return WafGeoRule{
		ID:        ruleID,
		ServerID:  serverID,
		Country:   input.Country,
		URL:       input.URL,
		Behavior:  input.Behavior,
		Operation: input.Operation,
		Status:    input.Status,
	}, nil
}

func (store *wafGeoStore) Delete(ctx context.Context, serverID, ruleID int64) error {
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM waf_geolocation WHERE id = ? AND server_id = ?`,
		ruleID,
		serverID,
	)
	return err
}

func (store *wafGeoStore) DeleteBatch(ctx context.Context, serverID int64, ruleIDs []int64) error {
	ids := uniqueInt64(ruleIDs)
	if len(ids) == 0 {
		return nil
	}

	placeholders := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids)+1)
	for _, id := range ids {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}
	args = append(args, serverID)

	query := "DELETE FROM waf_geolocation WHERE id IN (" + strings.Join(placeholders, ",") + ") AND server_id = ?"
	_, err := store.db.ExecContext(ctx, query, args...)
	return err
}

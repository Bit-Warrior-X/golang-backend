package store

import (
	"context"
	"database/sql"
	"strings"
)

type WafResponseRule struct {
	ID            int64  `json:"id"`
	ServerID      int64  `json:"serverId"`
	URL           string `json:"url"`
	ResponseCode  string `json:"responseCode"`
	TimeSeconds   int    `json:"time"`
	ResponseCount int    `json:"responseCount"`
	Behavior      string `json:"behavior"`
	Status        string `json:"status"`
}

type WafResponseInput struct {
	URL           string
	ResponseCode  string
	TimeSeconds   int
	ResponseCount int
	Behavior      string
	Status        string
}

type WafResponseStore interface {
	ListByServer(ctx context.Context, serverID int64) ([]WafResponseRule, error)
	Create(ctx context.Context, serverID int64, input WafResponseInput) (WafResponseRule, error)
	Update(ctx context.Context, serverID, ruleID int64, input WafResponseInput) (WafResponseRule, error)
	Delete(ctx context.Context, serverID, ruleID int64) error
	DeleteBatch(ctx context.Context, serverID int64, ruleIDs []int64) error
}

type wafResponseStore struct {
	db *sql.DB
}

func NewWafResponseStore(db *sql.DB) WafResponseStore {
	return &wafResponseStore{db: db}
}

func (store *wafResponseStore) ListByServer(ctx context.Context, serverID int64) ([]WafResponseRule, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, server_id, url, response_code, time, response_count, behavior, status
		FROM waf_responsefreq
		WHERE server_id = ?
		ORDER BY id DESC`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WafResponseRule
	for rows.Next() {
		var rule WafResponseRule
		var responseCount sql.NullInt64
		var status sql.NullString
		if err := rows.Scan(
			&rule.ID,
			&rule.ServerID,
			&rule.URL,
			&rule.ResponseCode,
			&rule.TimeSeconds,
			&responseCount,
			&rule.Behavior,
			&status,
		); err != nil {
			return nil, err
		}
		rule.ResponseCount = nullIntValue(responseCount)
		rule.Status = nullStringValue(status)
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func (store *wafResponseStore) Create(ctx context.Context, serverID int64, input WafResponseInput) (WafResponseRule, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO waf_responsefreq (server_id, url, response_code, time, response_count, behavior, status)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		serverID,
		input.URL,
		input.ResponseCode,
		input.TimeSeconds,
		nullableInt(input.ResponseCount),
		input.Behavior,
		nullableServerString(input.Status),
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafResponseRule{}, errNotFound
		}
		return WafResponseRule{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return WafResponseRule{}, err
	}

	return WafResponseRule{
		ID:            id,
		ServerID:      serverID,
		URL:           input.URL,
		ResponseCode:  input.ResponseCode,
		TimeSeconds:   input.TimeSeconds,
		ResponseCount: input.ResponseCount,
		Behavior:      input.Behavior,
		Status:        input.Status,
	}, nil
}

func (store *wafResponseStore) Update(ctx context.Context, serverID, ruleID int64, input WafResponseInput) (WafResponseRule, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE waf_responsefreq
		SET url = ?, response_code = ?, time = ?, response_count = ?, behavior = ?, status = ?
		WHERE id = ? AND server_id = ?`,
		input.URL,
		input.ResponseCode,
		input.TimeSeconds,
		nullableInt(input.ResponseCount),
		input.Behavior,
		nullableServerString(input.Status),
		ruleID,
		serverID,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafResponseRule{}, errNotFound
		}
		return WafResponseRule{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return WafResponseRule{}, err
	}
	if affected == 0 {
		return WafResponseRule{}, errNotFound
	}

	return WafResponseRule{
		ID:            ruleID,
		ServerID:      serverID,
		URL:           input.URL,
		ResponseCode:  input.ResponseCode,
		TimeSeconds:   input.TimeSeconds,
		ResponseCount: input.ResponseCount,
		Behavior:      input.Behavior,
		Status:        input.Status,
	}, nil
}

func (store *wafResponseStore) Delete(ctx context.Context, serverID, ruleID int64) error {
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM waf_responsefreq WHERE id = ? AND server_id = ?`,
		ruleID,
		serverID,
	)
	return err
}

func (store *wafResponseStore) DeleteBatch(ctx context.Context, serverID int64, ruleIDs []int64) error {
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

	query := "DELETE FROM waf_responsefreq WHERE id IN (" + strings.Join(placeholders, ",") + ") AND server_id = ?"
	_, err := store.db.ExecContext(ctx, query, args...)
	return err
}

package store

import (
	"context"
	"database/sql"
	"strings"
)

type WafUserAgentRule struct {
	ID        int64  `json:"id"`
	ServerID  int64  `json:"serverId"`
	URL       string `json:"url"`
	UserAgent string `json:"userAgent"`
	Match     string `json:"match"`
	Behavior  string `json:"behavior"`
	Status    string `json:"status"`
}

type WafUserAgentInput struct {
	URL       string
	UserAgent string
	Match     string
	Behavior  string
	Status    string
}

type WafUserAgentStore interface {
	ListByServer(ctx context.Context, serverID int64) ([]WafUserAgentRule, error)
	Create(ctx context.Context, serverID int64, input WafUserAgentInput) (WafUserAgentRule, error)
	Update(ctx context.Context, serverID, ruleID int64, input WafUserAgentInput) (WafUserAgentRule, error)
	Delete(ctx context.Context, serverID, ruleID int64) error
	DeleteBatch(ctx context.Context, serverID int64, ruleIDs []int64) error
}

type wafUserAgentStore struct {
	db *sql.DB
}

func NewWafUserAgentStore(db *sql.DB) WafUserAgentStore {
	return &wafUserAgentStore{db: db}
}

func (store *wafUserAgentStore) ListByServer(ctx context.Context, serverID int64) ([]WafUserAgentRule, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, server_id, url, user_agent, `+"`match`"+`, behavior, status
		FROM waf_useragent
		WHERE server_id = ?
		ORDER BY id DESC`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WafUserAgentRule
	for rows.Next() {
		var rule WafUserAgentRule
		var status sql.NullString
		if err := rows.Scan(
			&rule.ID,
			&rule.ServerID,
			&rule.URL,
			&rule.UserAgent,
			&rule.Match,
			&rule.Behavior,
			&status,
		); err != nil {
			return nil, err
		}
		rule.Status = nullStringValue(status)
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func (store *wafUserAgentStore) Create(ctx context.Context, serverID int64, input WafUserAgentInput) (WafUserAgentRule, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO waf_useragent (server_id, url, user_agent, `+"`match`"+`, behavior, status)
		VALUES (?, ?, ?, ?, ?, ?)`,
		serverID,
		input.URL,
		input.UserAgent,
		input.Match,
		input.Behavior,
		nullableServerString(input.Status),
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafUserAgentRule{}, errNotFound
		}
		return WafUserAgentRule{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return WafUserAgentRule{}, err
	}

	return WafUserAgentRule{
		ID:        id,
		ServerID:  serverID,
		URL:       input.URL,
		UserAgent: input.UserAgent,
		Match:     input.Match,
		Behavior:  input.Behavior,
		Status:    input.Status,
	}, nil
}

func (store *wafUserAgentStore) Update(ctx context.Context, serverID, ruleID int64, input WafUserAgentInput) (WafUserAgentRule, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE waf_useragent
		SET url = ?, user_agent = ?, `+"`match`"+` = ?, behavior = ?, status = ?
		WHERE id = ? AND server_id = ?`,
		input.URL,
		input.UserAgent,
		input.Match,
		input.Behavior,
		nullableServerString(input.Status),
		ruleID,
		serverID,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafUserAgentRule{}, errNotFound
		}
		return WafUserAgentRule{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return WafUserAgentRule{}, err
	}
	if affected == 0 {
		return WafUserAgentRule{}, errNotFound
	}

	return WafUserAgentRule{
		ID:        ruleID,
		ServerID:  serverID,
		URL:       input.URL,
		UserAgent: input.UserAgent,
		Match:     input.Match,
		Behavior:  input.Behavior,
		Status:    input.Status,
	}, nil
}

func (store *wafUserAgentStore) Delete(ctx context.Context, serverID, ruleID int64) error {
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM waf_useragent WHERE id = ? AND server_id = ?`,
		ruleID,
		serverID,
	)
	return err
}

func (store *wafUserAgentStore) DeleteBatch(ctx context.Context, serverID int64, ruleIDs []int64) error {
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

	query := "DELETE FROM waf_useragent WHERE id IN (" + strings.Join(placeholders, ",") + ") AND server_id = ?"
	_, err := store.db.ExecContext(ctx, query, args...)
	return err
}

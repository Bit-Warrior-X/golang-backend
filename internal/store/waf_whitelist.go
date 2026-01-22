package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/go-sql-driver/mysql"
)

type WafWhitelistRule struct {
	ID          int64  `json:"id"`
	ServerID    int64  `json:"serverId"`
	IPs         string `json:"ips"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	Description string `json:"description"`
}

type WafWhitelistInput struct {
	IPs         string
	URL         string
	Method      string
	Description string
}

type WafWhitelistStore interface {
	ListByServer(ctx context.Context, serverID int64) ([]WafWhitelistRule, error)
	Create(ctx context.Context, serverID int64, input WafWhitelistInput) (WafWhitelistRule, error)
	Update(ctx context.Context, serverID, ruleID int64, input WafWhitelistInput) (WafWhitelistRule, error)
	Delete(ctx context.Context, serverID, ruleID int64) error
	DeleteBatch(ctx context.Context, serverID int64, ruleIDs []int64) error
}

type wafWhitelistStore struct {
	db *sql.DB
}

func NewWafWhitelistStore(db *sql.DB) WafWhitelistStore {
	return &wafWhitelistStore{db: db}
}

func (store *wafWhitelistStore) ListByServer(ctx context.Context, serverID int64) ([]WafWhitelistRule, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, server_id, white_ip_list, url, method, description
		FROM waf_whitelist
		WHERE server_id = ?
		ORDER BY id DESC`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WafWhitelistRule
	for rows.Next() {
		var rule WafWhitelistRule
		var description sql.NullString
		if err := rows.Scan(
			&rule.ID,
			&rule.ServerID,
			&rule.IPs,
			&rule.URL,
			&rule.Method,
			&description,
		); err != nil {
			return nil, err
		}
		rule.Description = nullStringValue(description)
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func (store *wafWhitelistStore) Create(ctx context.Context, serverID int64, input WafWhitelistInput) (WafWhitelistRule, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO waf_whitelist (server_id, white_ip_list, url, method, description)
		VALUES (?, ?, ?, ?, ?)`,
		serverID,
		input.IPs,
		input.URL,
		input.Method,
		nullableServerString(input.Description),
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafWhitelistRule{}, errNotFound
		}
		return WafWhitelistRule{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return WafWhitelistRule{}, err
	}

	return WafWhitelistRule{
		ID:          id,
		ServerID:    serverID,
		IPs:         input.IPs,
		URL:         input.URL,
		Method:      input.Method,
		Description: input.Description,
	}, nil
}

func (store *wafWhitelistStore) Update(ctx context.Context, serverID, ruleID int64, input WafWhitelistInput) (WafWhitelistRule, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE waf_whitelist
		SET white_ip_list = ?, url = ?, method = ?, description = ?
		WHERE id = ? AND server_id = ?`,
		input.IPs,
		input.URL,
		input.Method,
		nullableServerString(input.Description),
		ruleID,
		serverID,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafWhitelistRule{}, errNotFound
		}
		return WafWhitelistRule{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return WafWhitelistRule{}, err
	}
	if affected == 0 {
		return WafWhitelistRule{}, errNotFound
	}

	return WafWhitelistRule{
		ID:          ruleID,
		ServerID:    serverID,
		IPs:         input.IPs,
		URL:         input.URL,
		Method:      input.Method,
		Description: input.Description,
	}, nil
}

func (store *wafWhitelistStore) Delete(ctx context.Context, serverID, ruleID int64) error {
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM waf_whitelist WHERE id = ? AND server_id = ?`,
		ruleID,
		serverID,
	)
	return err
}

func (store *wafWhitelistStore) DeleteBatch(ctx context.Context, serverID int64, ruleIDs []int64) error {
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

	query := "DELETE FROM waf_whitelist WHERE id IN (" + strings.Join(placeholders, ",") + ") AND server_id = ?"
	_, err := store.db.ExecContext(ctx, query, args...)
	return err
}

func isForeignKeyViolation(err error) bool {
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		return mysqlErr.Number == 1452
	}
	return false
}

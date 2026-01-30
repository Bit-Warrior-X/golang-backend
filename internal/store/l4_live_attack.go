package store

import (
	"context"
	"database/sql"
	"time"
)

type L4LiveAttackStore interface {
	CountBetween(ctx context.Context, start, end time.Time) (int64, error)
}

type l4LiveAttackStore struct {
	db *sql.DB
}

func NewL4LiveAttackStore(db *sql.DB) L4LiveAttackStore {
	return &l4LiveAttackStore{db: db}
}

func (store *l4LiveAttackStore) CountBetween(ctx context.Context, start, end time.Time) (int64, error) {
	var total int64
	row := store.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM l4_live_attack
		WHERE created_at >= ? AND created_at < ?`,
		start,
		end,
	)
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

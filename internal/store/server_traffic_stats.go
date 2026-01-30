package store

import (
	"context"
	"database/sql"
	"time"
)

type ServerBandwidthPoint struct {
	ServerID  int64  `json:"serverId"`
	Timestamp string `json:"timestamp"`
	Bandwidth int64  `json:"bandwidth"`
}

type RequestResponsePoint struct {
	Timestamp     string `json:"timestamp"`
	RequestCount  int64  `json:"requestCount"`
	ResponseCount int64  `json:"responseCount"`
}

type StatusCodePoint struct {
	Timestamp string `json:"timestamp"`
	Success   int64  `json:"success"`
	Redirect  int64  `json:"redirect"`
	Client    int64  `json:"client"`
	Server    int64  `json:"server"`
}

type ServerTrafficStatsStore interface {
	ListBandwidth(ctx context.Context, start, end time.Time, serverID int64) ([]ServerBandwidthPoint, error)
	ListRequestResponse(ctx context.Context, start, end time.Time, serverID int64) ([]RequestResponsePoint, error)
	ListStatusCodes(ctx context.Context, start, end time.Time, serverID int64) ([]StatusCodePoint, error)
	SumBlockedRequests(ctx context.Context, start, end time.Time) (int64, error)
}

type serverTrafficStatsStore struct {
	db *sql.DB
}

func NewServerTrafficStatsStore(db *sql.DB) ServerTrafficStatsStore {
	return &serverTrafficStatsStore{db: db}
}

func (store *serverTrafficStatsStore) ListBandwidth(ctx context.Context, start, end time.Time, serverID int64) ([]ServerBandwidthPoint, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT server_id, bucket_ts, bandwidth
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		  AND (? = 0 OR server_id = ?)
		ORDER BY server_id, bucket_ts`,
		start,
		end,
		serverID,
		serverID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []ServerBandwidthPoint
	for rows.Next() {
		var item ServerBandwidthPoint
		var bucket time.Time
		if err := rows.Scan(&item.ServerID, &bucket, &item.Bandwidth); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListRequestResponse(ctx context.Context, start, end time.Time, serverID int64) ([]RequestResponsePoint, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT bucket_ts,
		       SUM(request_count) AS request_count,
		       SUM(response_count) AS response_count
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		  AND (? = 0 OR server_id = ?)
		GROUP BY bucket_ts
		ORDER BY bucket_ts`,
		start,
		end,
		serverID,
		serverID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []RequestResponsePoint
	for rows.Next() {
		var item RequestResponsePoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.RequestCount, &item.ResponseCount); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListStatusCodes(ctx context.Context, start, end time.Time, serverID int64) ([]StatusCodePoint, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT bucket_ts,
		       SUM(code200 + code206) AS success_count,
		       SUM(code301 + code302) AS redirect_count,
		       SUM(code400 + code403 + code404 + code444 + code499) AS client_count,
		       SUM(code500 + code502 + code503 + code504 + code904 + code929 + code978) AS server_count
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		  AND (? = 0 OR server_id = ?)
		GROUP BY bucket_ts
		ORDER BY bucket_ts`,
		start,
		end,
		serverID,
		serverID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []StatusCodePoint
	for rows.Next() {
		var item StatusCodePoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.Success, &item.Redirect, &item.Client, &item.Server); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) SumBlockedRequests(ctx context.Context, start, end time.Time) (int64, error) {
	var total int64
	row := store.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(blocked_request_count), 0)
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts < ?`,
		start,
		end,
	)
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

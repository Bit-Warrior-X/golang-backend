package store

import (
	"context"
	"database/sql"
	"errors"
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

type TrafficPoint struct {
	Timestamp string `json:"timestamp"`
	Traffic   int64  `json:"traffic"`
}

type IpCountPoint struct {
	Timestamp string `json:"timestamp"`
	Count     int64  `json:"count"`
}

type MethodSeriesPoint struct {
	Timestamp   string `json:"timestamp"`
	GetCount    int64  `json:"getCount"`
	PostCount   int64  `json:"postCount"`
	DeleteCount int64  `json:"deleteCount"`
	PutCount    int64  `json:"putCount"`
	HeadCount   int64  `json:"headCount"`
	PatchCount  int64  `json:"patchCount"`
	OptionsCount int64 `json:"optionsCount"`
	OthersCount int64  `json:"othersCount"`
}

type ProtocolSeriesPoint struct {
	Timestamp   string `json:"timestamp"`
	Http1_0     int64  `json:"http1_0"`
	Http1_1     int64  `json:"http1_1"`
	Http2       int64  `json:"http2"`
	Http3       int64  `json:"http3"`
}

type StatusCodeSummary struct {
	Code200 int64 `json:"code200"`
	Code206 int64 `json:"code206"`
	Code301 int64 `json:"code301"`
	Code302 int64 `json:"code302"`
	Code400 int64 `json:"code400"`
	Code403 int64 `json:"code403"`
	Code404 int64 `json:"code404"`
	Code444 int64 `json:"code444"`
	Code499 int64 `json:"code499"`
	Code500 int64 `json:"code500"`
	Code502 int64 `json:"code502"`
	Code503 int64 `json:"code503"`
	Code504 int64 `json:"code504"`
	Code904 int64 `json:"code904"`
	Code929 int64 `json:"code929"`
	Code978 int64 `json:"code978"`
}

type MethodSummary struct {
	GetCount     int64 `json:"getCount"`
	PostCount    int64 `json:"postCount"`
	DeleteCount  int64 `json:"deleteCount"`
	PutCount     int64 `json:"putCount"`
	HeadCount    int64 `json:"headCount"`
	PatchCount   int64 `json:"patchCount"`
	OptionsCount int64 `json:"optionsCount"`
	OthersCount  int64 `json:"othersCount"`
}

type ProtocolSummary struct {
	Http1_0 int64 `json:"http1_0"`
	Http1_1 int64 `json:"http1_1"`
	Http2   int64 `json:"http2"`
	Http3   int64 `json:"http3"`
}

type TopIPRow struct {
	IP       string `json:"ip"`
	Requests int64  `json:"requests"`
}

type TopIspRow struct {
	ISP      string `json:"isp"`
	Requests int64  `json:"requests"`
}

type TopRefererRow struct {
	Referer  string `json:"referer"`
	Requests int64  `json:"requests"`
}

type CountryRequestRow struct {
	CountryCode string `json:"countryCode"`
	Requests    int64  `json:"requests"`
	Blocked     int64  `json:"blocked"`
}

type ServerTrafficStatsStore interface {
	ListBandwidth(ctx context.Context, start, end time.Time, serverID int64) ([]ServerBandwidthPoint, error)
	ListBandwidthAggregate(ctx context.Context, start, end time.Time, serverID int64) ([]TrafficPoint, error)
	ListRequestResponse(ctx context.Context, start, end time.Time, serverID int64) ([]RequestResponsePoint, error)
	ListStatusCodes(ctx context.Context, start, end time.Time, serverID int64) ([]StatusCodePoint, error)
	ListTraffic(ctx context.Context, start, end time.Time, serverID int64) ([]TrafficPoint, error)
	ListIpCount(ctx context.Context, start, end time.Time, serverID int64) ([]IpCountPoint, error)
	ListMethodSeries(ctx context.Context, start, end time.Time, serverID int64) ([]MethodSeriesPoint, error)
	ListProtocolSeries(ctx context.Context, start, end time.Time, serverID int64) ([]ProtocolSeriesPoint, error)
	SumStatusCodes(ctx context.Context, start, end time.Time, serverID int64) (StatusCodeSummary, error)
	SumMethods(ctx context.Context, start, end time.Time, serverID int64) (MethodSummary, error)
	SumProtocols(ctx context.Context, start, end time.Time, serverID int64) (ProtocolSummary, error)
	SumTotals(ctx context.Context, start, end time.Time, serverID int64) (int64, int64, int64, int64, error)
	LatestBandwidth(ctx context.Context, start, end time.Time, serverID int64) (int64, time.Time, error)
	SumBlockedRequests(ctx context.Context, start, end time.Time) (int64, error)
	ListTopIPs(ctx context.Context, start, end time.Time, serverID int64, limit int) ([]TopIPRow, error)
	ListTopIsps(ctx context.Context, start, end time.Time, serverID int64, limit int) ([]TopIspRow, error)
	ListTopReferers(ctx context.Context, start, end time.Time, serverID int64, limit int) ([]TopRefererRow, error)
	SumIspRequests(ctx context.Context, start, end time.Time, serverID int64) (int64, error)
	SumRefererRequests(ctx context.Context, start, end time.Time, serverID int64) (int64, error)
	ListCountryRequests(ctx context.Context, start, end time.Time, serverID int64) ([]CountryRequestRow, error)
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

func (store *serverTrafficStatsStore) ListBandwidthAggregate(ctx context.Context, start, end time.Time, serverID int64) ([]TrafficPoint, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT bucket_ts, SUM(bandwidth) AS bandwidth
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

	var points []TrafficPoint
	for rows.Next() {
		var item TrafficPoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.Traffic); err != nil {
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

func (store *serverTrafficStatsStore) ListTopIPs(ctx context.Context, start, end time.Time, serverID int64, limit int) ([]TopIPRow, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := store.db.QueryContext(ctx, `
		SELECT INET6_NTOA(ip) AS ip,
		       SUM(request_count) AS request_count
		FROM ip_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		  AND (? = 0 OR server_id = ?)
		GROUP BY ip
		ORDER BY request_count DESC
		LIMIT ?`,
		start,
		end,
		serverID,
		serverID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rowsOut []TopIPRow
	for rows.Next() {
		var row TopIPRow
		if err := rows.Scan(&row.IP, &row.Requests); err != nil {
			return nil, err
		}
		rowsOut = append(rowsOut, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rowsOut, nil
}

func (store *serverTrafficStatsStore) ListTopIsps(ctx context.Context, start, end time.Time, serverID int64, limit int) ([]TopIspRow, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := store.db.QueryContext(ctx, `
		SELECT request_isp AS isp,
		       SUM(request_count) AS request_count
		FROM isp_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		  AND (? = 0 OR server_id = ?)
		GROUP BY request_isp
		ORDER BY request_count DESC
		LIMIT ?`,
		start,
		end,
		serverID,
		serverID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rowsOut []TopIspRow
	for rows.Next() {
		var row TopIspRow
		if err := rows.Scan(&row.ISP, &row.Requests); err != nil {
			return nil, err
		}
		rowsOut = append(rowsOut, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rowsOut, nil
}

func (store *serverTrafficStatsStore) ListTopReferers(ctx context.Context, start, end time.Time, serverID int64, limit int) ([]TopRefererRow, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := store.db.QueryContext(ctx, `
		SELECT request_referer AS referer,
		       SUM(request_count) AS request_count
		FROM referer_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		  AND (? = 0 OR server_id = ?)
		GROUP BY request_referer
		ORDER BY request_count DESC
		LIMIT ?`,
		start,
		end,
		serverID,
		serverID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rowsOut []TopRefererRow
	for rows.Next() {
		var row TopRefererRow
		if err := rows.Scan(&row.Referer, &row.Requests); err != nil {
			return nil, err
		}
		rowsOut = append(rowsOut, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rowsOut, nil
}

func (store *serverTrafficStatsStore) SumIspRequests(ctx context.Context, start, end time.Time, serverID int64) (int64, error) {
	var total int64
	row := store.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(request_count), 0)
		FROM isp_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		  AND (? = 0 OR server_id = ?)`,
		start,
		end,
		serverID,
		serverID,
	)
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (store *serverTrafficStatsStore) SumRefererRequests(ctx context.Context, start, end time.Time, serverID int64) (int64, error) {
	var total int64
	row := store.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(request_count), 0)
		FROM referer_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		  AND (? = 0 OR server_id = ?)`,
		start,
		end,
		serverID,
		serverID,
	)
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (store *serverTrafficStatsStore) ListCountryRequests(ctx context.Context, start, end time.Time, serverID int64) ([]CountryRequestRow, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT country_code,
		       SUM(request_count) AS request_count,
		       SUM(blocked_request_count) AS blocked_request_count
		FROM country_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		  AND (? = 0 OR server_id = ?)
		GROUP BY country_code
		ORDER BY request_count DESC`,
		start,
		end,
		serverID,
		serverID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rowsOut []CountryRequestRow
	for rows.Next() {
		var row CountryRequestRow
		if err := rows.Scan(&row.CountryCode, &row.Requests, &row.Blocked); err != nil {
			return nil, err
		}
		rowsOut = append(rowsOut, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rowsOut, nil
}

func (store *serverTrafficStatsStore) ListTraffic(ctx context.Context, start, end time.Time, serverID int64) ([]TrafficPoint, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT bucket_ts, SUM(traffic) AS traffic
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

	var points []TrafficPoint
	for rows.Next() {
		var item TrafficPoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.Traffic); err != nil {
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

func (store *serverTrafficStatsStore) ListIpCount(ctx context.Context, start, end time.Time, serverID int64) ([]IpCountPoint, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT bucket_ts, SUM(ip_count) AS ip_count
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

	var points []IpCountPoint
	for rows.Next() {
		var item IpCountPoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.Count); err != nil {
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

func (store *serverTrafficStatsStore) ListMethodSeries(ctx context.Context, start, end time.Time, serverID int64) ([]MethodSeriesPoint, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT bucket_ts,
		       SUM(get_count) AS get_count,
		       SUM(post_count) AS post_count,
		       SUM(delete_count) AS delete_count,
		       SUM(put_count) AS put_count,
		       SUM(head_count) AS head_count,
		       SUM(patch_count) AS patch_count,
		       SUM(options_count) AS options_count,
		       SUM(others_count) AS others_count
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

	var points []MethodSeriesPoint
	for rows.Next() {
		var item MethodSeriesPoint
		var bucket time.Time
		if err := rows.Scan(
			&bucket,
			&item.GetCount,
			&item.PostCount,
			&item.DeleteCount,
			&item.PutCount,
			&item.HeadCount,
			&item.PatchCount,
			&item.OptionsCount,
			&item.OthersCount,
		); err != nil {
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

func (store *serverTrafficStatsStore) ListProtocolSeries(ctx context.Context, start, end time.Time, serverID int64) ([]ProtocolSeriesPoint, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT bucket_ts,
		       SUM(http1_0_count) AS http1_0_count,
		       SUM(http1_1_count) AS http1_1_count,
		       SUM(http2_count) AS http2_count,
		       SUM(http3_count) AS http3_count
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

	var points []ProtocolSeriesPoint
	for rows.Next() {
		var item ProtocolSeriesPoint
		var bucket time.Time
		if err := rows.Scan(
			&bucket,
			&item.Http1_0,
			&item.Http1_1,
			&item.Http2,
			&item.Http3,
		); err != nil {
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

func (store *serverTrafficStatsStore) SumStatusCodes(ctx context.Context, start, end time.Time, serverID int64) (StatusCodeSummary, error) {
	var summary StatusCodeSummary
	row := store.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(code200), 0),
			COALESCE(SUM(code206), 0),
			COALESCE(SUM(code301), 0),
			COALESCE(SUM(code302), 0),
			COALESCE(SUM(code400), 0),
			COALESCE(SUM(code403), 0),
			COALESCE(SUM(code404), 0),
			COALESCE(SUM(code444), 0),
			COALESCE(SUM(code499), 0),
			COALESCE(SUM(code500), 0),
			COALESCE(SUM(code502), 0),
			COALESCE(SUM(code503), 0),
			COALESCE(SUM(code504), 0),
			COALESCE(SUM(code904), 0),
			COALESCE(SUM(code929), 0),
			COALESCE(SUM(code978), 0)
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		  AND (? = 0 OR server_id = ?)`,
		start,
		end,
		serverID,
		serverID,
	)
	if err := row.Scan(
		&summary.Code200,
		&summary.Code206,
		&summary.Code301,
		&summary.Code302,
		&summary.Code400,
		&summary.Code403,
		&summary.Code404,
		&summary.Code444,
		&summary.Code499,
		&summary.Code500,
		&summary.Code502,
		&summary.Code503,
		&summary.Code504,
		&summary.Code904,
		&summary.Code929,
		&summary.Code978,
	); err != nil {
		return StatusCodeSummary{}, err
	}
	return summary, nil
}

func (store *serverTrafficStatsStore) SumMethods(ctx context.Context, start, end time.Time, serverID int64) (MethodSummary, error) {
	var summary MethodSummary
	row := store.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(get_count), 0),
			COALESCE(SUM(post_count), 0),
			COALESCE(SUM(delete_count), 0),
			COALESCE(SUM(put_count), 0),
			COALESCE(SUM(head_count), 0),
			COALESCE(SUM(patch_count), 0),
			COALESCE(SUM(options_count), 0),
			COALESCE(SUM(others_count), 0)
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		  AND (? = 0 OR server_id = ?)`,
		start,
		end,
		serverID,
		serverID,
	)
	if err := row.Scan(
		&summary.GetCount,
		&summary.PostCount,
		&summary.DeleteCount,
		&summary.PutCount,
		&summary.HeadCount,
		&summary.PatchCount,
		&summary.OptionsCount,
		&summary.OthersCount,
	); err != nil {
		return MethodSummary{}, err
	}
	return summary, nil
}

func (store *serverTrafficStatsStore) SumProtocols(ctx context.Context, start, end time.Time, serverID int64) (ProtocolSummary, error) {
	var summary ProtocolSummary
	row := store.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(http1_0_count), 0),
			COALESCE(SUM(http1_1_count), 0),
			COALESCE(SUM(http2_count), 0),
			COALESCE(SUM(http3_count), 0)
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		  AND (? = 0 OR server_id = ?)`,
		start,
		end,
		serverID,
		serverID,
	)
	if err := row.Scan(
		&summary.Http1_0,
		&summary.Http1_1,
		&summary.Http2,
		&summary.Http3,
	); err != nil {
		return ProtocolSummary{}, err
	}
	return summary, nil
}

func (store *serverTrafficStatsStore) SumTotals(ctx context.Context, start, end time.Time, serverID int64) (int64, int64, int64, int64, error) {
	var totalTraffic int64
	var totalRequest int64
	var totalResponse int64
	var totalIp int64
	row := store.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(traffic), 0),
			COALESCE(SUM(request_count), 0),
			COALESCE(SUM(response_count), 0),
			COALESCE(SUM(ip_count), 0)
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		  AND (? = 0 OR server_id = ?)`,
		start,
		end,
		serverID,
		serverID,
	)
	if err := row.Scan(&totalTraffic, &totalRequest, &totalResponse, &totalIp); err != nil {
		return 0, 0, 0, 0, err
	}
	return totalTraffic, totalRequest, totalResponse, totalIp, nil
}

func (store *serverTrafficStatsStore) LatestBandwidth(ctx context.Context, start, end time.Time, serverID int64) (int64, time.Time, error) {
	var bucket time.Time
	var bandwidth int64
	row := store.db.QueryRowContext(ctx, `
		SELECT bucket_ts, SUM(bandwidth) AS bandwidth
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		  AND (? = 0 OR server_id = ?)
		GROUP BY bucket_ts
		ORDER BY bucket_ts DESC
		LIMIT 1`,
		start,
		end,
		serverID,
		serverID,
	)
	if err := row.Scan(&bucket, &bandwidth); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, time.Time{}, nil
		}
		return 0, time.Time{}, err
	}
	return bandwidth, bucket, nil
}

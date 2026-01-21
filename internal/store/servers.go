package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

type Server struct {
	ID          int64
	Name        string
	IP          string
	Status      string
	LicenseType string
	LicenseFile string
	Version     string
	Created     sql.NullTime
	Expired     sql.NullTime
}

type ServerView struct {
	ID             int64    `json:"id"`
	Name           string   `json:"name"`
	IP             string   `json:"ip"`
	Status         string   `json:"status"`
	StatusLabel    string   `json:"statusLabel"`
	StatusClass    string   `json:"statusClass"`
	License        string   `json:"license"`
	LicenseFile    string   `json:"licenseFile"`
	Version        string   `json:"version"`
	ExpiredDate    string   `json:"expiredDate"`
	Created        string   `json:"created"`
	Users          int      `json:"users"`
	ManagedUsers   []string `json:"managedUsers"`
	ManagedUserIds []int64  `json:"managedUserIds"`
}

type ServerStore interface {
	ListWithUsers(ctx context.Context) ([]ServerView, error)
	UpdateServerUsers(ctx context.Context, serverID int64, userIDs []int64) error
}

type serverStore struct {
	db *sql.DB
}

func NewServerStore(db *sql.DB) ServerStore {
	return &serverStore{db: db}
}

type userRef struct {
	ID   int64
	Name string
}

func (store *serverStore) ListWithUsers(ctx context.Context) ([]ServerView, error) {
	servers, err := store.listServers(ctx)
	if err != nil {
		return nil, err
	}

	userMap, err := store.serverUsers(ctx)
	if err != nil {
		return nil, err
	}

	views := make([]ServerView, 0, len(servers))
	for _, server := range servers {
		users := userMap[server.ID]
		names := make([]string, 0, len(users))
		ids := make([]int64, 0, len(users))
		for _, user := range users {
			names = append(names, user.Name)
			ids = append(ids, user.ID)
		}
		sort.Strings(names)

		statusLabel, statusClass := normalizeStatus(server.Status)

		views = append(views, ServerView{
			ID:             server.ID,
			Name:           server.Name,
			IP:             server.IP,
			Status:         server.Status,
			StatusLabel:    statusLabel,
			StatusClass:    statusClass,
			License:        server.LicenseType,
			LicenseFile:    server.LicenseFile,
			Version:        server.Version,
			ExpiredDate:    formatDate(server.Expired),
			Created:        formatDate(server.Created),
			Users:          len(users),
			ManagedUsers:   names,
			ManagedUserIds: ids,
		})
	}

	return views, nil
}

func (store *serverStore) UpdateServerUsers(ctx context.Context, serverID int64, userIDs []int64) error {
	uniqueIDs := uniqueInt64(userIDs)
	filteredIDs, err := store.filterUserRoleIDs(ctx, uniqueIDs, "User")
	if err != nil {
		return err
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM server_users WHERE server_id = ?`, serverID); err != nil {
		_ = tx.Rollback()
		return err
	}

	for _, userID := range filteredIDs {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO server_users (server_id, user_id)
			VALUES (?, ?)`,
			serverID,
			userID,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

func (store *serverStore) listServers(ctx context.Context) ([]Server, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, name, ip, status, license_type, license_file, version, created, expired
		FROM servers
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []Server
	for rows.Next() {
		var item Server
		var name sql.NullString
		var ip sql.NullString
		var status sql.NullString
		var licenseType sql.NullString
		var licenseFile sql.NullString
		var version sql.NullString
		if err := rows.Scan(
			&item.ID,
			&name,
			&ip,
			&status,
			&licenseType,
			&licenseFile,
			&version,
			&item.Created,
			&item.Expired,
		); err != nil {
			return nil, err
		}
		item.Name = nullStringValue(name)
		item.IP = nullStringValue(ip)
		item.Status = nullStringValue(status)
		item.LicenseType = nullStringValue(licenseType)
		item.LicenseFile = nullStringValue(licenseFile)
		item.Version = nullStringValue(version)
		servers = append(servers, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return servers, nil
}

func nullStringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func (store *serverStore) serverUsers(ctx context.Context) (map[int64][]userRef, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT su.server_id, u.id, u.name
		FROM server_users su
		JOIN users u ON u.id = su.user_id
		WHERE u.role = 'User'
		ORDER BY u.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := map[int64][]userRef{}
	for rows.Next() {
		var serverID int64
		var userID int64
		var name string
		if err := rows.Scan(&serverID, &userID, &name); err != nil {
			return nil, err
		}
		result[serverID] = append(result[serverID], userRef{ID: userID, Name: name})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func formatDate(value sql.NullTime) string {
	if !value.Valid {
		return ""
	}
	return value.Time.Format("Jan 02, 2006")
}

func normalizeStatus(status string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "normal":
		return "Normal", "active"
	case "pause":
		return "Pause", "inactive"
	case "expired":
		return "Expired", "maintenance"
	default:
		return status, "inactive"
	}
}

func uniqueInt64(values []int64) []int64 {
	if len(values) == 0 {
		return nil
	}
	seen := map[int64]struct{}{}
	result := make([]int64, 0, len(values))
	for _, value := range values {
		if value == 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func (store *serverStore) filterUserRoleIDs(ctx context.Context, ids []int64, role string) ([]int64, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	placeholders := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids)+1)
	for _, id := range ids {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}
	args = append(args, role)

	query := fmt.Sprintf(
		`SELECT id FROM users WHERE id IN (%s) AND role = ?`,
		strings.Join(placeholders, ","),
	)

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var filtered []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		filtered = append(filtered, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return filtered, nil
}

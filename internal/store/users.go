package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/go-sql-driver/mysql"
)

type User struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
	Status   string `json:"status"`
}

type UserInput struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
	Status   string `json:"status"`
}

func (input UserInput) Normalize() UserInput {
	return UserInput{
		Name:     strings.TrimSpace(input.Name),
		Email:    strings.ToLower(strings.TrimSpace(input.Email)),
		Password: strings.TrimSpace(input.Password),
		Role:     strings.TrimSpace(input.Role),
		Status:   strings.TrimSpace(input.Status),
	}
}

type UserStore interface {
	List(ctx context.Context) ([]User, error)
	FindByCredentials(ctx context.Context, email, password string) (User, error)
	Create(ctx context.Context, input UserInput) (User, error)
	Update(ctx context.Context, id int64, input UserInput) (User, error)
	Delete(ctx context.Context, id int64) error
}

type userStore struct {
	db *sql.DB
}

func NewUserStore(db *sql.DB) UserStore {
	return &userStore{db: db}
}

func (store *userStore) List(ctx context.Context) ([]User, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, name, email, password, role, status
		FROM users
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var item User
		if err := rows.Scan(&item.ID, &item.Name, &item.Email, &item.Password, &item.Role, &item.Status); err != nil {
			return nil, err
		}
		users = append(users, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func (store *userStore) FindByCredentials(ctx context.Context, email, password string) (User, error) {
	var user User
	row := store.db.QueryRowContext(ctx, `
		SELECT id, name, email, password, role, status
		FROM users
		WHERE email = ? AND password = ?
		LIMIT 1`,
		email,
		password,
	)
	if err := row.Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Role, &user.Status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, errNotFound
		}
		return User{}, err
	}
	return user, nil
}

func (store *userStore) Create(ctx context.Context, input UserInput) (User, error) {
	password := nullableString(input.Password)
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO users (name, email, password, role, status)
		VALUES (?, ?, ?, ?, ?)`,
		input.Name,
		input.Email,
		password,
		coalesce(input.Role, "User"),
		coalesce(input.Status, "Waiting"),
	)
	if err != nil {
		return User{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return User{}, err
	}

	return User{
		ID:       id,
		Name:     input.Name,
		Email:    input.Email,
		Password: input.Password,
		Role:     coalesce(input.Role, "User"),
		Status:   coalesce(input.Status, "Waiting"),
	}, nil
}

func (store *userStore) Update(ctx context.Context, id int64, input UserInput) (User, error) {
	password := nullableString(input.Password)
	result, err := store.db.ExecContext(ctx, `
		UPDATE users
		SET name = ?, email = ?, password = ?, role = ?, status = ?
		WHERE id = ?`,
		input.Name,
		input.Email,
		password,
		coalesce(input.Role, "User"),
		coalesce(input.Status, "Waiting"),
		id,
	)
	if err != nil {
		return User{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return User{}, err
	}
	if affected == 0 {
		return User{}, errNotFound
	}

	return User{
		ID:       id,
		Name:     input.Name,
		Email:    input.Email,
		Password: input.Password,
		Role:     coalesce(input.Role, "User"),
		Status:   coalesce(input.Status, "Waiting"),
	}, nil
}

func (store *userStore) Delete(ctx context.Context, id int64) error {
	result, err := store.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errNotFound
	}
	return nil
}

var errNotFound = errors.New("not found")

func IsNotFound(err error) bool {
	return errors.Is(err, errNotFound)
}

func IsDuplicateEmail(err error) bool {
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		return mysqlErr.Number == 1062
	}
	return false
}

func coalesce(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func nullableString(value string) sql.NullString {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: trimmed, Valid: true}
}

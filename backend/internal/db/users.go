package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("not found")

// Role constants.
const (
	RoleAdmin    = "admin"
	RoleCustomer = "customer"
)

// User is an account row.
type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	DisplayName  string    `json:"displayName"`
	CreatedAt    time.Time `json:"createdAt"`
}

// CreateUser inserts a user. The caller supplies an already-hashed password.
func (d *DB) CreateUser(ctx context.Context, username, passwordHash, role, displayName string) (User, error) {
	var u User
	err := d.pool.QueryRow(ctx,
		`INSERT INTO users (username, password_hash, role, display_name)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, username, password_hash, role, display_name, created_at`,
		username, passwordHash, role, displayName,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.DisplayName, &u.CreatedAt)
	return u, err
}

// GetUserByUsername looks a user up by username.
func (d *DB) GetUserByUsername(ctx context.Context, username string) (User, error) {
	var u User
	err := d.pool.QueryRow(ctx,
		`SELECT id, username, password_hash, role, display_name, created_at
		 FROM users WHERE username = $1`, username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.DisplayName, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// GetUser looks a user up by id.
func (d *DB) GetUser(ctx context.Context, id int64) (User, error) {
	var u User
	err := d.pool.QueryRow(ctx,
		`SELECT id, username, password_hash, role, display_name, created_at
		 FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.DisplayName, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// CustomerSummary is a customer row enriched with host/scan counts for the
// admin panel.
type CustomerSummary struct {
	User
	HostCount int        `json:"hostCount"`
	ScanCount int        `json:"scanCount"`
	LastScan  *time.Time `json:"lastScan"`
}

// ListCustomers returns all customer accounts with aggregate counts.
func (d *DB) ListCustomers(ctx context.Context) ([]CustomerSummary, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT u.id, u.username, u.role, u.display_name, u.created_at,
		       COALESCE(h.cnt, 0)  AS host_count,
		       COALESCE(s.cnt, 0)  AS scan_count,
		       s.last_scan
		FROM users u
		LEFT JOIN (SELECT customer_id, COUNT(*) cnt FROM hosts GROUP BY customer_id) h
		       ON h.customer_id = u.id
		LEFT JOIN (SELECT customer_id, COUNT(*) cnt, MAX(uploaded_at) last_scan
		           FROM scans GROUP BY customer_id) s
		       ON s.customer_id = u.id
		WHERE u.role = 'customer'
		ORDER BY u.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []CustomerSummary{}
	for rows.Next() {
		var c CustomerSummary
		if err := rows.Scan(&c.ID, &c.Username, &c.Role, &c.DisplayName, &c.CreatedAt,
			&c.HostCount, &c.ScanCount, &c.LastScan); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CountUsers returns how many accounts exist (used to decide admin bootstrap).
func (d *DB) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := d.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

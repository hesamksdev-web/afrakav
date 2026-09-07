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
	TokenVersion int       `json:"-"`
	Disabled     bool      `json:"disabled"`
	TOTPSecret   string    `json:"-"`
	TOTPEnabled  bool      `json:"totpEnabled"`
	TOTPLastStep int64     `json:"-"`
}

// CreateUser inserts a user. The caller supplies an already-hashed password.
func (d *DB) CreateUser(ctx context.Context, username, passwordHash, role, displayName string) (User, error) {
	var u User
	err := d.pool.QueryRow(ctx,
		`INSERT INTO users (username, password_hash, role, display_name)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, username, password_hash, role, display_name, created_at, token_version, disabled, totp_secret, totp_enabled, totp_last_step`,
		username, passwordHash, role, displayName,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.DisplayName, &u.CreatedAt, &u.TokenVersion, &u.Disabled, &u.TOTPSecret, &u.TOTPEnabled, &u.TOTPLastStep)
	return u, err
}

// GetUserByUsername looks a user up by username.
func (d *DB) GetUserByUsername(ctx context.Context, username string) (User, error) {
	var u User
	err := d.pool.QueryRow(ctx,
		`SELECT id, username, password_hash, role, display_name, created_at, token_version, disabled, totp_secret, totp_enabled, totp_last_step
		 FROM users WHERE username = $1`, username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.DisplayName, &u.CreatedAt, &u.TokenVersion, &u.Disabled, &u.TOTPSecret, &u.TOTPEnabled, &u.TOTPLastStep)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// GetUser looks a user up by id.
func (d *DB) GetUser(ctx context.Context, id int64) (User, error) {
	var u User
	err := d.pool.QueryRow(ctx,
		`SELECT id, username, password_hash, role, display_name, created_at, token_version, disabled, totp_secret, totp_enabled, totp_last_step
		 FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.DisplayName, &u.CreatedAt, &u.TokenVersion, &u.Disabled, &u.TOTPSecret, &u.TOTPEnabled, &u.TOTPLastStep)
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
		SELECT u.id, u.username, u.role, u.display_name, u.created_at, u.disabled, u.totp_enabled,
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
		if err := rows.Scan(&c.ID, &c.Username, &c.Role, &c.DisplayName, &c.CreatedAt, &c.Disabled, &c.TOTPEnabled,
			&c.HostCount, &c.ScanCount, &c.LastScan); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetPassword replaces a user's password hash and invalidates every token that
// was issued before the change.
func (d *DB) SetPassword(ctx context.Context, id int64, passwordHash string) error {
	tag, err := d.pool.Exec(ctx,
		`UPDATE users SET password_hash = $2, token_version = token_version + 1
		 WHERE id = $1`, id, passwordHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetDisabled suspends or restores an account. Either way outstanding tokens
// stop working, so a suspension takes effect immediately rather than at expiry.
func (d *DB) SetDisabled(ctx context.Context, id int64, disabled bool) error {
	tag, err := d.pool.Exec(ctx,
		`UPDATE users SET disabled = $2, token_version = token_version + 1
		 WHERE id = $1`, id, disabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountUsers returns how many accounts exist (used to decide admin bootstrap).
func (d *DB) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := d.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// ── two-factor authentication ───────────────────────────────────────────────

// StartTOTPEnrolment stores a pending secret. Two-factor stays off until the
// account proves it can produce a code, so a half-finished enrolment can never
// lock anyone out.
func (d *DB) StartTOTPEnrolment(ctx context.Context, id int64, secret string) error {
	tag, err := d.pool.Exec(ctx,
		`UPDATE users SET totp_secret = $2, totp_enabled = false, totp_last_step = 0
		 WHERE id = $1`, id, secret)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// EnableTOTP switches two-factor on and replaces the recovery codes, in one
// transaction so an account never ends up enabled with nobody's codes.
func (d *DB) EnableTOTP(ctx context.Context, id int64, step int64, codeHashes []string) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx,
		`UPDATE users SET totp_enabled = true, totp_last_step = $2, token_version = token_version + 1
		 WHERE id = $1 AND totp_secret <> ''`, id, step)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, id); err != nil {
		return err
	}
	for _, h := range codeHashes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)`, id, h); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// DisableTOTP clears the secret and every recovery code, and invalidates the
// account's tokens so the change cannot be outrun by an open session.
func (d *DB) DisableTOTP(ctx context.Context, id int64) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx,
		`UPDATE users SET totp_secret = '', totp_enabled = false, totp_last_step = 0,
		                  token_version = token_version + 1
		 WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// MarkTOTPStep records the counter step a code was accepted for. The update is
// conditional, so a replay of the same code inside its window affects no rows
// and the caller can reject it.
func (d *DB) MarkTOTPStep(ctx context.Context, id int64, step int64) (accepted bool, err error) {
	tag, err := d.pool.Exec(ctx,
		`UPDATE users SET totp_last_step = $2 WHERE id = $1 AND totp_last_step < $2`, id, step)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ConsumeRecoveryCode deletes a matching code and reports whether it existed.
// Deleting is the check: a code is good exactly once.
func (d *DB) ConsumeRecoveryCode(ctx context.Context, id int64, codeHash string) (bool, error) {
	tag, err := d.pool.Exec(ctx,
		`DELETE FROM recovery_codes WHERE user_id = $1 AND code_hash = $2`, id, codeHash)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// CountRecoveryCodes reports how many unused codes an account has left.
func (d *DB) CountRecoveryCodes(ctx context.Context, id int64) (int, error) {
	var n int
	err := d.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM recovery_codes WHERE user_id = $1`, id).Scan(&n)
	return n, err
}

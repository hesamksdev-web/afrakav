package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Access-request states.
const (
	RequestPending  = "pending"
	RequestApproved = "approved"
	RequestRejected = "rejected"
)

// AccessRequest is someone asking to be given an account. It is untrusted input
// from the public login page and confers nothing until an admin acts on it.
type AccessRequest struct {
	ID             int64      `json:"id"`
	CompanyName    string     `json:"companyName"`
	ContactName    string     `json:"contactName"`
	Email          string     `json:"email"`
	Phone          string     `json:"phone"`
	WantedUsername string     `json:"wantedUsername"`
	Note           string     `json:"note"`
	Status         string     `json:"status"`
	SourceIP       string     `json:"sourceIp"`
	CreatedAt      time.Time  `json:"createdAt"`
	ReviewedAt     *time.Time `json:"reviewedAt"`
	ReviewedBy     string     `json:"reviewedBy"`
	CreatedUserID  *int64     `json:"createdUserId"`
}

const requestColumns = `id, company_name, contact_name, email, phone, wanted_username,
	note, status, source_ip, created_at, reviewed_at, reviewed_by, created_user_id`

func scanRequest(row pgx.Row) (AccessRequest, error) {
	var a AccessRequest
	err := row.Scan(&a.ID, &a.CompanyName, &a.ContactName, &a.Email, &a.Phone,
		&a.WantedUsername, &a.Note, &a.Status, &a.SourceIP, &a.CreatedAt,
		&a.ReviewedAt, &a.ReviewedBy, &a.CreatedUserID)
	return a, err
}

// CreateAccessRequest records a new request. The caller has already validated
// and trimmed the fields.
func (d *DB) CreateAccessRequest(ctx context.Context, a AccessRequest) (AccessRequest, error) {
	return scanRequest(d.pool.QueryRow(ctx,
		`INSERT INTO access_requests
		   (company_name, contact_name, email, phone, wanted_username, note, source_ip)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING `+requestColumns,
		a.CompanyName, a.ContactName, a.Email, a.Phone, a.WantedUsername, a.Note, a.SourceIP))
}

// CountPendingRequestsSince limits how many requests one address can file in a
// window, so the public form cannot be used to flood the admin panel.
func (d *DB) CountPendingRequestsSince(ctx context.Context, sourceIP string, since time.Time) (int, error) {
	var n int
	err := d.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM access_requests
		 WHERE source_ip = $1 AND created_at >= $2`, sourceIP, since).Scan(&n)
	return n, err
}

// ListAccessRequests returns requests, newest first. An empty status means all.
func (d *DB) ListAccessRequests(ctx context.Context, status string) ([]AccessRequest, error) {
	query := `SELECT ` + requestColumns + ` FROM access_requests`
	args := []any{}
	if status != "" {
		query += ` WHERE status = $1`
		args = append(args, status)
	}
	query += ` ORDER BY created_at DESC LIMIT 200`

	rows, err := d.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AccessRequest{}
	for rows.Next() {
		a, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetAccessRequest looks one up by id.
func (d *DB) GetAccessRequest(ctx context.Context, id int64) (AccessRequest, error) {
	a, err := scanRequest(d.pool.QueryRow(ctx,
		`SELECT `+requestColumns+` FROM access_requests WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return AccessRequest{}, ErrNotFound
	}
	return a, err
}

// ApproveAccessRequest creates the customer account and marks the request
// approved in one transaction, so a request can never be marked done without
// the account existing — or an account created twice from one request.
func (d *DB) ApproveAccessRequest(
	ctx context.Context, requestID int64, reviewedBy string,
	username, passwordHash, displayName string,
) (User, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)

	// Claim the request first: the UPDATE matches no rows if another admin got
	// there a moment earlier.
	var claimed int64
	err = tx.QueryRow(ctx,
		`UPDATE access_requests SET status = $2, reviewed_at = now(), reviewed_by = $3
		 WHERE id = $1 AND status = $4
		 RETURNING id`,
		requestID, RequestApproved, reviewedBy, RequestPending).Scan(&claimed)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}

	var u User
	err = tx.QueryRow(ctx,
		`INSERT INTO users (username, password_hash, role, display_name)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, username, password_hash, role, display_name, created_at,
		           token_version, disabled, totp_secret, totp_enabled, totp_last_step`,
		username, passwordHash, RoleCustomer, displayName,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.DisplayName, &u.CreatedAt,
		&u.TokenVersion, &u.Disabled, &u.TOTPSecret, &u.TOTPEnabled, &u.TOTPLastStep)
	if err != nil {
		return User{}, err
	}

	if _, err := tx.Exec(ctx,
		`UPDATE access_requests SET created_user_id = $2 WHERE id = $1`, requestID, u.ID); err != nil {
		return User{}, err
	}
	return u, tx.Commit(ctx)
}

// RejectAccessRequest marks a pending request as declined.
func (d *DB) RejectAccessRequest(ctx context.Context, id int64, reviewedBy string) error {
	tag, err := d.pool.Exec(ctx,
		`UPDATE access_requests SET status = $2, reviewed_at = now(), reviewed_by = $3
		 WHERE id = $1 AND status = $4`,
		id, RequestRejected, reviewedBy, RequestPending)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/afranet/afrashodan/internal/audit"
)

// AuditEvent is one row of the append-only security log.
type AuditEvent struct {
	ID            int64          `json:"id"`
	OccurredAt    time.Time      `json:"occurredAt"`
	ActorID       *int64         `json:"actorId"`
	ActorUsername string         `json:"actorUsername"`
	ActorRole     string         `json:"actorRole"`
	Action        string         `json:"action"`
	Outcome       string         `json:"outcome"`
	TargetType    string         `json:"targetType"`
	TargetID      string         `json:"targetId"`
	TargetLabel   string         `json:"targetLabel"`
	CustomerID    *int64         `json:"customerId"`
	IP            string         `json:"ip"`
	UserAgent     string         `json:"userAgent"`
	Details       map[string]any `json:"details"`
	Hash          string         `json:"hash"`
}

// auditChainLockKey is an arbitrary constant used with pg_advisory_xact_lock
// to serialize hash-chain writes: two concurrent inserts must not read the
// same "latest hash" and both chain from it, or the chain forks.
const auditChainLockKey = 918_273_645

// RecordAuditEvent appends one row to audit_events, chaining it to the
// previous row's hash. Called from within the same request that produced the
// event; failures are the caller's to decide whether they should fail the
// request.
func (d *DB) RecordAuditEvent(ctx context.Context, e audit.Event) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(auditChainLockKey)); err != nil {
		return err
	}

	var prevHash string
	err = tx.QueryRow(ctx, `SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	occurredAt := time.Now().UTC()
	details := e.Details
	if details == nil {
		details = map[string]any{}
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return err
	}

	hash := chainHash(prevHash, occurredAt, e)

	var actorID, customerID any
	if e.ActorID != 0 {
		actorID = e.ActorID
	}
	if e.CustomerID != 0 {
		customerID = e.CustomerID
	}
	outcome := string(e.Outcome)
	if outcome == "" {
		outcome = string(audit.Success)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO audit_events
			(occurred_at, actor_id, actor_username, actor_role, action, outcome,
			 target_type, target_id, target_label, customer_id, ip, user_agent,
			 details, prev_hash, hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		occurredAt, actorID, e.ActorUsername, e.ActorRole, e.Action, outcome,
		e.TargetType, e.TargetID, e.TargetLabel, customerID, e.IP, e.UserAgent,
		detailsJSON, prevHash, hash)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// chainHash commits to the previous row's hash plus this row's own fields, so
// altering or removing a row (or reordering the sequence) is detectable by
// recomputing the chain from row 1.
func chainHash(prevHash string, occurredAt time.Time, e audit.Event) string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s",
		prevHash, occurredAt.Format(time.RFC3339Nano), e.Action, e.Outcome,
		e.ActorUsername, e.TargetType, e.TargetID, e.TargetLabel, e.IP)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// VerifyAuditChain recomputes every row's hash from row 1 and reports the id
// of the first row whose stored hash no longer matches — the point at which
// the log stopped being trustworthy. ok is true when the whole chain (up to
// `limit` rows, 0 = unlimited) is intact.
func (d *DB) VerifyAuditChain(ctx context.Context, limit int) (ok bool, brokenAt int64, err error) {
	query := `SELECT id, occurred_at, action, outcome, actor_username, target_type,
	                  target_id, target_label, ip, prev_hash, hash
	           FROM audit_events ORDER BY id ASC`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := d.pool.Query(ctx, query)
	if err != nil {
		return false, 0, err
	}
	defer rows.Close()

	prevHash := ""
	for rows.Next() {
		var id int64
		var occurredAt time.Time
		var action, outcome, actorUsername, targetType, targetID, targetLabel, ip, storedPrev, storedHash string
		if err := rows.Scan(&id, &occurredAt, &action, &outcome, &actorUsername,
			&targetType, &targetID, &targetLabel, &ip, &storedPrev, &storedHash); err != nil {
			return false, 0, err
		}
		if storedPrev != prevHash {
			return false, id, nil
		}
		want := chainHash(prevHash, occurredAt, audit.Event{
			Action: action, Outcome: audit.Outcome(outcome), ActorUsername: actorUsername,
			TargetType: targetType, TargetID: targetID, TargetLabel: targetLabel, IP: ip,
		})
		if want != storedHash {
			return false, id, nil
		}
		prevHash = storedHash
	}
	return true, 0, rows.Err()
}

// AuditFilter narrows GET /api/admin/events. Zero values mean "no filter" on
// that dimension. Cursor is the id of the last row already seen (from a
// previous page); results are strictly older than it.
type AuditFilter struct {
	Action     string
	Outcome    string
	ActorLike  string
	CustomerID int64
	Since      time.Time
	Until      time.Time
	Cursor     int64
	Limit      int
}

func scanAuditEvent(row pgx.Row) (AuditEvent, error) {
	var e AuditEvent
	var detailsRaw []byte
	err := row.Scan(&e.ID, &e.OccurredAt, &e.ActorID, &e.ActorUsername, &e.ActorRole,
		&e.Action, &e.Outcome, &e.TargetType, &e.TargetID, &e.TargetLabel,
		&e.CustomerID, &e.IP, &e.UserAgent, &detailsRaw, &e.Hash)
	if err != nil {
		return AuditEvent{}, err
	}
	if len(detailsRaw) > 0 {
		_ = json.Unmarshal(detailsRaw, &e.Details)
	}
	return e, nil
}

const auditColumns = `id, occurred_at, actor_id, actor_username, actor_role, action, outcome,
	target_type, target_id, target_label, customer_id, ip, user_agent, details, hash`

// ListAuditEvents returns events for the admin panel, newest first, filtered
// and cursor-paginated.
func (d *DB) ListAuditEvents(ctx context.Context, f AuditFilter) ([]AuditEvent, error) {
	query := `SELECT ` + auditColumns + ` FROM audit_events WHERE true`
	args := []any{}
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if f.Action != "" {
		query += ` AND action = ` + arg(f.Action)
	}
	if f.Outcome != "" {
		query += ` AND outcome = ` + arg(f.Outcome)
	}
	if f.ActorLike != "" {
		query += ` AND actor_username ILIKE ` + arg("%"+f.ActorLike+"%")
	}
	if f.CustomerID != 0 {
		query += ` AND customer_id = ` + arg(f.CustomerID)
	}
	if !f.Since.IsZero() {
		query += ` AND occurred_at >= ` + arg(f.Since)
	}
	if !f.Until.IsZero() {
		query += ` AND occurred_at <= ` + arg(f.Until)
	}
	if f.Cursor != 0 {
		query += ` AND id < ` + arg(f.Cursor)
	}
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	query += ` ORDER BY id DESC LIMIT ` + fmt.Sprintf("%d", limit)

	rows, err := d.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AuditEvent{}
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListAuditEventsForActor returns one account's own events (its activity
// feed), newest first, cursor-paginated.
func (d *DB) ListAuditEventsForActor(ctx context.Context, actorID int64, cursor int64, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query := `SELECT ` + auditColumns + ` FROM audit_events WHERE actor_id = $1`
	args := []any{actorID}
	if cursor != 0 {
		query += ` AND id < $2`
		args = append(args, cursor)
	}
	query += ` ORDER BY id DESC LIMIT ` + fmt.Sprintf("%d", limit)

	rows, err := d.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AuditEvent{}
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ── session revocation (logout) ─────────────────────────────────────────────

// RevokeToken denies one token's jti until it would have expired anyway. It
// is what makes logout actually end a session rather than just forgetting the
// token client-side.
func (d *DB) RevokeToken(ctx context.Context, jti string, userID int64, expiresAt time.Time) error {
	_, err := d.pool.Exec(ctx,
		`INSERT INTO revoked_tokens (jti, user_id, expires_at) VALUES ($1, $2, $3)
		 ON CONFLICT (jti) DO NOTHING`, jti, userID, expiresAt)
	return err
}

// IsTokenRevoked reports whether a jti was logged out.
func (d *DB) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	var exists bool
	err := d.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1)`, jti).Scan(&exists)
	return exists, err
}

// PruneExpiredRevocations deletes revoked-token rows past their own token
// expiry — they can no longer match a live token, so keeping them serves no
// purpose. Safe to run on every boot.
func (d *DB) PruneExpiredRevocations(ctx context.Context) error {
	_, err := d.pool.Exec(ctx, `DELETE FROM revoked_tokens WHERE expires_at < now()`)
	return err
}

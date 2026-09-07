// Package db is the PostgreSQL persistence layer for Afrashodan: users
// (admins + customers), uploaded scans, and per-customer hosts. Every host is
// owned by a customer, and all reads are scoped by customer_id so tenants are
// fully isolated.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps a pgx connection pool.
type DB struct {
	pool *pgxpool.Pool
}

// Connect opens a pooled connection, retrying briefly so the backend can start
// alongside Postgres in Docker before the database finishes booting.
func Connect(ctx context.Context, dsn string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 10

	var pool *pgxpool.Pool
	for attempt := 1; attempt <= 30; attempt++ {
		pool, err = pgxpool.NewWithConfig(ctx, cfg)
		if err == nil {
			if pingErr := pool.Ping(ctx); pingErr == nil {
				return &DB{pool: pool}, nil
			} else {
				err = pingErr
				pool.Close()
			}
		}
		time.Sleep(time.Second)
	}
	return nil, fmt.Errorf("connect postgres after retries: %w", err)
}

// Close releases the pool.
func (d *DB) Close() { d.pool.Close() }

// Migrate creates the schema if it does not already exist.
func (d *DB) Migrate(ctx context.Context) error {
	_, err := d.pool.Exec(ctx, schema)
	return err
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin','customer')),
    display_name  TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scans (
    id           BIGSERIAL PRIMARY KEY,
    customer_id  BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    hosts_count  INT NOT NULL DEFAULT 0,
    uploaded_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS scans_customer_idx ON scans (customer_id);

CREATE TABLE IF NOT EXISTS hosts (
    id           BIGSERIAL PRIMARY KEY,
    customer_id  BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip           TEXT NOT NULL,
    data         JSONB NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (customer_id, ip)
);
CREATE INDEX IF NOT EXISTS hosts_customer_idx ON hosts (customer_id);

-- token_version invalidates a user's outstanding tokens: every password change
-- or account suspension bumps it, and tokens carry the value they were issued
-- with. disabled locks an account without destroying its scan history.
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INT     NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled      BOOLEAN NOT NULL DEFAULT false;

-- Two-factor authentication. totp_secret holds a pending secret from the moment
-- enrolment starts; totp_enabled only turns true once the account has proved it
-- can produce a code. totp_last_step blocks replay of a code inside its window.
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret    TEXT    NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled   BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step BIGINT  NOT NULL DEFAULT 0;

-- One-time recovery codes, stored as SHA-256 hashes. A used code is deleted
-- rather than flagged, so a row's presence is the whole state.
-- Access requests come from the public login page, so every row is untrusted
-- input from an unauthenticated visitor. Nothing here grants access on its own:
-- an admin reads the request and creates the account separately.
CREATE TABLE IF NOT EXISTS access_requests (
    id              BIGSERIAL PRIMARY KEY,
    company_name    TEXT NOT NULL,
    contact_name    TEXT NOT NULL,
    email           TEXT NOT NULL,
    phone           TEXT NOT NULL,
    wanted_username TEXT NOT NULL DEFAULT '',
    note            TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','approved','rejected')),
    source_ip       TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at     TIMESTAMPTZ,
    reviewed_by     TEXT NOT NULL DEFAULT '',
    created_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS access_requests_status_idx
    ON access_requests (status, created_at DESC);

CREATE TABLE IF NOT EXISTS recovery_codes (
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT   NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, code_hash)
);

-- scan_id ties the current snapshot of a host to the upload that last touched
-- it, so an upload made against the wrong customer (or a stale scan) can be
-- undone by deleting that scan rather than living in the tenant forever.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS scan_id BIGINT REFERENCES scans(id) ON DELETE SET NULL;

-- revoked_tokens is the deny-list logout uses: a session token carries a jti,
-- and logging out records that jti here until the token would have expired
-- anyway. This is the only way a still-valid token stops working before its
-- natural expiry from an action the user themselves took (as opposed to a
-- password change or suspension, which invalidate via token_version).
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        TEXT PRIMARY KEY,
    user_id    BIGINT NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS revoked_tokens_expires_idx ON revoked_tokens (expires_at);

-- audit_events is the append-only security log: every login, logout, admin
-- action, and data-scoping decision worth a record. Rows are never updated or
-- deleted by the application — the triggers below make that a database-level
-- guarantee, not just a convention — and each row's hash commits to the row
-- before it, so a row deleted or edited by hand (e.g. a superuser bypassing
-- the app) breaks the chain visibly instead of silently.
CREATE TABLE IF NOT EXISTS audit_events (
    id             BIGSERIAL PRIMARY KEY,
    occurred_at    TIMESTAMPTZ NOT NULL,
    actor_id       BIGINT REFERENCES users(id) ON DELETE SET NULL,
    actor_username TEXT NOT NULL DEFAULT '',
    actor_role     TEXT NOT NULL DEFAULT '',
    action         TEXT NOT NULL,
    outcome        TEXT NOT NULL DEFAULT 'success' CHECK (outcome IN ('success','failure','denied')),
    target_type    TEXT NOT NULL DEFAULT '',
    target_id      TEXT NOT NULL DEFAULT '',
    target_label   TEXT NOT NULL DEFAULT '',
    customer_id    BIGINT REFERENCES users(id) ON DELETE SET NULL,
    ip             TEXT NOT NULL DEFAULT '',
    user_agent     TEXT NOT NULL DEFAULT '',
    details        JSONB NOT NULL DEFAULT '{}',
    prev_hash      TEXT NOT NULL DEFAULT '',
    hash           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_events_time_idx     ON audit_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_actor_idx    ON audit_events (actor_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_customer_idx ON audit_events (customer_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_action_idx   ON audit_events (action, occurred_at DESC);

CREATE OR REPLACE FUNCTION audit_events_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();

DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();
`

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
CREATE TABLE IF NOT EXISTS recovery_codes (
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT   NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, code_hash)
);
`

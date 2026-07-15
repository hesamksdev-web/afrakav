package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/afranet/afrashodan/internal/nessus"
)

// Scan is an uploaded-file record.
type Scan struct {
	ID         int64     `json:"id"`
	CustomerID int64     `json:"customerId"`
	Filename   string    `json:"filename"`
	HostsCount int       `json:"hostsCount"`
	UploadedAt time.Time `json:"uploadedAt"`
}

// SaveScan records an upload and upserts its hosts under the given customer,
// all in one transaction. Existing hosts (same customer + IP) are updated with
// the newest data; new hosts are inserted.
func (d *DB) SaveScan(ctx context.Context, customerID int64, filename string, hosts []nessus.Host) (Scan, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return Scan{}, err
	}
	defer tx.Rollback(ctx)

	var scan Scan
	err = tx.QueryRow(ctx,
		`INSERT INTO scans (customer_id, filename, hosts_count)
		 VALUES ($1, $2, $3)
		 RETURNING id, customer_id, filename, hosts_count, uploaded_at`,
		customerID, filename, len(hosts),
	).Scan(&scan.ID, &scan.CustomerID, &scan.Filename, &scan.HostsCount, &scan.UploadedAt)
	if err != nil {
		return Scan{}, err
	}

	for _, h := range hosts {
		payload, err := json.Marshal(h)
		if err != nil {
			return Scan{}, err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO hosts (customer_id, ip, data, updated_at)
			 VALUES ($1, $2, $3, now())
			 ON CONFLICT (customer_id, ip)
			 DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
			customerID, h.IP, payload,
		); err != nil {
			return Scan{}, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return Scan{}, err
	}
	return scan, nil
}

// ListHosts returns every host owned by a customer, newest-updated first.
func (d *DB) ListHosts(ctx context.Context, customerID int64) ([]nessus.Host, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT data FROM hosts WHERE customer_id = $1 ORDER BY updated_at DESC`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []nessus.Host{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var h nessus.Host
		if err := json.Unmarshal(raw, &h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// GetHost returns a single host by IP, scoped to the owning customer.
func (d *DB) GetHost(ctx context.Context, customerID int64, ip string) (nessus.Host, error) {
	var raw []byte
	err := d.pool.QueryRow(ctx,
		`SELECT data FROM hosts WHERE customer_id = $1 AND ip = $2`, customerID, ip,
	).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nessus.Host{}, ErrNotFound
	}
	if err != nil {
		return nessus.Host{}, err
	}
	var h nessus.Host
	err = json.Unmarshal(raw, &h)
	return h, err
}

// ListScans returns a customer's upload history, newest first.
func (d *DB) ListScans(ctx context.Context, customerID int64) ([]Scan, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT id, customer_id, filename, hosts_count, uploaded_at
		 FROM scans WHERE customer_id = $1 ORDER BY uploaded_at DESC`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Scan{}
	for rows.Next() {
		var s Scan
		if err := rows.Scan(&s.ID, &s.CustomerID, &s.Filename, &s.HostsCount, &s.UploadedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

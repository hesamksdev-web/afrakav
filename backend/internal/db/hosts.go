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
			`INSERT INTO hosts (customer_id, ip, data, scan_id, updated_at)
			 VALUES ($1, $2, $3, $4, now())
			 ON CONFLICT (customer_id, ip)
			 DO UPDATE SET data = EXCLUDED.data, scan_id = EXCLUDED.scan_id, updated_at = now()`,
			customerID, h.IP, payload, scan.ID,
		); err != nil {
			return Scan{}, err
		}
	}

	// Record the state of the whole estate after the merge. A scan file often
	// covers only part of the network, so snapshotting the file's own contents
	// would make the trend dip every time a partial scan landed.
	if err := snapshotEstate(ctx, tx, customerID, scan.ID); err != nil {
		return Scan{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Scan{}, err
	}
	return scan, nil
}

// snapshotEstate aggregates every host the customer currently owns and stores
// one row describing it. Runs inside the caller's transaction so a snapshot can
// never disagree with the hosts it summarises.
func snapshotEstate(ctx context.Context, tx pgx.Tx, customerID, scanID int64) error {
	rows, err := tx.Query(ctx, `SELECT data FROM hosts WHERE customer_id = $1`, customerID)
	if err != nil {
		return err
	}
	all := []nessus.Host{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var h nessus.Host
		if err := json.Unmarshal(raw, &h); err != nil {
			rows.Close()
			return err
		}
		all = append(all, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	s := nessus.ComputeStats(all, "")
	_, err = tx.Exec(ctx, `
		INSERT INTO estate_snapshots
			(customer_id, scan_id, hosts, critical, high, medium, low, info, exploitable, cves)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		customerID, scanID, s.Hosts,
		s.BySeverity[string(nessus.SeverityCritical)],
		s.BySeverity[string(nessus.SeverityHigh)],
		s.BySeverity[string(nessus.SeverityMedium)],
		s.BySeverity[string(nessus.SeverityLow)],
		s.BySeverity[string(nessus.SeverityInfo)],
		s.ExploitableFindings, s.TotalCVEs)
	return err
}

// EstateSnapshot is one point on the customer's trend line.
type EstateSnapshot struct {
	TakenAt     time.Time `json:"takenAt"`
	Hosts       int       `json:"hosts"`
	Critical    int       `json:"critical"`
	High        int       `json:"high"`
	Medium      int       `json:"medium"`
	Low         int       `json:"low"`
	Info        int       `json:"info"`
	Exploitable int       `json:"exploitable"`
	CVEs        int       `json:"cves"`
}

// ListEstateSnapshots returns a customer's trend points, oldest first so the
// caller can plot them left to right without re-sorting.
func (d *DB) ListEstateSnapshots(ctx context.Context, customerID int64) ([]EstateSnapshot, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT taken_at, hosts, critical, high, medium, low, info, exploitable, cves
		 FROM estate_snapshots WHERE customer_id = $1
		 ORDER BY taken_at ASC LIMIT 200`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []EstateSnapshot{}
	for rows.Next() {
		var s EstateSnapshot
		if err := rows.Scan(&s.TakenAt, &s.Hosts, &s.Critical, &s.High, &s.Medium,
			&s.Low, &s.Info, &s.Exploitable, &s.CVEs); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// BackfillEstateSnapshot gives a customer who already had scans before this
// feature existed one starting point, dated at their most recent upload. That
// timestamp is honest: the estate as it stands now IS the result of that scan.
// Older scans get nothing — the state at those times was never recorded.
func (d *DB) BackfillEstateSnapshot(ctx context.Context, customerID int64) error {
	var existing int
	if err := d.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM estate_snapshots WHERE customer_id = $1`, customerID).Scan(&existing); err != nil {
		return err
	}
	if existing > 0 {
		return nil
	}

	var scanID int64
	var uploadedAt time.Time
	err := d.pool.QueryRow(ctx,
		`SELECT id, uploaded_at FROM scans WHERE customer_id = $1
		 ORDER BY uploaded_at DESC LIMIT 1`, customerID).Scan(&scanID, &uploadedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // nothing has ever been uploaded for this customer
	}
	if err != nil {
		return err
	}

	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := snapshotEstate(ctx, tx, customerID, scanID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE estate_snapshots SET taken_at = $2 WHERE customer_id = $1 AND scan_id = $3`,
		customerID, uploadedAt, scanID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DeleteScan undoes an upload: it removes the scan record and every host still
// pointing at it as the source of its current data (a host later touched by a
// different scan is left alone). This is the recovery path for the two things
// that make an upload dangerous to leave in place — a file assigned to the
// wrong customer, or hosts that should never have been merged in.
func (d *DB) DeleteScan(ctx context.Context, customerID, scanID int64) (hostsRemoved int64, err error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM scans WHERE id = $1 AND customer_id = $2)`,
		scanID, customerID).Scan(&exists); err != nil {
		return 0, err
	}
	if !exists {
		return 0, ErrNotFound
	}

	tag, err := tx.Exec(ctx,
		`DELETE FROM hosts WHERE customer_id = $1 AND scan_id = $2`, customerID, scanID)
	if err != nil {
		return 0, err
	}
	hostsRemoved = tag.RowsAffected()

	// Undoing an upload also removes the trend point it produced, so the chart
	// never shows a state the customer has just erased.
	if _, err := tx.Exec(ctx,
		`DELETE FROM estate_snapshots WHERE customer_id = $1 AND scan_id = $2`,
		customerID, scanID); err != nil {
		return 0, err
	}

	if _, err := tx.Exec(ctx, `DELETE FROM scans WHERE id = $1`, scanID); err != nil {
		return 0, err
	}
	return hostsRemoved, tx.Commit(ctx)
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

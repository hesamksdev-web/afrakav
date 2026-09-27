package db

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/afranet/afrashodan/internal/showcase"
)

// ShowcaseRecord is the published landing-page sample plus who published it.
type ShowcaseRecord struct {
	SourceLabel string            `json:"sourceLabel"`
	PublishedBy string            `json:"-"` // admin only; never sent to the public page
	Showcase    showcase.Showcase `json:"showcase"`
}

// SaveShowcase replaces the published sample. The payload must already be
// anonymised — this layer stores what it is given and never sees a raw scan.
func (d *DB) SaveShowcase(ctx context.Context, label, by string, s showcase.Showcase) error {
	payload, err := json.Marshal(s)
	if err != nil {
		return err
	}
	_, err = d.pool.Exec(ctx, `
		INSERT INTO showcase (id, published_at, published_by, source_label, data)
		VALUES (1, now(), $1, $2, $3)
		ON CONFLICT (id) DO UPDATE
		SET published_at = now(), published_by = EXCLUDED.published_by,
		    source_label = EXCLUDED.source_label, data = EXCLUDED.data`,
		by, label, payload)
	return err
}

// GetShowcase returns the published sample, or ErrNotFound when the landing
// page has none yet.
func (d *DB) GetShowcase(ctx context.Context) (ShowcaseRecord, error) {
	var rec ShowcaseRecord
	var raw []byte
	err := d.pool.QueryRow(ctx,
		`SELECT source_label, published_by, data FROM showcase WHERE id = 1`,
	).Scan(&rec.SourceLabel, &rec.PublishedBy, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return ShowcaseRecord{}, ErrNotFound
	}
	if err != nil {
		return ShowcaseRecord{}, err
	}
	err = json.Unmarshal(raw, &rec.Showcase)
	return rec, err
}

// ClearShowcase takes the sample off the landing page.
func (d *DB) ClearShowcase(ctx context.Context) error {
	_, err := d.pool.Exec(ctx, `DELETE FROM showcase WHERE id = 1`)
	return err
}

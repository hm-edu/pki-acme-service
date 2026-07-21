package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/nosql"
)

type dbRenewalInfoOverride struct {
	Serial         string    `json:"serial"`
	Start          time.Time `json:"start"`
	End            time.Time `json:"end"`
	ExplanationURL string    `json:"explanationURL,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// getDBRenewalInfoOverride returns the stored override for the given serial,
// or nil if none exists.
func (db *DB) getDBRenewalInfoOverride(_ context.Context, serial string) (*dbRenewalInfoOverride, error) {
	b, err := db.db.Get(renewalInfoOverrideTable, []byte(serial))
	if nosql.IsErrNotFound(err) {
		return nil, nil
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading renewal info override for serial %s", serial)
	}
	dbrio := new(dbRenewalInfoOverride)
	if err := json.Unmarshal(b, dbrio); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling renewal info override for serial %s", serial)
	}
	return dbrio, nil
}

// SaveRenewalInfoOverride stores a manual renewal window for a certificate
// serial, creating or updating the entry as necessary.
func (db *DB) SaveRenewalInfoOverride(ctx context.Context, o *acme.RenewalInfoOverride) error {
	now := clock.Now()
	old, err := db.getDBRenewalInfoOverride(ctx, o.Serial)
	if err != nil {
		return err
	}

	nu := &dbRenewalInfoOverride{
		Serial:         o.Serial,
		Start:          o.Start.UTC(),
		End:            o.End.UTC(),
		ExplanationURL: o.ExplanationURL,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if old != nil {
		nu.CreatedAt = old.CreatedAt
	}

	var oldValue interface{}
	if old != nil {
		oldValue = old
	}
	return db.save(ctx, o.Serial, nu, oldValue, "renewal info override", renewalInfoOverrideTable)
}

// GetRenewalInfoOverride retrieves the manual renewal window for a certificate
// serial. It returns acme.ErrNotFound if no override is configured.
func (db *DB) GetRenewalInfoOverride(ctx context.Context, serial string) (*acme.RenewalInfoOverride, error) {
	dbrio, err := db.getDBRenewalInfoOverride(ctx, serial)
	if err != nil {
		return nil, err
	}
	if dbrio == nil {
		return nil, acme.ErrNotFound
	}
	return &acme.RenewalInfoOverride{
		Serial:         dbrio.Serial,
		Start:          dbrio.Start,
		End:            dbrio.End,
		ExplanationURL: dbrio.ExplanationURL,
	}, nil
}

// ListRenewalInfoOverrides returns all stored manual renewal windows.
func (db *DB) ListRenewalInfoOverrides(_ context.Context) ([]*acme.RenewalInfoOverride, error) {
	entries, err := db.db.List(renewalInfoOverrideTable)
	if err != nil {
		return nil, errors.Wrap(err, "error listing renewal info overrides")
	}
	overrides := make([]*acme.RenewalInfoOverride, 0, len(entries))
	for _, e := range entries {
		dbrio := new(dbRenewalInfoOverride)
		if err := json.Unmarshal(e.Value, dbrio); err != nil {
			return nil, errors.Wrapf(err, "error unmarshaling renewal info override for serial %s", string(e.Key))
		}
		overrides = append(overrides, &acme.RenewalInfoOverride{
			Serial:         dbrio.Serial,
			Start:          dbrio.Start,
			End:            dbrio.End,
			ExplanationURL: dbrio.ExplanationURL,
		})
	}
	return overrides, nil
}

// DeleteRenewalInfoOverride removes the manual renewal window for a
// certificate serial. Deleting a non-existent override is not an error.
func (db *DB) DeleteRenewalInfoOverride(_ context.Context, serial string) error {
	if err := db.db.Del(renewalInfoOverrideTable, []byte(serial)); err != nil && !nosql.IsErrNotFound(err) {
		return errors.Wrapf(err, "error deleting renewal info override for serial %s", serial)
	}
	return nil
}

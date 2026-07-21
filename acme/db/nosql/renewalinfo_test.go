package nosql

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/db"
	nosqldb "github.com/smallstep/nosql/database"
)

func TestDB_SaveGetDeleteRenewalInfoOverride(t *testing.T) {
	serial := "1234567890"
	override := &acme.RenewalInfoOverride{
		Serial:         serial,
		Start:          time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		End:            time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC),
		ExplanationURL: "https://pki.example.com/incident",
	}

	t.Run("save-new", func(t *testing.T) {
		d := &DB{db: &db.MockNoSQLDB{
			MGet: func(bucket, key []byte) ([]byte, error) {
				assert.Equals(t, bucket, renewalInfoOverrideTable)
				assert.Equals(t, key, []byte(serial))
				return nil, nosqldb.ErrNotFound
			},
			MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
				assert.Equals(t, bucket, renewalInfoOverrideTable)
				assert.Equals(t, key, []byte(serial))
				assert.Equals(t, old, nil)

				dbrio := new(dbRenewalInfoOverride)
				assert.FatalError(t, json.Unmarshal(nu, dbrio))
				assert.Equals(t, dbrio.Serial, serial)
				assert.Equals(t, dbrio.Start, override.Start)
				assert.Equals(t, dbrio.End, override.End)
				assert.Equals(t, dbrio.ExplanationURL, override.ExplanationURL)
				assert.True(t, clock.Now().Add(-time.Minute).Before(dbrio.CreatedAt))
				return nu, true, nil
			},
		}}
		assert.FatalError(t, d.SaveRenewalInfoOverride(context.Background(), override))
	})

	t.Run("save-update-keeps-createdAt", func(t *testing.T) {
		createdAt := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
		existing, err := json.Marshal(&dbRenewalInfoOverride{
			Serial:    serial,
			Start:     override.Start.Add(-time.Hour),
			End:       override.End.Add(-time.Hour),
			CreatedAt: createdAt,
			UpdatedAt: createdAt,
		})
		assert.FatalError(t, err)

		d := &DB{db: &db.MockNoSQLDB{
			MGet: func(bucket, key []byte) ([]byte, error) {
				return existing, nil
			},
			MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
				assert.Equals(t, old, existing)
				dbrio := new(dbRenewalInfoOverride)
				assert.FatalError(t, json.Unmarshal(nu, dbrio))
				assert.Equals(t, dbrio.CreatedAt, createdAt)
				assert.Equals(t, dbrio.Start, override.Start)
				return nu, true, nil
			},
		}}
		assert.FatalError(t, d.SaveRenewalInfoOverride(context.Background(), override))
	})

	t.Run("get-not-found", func(t *testing.T) {
		d := &DB{db: &db.MockNoSQLDB{
			MGet: func(bucket, key []byte) ([]byte, error) {
				return nil, nosqldb.ErrNotFound
			},
		}}
		_, err := d.GetRenewalInfoOverride(context.Background(), serial)
		assert.True(t, acme.IsErrNotFound(err))
	})

	t.Run("get-ok", func(t *testing.T) {
		b, err := json.Marshal(&dbRenewalInfoOverride{
			Serial:         serial,
			Start:          override.Start,
			End:            override.End,
			ExplanationURL: override.ExplanationURL,
			CreatedAt:      clock.Now(),
			UpdatedAt:      clock.Now(),
		})
		assert.FatalError(t, err)
		d := &DB{db: &db.MockNoSQLDB{
			MGet: func(bucket, key []byte) ([]byte, error) {
				return b, nil
			},
		}}
		got, err := d.GetRenewalInfoOverride(context.Background(), serial)
		assert.FatalError(t, err)
		assert.Equals(t, got, override)
	})

	t.Run("delete", func(t *testing.T) {
		d := &DB{db: &db.MockNoSQLDB{
			MDel: func(bucket, key []byte) error {
				assert.Equals(t, bucket, renewalInfoOverrideTable)
				assert.Equals(t, key, []byte(serial))
				return nil
			},
		}}
		assert.FatalError(t, d.DeleteRenewalInfoOverride(context.Background(), serial))
	})
}

func TestDB_ListRenewalInfoOverrides(t *testing.T) {
	overrides := []*acme.RenewalInfoOverride{
		{
			Serial: "1234567890",
			Start:  time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
			End:    time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			Serial:         "987654321",
			Start:          time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
			End:            time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC),
			ExplanationURL: "https://pki.example.com/incident",
		},
	}

	t.Run("ok", func(t *testing.T) {
		var entries []*nosqldb.Entry
		for _, o := range overrides {
			b, err := json.Marshal(&dbRenewalInfoOverride{
				Serial:         o.Serial,
				Start:          o.Start,
				End:            o.End,
				ExplanationURL: o.ExplanationURL,
				CreatedAt:      clock.Now(),
				UpdatedAt:      clock.Now(),
			})
			assert.FatalError(t, err)
			entries = append(entries, &nosqldb.Entry{
				Bucket: renewalInfoOverrideTable,
				Key:    []byte(o.Serial),
				Value:  b,
			})
		}
		d := &DB{db: &db.MockNoSQLDB{
			MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
				assert.Equals(t, bucket, renewalInfoOverrideTable)
				return entries, nil
			},
		}}
		got, err := d.ListRenewalInfoOverrides(context.Background())
		assert.FatalError(t, err)
		assert.Equals(t, got, overrides)
	})

	t.Run("empty", func(t *testing.T) {
		d := &DB{db: &db.MockNoSQLDB{
			MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
				return nil, nil
			},
		}}
		got, err := d.ListRenewalInfoOverrides(context.Background())
		assert.FatalError(t, err)
		assert.Equals(t, len(got), 0)
	})

	t.Run("fail-unmarshal", func(t *testing.T) {
		d := &DB{db: &db.MockNoSQLDB{
			MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
				return []*nosqldb.Entry{
					{Bucket: renewalInfoOverrideTable, Key: []byte("123"), Value: []byte("not json")},
				}, nil
			},
		}}
		_, err := d.ListRenewalInfoOverrides(context.Background())
		assert.NotNil(t, err)
	})
}

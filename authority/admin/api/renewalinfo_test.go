package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/db"
)

func batchRequest(t *testing.T, ctx context.Context, body interface{}) *http.Request {
	t.Helper()
	b, err := json.Marshal(body)
	assert.FatalError(t, err)
	return httptest.NewRequest("POST", "/admin/acme/renewal-info/batch", bytes.NewReader(b)).WithContext(ctx)
}

func TestBatchSetRenewalInfoOverrideRequest_Validate(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	tests := map[string]struct {
		req     *BatchSetRenewalInfoOverrideRequest
		wantErr bool
	}{
		"ok-serials": {
			req: &BatchSetRenewalInfoOverrideRequest{
				Serials:           []string{"1", "2"},
				RenewalInfoWindow: RenewalInfoWindow{RenewNow: true},
			},
		},
		"ok-filter": {
			req: &BatchSetRenewalInfoOverrideRequest{
				Filter:            &db.CertificateFilter{Provisioner: "acme"},
				RenewalInfoWindow: RenewalInfoWindow{Start: &start, End: &end},
			},
		},
		"fail-no-selection": {
			req:     &BatchSetRenewalInfoOverrideRequest{RenewalInfoWindow: RenewalInfoWindow{RenewNow: true}},
			wantErr: true,
		},
		"fail-serials-and-filter": {
			req: &BatchSetRenewalInfoOverrideRequest{
				Serials:           []string{"1"},
				Filter:            &db.CertificateFilter{Provisioner: "acme"},
				RenewalInfoWindow: RenewalInfoWindow{RenewNow: true},
			},
			wantErr: true,
		},
		"fail-empty-serial": {
			req: &BatchSetRenewalInfoOverrideRequest{
				Serials:           []string{"1", ""},
				RenewalInfoWindow: RenewalInfoWindow{RenewNow: true},
			},
			wantErr: true,
		},
		"fail-invalid-filter-status": {
			req: &BatchSetRenewalInfoOverrideRequest{
				Filter:            &db.CertificateFilter{Status: "bogus"},
				RenewalInfoWindow: RenewalInfoWindow{RenewNow: true},
			},
			wantErr: true,
		},
		"fail-no-window": {
			req:     &BatchSetRenewalInfoOverrideRequest{Serials: []string{"1"}},
			wantErr: true,
		},
		"fail-end-before-start": {
			req: &BatchSetRenewalInfoOverrideRequest{
				Serials:           []string{"1"},
				RenewalInfoWindow: RenewalInfoWindow{Start: &end, End: &start},
			},
			wantErr: true,
		},
		"fail-relative-explanation-url": {
			req: &BatchSetRenewalInfoOverrideRequest{
				Serials:           []string{"1"},
				RenewalInfoWindow: RenewalInfoWindow{RenewNow: true, ExplanationURL: "/incident"},
			},
			wantErr: true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.req.Validate()
			if tc.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestHandler_BatchSetRenewalInfoOverride(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	t.Run("ok-serials", func(t *testing.T) {
		var saved []*acme.RenewalInfoOverride
		acmeDB := &acme.MockDB{
			MockSaveRenewalInfoOverride: func(ctx context.Context, o *acme.RenewalInfoOverride) error {
				saved = append(saved, o)
				return nil
			},
		}
		ctx := acme.NewDatabaseContext(context.Background(), acmeDB)
		req := batchRequest(t, ctx, &BatchSetRenewalInfoOverrideRequest{
			Serials: []string{"1", "2"},
			RenewalInfoWindow: RenewalInfoWindow{
				Start:          &start,
				End:            &end,
				ExplanationURL: "https://pki.example.com/incident",
			},
		})
		w := httptest.NewRecorder()

		BatchSetRenewalInfoOverride(w, req)
		res := w.Result()
		defer res.Body.Close()
		assert.Equals(t, res.StatusCode, http.StatusCreated)

		var body BatchSetRenewalInfoOverrideResponse
		assert.FatalError(t, json.NewDecoder(res.Body).Decode(&body))
		assert.Equals(t, body.Count, 2)
		assert.Equals(t, len(saved), 2)
		assert.Equals(t, saved[0].Serial, "1")
		assert.Equals(t, saved[0].Start, start)
		assert.Equals(t, saved[0].End, end)
		assert.Equals(t, saved[0].ExplanationURL, "https://pki.example.com/incident")
		assert.Equals(t, saved[1].Serial, "2")
	})

	t.Run("ok-filter", func(t *testing.T) {
		var saved []*acme.RenewalInfoOverride
		acmeDB := &acme.MockDB{
			MockSaveRenewalInfoOverride: func(ctx context.Context, o *acme.RenewalInfoOverride) error {
				saved = append(saved, o)
				return nil
			},
		}
		authDB := &db.MockAuthDB{
			MListCertificates: func(filter *db.CertificateFilter) ([]*db.CertificateInfo, error) {
				assert.Equals(t, filter.Provisioner, "acme")
				// without an explicit status the filter selects active certificates only
				assert.Equals(t, filter.Status, db.CertificateStatusActive)
				return []*db.CertificateInfo{
					{Serial: "10", Status: db.CertificateStatusActive},
					{Serial: "11", Status: db.CertificateStatusActive},
				}, nil
			},
		}
		ctx := acme.NewDatabaseContext(db.NewContext(context.Background(), authDB), acmeDB)
		req := batchRequest(t, ctx, &BatchSetRenewalInfoOverrideRequest{
			Filter:            &db.CertificateFilter{Provisioner: "acme"},
			RenewalInfoWindow: RenewalInfoWindow{RenewNow: true},
		})
		w := httptest.NewRecorder()

		BatchSetRenewalInfoOverride(w, req)
		res := w.Result()
		defer res.Body.Close()
		assert.Equals(t, res.StatusCode, http.StatusCreated)

		var body BatchSetRenewalInfoOverrideResponse
		assert.FatalError(t, json.NewDecoder(res.Body).Decode(&body))
		assert.Equals(t, body.Count, 2)
		assert.Equals(t, len(saved), 2)
		assert.Equals(t, saved[0].Serial, "10")
		assert.Equals(t, saved[1].Serial, "11")
		// renewNow yields a window that lies entirely in the past
		assert.True(t, !saved[0].End.After(time.Now()))
		assert.True(t, saved[0].Start.Before(saved[0].End))
	})

	t.Run("fail/no-acme-db", func(t *testing.T) {
		req := batchRequest(t, context.Background(), &BatchSetRenewalInfoOverrideRequest{
			Serials:           []string{"1"},
			RenewalInfoWindow: RenewalInfoWindow{RenewNow: true},
		})
		w := httptest.NewRecorder()
		BatchSetRenewalInfoOverride(w, req)
		res := w.Result()
		res.Body.Close()
		assert.Equals(t, res.StatusCode, http.StatusInternalServerError)
	})

	t.Run("fail/validation", func(t *testing.T) {
		ctx := acme.NewDatabaseContext(context.Background(), &acme.MockDB{})
		req := batchRequest(t, ctx, &BatchSetRenewalInfoOverrideRequest{
			RenewalInfoWindow: RenewalInfoWindow{RenewNow: true},
		})
		w := httptest.NewRecorder()
		BatchSetRenewalInfoOverride(w, req)
		res := w.Result()
		res.Body.Close()
		assert.Equals(t, res.StatusCode, http.StatusBadRequest)
	})

	t.Run("fail/filter-without-authority-db", func(t *testing.T) {
		ctx := acme.NewDatabaseContext(context.Background(), &acme.MockDB{})
		req := batchRequest(t, ctx, &BatchSetRenewalInfoOverrideRequest{
			Filter:            &db.CertificateFilter{Provisioner: "acme"},
			RenewalInfoWindow: RenewalInfoWindow{RenewNow: true},
		})
		w := httptest.NewRecorder()
		BatchSetRenewalInfoOverride(w, req)
		res := w.Result()
		res.Body.Close()
		assert.Equals(t, res.StatusCode, http.StatusInternalServerError)
	})

	t.Run("fail/filter-without-lister-support", func(t *testing.T) {
		ctx := db.NewContext(context.Background(), &noListAuthDB{})
		ctx = acme.NewDatabaseContext(ctx, &acme.MockDB{})
		req := batchRequest(t, ctx, &BatchSetRenewalInfoOverrideRequest{
			Filter:            &db.CertificateFilter{Provisioner: "acme"},
			RenewalInfoWindow: RenewalInfoWindow{RenewNow: true},
		})
		w := httptest.NewRecorder()
		BatchSetRenewalInfoOverride(w, req)
		res := w.Result()
		res.Body.Close()
		assert.Equals(t, res.StatusCode, http.StatusNotImplemented)
	})

	t.Run("fail/list-error", func(t *testing.T) {
		authDB := &db.MockAuthDB{
			MListCertificates: func(filter *db.CertificateFilter) ([]*db.CertificateInfo, error) {
				return nil, errors.New("force")
			},
		}
		ctx := acme.NewDatabaseContext(db.NewContext(context.Background(), authDB), &acme.MockDB{})
		req := batchRequest(t, ctx, &BatchSetRenewalInfoOverrideRequest{
			Filter:            &db.CertificateFilter{Provisioner: "acme"},
			RenewalInfoWindow: RenewalInfoWindow{RenewNow: true},
		})
		w := httptest.NewRecorder()
		BatchSetRenewalInfoOverride(w, req)
		res := w.Result()
		res.Body.Close()
		assert.Equals(t, res.StatusCode, http.StatusInternalServerError)
	})

	t.Run("fail/save-error", func(t *testing.T) {
		acmeDB := &acme.MockDB{
			MockSaveRenewalInfoOverride: func(ctx context.Context, o *acme.RenewalInfoOverride) error {
				return errors.New("force")
			},
		}
		ctx := acme.NewDatabaseContext(context.Background(), acmeDB)
		req := batchRequest(t, ctx, &BatchSetRenewalInfoOverrideRequest{
			Serials:           []string{"1"},
			RenewalInfoWindow: RenewalInfoWindow{RenewNow: true},
		})
		w := httptest.NewRecorder()
		BatchSetRenewalInfoOverride(w, req)
		res := w.Result()
		res.Body.Close()
		assert.Equals(t, res.StatusCode, http.StatusInternalServerError)
	})
}

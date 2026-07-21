package api

import (
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

// noListAuthDB is an AuthDB that does not implement db.CertificateLister.
type noListAuthDB struct {
	db.AuthDB
}

func TestHandler_GetCertificates(t *testing.T) {
	expiresBefore := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	certs := []*db.CertificateInfo{
		{
			Serial:     "1",
			CommonName: "leaf.example.com",
			DNSNames:   []string{"leaf.example.com"},
			NotBefore:  time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:   time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC),
			Status:     db.CertificateStatusActive,
		},
		{
			Serial:     "2",
			CommonName: "other.example.com",
			NotBefore:  time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:   time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC),
			Status:     db.CertificateStatusActive,
		},
	}
	override := &acme.RenewalInfoOverride{
		Serial: "2",
		Start:  time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		End:    time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC),
	}

	t.Run("ok", func(t *testing.T) {
		authDB := &db.MockAuthDB{
			MListCertificates: func(filter *db.CertificateFilter) ([]*db.CertificateInfo, error) {
				assert.Equals(t, filter.CommonName, "leaf.example.com")
				assert.Equals(t, filter.SAN, "leaf.example.com")
				assert.Equals(t, filter.Provisioner, "acme")
				assert.Equals(t, filter.Status, db.CertificateStatusActive)
				assert.Equals(t, filter.ExpiresBefore, expiresBefore)
				return certs, nil
			},
		}
		acmeDB := &acme.MockDB{
			MockListRenewalInfoOverrides: func(ctx context.Context) ([]*acme.RenewalInfoOverride, error) {
				return []*acme.RenewalInfoOverride{override}, nil
			},
		}
		ctx := db.NewContext(context.Background(), authDB)
		ctx = acme.NewDatabaseContext(ctx, acmeDB)
		req := httptest.NewRequest("GET",
			"/admin/certificates?cn=leaf.example.com&san=leaf.example.com&provisioner=acme&status=active&expiresBefore=2026-08-01T00:00:00Z",
			nil).WithContext(ctx)
		w := httptest.NewRecorder()

		GetCertificates(w, req)
		res := w.Result()
		defer res.Body.Close()
		assert.Equals(t, res.StatusCode, http.StatusOK)

		var body GetCertificatesResponse
		assert.FatalError(t, json.NewDecoder(res.Body).Decode(&body))
		assert.Equals(t, len(body.Certificates), 2)
		assert.Equals(t, body.Certificates[0].Serial, "1")
		assert.Nil(t, body.Certificates[0].RenewalInfoOverride)
		assert.Equals(t, body.Certificates[1].Serial, "2")
		assert.Equals(t, body.Certificates[1].RenewalInfoOverride, override)
	})

	t.Run("ok-without-acme-db", func(t *testing.T) {
		authDB := &db.MockAuthDB{
			MListCertificates: func(filter *db.CertificateFilter) ([]*db.CertificateInfo, error) {
				return certs, nil
			},
		}
		ctx := db.NewContext(context.Background(), authDB)
		req := httptest.NewRequest("GET", "/admin/certificates", nil).WithContext(ctx)
		w := httptest.NewRecorder()

		GetCertificates(w, req)
		res := w.Result()
		defer res.Body.Close()
		assert.Equals(t, res.StatusCode, http.StatusOK)

		var body GetCertificatesResponse
		assert.FatalError(t, json.NewDecoder(res.Body).Decode(&body))
		assert.Equals(t, len(body.Certificates), 2)
		assert.Nil(t, body.Certificates[1].RenewalInfoOverride)
	})

	t.Run("fail/no-authority-db", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin/certificates", nil)
		w := httptest.NewRecorder()
		GetCertificates(w, req)
		res := w.Result()
		res.Body.Close()
		assert.Equals(t, res.StatusCode, http.StatusInternalServerError)
	})

	t.Run("fail/no-lister-support", func(t *testing.T) {
		ctx := db.NewContext(context.Background(), &noListAuthDB{})
		req := httptest.NewRequest("GET", "/admin/certificates", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		GetCertificates(w, req)
		res := w.Result()
		res.Body.Close()
		assert.Equals(t, res.StatusCode, http.StatusNotImplemented)
	})

	t.Run("fail/bad-time-param", func(t *testing.T) {
		ctx := db.NewContext(context.Background(), &db.MockAuthDB{})
		req := httptest.NewRequest("GET", "/admin/certificates?expiresBefore=tomorrow", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		GetCertificates(w, req)
		res := w.Result()
		res.Body.Close()
		assert.Equals(t, res.StatusCode, http.StatusBadRequest)
	})

	t.Run("fail/bad-status-param", func(t *testing.T) {
		ctx := db.NewContext(context.Background(), &db.MockAuthDB{})
		req := httptest.NewRequest("GET", "/admin/certificates?status=bogus", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		GetCertificates(w, req)
		res := w.Result()
		res.Body.Close()
		assert.Equals(t, res.StatusCode, http.StatusBadRequest)
	})

	t.Run("fail/list-error", func(t *testing.T) {
		authDB := &db.MockAuthDB{
			MListCertificates: func(filter *db.CertificateFilter) ([]*db.CertificateInfo, error) {
				return nil, errors.New("force")
			},
		}
		ctx := db.NewContext(context.Background(), authDB)
		req := httptest.NewRequest("GET", "/admin/certificates", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		GetCertificates(w, req)
		res := w.Result()
		res.Body.Close()
		assert.Equals(t, res.StatusCode, http.StatusInternalServerError)
	})

	t.Run("fail/list-overrides-error", func(t *testing.T) {
		authDB := &db.MockAuthDB{
			MListCertificates: func(filter *db.CertificateFilter) ([]*db.CertificateInfo, error) {
				return certs, nil
			},
		}
		acmeDB := &acme.MockDB{
			MockListRenewalInfoOverrides: func(ctx context.Context) ([]*acme.RenewalInfoOverride, error) {
				return nil, errors.New("force")
			},
		}
		ctx := db.NewContext(context.Background(), authDB)
		ctx = acme.NewDatabaseContext(ctx, acmeDB)
		req := httptest.NewRequest("GET", "/admin/certificates", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		GetCertificates(w, req)
		res := w.Result()
		res.Body.Close()
		assert.Equals(t, res.StatusCode, http.StatusInternalServerError)
	})
}

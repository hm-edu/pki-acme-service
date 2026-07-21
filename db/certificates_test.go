package db

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/smallstep/nosql/database"
)

func mustCertificate(t *testing.T, serial int64, cn string, notBefore, notAfter time.Time, dnsNames []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	assert.FatalError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.FatalError(t, err)
	return cert
}

func TestDB_ListCertificates(t *testing.T) {
	now := time.Now()
	active := mustCertificate(t, 1, "active.example.com", now.Add(-time.Hour), now.Add(24*time.Hour), []string{"active.example.com"})
	expired := mustCertificate(t, 2, "expired.example.com", now.Add(-48*time.Hour), now.Add(-time.Hour), []string{"expired.example.com"})
	revoked := mustCertificate(t, 3, "revoked.example.com", now.Add(-time.Hour), now.Add(48*time.Hour), []string{"revoked.example.com"})

	provData, err := json.Marshal(&CertificateData{
		Provisioner: &ProvisionerData{ID: "acme/1", Name: "acme", Type: "ACME"},
	})
	assert.FatalError(t, err)

	mock := &MockNoSQLDB{
		MList: func(bucket []byte) ([]*database.Entry, error) {
			switch string(bucket) {
			case string(certsTable):
				return []*database.Entry{
					{Bucket: bucket, Key: []byte("1"), Value: active.Raw},
					{Bucket: bucket, Key: []byte("2"), Value: expired.Raw},
					{Bucket: bucket, Key: []byte("3"), Value: revoked.Raw},
					{Bucket: bucket, Key: []byte("4"), Value: []byte("not a certificate")},
				}, nil
			case string(revokedCertsTable):
				return []*database.Entry{
					{Bucket: bucket, Key: []byte("3"), Value: []byte("{}")},
				}, nil
			case string(certsDataTable):
				return []*database.Entry{
					{Bucket: bucket, Key: []byte("1"), Value: provData},
					{Bucket: bucket, Key: []byte("2"), Value: []byte("not json")},
				}, nil
			default:
				t.Fatalf("unexpected bucket %s", string(bucket))
				return nil, nil
			}
		},
	}
	d := &DB{mock, true}

	t.Run("all", func(t *testing.T) {
		certs, err := d.ListCertificates(nil)
		assert.FatalError(t, err)
		assert.Equals(t, len(certs), 3)
		// sorted by expiration: expired (2), active (1), revoked (3)
		assert.Equals(t, certs[0].Serial, "2")
		assert.Equals(t, certs[0].Status, CertificateStatusExpired)
		assert.Equals(t, certs[1].Serial, "1")
		assert.Equals(t, certs[1].Status, CertificateStatusActive)
		assert.Equals(t, certs[1].CommonName, "active.example.com")
		assert.Equals(t, certs[1].DNSNames, []string{"active.example.com"})
		assert.Equals(t, certs[1].IPAddresses, []string{"127.0.0.1"})
		assert.Equals(t, certs[1].Provisioner, &ProvisionerData{ID: "acme/1", Name: "acme", Type: "ACME"})
		assert.Equals(t, certs[2].Serial, "3")
		assert.Equals(t, certs[2].Status, CertificateStatusRevoked)
		assert.Nil(t, certs[2].Provisioner)
	})

	t.Run("filter-status-active", func(t *testing.T) {
		certs, err := d.ListCertificates(&CertificateFilter{Status: CertificateStatusActive})
		assert.FatalError(t, err)
		assert.Equals(t, len(certs), 1)
		assert.Equals(t, certs[0].Serial, "1")
	})

	t.Run("filter-cn", func(t *testing.T) {
		certs, err := d.ListCertificates(&CertificateFilter{CommonName: "revoked.example.com"})
		assert.FatalError(t, err)
		assert.Equals(t, len(certs), 1)
		assert.Equals(t, certs[0].Serial, "3")
	})

	t.Run("filter-san", func(t *testing.T) {
		certs, err := d.ListCertificates(&CertificateFilter{SAN: "EXPIRED.example.com"})
		assert.FatalError(t, err)
		assert.Equals(t, len(certs), 1)
		assert.Equals(t, certs[0].Serial, "2")
	})

	t.Run("filter-provisioner", func(t *testing.T) {
		certs, err := d.ListCertificates(&CertificateFilter{Provisioner: "acme"})
		assert.FatalError(t, err)
		assert.Equals(t, len(certs), 1)
		assert.Equals(t, certs[0].Serial, "1")
	})

	t.Run("filter-issued-expires", func(t *testing.T) {
		certs, err := d.ListCertificates(&CertificateFilter{
			IssuedAfter:   now.Add(-2 * time.Hour),
			ExpiresBefore: now.Add(36 * time.Hour),
		})
		assert.FatalError(t, err)
		assert.Equals(t, len(certs), 1)
		assert.Equals(t, certs[0].Serial, "1")
	})

	t.Run("filter-no-match", func(t *testing.T) {
		certs, err := d.ListCertificates(&CertificateFilter{CommonName: "missing.example.com"})
		assert.FatalError(t, err)
		assert.Equals(t, len(certs), 0)
	})

	t.Run("invalid-status", func(t *testing.T) {
		_, err := d.ListCertificates(&CertificateFilter{Status: "bogus"})
		assert.NotNil(t, err)
	})

	t.Run("list-error", func(t *testing.T) {
		failing := &DB{&MockNoSQLDB{
			MList: func(bucket []byte) ([]*database.Entry, error) {
				return nil, database.ErrNotFound
			},
		}, true}
		_, err := failing.ListCertificates(nil)
		assert.NotNil(t, err)
	})
}

func TestCertificateFilter_Match(t *testing.T) {
	ci := &CertificateInfo{
		Serial:      "1",
		CommonName:  "leaf.example.com",
		DNSNames:    []string{"leaf.example.com", "alt.example.com"},
		NotBefore:   time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:    time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		Provisioner: &ProvisionerData{Name: "acme"},
		Status:      CertificateStatusActive,
	}

	tests := map[string]struct {
		filter *CertificateFilter
		want   bool
	}{
		"nil filter":           {nil, true},
		"empty filter":         {&CertificateFilter{}, true},
		"cn match":             {&CertificateFilter{CommonName: "leaf.example.com"}, true},
		"cn mismatch":          {&CertificateFilter{CommonName: "other.example.com"}, false},
		"san match":            {&CertificateFilter{SAN: "alt.example.com"}, true},
		"san case-insensitive": {&CertificateFilter{SAN: "ALT.EXAMPLE.COM"}, true},
		"san mismatch":         {&CertificateFilter{SAN: "missing.example.com"}, false},
		"provisioner match":    {&CertificateFilter{Provisioner: "acme"}, true},
		"provisioner mismatch": {&CertificateFilter{Provisioner: "jwk"}, false},
		"status match":         {&CertificateFilter{Status: CertificateStatusActive}, true},
		"status mismatch":      {&CertificateFilter{Status: CertificateStatusRevoked}, false},
		"issued after ok":      {&CertificateFilter{IssuedAfter: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)}, true},
		"issued after fail":    {&CertificateFilter{IssuedAfter: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}, false},
		"issued before ok":     {&CertificateFilter{IssuedBefore: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}, true},
		"issued before fail":   {&CertificateFilter{IssuedBefore: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)}, false},
		"expires after ok":     {&CertificateFilter{ExpiresAfter: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}, true},
		"expires after fail":   {&CertificateFilter{ExpiresAfter: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}, false},
		"expires before ok":    {&CertificateFilter{ExpiresBefore: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}, true},
		"expires before fail":  {&CertificateFilter{ExpiresBefore: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}, false},
		"combined match":       {&CertificateFilter{CommonName: "leaf.example.com", Provisioner: "acme", Status: CertificateStatusActive}, true},
		"combined mismatch":    {&CertificateFilter{CommonName: "leaf.example.com", Provisioner: "jwk"}, false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equals(t, tc.filter.Match(ci), tc.want)
		})
	}
}

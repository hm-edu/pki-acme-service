package db

import (
	"crypto/x509"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// Certificate status values used in CertificateInfo.Status and
// CertificateFilter.Status.
const (
	CertificateStatusActive  = "active"
	CertificateStatusExpired = "expired"
	CertificateStatusRevoked = "revoked"
)

// CertificateInfo describes an x509 certificate stored in the database.
type CertificateInfo struct {
	Serial         string           `json:"serial"`
	CommonName     string           `json:"commonName"`
	DNSNames       []string         `json:"dnsNames,omitempty"`
	IPAddresses    []string         `json:"ipAddresses,omitempty"`
	EmailAddresses []string         `json:"emailAddresses,omitempty"`
	URIs           []string         `json:"uris,omitempty"`
	NotBefore      time.Time        `json:"notBefore"`
	NotAfter       time.Time        `json:"notAfter"`
	Provisioner    *ProvisionerData `json:"provisioner,omitempty"`
	Status         string           `json:"status"`
}

// HasSAN returns whether the certificate contains the given DNS, IP, email or
// URI subject alternative name. DNS names are compared case-insensitively.
func (ci *CertificateInfo) HasSAN(san string) bool {
	for _, sans := range [][]string{ci.DNSNames, ci.IPAddresses, ci.EmailAddresses, ci.URIs} {
		for _, s := range sans {
			if strings.EqualFold(s, san) {
				return true
			}
		}
	}
	return false
}

// CertificateFilter selects stored certificates. Zero-valued fields are
// ignored; all set fields must match.
type CertificateFilter struct {
	// CommonName is an exact match on the subject common name.
	CommonName string `json:"commonName,omitempty"`
	// SAN is an exact match on any DNS, IP, email or URI subject
	// alternative name.
	SAN string `json:"san,omitempty"`
	// Provisioner is an exact match on the name of the provisioner that
	// authorized the certificate.
	Provisioner string `json:"provisioner,omitempty"`
	// Status matches the certificate status: active, expired or revoked.
	Status string `json:"status,omitempty"`
	// IssuedAfter and IssuedBefore bound the certificate notBefore time.
	IssuedAfter  time.Time `json:"issuedAfter,omitempty"`
	IssuedBefore time.Time `json:"issuedBefore,omitempty"`
	// ExpiresAfter and ExpiresBefore bound the certificate notAfter time.
	ExpiresAfter  time.Time `json:"expiresAfter,omitempty"`
	ExpiresBefore time.Time `json:"expiresBefore,omitempty"`
}

// Validate returns an error if the filter contains invalid values.
func (f *CertificateFilter) Validate() error {
	if f == nil {
		return nil
	}
	switch f.Status {
	case "", CertificateStatusActive, CertificateStatusExpired, CertificateStatusRevoked:
		return nil
	default:
		return errors.Errorf("invalid certificate status %q", f.Status)
	}
}

// Match reports whether the certificate matches all criteria set on the
// filter. A nil filter matches every certificate.
func (f *CertificateFilter) Match(ci *CertificateInfo) bool {
	if f == nil {
		return true
	}
	switch {
	case f.CommonName != "" && ci.CommonName != f.CommonName:
		return false
	case f.SAN != "" && !ci.HasSAN(f.SAN):
		return false
	case f.Provisioner != "" && (ci.Provisioner == nil || ci.Provisioner.Name != f.Provisioner):
		return false
	case f.Status != "" && ci.Status != f.Status:
		return false
	case !f.IssuedAfter.IsZero() && ci.NotBefore.Before(f.IssuedAfter):
		return false
	case !f.IssuedBefore.IsZero() && !ci.NotBefore.Before(f.IssuedBefore):
		return false
	case !f.ExpiresAfter.IsZero() && ci.NotAfter.Before(f.ExpiresAfter):
		return false
	case !f.ExpiresBefore.IsZero() && !ci.NotAfter.Before(f.ExpiresBefore):
		return false
	default:
		return true
	}
}

// CertificateLister is an extension of AuthDB that allows listing the stored
// x509 certificates.
type CertificateLister interface {
	ListCertificates(filter *CertificateFilter) ([]*CertificateInfo, error)
}

// newCertificateInfo builds the CertificateInfo for a stored certificate.
func newCertificateInfo(cert *x509.Certificate, prov *ProvisionerData, revoked bool, now time.Time) *CertificateInfo {
	status := CertificateStatusActive
	switch {
	case revoked:
		status = CertificateStatusRevoked
	case now.After(cert.NotAfter):
		status = CertificateStatusExpired
	}
	ci := &CertificateInfo{
		Serial:         cert.SerialNumber.String(),
		CommonName:     cert.Subject.CommonName,
		DNSNames:       cert.DNSNames,
		EmailAddresses: cert.EmailAddresses,
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		Provisioner:    prov,
		Status:         status,
	}
	for _, ip := range cert.IPAddresses {
		ci.IPAddresses = append(ci.IPAddresses, ip.String())
	}
	for _, u := range cert.URIs {
		ci.URIs = append(ci.URIs, u.String())
	}
	return ci
}

// ListCertificates returns information about the stored x509 certificates
// matching the given filter, sorted by expiration time. A nil filter matches
// all certificates.
func (db *DB) ListCertificates(filter *CertificateFilter) ([]*CertificateInfo, error) {
	if err := filter.Validate(); err != nil {
		return nil, err
	}

	entries, err := db.List(certsTable)
	if err != nil {
		return nil, errors.Wrap(err, "error listing certificates")
	}

	revokedEntries, err := db.List(revokedCertsTable)
	if err != nil {
		return nil, errors.Wrap(err, "error listing revoked certificates")
	}
	revoked := make(map[string]bool, len(revokedEntries))
	for _, e := range revokedEntries {
		revoked[string(e.Key)] = true
	}

	dataEntries, err := db.List(certsDataTable)
	if err != nil {
		return nil, errors.Wrap(err, "error listing certificate data")
	}
	provisioners := make(map[string]*ProvisionerData, len(dataEntries))
	for _, e := range dataEntries {
		var data CertificateData
		if err := json.Unmarshal(e.Value, &data); err != nil {
			continue
		}
		provisioners[string(e.Key)] = data.Provisioner
	}

	now := time.Now()
	var certs []*CertificateInfo
	for _, e := range entries {
		cert, err := x509.ParseCertificate(e.Value)
		if err != nil {
			// skip entries that do not contain a parseable certificate
			continue
		}
		serial := string(e.Key)
		ci := newCertificateInfo(cert, provisioners[serial], revoked[serial], now)
		if filter.Match(ci) {
			certs = append(certs, ci)
		}
	}

	sort.Slice(certs, func(i, j int) bool {
		if certs[i].NotAfter.Equal(certs[j].NotAfter) {
			return certs[i].Serial < certs[j].Serial
		}
		return certs[i].NotAfter.Before(certs[j].NotAfter)
	})
	return certs, nil
}

package api

import (
	"net/http"
	"time"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/db"
)

// Certificate is the certificate resource returned by GET
// /admin/certificates. It extends the stored certificate information with the
// manual ACME renewal window, if one is configured.
type Certificate struct {
	*db.CertificateInfo
	RenewalInfoOverride *acme.RenewalInfoOverride `json:"renewalInfoOverride,omitempty"`
}

// GetCertificatesResponse is the response for GET /admin/certificates
// requests.
type GetCertificatesResponse struct {
	Certificates []*Certificate `json:"certificates"`
}

// certificateFilterFromQuery builds a certificate filter from the request
// query parameters cn, san, provisioner, status, issuedAfter, issuedBefore,
// expiresAfter and expiresBefore.
func certificateFilterFromQuery(r *http.Request) (*db.CertificateFilter, error) {
	q := r.URL.Query()
	filter := &db.CertificateFilter{
		CommonName:  q.Get("cn"),
		SAN:         q.Get("san"),
		Provisioner: q.Get("provisioner"),
		Status:      q.Get("status"),
	}
	for name, target := range map[string]*time.Time{
		"issuedAfter":   &filter.IssuedAfter,
		"issuedBefore":  &filter.IssuedBefore,
		"expiresAfter":  &filter.ExpiresAfter,
		"expiresBefore": &filter.ExpiresBefore,
	} {
		if value := q.Get(name); value != "" {
			t, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return nil, admin.WrapError(admin.ErrorBadRequestType, err, "error parsing %s", name)
			}
			*target = t
		}
	}
	if err := filter.Validate(); err != nil {
		return nil, admin.WrapError(admin.ErrorBadRequestType, err, "invalid filter")
	}
	return filter, nil
}

// GetCertificates handles GET /admin/certificates requests and returns the
// x509 certificates stored in the database, annotated with their manual ACME
// renewal windows. The list can be narrowed with the cn, san, provisioner,
// status, issuedAfter, issuedBefore, expiresAfter and expiresBefore query
// parameters.
func GetCertificates(w http.ResponseWriter, r *http.Request) {
	authDB, ok := db.FromContext(r.Context())
	if !ok {
		render.Error(w, r, admin.NewError(admin.ErrorServerInternalType, "authority database is not configured"))
		return
	}
	lister, ok := authDB.(db.CertificateLister)
	if !ok {
		render.Error(w, r, admin.NewError(admin.ErrorNotImplementedType, "database does not support listing certificates"))
		return
	}

	filter, err := certificateFilterFromQuery(r)
	if err != nil {
		render.Error(w, r, err)
		return
	}

	certs, err := lister.ListCertificates(filter)
	if err != nil {
		render.Error(w, r, admin.WrapErrorISE(err, "error listing certificates"))
		return
	}

	// The ACME database is optional here; without it the certificates are
	// returned without renewal info overrides.
	overrides := make(map[string]*acme.RenewalInfoOverride)
	if acmeDB, ok := acme.DatabaseFromContext(r.Context()); ok && acmeDB != nil {
		list, err := acmeDB.ListRenewalInfoOverrides(r.Context())
		if err != nil {
			render.Error(w, r, admin.WrapErrorISE(err, "error listing renewal info overrides"))
			return
		}
		for _, o := range list {
			overrides[o.Serial] = o
		}
	}

	resp := &GetCertificatesResponse{
		Certificates: make([]*Certificate, len(certs)),
	}
	for i, ci := range certs {
		resp.Certificates[i] = &Certificate{
			CertificateInfo:     ci,
			RenewalInfoOverride: overrides[ci.Serial],
		}
	}
	render.JSON(w, r, resp)
}

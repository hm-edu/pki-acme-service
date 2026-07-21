package api

import (
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/read"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/db"
)

// RenewalInfoWindow is the manual renewal window shared by the single and
// batch override requests. Either RenewNow must be true or an explicit window
// must be given via Start and End.
type RenewalInfoWindow struct {
	RenewNow       bool       `json:"renewNow,omitempty"`
	Start          *time.Time `json:"start,omitempty"`
	End            *time.Time `json:"end,omitempty"`
	ExplanationURL string     `json:"explanationURL,omitempty"`
}

// Validate validates the manual renewal window.
func (r *RenewalInfoWindow) Validate() error {
	if !r.RenewNow {
		if r.Start == nil || r.End == nil {
			return admin.NewError(admin.ErrorBadRequestType, "either renewNow or both start and end are required")
		}
		if !r.End.After(*r.Start) {
			return admin.NewError(admin.ErrorBadRequestType, "end must be after start")
		}
	}
	if r.ExplanationURL != "" {
		u, err := url.Parse(r.ExplanationURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return admin.NewError(admin.ErrorBadRequestType, "explanationURL must be an absolute URL")
		}
	}
	return nil
}

// override returns the renewal info override for the given serial. With
// RenewNow the window lies entirely in the past, which signals ACME clients
// to renew immediately.
func (r *RenewalInfoWindow) override(serial string) *acme.RenewalInfoOverride {
	override := &acme.RenewalInfoOverride{
		Serial:         serial,
		ExplanationURL: r.ExplanationURL,
	}
	if r.RenewNow {
		now := time.Now().UTC().Truncate(time.Second)
		override.Start = now.Add(-24 * time.Hour)
		override.End = now
	} else {
		override.Start = r.Start.UTC()
		override.End = r.End.UTC()
	}
	return override
}

// SetRenewalInfoOverrideRequest is the type for POST /admin/acme/renewal-info
// requests.
type SetRenewalInfoOverrideRequest struct {
	Serial string `json:"serial"`
	RenewalInfoWindow
}

// Validate validates a renewal info override request body.
func (r *SetRenewalInfoOverrideRequest) Validate() error {
	if r.Serial == "" {
		return admin.NewError(admin.ErrorBadRequestType, "serial is required")
	}
	return r.RenewalInfoWindow.Validate()
}

// BatchSetRenewalInfoOverrideRequest is the type for POST
// /admin/acme/renewal-info/batch requests. The certificates are selected
// either by an explicit list of serials or by a certificate filter, and the
// same renewal window is applied to all of them.
type BatchSetRenewalInfoOverrideRequest struct {
	Serials []string              `json:"serials,omitempty"`
	Filter  *db.CertificateFilter `json:"filter,omitempty"`
	RenewalInfoWindow
}

// Validate validates a batch renewal info override request body.
func (r *BatchSetRenewalInfoOverrideRequest) Validate() error {
	switch {
	case len(r.Serials) == 0 && r.Filter == nil:
		return admin.NewError(admin.ErrorBadRequestType, "either serials or filter is required")
	case len(r.Serials) > 0 && r.Filter != nil:
		return admin.NewError(admin.ErrorBadRequestType, "serials and filter are mutually exclusive")
	}
	for _, serial := range r.Serials {
		if serial == "" {
			return admin.NewError(admin.ErrorBadRequestType, "serials must not contain empty values")
		}
	}
	if err := r.Filter.Validate(); err != nil {
		return admin.WrapError(admin.ErrorBadRequestType, err, "invalid filter")
	}
	return r.RenewalInfoWindow.Validate()
}

// BatchSetRenewalInfoOverrideResponse is the response for POST
// /admin/acme/renewal-info/batch requests.
type BatchSetRenewalInfoOverrideResponse struct {
	Overrides []*acme.RenewalInfoOverride `json:"overrides"`
	Count     int                         `json:"count"`
}

// requireACMEDatabase returns the ACME database from the request context or
// renders an error if it is not configured.
func requireACMEDatabase(w http.ResponseWriter, r *http.Request) (acme.DB, bool) {
	acmeDB, ok := acme.DatabaseFromContext(r.Context())
	if !ok || acmeDB == nil {
		render.Error(w, r, admin.NewError(admin.ErrorServerInternalType, "acme database is not configured"))
		return nil, false
	}
	return acmeDB, true
}

// SetRenewalInfoOverride handles POST /admin/acme/renewal-info requests. It
// stores a manual renewal window for a certificate serial that is served by
// the ACME renewalInfo endpoint (RFC 9773) instead of the default window.
func SetRenewalInfoOverride(w http.ResponseWriter, r *http.Request) {
	acmeDB, ok := requireACMEDatabase(w, r)
	if !ok {
		return
	}

	var body SetRenewalInfoOverrideRequest
	if err := read.JSON(r.Body, &body); err != nil {
		render.Error(w, r, admin.WrapError(admin.ErrorBadRequestType, err, "error reading request body"))
		return
	}
	if err := body.Validate(); err != nil {
		render.Error(w, r, err)
		return
	}

	override := body.override(body.Serial)
	if err := acmeDB.SaveRenewalInfoOverride(r.Context(), override); err != nil {
		render.Error(w, r, admin.WrapErrorISE(err, "error saving renewal info override for serial %s", body.Serial))
		return
	}

	render.JSONStatus(w, r, override, http.StatusCreated)
}

// BatchSetRenewalInfoOverride handles POST /admin/acme/renewal-info/batch
// requests. It stores the same manual renewal window for a set of
// certificates, selected either by an explicit list of serials or by a
// certificate filter. When a filter is used, only active (not expired, not
// revoked) certificates are selected unless the filter specifies a status.
func BatchSetRenewalInfoOverride(w http.ResponseWriter, r *http.Request) {
	acmeDB, ok := requireACMEDatabase(w, r)
	if !ok {
		return
	}

	var body BatchSetRenewalInfoOverrideRequest
	if err := read.JSON(r.Body, &body); err != nil {
		render.Error(w, r, admin.WrapError(admin.ErrorBadRequestType, err, "error reading request body"))
		return
	}
	if err := body.Validate(); err != nil {
		render.Error(w, r, err)
		return
	}

	serials := body.Serials
	if body.Filter != nil {
		authDB, dbOK := db.FromContext(r.Context())
		if !dbOK {
			render.Error(w, r, admin.NewError(admin.ErrorServerInternalType, "authority database is not configured"))
			return
		}
		lister, listerOK := authDB.(db.CertificateLister)
		if !listerOK {
			render.Error(w, r, admin.NewError(admin.ErrorNotImplementedType, "database does not support listing certificates"))
			return
		}
		if body.Filter.Status == "" {
			body.Filter.Status = db.CertificateStatusActive
		}
		certs, err := lister.ListCertificates(body.Filter)
		if err != nil {
			render.Error(w, r, admin.WrapErrorISE(err, "error listing certificates"))
			return
		}
		serials = make([]string, len(certs))
		for i, cert := range certs {
			serials[i] = cert.Serial
		}
	}

	overrides := make([]*acme.RenewalInfoOverride, 0, len(serials))
	for _, serial := range serials {
		override := body.override(serial)
		if err := acmeDB.SaveRenewalInfoOverride(r.Context(), override); err != nil {
			render.Error(w, r, admin.WrapErrorISE(err, "error saving renewal info override for serial %s (%d of %d overrides saved)", serial, len(overrides), len(serials)))
			return
		}
		overrides = append(overrides, override)
	}

	render.JSONStatus(w, r, &BatchSetRenewalInfoOverrideResponse{
		Overrides: overrides,
		Count:     len(overrides),
	}, http.StatusCreated)
}

// GetRenewalInfoOverride handles GET /admin/acme/renewal-info/{serial}
// requests and returns the stored manual renewal window for the serial.
func GetRenewalInfoOverride(w http.ResponseWriter, r *http.Request) {
	acmeDB, ok := requireACMEDatabase(w, r)
	if !ok {
		return
	}

	serial := chi.URLParam(r, "serial")
	override, err := acmeDB.GetRenewalInfoOverride(r.Context(), serial)
	if err != nil {
		if acme.IsErrNotFound(err) {
			render.Error(w, r, admin.NewError(admin.ErrorNotFoundType, "no renewal info override for serial %s", serial))
			return
		}
		render.Error(w, r, admin.WrapErrorISE(err, "error retrieving renewal info override for serial %s", serial))
		return
	}

	render.JSON(w, r, override)
}

// DeleteRenewalInfoOverride handles DELETE /admin/acme/renewal-info/{serial}
// requests and removes the stored manual renewal window for the serial.
func DeleteRenewalInfoOverride(w http.ResponseWriter, r *http.Request) {
	acmeDB, ok := requireACMEDatabase(w, r)
	if !ok {
		return
	}

	serial := chi.URLParam(r, "serial")
	if err := acmeDB.DeleteRenewalInfoOverride(r.Context(), serial); err != nil {
		render.Error(w, r, admin.WrapErrorISE(err, "error deleting renewal info override for serial %s", serial))
		return
	}

	render.JSON(w, r, &DeleteResponse{Status: "ok"})
}

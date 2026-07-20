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
)

// SetRenewalInfoOverrideRequest is the type for POST /admin/acme/renewal-info
// requests. Either RenewNow must be true or an explicit window must be given
// via Start and End.
type SetRenewalInfoOverrideRequest struct {
	Serial         string     `json:"serial"`
	RenewNow       bool       `json:"renewNow,omitempty"`
	Start          *time.Time `json:"start,omitempty"`
	End            *time.Time `json:"end,omitempty"`
	ExplanationURL string     `json:"explanationURL,omitempty"`
}

// Validate validates a renewal info override request body.
func (r *SetRenewalInfoOverrideRequest) Validate() error {
	if r.Serial == "" {
		return admin.NewError(admin.ErrorBadRequestType, "serial is required")
	}
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

// requireACMEDatabase returns the ACME database from the request context or
// renders an error if it is not configured.
func requireACMEDatabase(w http.ResponseWriter, r *http.Request) (acme.DB, bool) {
	db, ok := acme.DatabaseFromContext(r.Context())
	if !ok || db == nil {
		render.Error(w, r, admin.NewError(admin.ErrorServerInternalType, "acme database is not configured"))
		return nil, false
	}
	return db, true
}

// SetRenewalInfoOverride handles POST /admin/acme/renewal-info requests. It
// stores a manual renewal window for a certificate serial that is served by
// the ACME renewalInfo endpoint (RFC 9773) instead of the default window.
func SetRenewalInfoOverride(w http.ResponseWriter, r *http.Request) {
	db, ok := requireACMEDatabase(w, r)
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

	override := &acme.RenewalInfoOverride{
		Serial:         body.Serial,
		ExplanationURL: body.ExplanationURL,
	}
	if body.RenewNow {
		// A window that lies entirely in the past signals ACME clients to
		// renew immediately.
		now := time.Now().UTC().Truncate(time.Second)
		override.Start = now.Add(-24 * time.Hour)
		override.End = now
	} else {
		override.Start = body.Start.UTC()
		override.End = body.End.UTC()
	}

	if err := db.SaveRenewalInfoOverride(r.Context(), override); err != nil {
		render.Error(w, r, admin.WrapErrorISE(err, "error saving renewal info override for serial %s", body.Serial))
		return
	}

	render.JSONStatus(w, r, override, http.StatusCreated)
}

// GetRenewalInfoOverride handles GET /admin/acme/renewal-info/{serial}
// requests and returns the stored manual renewal window for the serial.
func GetRenewalInfoOverride(w http.ResponseWriter, r *http.Request) {
	db, ok := requireACMEDatabase(w, r)
	if !ok {
		return
	}

	serial := chi.URLParam(r, "serial")
	override, err := db.GetRenewalInfoOverride(r.Context(), serial)
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
	db, ok := requireACMEDatabase(w, r)
	if !ok {
		return
	}

	serial := chi.URLParam(r, "serial")
	if err := db.DeleteRenewalInfoOverride(r.Context(), serial); err != nil {
		render.Error(w, r, admin.WrapErrorISE(err, "error deleting renewal info override for serial %s", serial))
		return
	}

	render.JSON(w, r, &DeleteResponse{Status: "ok"})
}

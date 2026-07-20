package api

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/render"
)

// renewalInfoRetryAfter is the polling interval in seconds suggested to ACME
// clients via the Retry-After header on renewalInfo responses (RFC 9773).
const renewalInfoRetryAfter = "21600" // 6 hours

// GetRenewalInfo is the ACME renewalInfo resource defined in RFC 9773. It is
// served on unauthenticated GET requests; the certificate is identified by
// the certID path segment (base64url(AKI) "." base64url(serial)).
func GetRenewalInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)

	aki, serial, err := acme.ParseCertID(chi.URLParam(r, "certID"))
	if err != nil {
		render.Error(w, r, err)
		return
	}

	cert, err := db.GetCertificateBySerial(ctx, serial)
	if err != nil {
		var ae *acme.Error
		if errors.As(err, &ae) && ae.Status < 500 {
			// RFC 9773 requires a 404 for certificates the server has no
			// record of.
			ae.Status = http.StatusNotFound
			render.Error(w, r, ae)
			return
		}
		render.Error(w, r, acme.WrapErrorISE(err, "error retrieving certificate with serial %s", serial))
		return
	}
	if !acme.MatchesCertID(cert.Leaf, aki, serial) {
		notFound := acme.NewError(acme.ErrorMalformedType, "no certificate found for the given certID")
		notFound.Status = http.StatusNotFound
		render.Error(w, r, notFound)
		return
	}

	renewalInfo := acme.DefaultRenewalInfo(cert.Leaf)
	if override, err := db.GetRenewalInfoOverride(ctx, serial); err == nil {
		renewalInfo = override.RenewalInfo()
	} else if !acme.IsErrNotFound(err) {
		render.Error(w, r, acme.WrapErrorISE(err, "error retrieving renewal info override for serial %s", serial))
		return
	}

	w.Header().Set("Retry-After", renewalInfoRetryAfter)
	render.JSON(w, r, renewalInfo)
}

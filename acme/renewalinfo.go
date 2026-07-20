package acme

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"strings"
	"time"
)

// RenewalInfo is the renewal info resource returned by the ACME renewalInfo
// endpoint defined in RFC 9773 (ACME Renewal Information Extension).
type RenewalInfo struct {
	SuggestedWindow SuggestedWindow `json:"suggestedWindow"`
	ExplanationURL  string          `json:"explanationURL,omitempty"`
}

// SuggestedWindow is the window of time in which RFC 9773 suggests the
// certificate should be renewed.
type SuggestedWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// RenewalInfoOverride is a manually configured renewal window for a single
// certificate, identified by its serial number. When present, the renewalInfo
// endpoint returns this window instead of the default policy, e.g. to signal
// clients that a certificate must be replaced immediately.
type RenewalInfoOverride struct {
	Serial         string    `json:"serial"`
	Start          time.Time `json:"start"`
	End            time.Time `json:"end"`
	ExplanationURL string    `json:"explanationURL,omitempty"`
}

// ParseCertID parses an RFC 9773 certificate identifier of the form
// base64url(AKI keyIdentifier) "." base64url(DER serial number) and returns
// the authority key identifier bytes and the serial number in the decimal
// string representation used to index certificates in the database.
func ParseCertID(certID string) (aki []byte, serial string, err error) {
	akiPart, serialPart, found := strings.Cut(certID, ".")
	if !found {
		return nil, "", NewError(ErrorMalformedType, "certID %q is not of the form <aki>.<serial>", certID)
	}
	aki, err = base64.RawURLEncoding.DecodeString(akiPart)
	if err != nil {
		return nil, "", WrapError(ErrorMalformedType, err, "error base64url decoding authority key identifier %q", akiPart)
	}
	serialBytes, err := base64.RawURLEncoding.DecodeString(serialPart)
	if err != nil {
		return nil, "", WrapError(ErrorMalformedType, err, "error base64url decoding serial number %q", serialPart)
	}
	if len(aki) == 0 || len(serialBytes) == 0 {
		return nil, "", NewError(ErrorMalformedType, "certID %q contains an empty component", certID)
	}
	// Serial numbers are positive per RFC 5280, so the DER integer bytes can
	// be interpreted as an unsigned big-endian integer; a leading 0x00 pad
	// byte does not change the value.
	return aki, new(big.Int).SetBytes(serialBytes).String(), nil
}

// CertID returns the RFC 9773 certificate identifier for the given leaf
// certificate: base64url(AKI keyIdentifier) "." base64url(DER serial number).
func CertID(leaf *x509.Certificate) string {
	serialBytes := leaf.SerialNumber.Bytes()
	if len(serialBytes) == 0 {
		serialBytes = []byte{0}
	}
	// DER encodes integers in two's complement, so positive serials with the
	// high bit set are prefixed with a zero byte.
	if serialBytes[0]&0x80 != 0 {
		serialBytes = append([]byte{0}, serialBytes...)
	}
	return base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId) +
		"." + base64.RawURLEncoding.EncodeToString(serialBytes)
}

// MatchesCertID returns true if the given authority key identifier and serial
// belong to the given leaf certificate.
func MatchesCertID(leaf *x509.Certificate, aki []byte, serial string) bool {
	return bytes.Equal(leaf.AuthorityKeyId, aki) && leaf.SerialNumber.String() == serial
}

// DefaultRenewalInfo returns the renewal info for a certificate without a
// manual override: a window centered at 2/3 of the certificate lifetime with
// a width of 1/24 of the lifetime, clamped to the certificate validity.
func DefaultRenewalInfo(leaf *x509.Certificate) *RenewalInfo {
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	center := leaf.NotBefore.Add(lifetime * 2 / 3)
	halfWidth := lifetime / 48

	start := center.Add(-halfWidth)
	end := center.Add(halfWidth)
	if start.Before(leaf.NotBefore) {
		start = leaf.NotBefore
	}
	if end.After(leaf.NotAfter) {
		end = leaf.NotAfter
	}

	return &RenewalInfo{
		SuggestedWindow: SuggestedWindow{
			Start: start.UTC().Truncate(time.Second),
			End:   end.UTC().Truncate(time.Second),
		},
	}
}

// RenewalInfo returns the RFC 9773 renewal info resource represented by the
// override.
func (o *RenewalInfoOverride) RenewalInfo() *RenewalInfo {
	return &RenewalInfo{
		SuggestedWindow: SuggestedWindow{
			Start: o.Start.UTC().Truncate(time.Second),
			End:   o.End.UTC().Truncate(time.Second),
		},
		ExplanationURL: o.ExplanationURL,
	}
}

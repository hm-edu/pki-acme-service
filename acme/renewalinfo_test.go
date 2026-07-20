package acme

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLeaf(serial *big.Int, aki []byte, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:   serial,
		AuthorityKeyId: aki,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
	}
}

func TestCertID_RoundTrip(t *testing.T) {
	aki := []byte{0x69, 0x88, 0x5b, 0x6b, 0x87, 0x46, 0x40, 0x41}

	tests := map[string]*big.Int{
		"small serial":        big.NewInt(1234567890),
		"high bit set serial": new(big.Int).SetBytes([]byte{0x87, 0x65, 0x43, 0x21, 0x00, 0xff}),
		"zero serial":         big.NewInt(0),
	}
	for name, serial := range tests {
		t.Run(name, func(t *testing.T) {
			leaf := newTestLeaf(serial, aki, time.Now(), time.Now().Add(time.Hour))
			certID := CertID(leaf)

			gotAKI, gotSerial, err := ParseCertID(certID)
			require.NoError(t, err)
			assert.Equal(t, aki, gotAKI)
			assert.Equal(t, serial.String(), gotSerial)
			assert.True(t, MatchesCertID(leaf, gotAKI, gotSerial))
		})
	}
}

func TestCertID_KnownValue(t *testing.T) {
	// Example from RFC 9773: AKI 69:88:5B:6B:87:46:40:41 and serial
	// 00:87:65:43:21 yield "aYhba4dGQEE.AIdlQyE".
	leaf := newTestLeaf(
		new(big.Int).SetBytes([]byte{0x87, 0x65, 0x43, 0x21}),
		[]byte{0x69, 0x88, 0x5b, 0x6b, 0x87, 0x46, 0x40, 0x41},
		time.Now(), time.Now().Add(time.Hour),
	)
	assert.Equal(t, "aYhba4dGQEE.AIdlQyE", CertID(leaf))
}

func TestParseCertID_Errors(t *testing.T) {
	tests := map[string]string{
		"missing separator": "aYhba4dGQEE",
		"empty aki":         ".AIdlQyE",
		"empty serial":      "aYhba4dGQEE.",
		"invalid base64":    "aYhba4dGQEE.AIdl!yE",
		"padded base64":     "aYhba4dGQEE=.AIdlQyE",
	}
	for name, certID := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := ParseCertID(certID)
			require.Error(t, err)
			var ae *Error
			require.ErrorAs(t, err, &ae)
			assert.Equal(t, 400, ae.Status)
		})
	}
}

func TestDefaultRenewalInfo(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(90 * 24 * time.Hour)
	leaf := newTestLeaf(big.NewInt(1), []byte{0x01}, notBefore, notAfter)

	ri := DefaultRenewalInfo(leaf)

	lifetime := notAfter.Sub(notBefore)
	center := notBefore.Add(lifetime * 2 / 3)
	assert.Equal(t, center.Add(-lifetime/48), ri.SuggestedWindow.Start)
	assert.Equal(t, center.Add(lifetime/48), ri.SuggestedWindow.End)
	assert.True(t, ri.SuggestedWindow.Start.Before(ri.SuggestedWindow.End))
	assert.False(t, ri.SuggestedWindow.Start.Before(notBefore))
	assert.False(t, ri.SuggestedWindow.End.After(notAfter))
	assert.Empty(t, ri.ExplanationURL)
}

func TestRenewalInfoOverride_RenewalInfo(t *testing.T) {
	start := time.Date(2026, 7, 1, 12, 0, 0, 0, time.FixedZone("CEST", 2*3600))
	end := start.Add(24 * time.Hour)
	o := &RenewalInfoOverride{
		Serial:         "1234",
		Start:          start,
		End:            end,
		ExplanationURL: "https://pki.example.com/incident",
	}

	ri := o.RenewalInfo()
	assert.Equal(t, start.UTC(), ri.SuggestedWindow.Start)
	assert.Equal(t, end.UTC(), ri.SuggestedWindow.End)
	assert.Equal(t, "https://pki.example.com/incident", ri.ExplanationURL)
}

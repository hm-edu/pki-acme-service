package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/certificates/acme"
)

func TestHandler_GetRenewalInfo(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(90 * 24 * time.Hour)
	leaf := &x509.Certificate{
		SerialNumber:   big.NewInt(1234567890),
		AuthorityKeyId: []byte{0x69, 0x88, 0x5b, 0x6b, 0x87, 0x46, 0x40, 0x41},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
	}
	serial := leaf.SerialNumber.String()
	certID := acme.CertID(leaf)

	prov := newProv()
	provName := url.PathEscape(prov.GetName())
	baseURL := &url.URL{Scheme: "https", Host: "test.ca.smallstep.com"}

	newContext := func(certID string) context.Context {
		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("certID", certID)
		return context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
	}

	type test struct {
		db          acme.DB
		ctx         context.Context
		statusCode  int
		wantErrType string
		want        *acme.RenewalInfo
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/malformed-certID": func(t *testing.T) test {
			return test{
				db:          &acme.MockDB{},
				ctx:         newContext("not-a-cert-id"),
				statusCode:  400,
				wantErrType: "urn:ietf:params:acme:error:malformed",
			}
		},
		"fail/certificate-not-found": func(t *testing.T) test {
			return test{
				db: &acme.MockDB{
					MockGetCertificateBySerial: func(ctx context.Context, s string) (*acme.Certificate, error) {
						assert.Equal(t, serial, s)
						return nil, acme.NewError(acme.ErrorMalformedType, "certificate with serial %s not found", s)
					},
				},
				ctx:         newContext(certID),
				statusCode:  404,
				wantErrType: "urn:ietf:params:acme:error:malformed",
			}
		},
		"fail/db-error": func(t *testing.T) test {
			return test{
				db: &acme.MockDB{
					MockGetCertificateBySerial: func(ctx context.Context, s string) (*acme.Certificate, error) {
						return nil, acme.NewErrorISE("force")
					},
				},
				ctx:         newContext(certID),
				statusCode:  500,
				wantErrType: "urn:ietf:params:acme:error:serverInternal",
			}
		},
		"fail/aki-mismatch": func(t *testing.T) test {
			otherLeaf := &x509.Certificate{
				SerialNumber:   leaf.SerialNumber,
				AuthorityKeyId: []byte{0xff, 0xff},
				NotBefore:      notBefore,
				NotAfter:       notAfter,
			}
			return test{
				db: &acme.MockDB{
					MockGetCertificateBySerial: func(ctx context.Context, s string) (*acme.Certificate, error) {
						return &acme.Certificate{Leaf: otherLeaf}, nil
					},
				},
				ctx:         newContext(certID),
				statusCode:  404,
				wantErrType: "urn:ietf:params:acme:error:malformed",
			}
		},
		"ok/default-window": func(t *testing.T) test {
			return test{
				db: &acme.MockDB{
					MockGetCertificateBySerial: func(ctx context.Context, s string) (*acme.Certificate, error) {
						return &acme.Certificate{Leaf: leaf}, nil
					},
					MockGetRenewalInfoOverride: func(ctx context.Context, s string) (*acme.RenewalInfoOverride, error) {
						assert.Equal(t, serial, s)
						return nil, acme.ErrNotFound
					},
				},
				ctx:        newContext(certID),
				statusCode: 200,
				want:       acme.DefaultRenewalInfo(leaf),
			}
		},
		"ok/override": func(t *testing.T) test {
			override := &acme.RenewalInfoOverride{
				Serial:         serial,
				Start:          time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
				End:            time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC),
				ExplanationURL: "https://pki.example.com/incident",
			}
			return test{
				db: &acme.MockDB{
					MockGetCertificateBySerial: func(ctx context.Context, s string) (*acme.Certificate, error) {
						return &acme.Certificate{Leaf: leaf}, nil
					},
					MockGetRenewalInfoOverride: func(ctx context.Context, s string) (*acme.RenewalInfoOverride, error) {
						return override, nil
					},
				},
				ctx:        newContext(certID),
				statusCode: 200,
				want:       override.RenewalInfo(),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			ctx := acme.NewDatabaseContext(tc.ctx, tc.db)
			u := fmt.Sprintf("%s/acme/%s/renewal-info/%s", baseURL.String(), provName, certID)
			req := httptest.NewRequest("GET", u, http.NoBody)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			GetRenewalInfo(w, req)
			res := w.Result()
			defer res.Body.Close()

			assert.Equal(t, tc.statusCode, res.StatusCode)

			if tc.statusCode >= 400 {
				var ae acme.Error
				require.NoError(t, json.NewDecoder(res.Body).Decode(&ae))
				assert.Equal(t, tc.wantErrType, ae.Type)
				assert.Equal(t, []string{"application/problem+json"}, res.Header["Content-Type"])
				return
			}

			var ri acme.RenewalInfo
			require.NoError(t, json.NewDecoder(res.Body).Decode(&ri))
			assert.Equal(t, *tc.want, ri)
			assert.Equal(t, renewalInfoRetryAfter, res.Header.Get("Retry-After"))
			assert.Equal(t, []string{"application/json"}, res.Header["Content-Type"])
		})
	}
}

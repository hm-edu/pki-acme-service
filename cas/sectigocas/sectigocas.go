package sectigocas

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/acme/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/monitoring"

	pb "github.com/hm-edu/portal-apis"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/smallstep/certificates/cas/apiv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// issueAttempts is the maximum number of tries for the initial issue
	// request, issueRetryBackoff the base delay between two of them.
	issueAttempts     = 3
	issueRetryBackoff = 2 * time.Second

	// collectInterval is the delay between two attempts to collect a
	// certificate from the PKI backend.
	collectInterval = 5 * time.Second
	// collectCallTimeout bounds a single collect RPC so that a terminated
	// connection surfaces quickly and the next poll can start.
	collectCallTimeout = 30 * time.Second
	// collectTimeout bounds the overall time waiting for a certificate.
	collectTimeout = 15 * time.Minute
)

type Options struct {
	PKIBackend string `json:"pkiBackend"`
	EABBackend string `json:"eabBackend"`
}

func init() {
	apiv1.Register(apiv1.SectigoCAS, func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return New(ctx, opts)
	})
}

const defaultClientOperationName = "grpc.client"

func sentryInterceptor(ctx context.Context,
	method string,
	req, reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	callOpts ...grpc.CallOption) error {

	hub := sentry.GetHubFromContext(ctx)
	if hub == nil {
		hub = sentry.CurrentHub().Clone()
		ctx = sentry.SetHubOnContext(ctx, hub)
	}

	operationName := defaultClientOperationName

	options := []sentry.SpanOption{sentry.WithTransactionName(method), sentry.WithDescription(method)}

	options = append(options, monitoring.GetSpanOptions(ctx)...)

	span := sentry.StartSpan(ctx, operationName, options...)
	span.SetData("grpc.request.method", method)

	ctx = span.Context()
	md, ok := metadata.FromOutgoingContext(ctx)
	if ok {
		md.Append(sentry.SentryTraceHeader, span.ToSentryTrace())
		md.Append(sentry.SentryBaggageHeader, span.ToBaggage())
	} else {
		md = metadata.Pairs(
			sentry.SentryTraceHeader, span.ToSentryTrace(),
			sentry.SentryBaggageHeader, span.ToBaggage(),
		)
	}

	ctx = metadata.NewOutgoingContext(ctx, md)
	defer span.Finish()

	err := invoker(ctx, method, req, reply, cc, callOpts...)

	if err != nil {
		hub.CaptureException(err)
	}

	return err
}

func New(ctx context.Context, opts apiv1.Options) (*SectigoCAS, error) {
	var config Options
	err := json.Unmarshal(opts.Config, &config)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(
		config.PKIBackend,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(sentryInterceptor),
	)
	if err != nil {
		return nil, err
	}
	sslServiceClient := pb.NewSSLServiceClient(conn)
	var eabClient pb.EABServiceClient
	if config.EABBackend != "" {
		conn, err = grpc.NewClient(
			config.EABBackend,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithUnaryInterceptor(sentryInterceptor),
		)
		if err != nil {
			return nil, err
		}
		eabClient = pb.NewEABServiceClient(conn)
	}
	return &SectigoCAS{sslServiceClient: sslServiceClient, eabClient: eabClient, logger: logrus.StandardLogger()}, nil
}

type SectigoCAS struct {
	sslServiceClient pb.SSLServiceClient
	eabClient        pb.EABServiceClient
	logger           *logrus.Logger
}

func parseCertificates(cert []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for block, rest := pem.Decode(cert); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		default:
			return nil, errors.New("Unknown entry in cert chain")
		}
	}
	return certs, nil
}
func accountFromContext(ctx context.Context) *acme.Account {
	val, ok := ctx.Value(api.AccContextKey).(*acme.Account)
	if !ok || val == nil {
		return nil
	}
	return val
}

func (s *SectigoCAS) signCertificate(ctx context.Context, cr *x509.CertificateRequest) (*x509.Certificate, []*x509.Certificate, error) {
	sans := make([]string, 0, len(cr.DNSNames)+len(cr.EmailAddresses)+len(cr.IPAddresses)+len(cr.URIs))
	sans = append(sans, cr.DNSNames...)
	for _, ip := range cr.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, u := range cr.URIs {
		sans = append(sans, u.String())
	}

	issuer := ""
	prov, ok := acme.ProvisionerFromContext(ctx)
	if !ok || prov == nil {
		issuer = "Internal"
	} else {
		acmeProv, ok := prov.(*provisioner.ACME)
		if !ok || acmeProv == nil {
			return nil, nil, errors.New("No ACME provisioner passed!")
		}
		if acmeProv.RequireEAB {
			acc := accountFromContext(ctx)
			if acc == nil {
				return nil, nil, errors.New("No account passed!")
			}
			ctxResolve, hub := monitoring.WrapSentryTrace(ctx)
			user, err := s.eabClient.ResolveAccountId(ctxResolve, &pb.ResolveAccountIdRequest{AccountId: acc.ID})
			if err != nil {
				return nil, nil, errors.WithMessage(err, "Error resolving user account!")
			}
			issuer = fmt.Sprintf("%v (EAB: %v)", user.User, user.EabKey)
			hub.ConfigureScope(func(scope *sentry.Scope) {
				scope.SetUser(sentry.User{Email: issuer})
			})
		}

	}

	ctxSign, _ := monitoring.WrapSentryTrace(ctx)
	response, err := s.issueCertificate(ctxSign, &pb.IssueSslRequest{
		Issuer:                  issuer,
		SubjectAlternativeNames: sans,
		Source:                  "ACME",
		Csr:                     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: cr.Raw})),
		WaitForIssue:            false,
	})
	if err != nil {
		s.logger.WithField("error", err).Error("Failed to request certificate")
		return nil, nil, err
	}

	// Old backends issue synchronously and reply with the certificate right
	// away, new ones only return a transaction id that has to be polled.
	pemData := response.Certificate
	if pemData == "" {
		transactionID := response.TransactionId
		if transactionID == "" {
			return nil, nil, errors.New("Backend returned neither a certificate nor a transaction id")
		}
		pemData, err = s.collectCertificate(ctxSign, transactionID)
		if err != nil {
			s.logger.WithField("error", err).WithField("transaction_id", transactionID).Error("Failed to collect certificate")
			return nil, nil, err
		}
	}

	certs, err := parseCertificates([]byte(pemData))
	if err != nil {
		s.logger.WithField("error", err).Error("Failed to parse certificate")
		return nil, nil, err
	}
	return certs[0], certs[1:], nil
}

// issueCertificate requests a new certificate from the PKI backend. The
// backend does not wait for the actual issuance, so the request itself is
// short-lived and a terminated connection can safely be retried before any
// polling starts.
func (s *SectigoCAS) issueCertificate(ctx context.Context, req *pb.IssueSslRequest) (*pb.IssueSslResponse, error) {
	for attempt := 1; ; attempt++ {
		response, err := s.sslServiceClient.IssueCertificate(ctx, req)
		if err == nil {
			return response, nil
		}
		if status.Code(err) != codes.Unavailable || attempt >= issueAttempts {
			return nil, err
		}
		s.logger.WithField("error", err).WithField("attempt", attempt).Warn("Requesting certificate failed, retrying")
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt) * issueRetryBackoff):
		}
	}
}

// collectCertificate busy-polls the PKI backend until the certificate was
// issued. Every poll is a fresh short-lived RPC, so connections that are
// terminated by proxies or load balancers in between only delay the
// collection instead of failing the whole signing request.
func (s *SectigoCAS) collectCertificate(ctx context.Context, transactionID string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	logger := s.logger.WithField("transaction_id", transactionID)
	logger.Info("Waiting for certificate issuance")
	for {
		callCtx, cancelCall := context.WithTimeout(ctx, collectCallTimeout)
		response, err := s.sslServiceClient.CollectCertificate(callCtx, &pb.CollectSslRequest{TransactionId: transactionID})
		cancelCall()
		if err == nil && response.Certificate != "" {
			return response.Certificate, nil
		}
		if err != nil {
			switch status.Code(err) {
			case codes.Unavailable, codes.DeadlineExceeded:
				// Transient failure (terminated connection, busy backend):
				// keep polling until the overall deadline is reached.
				logger.WithField("error", err).Warn("Collecting certificate failed, retrying")
			default:
				return "", err
			}
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("certificate was not issued in time: %w", ctx.Err())
		case <-time.After(collectInterval):
		}
	}
}

func (s *SectigoCAS) CreateCertificate(ctx context.Context, req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	cert, chain, err := s.signCertificate(ctx, req.CSR)
	if err != nil {
		return nil, err
	}
	return &apiv1.CreateCertificateResponse{
		Certificate:      cert,
		CertificateChain: chain,
	}, nil
}

func (s *SectigoCAS) RenewCertificate(ctx context.Context, req *apiv1.RenewCertificateRequest) (*apiv1.RenewCertificateResponse, error) {
	cert, chain, err := s.signCertificate(ctx, req.CSR)
	if err != nil {
		return nil, err
	}
	return &apiv1.RenewCertificateResponse{
		Certificate:      cert,
		CertificateChain: chain,
	}, nil
}

func (s *SectigoCAS) RevokeCertificate(ctx context.Context, req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	ctx, _ = monitoring.WrapSentryTrace(ctx)
	_, err := s.sslServiceClient.RevokeCertificate(ctx, &pb.RevokeSslRequest{
		Identifier: &pb.RevokeSslRequest_Serial{Serial: req.SerialNumber},
		Reason:     req.Reason,
	})
	if err != nil {
		s.logger.WithField("error", err).Error("Failed to revoke certificate")
		return nil, err
	}

	return &apiv1.RevokeCertificateResponse{
		Certificate:      req.Certificate,
		CertificateChain: nil,
	}, nil
}

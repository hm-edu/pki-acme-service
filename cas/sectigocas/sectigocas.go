package sectigocas

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"

	pb "github.com/hm-edu/portal-apis"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/smallstep/certificates/cas/apiv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Options struct {
	PKIBackend string `json:"pkiBackend"`
}

func init() {
	apiv1.Register(apiv1.SectigoCAS, func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return New(ctx, opts)
	})
}

func New(ctx context.Context, opts apiv1.Options) (*SectigoCAS, error) {
	var config Options
	err := json.Unmarshal(opts.Config, &config)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		config.PKIBackend,
		grpc.WithBlock(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()),
	)
	if err != nil {
		return nil, err
	}
	apiClient := pb.NewSSLServiceClient(conn)

	return &SectigoCAS{client: apiClient, logger: logrus.StandardLogger()}, nil
}

type SectigoCAS struct {
	client pb.SSLServiceClient
	logger *logrus.Logger
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

func (s *SectigoCAS) signCertificate(cr *x509.CertificateRequest) (*x509.Certificate, []*x509.Certificate, error) {
	sans := make([]string, 0, len(cr.DNSNames)+len(cr.EmailAddresses)+len(cr.IPAddresses)+len(cr.URIs))
	sans = append(sans, cr.DNSNames...)
	for _, ip := range cr.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, u := range cr.URIs {
		sans = append(sans, u.String())
	}

	certificates, err := s.client.IssueCertificate(context.Background(), &pb.IssueSslRequest{
		SubjectAlternativeNames: sans,
		Csr:                     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: cr.Raw})),
	})
	if err != nil {
		s.logger.WithField("error", err).Error("Failed to sign certificate")
		return nil, nil, err
	}
	certs, err := parseCertificates([]byte(certificates.Certificate))
	if err != nil {
		s.logger.WithField("error", err).Error("Failed to parse certificate")
		return nil, nil, err
	}
	return certs[0], certs[1:], nil
}

func (s *SectigoCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	cert, chain, err := s.signCertificate(req.CSR)
	if err != nil {
		return nil, err
	}
	return &apiv1.CreateCertificateResponse{
		Certificate:      cert,
		CertificateChain: chain,
	}, nil
}

func (s *SectigoCAS) RenewCertificate(req *apiv1.RenewCertificateRequest) (*apiv1.RenewCertificateResponse, error) {
	cert, chain, err := s.signCertificate(req.CSR)
	if err != nil {
		return nil, err
	}
	return &apiv1.RenewCertificateResponse{
		Certificate:      cert,
		CertificateChain: chain,
	}, nil
}

func (s *SectigoCAS) RevokeCertificate(req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	_, err := s.client.RevokeCertificate(context.Background(), &pb.RevokeSslRequest{
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

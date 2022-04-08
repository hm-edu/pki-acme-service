package sectigocas

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	legoLog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hm-edu/sectigo-client/sectigo"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/cas/apiv1"
	"go.uber.org/zap"
)

type Options struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Kid         string `json:"kid"`
	HMAC        string `json:"hmac"`
	CustomerURI string `json:"customerUri"`
	AcmeStorage string `json:"acmeStorage"`
}

func init() {
	apiv1.Register(apiv1.SectigoCAS, func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return New(opts)
	})
}

func New(opts apiv1.Options) (*SectigoCAS, error) {
	var config Options
	err := json.Unmarshal(opts.Config, &config)
	if err != nil {
		return nil, err
	}
	var account User
	err = os.Mkdir(config.AcmeStorage, 0600)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}
	accountFile := filepath.Join(config.AcmeStorage, "reg.json")
	keyFile := filepath.Join(config.AcmeStorage, "reg.key")
	if ok, _ := fileExists(accountFile); !ok {
		// Actually we would not need a private key but the lego API requires one.
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}

		account = User{
			key: privateKey,
		}

	} else {
		data, err := os.ReadFile(accountFile)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(data, &account)
		if err != nil {
			return nil, err
		}
		account.key, err = loadPrivateKey(keyFile)
		if err != nil {
			return nil, err
		}

	}
	cfg := lego.NewConfig(&account)
	cfg.CADirURL = "https://acme.sectigo.com/v2/OV"
	cfg.Certificate.Timeout = time.Duration(10) * time.Minute
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	if account.Registration == nil {
		reg, err := client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  config.Kid,
			HmacEncoded:          config.HMAC,
		})
		if err != nil {
			return nil, err
		}
		account.Registration = reg
		data, err := json.Marshal(account)
		if err != nil {
			return nil, err
		}
		err = os.WriteFile(accountFile, data, 0644)
		if err != nil {
			return nil, err
		}
		certOut, err := os.OpenFile(keyFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return nil, err
		}
		defer func(certOut *os.File) {
			_ = certOut.Close()
		}(certOut)

		pemKey := certcrypto.PEMBlock(account.key)
		err = pem.Encode(certOut, pemKey)
		if err != nil {
			return nil, err
		}
	}
	logger, _ := zap.NewProduction()
	return &SectigoCAS{
		c:      sectigo.NewClient(http.DefaultClient, logger, config.Username, config.Password, config.CustomerURI),
		acc:    &account,
		logger: &ZapLogger{logger: logger},
	}, nil
}

type SectigoCAS struct {
	c      *sectigo.Client
	acc    *User
	logger *ZapLogger
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

func fileExists(name string) (bool, error) {
	_, err := os.Stat(name)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func loadPrivateKey(file string) (crypto.PrivateKey, error) {
	keyBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyBytes)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	return nil, errors.New("unknown private key type")
}

func (s *SectigoCAS) signCertificate(cr *x509.CertificateRequest) (*x509.Certificate, []*x509.Certificate, error) {
	legoLog.Logger = s.logger
	sans := make([]string, 0, len(cr.DNSNames)+len(cr.EmailAddresses)+len(cr.IPAddresses)+len(cr.URIs))
	sans = append(sans, cr.DNSNames...)
	sans = append(sans, cr.EmailAddresses...)
	for _, ip := range cr.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, u := range cr.URIs {
		sans = append(sans, u.String())
	}
	s.logger.logger.Info("Start obtaining certificate.", zap.Strings("san", sans))

	cfg := lego.NewConfig(s.acc)
	cfg.CADirURL = "https://acme.sectigo.com/v2/OV"
	cfg.Certificate.Timeout = time.Duration(10) * time.Minute
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}
	certificates, err := client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{CSR: cr, Bundle: true})
	if err != nil {
		return nil, nil, err
	}
	certs, err := parseCertificates(certificates.Certificate)
	if err != nil {
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
	err := s.c.SslService.Revoke(req.SerialNumber, req.Reason)
	if err != nil {
		return nil, err
	}

	return &apiv1.RevokeCertificateResponse{
		Certificate:      req.Certificate,
		CertificateChain: nil,
	}, nil
}

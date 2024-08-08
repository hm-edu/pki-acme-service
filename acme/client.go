package acme

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Client is the interface used to verify ACME challenges.
type Client interface {
	// Get issues an HTTP GET to the specified URL.
	Get(url string) (*http.Response, error)

	// LookupTXT returns the DNS TXT records for the given domain name.
	LookupTxt(name string) ([]string, error)

	// TLSDial connects to the given network address using net.Dialer and then
	// initiates a TLS handshake, returning the resulting TLS connection.
	TLSDial(network, addr string, config *tls.Config) (*tls.Conn, error)
}

type clientKey struct{}

// NewClientContext adds the given client to the context.
func NewClientContext(ctx context.Context, c Client) context.Context {
	return context.WithValue(ctx, clientKey{}, c)
}

// ClientFromContext returns the current client from the given context.
func ClientFromContext(ctx context.Context) (c Client, ok bool) {
	c, ok = ctx.Value(clientKey{}).(Client)
	return
}

// MustClientFromContext returns the current client from the given context. It will
// return a new instance of the client if it does not exist.
func MustClientFromContext(ctx context.Context) Client {
	c, ok := ClientFromContext(ctx)
	if !ok {
		return NewClient()
	}
	return c
}

type client struct {
	http   *http.Client
	dialer *net.Dialer
}

// NewClient returns an implementation of Client for verifying ACME challenges.
func NewClient() Client {
	return &client{
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{
					//nolint:gosec // used on tls-alpn-01 challenge
					InsecureSkipVerify: true, // lgtm[go/disabled-certificate-check]
				},
			},
		},
		dialer: &net.Dialer{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *client) Get(url string) (*http.Response, error) {
	return c.http.Get(url)
}

var timeouts [5]time.Duration = [5]time.Duration{(time.Second * 1), (time.Second * 1), (time.Second * 2), (time.Second * 4), (time.Second * 2)}

func ResolveWithTimeout(name, resolver string, qtype, qclass uint16) (*dns.Msg, error) {
	client := new(dns.Client)
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{Name: dns.Fqdn(name), Qtype: qtype, Qclass: qclass}},
	}
	msg.AuthenticatedData = true
	msg.SetEdns0(4096, true)

	for i := 0; i < len(timeouts); i++ {

		client.Timeout = timeouts[i]
		resp, _, err := client.Exchange(msg, fmt.Sprintf("%s:53", resolver))
		if err == nil && resp.Truncated {
			tcpConn, _ := dns.Dial("tcp", fmt.Sprintf("%s:53", resolver))
			resp, _, err = client.ExchangeWithConn(msg, tcpConn)
		}
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				logrus.Warnf("Timeout querying %s records '%s' after %v", dns.TypeToString[qtype], name, timeouts[i])
				continue
			}
			return nil, err
		}

		return resp, nil

	}
	return nil, &net.DNSError{
		Name:      name,
		Err:       "Final timeout.",
		IsTimeout: true,
	}
}

func LookupTxt(name, resolver string) ([]string, error) {
	logrus.Infof("Using custom resolver %s for lookup of %s", resolver, name)
	resp, err := ResolveWithTimeout(name, resolver, dns.TypeTXT, dns.ClassINET)
	if err != nil {
		logrus.Warnf("Failed to lookup %s: %v", name, err)
		return nil, err
	}
	nsData := []string{}
	data := []string{}

	// Check if TXT records are present
	for _, answer := range resp.Answer {
		if txt, ok := answer.(*dns.TXT); ok {
			logrus.Infof("Resolved TXT records for %s: %s", name, txt.Txt)
			data = append(data, txt.Txt...)
		}
	}
	if len(data) > 0 {
		return data, nil
	}
	resp, err = ResolveWithTimeout(name, resolver, dns.TypeCNAME, dns.ClassINET)
	if err != nil {
		logrus.Warnf("Failed to lookup %s: %v", name, err)
		return nil, err
	}
	// Check if CNAME records are present
	for _, answer := range resp.Answer {
		if cname, ok := answer.(*dns.CNAME); ok {
			logrus.Infof("Resolved CNAME records for %s: %s", name, cname.Target)
			// Get NS records for the CNAME
			resp, err := ResolveWithTimeout(cname.Target, resolver, dns.TypeSOA, dns.ClassINET)
			if err != nil {
				logrus.Warnf("Failed to lookup %s: %v", cname.Target, err)
				continue
			}
			for _, answer := range resp.Ns {
				if ns, ok := answer.(*dns.SOA); ok {
					logrus.Infof("Resolved NS records for %s: %s", cname.Target, ns.Ns)
					nsData = append(nsData, ns.Ns)
				}
			}
			for _, ns := range nsData {
				logrus.Infof("Resolving %s using %s", cname.Target, ns)
				return LookupTxt(cname.Target, ns)
			}
		}
	}

	return data, nil
}
func (c *client) LookupTxt(name string) ([]string, error) {
	resolver := os.Getenv("DNS_RESOLVER")
	if resolver != "" {
		return LookupTxt(name, resolver)
	}
	return c.LookupTxt(name)
}

func (c *client) TLSDial(network, addr string, config *tls.Config) (*tls.Conn, error) {
	return tls.DialWithDialer(c.dialer, network, addr, config)
}

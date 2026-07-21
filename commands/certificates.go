package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/nosql"

	"github.com/smallstep/certificates/acme"
	acmeNoSQL "github.com/smallstep/certificates/acme/db/nosql"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/db"
)

func init() {
	command.Register(cli.Command{
		Name:      "certificates",
		Usage:     "manage the x509 certificates stored in the CA database",
		UsageText: "**step-ca certificates** <subcommand> [arguments] [subcommand-flags]",
		Description: `**step-ca certificates** provides access to the x509 certificates stored
in the CA database.

This command opens the CA database directly. With the badger backend the CA
must be stopped first; with MySQL or PostgreSQL it can run alongside the CA.`,
		Subcommands: cli.Commands{
			{
				Name:      "list",
				Usage:     "list the certificates stored in the CA database",
				UsageText: "**step-ca certificates list** <config> [**--json**] [filter-flags]",
				Action:    certificatesListAction,
				Flags: append(certificateFilterFlags(),
					cli.StringFlag{
						Name:  "status",
						Usage: "only list certificates with this status: active, expired or revoked",
					},
					cli.BoolFlag{
						Name:  "json",
						Usage: "print the certificate list as JSON",
					},
				),
				Description: `**step-ca certificates list** lists the certificates stored in the CA
database together with their status and, if configured, their manual ACME
renewal window (RFC 9773).

## EXAMPLES

List all certificates:
'''
$ step-ca certificates list $(step path)/config/ca.json
'''

List active certificates issued by the ACME provisioner that expire within
the next month:
'''
$ step-ca certificates list $(step path)/config/ca.json --status active \
    --provisioner acme --expires-before $(date -v +1m +%Y-%m-%dT%H:%M:%SZ)
'''`,
			},
		},
	})
}

// certificateFilterFlags returns the flags used to select certificates from
// the CA database. They are shared by 'certificates list' and
// 'renewal-info set'.
func certificateFilterFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:  "cn",
			Usage: "select certificates with this subject common name",
		},
		cli.StringFlag{
			Name:  "san",
			Usage: "select certificates with this DNS, IP, email or URI subject alternative name",
		},
		cli.StringFlag{
			Name:  "provisioner",
			Usage: "select certificates authorized by the provisioner with this name",
		},
		cli.StringFlag{
			Name:  "issued-after",
			Usage: "select certificates issued after this RFC 3339 timestamp",
		},
		cli.StringFlag{
			Name:  "issued-before",
			Usage: "select certificates issued before this RFC 3339 timestamp",
		},
		cli.StringFlag{
			Name:  "expires-after",
			Usage: "select certificates expiring after this RFC 3339 timestamp",
		},
		cli.StringFlag{
			Name:  "expires-before",
			Usage: "select certificates expiring before this RFC 3339 timestamp",
		},
	}
}

// certificateFilterFromFlags builds a certificate filter from the flags
// returned by certificateFilterFlags. The second return value reports whether
// any filter flag was set.
func certificateFilterFromFlags(ctx *cli.Context) (*db.CertificateFilter, bool, error) {
	filter := &db.CertificateFilter{
		CommonName:  ctx.String("cn"),
		SAN:         ctx.String("san"),
		Provisioner: ctx.String("provisioner"),
	}
	set := filter.CommonName != "" || filter.SAN != "" || filter.Provisioner != ""
	for flag, target := range map[string]*time.Time{
		"issued-after":   &filter.IssuedAfter,
		"issued-before":  &filter.IssuedBefore,
		"expires-after":  &filter.ExpiresAfter,
		"expires-before": &filter.ExpiresBefore,
	} {
		if value := ctx.String(flag); value != "" {
			t, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return nil, false, errors.Wrapf(err, "error parsing --%s", flag)
			}
			*target = t
			set = true
		}
	}
	return filter, set, nil
}

// openCADatabase opens the CA database configured in the given ca.json and
// returns the authority and ACME interfaces to it.
func openCADatabase(configFile string) (db.AuthDB, acme.DB, func() error, error) {
	cfg, err := config.LoadConfiguration(configFile)
	if err != nil {
		return nil, nil, nil, err
	}
	if cfg.DB == nil {
		return nil, nil, nil, errors.New("no database configured in " + configFile)
	}

	database, err := db.New(cfg.DB)
	if err != nil {
		return nil, nil, nil, err
	}
	nosqlDB, ok := database.(nosql.DB)
	if !ok {
		database.Shutdown()
		return nil, nil, nil, errors.Errorf("database type %s does not support ACME", cfg.DB.Type)
	}
	acmeDB, err := acmeNoSQL.New(nosqlDB)
	if err != nil {
		database.Shutdown()
		return nil, nil, nil, errors.Wrap(err, "error configuring ACME DB interface")
	}
	return database, acmeDB, database.Shutdown, nil
}

// certificateListItem is the JSON representation of a stored certificate
// combined with its manual ACME renewal window, if configured.
type certificateListItem struct {
	*db.CertificateInfo
	RenewalInfoOverride *acme.RenewalInfoOverride `json:"renewalInfoOverride,omitempty"`
}

func certificatesListAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}
	configFile := ctx.Args().Get(0)

	filter, _, err := certificateFilterFromFlags(ctx)
	if err != nil {
		return err
	}
	filter.Status = ctx.String("status")
	if err := filter.Validate(); err != nil {
		return err
	}

	authDB, acmeDB, shutdown, err := openCADatabase(configFile)
	if err != nil {
		return err
	}
	defer shutdown()

	lister, ok := authDB.(db.CertificateLister)
	if !ok {
		return errors.New("database does not support listing certificates")
	}
	certs, err := lister.ListCertificates(filter)
	if err != nil {
		return err
	}

	overrides := make(map[string]*acme.RenewalInfoOverride)
	list, err := acmeDB.ListRenewalInfoOverrides(context.Background())
	if err != nil {
		return err
	}
	for _, o := range list {
		overrides[o.Serial] = o
	}

	items := make([]*certificateListItem, len(certs))
	for i, ci := range certs {
		items[i] = &certificateListItem{
			CertificateInfo:     ci,
			RenewalInfoOverride: overrides[ci.Serial],
		}
	}

	if ctx.Bool("json") {
		b, err := json.MarshalIndent(items, "", "\t")
		if err != nil {
			return errors.Wrap(err, "error marshaling certificate list")
		}
		fmt.Println(string(b))
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(w, "SERIAL\tCOMMON NAME\tSANS\tNOT AFTER\tPROVISIONER\tSTATUS\tRENEWAL WINDOW")
	for _, item := range items {
		sans := strings.Join(allSANs(item.CertificateInfo), ",")
		provisioner := ""
		if item.Provisioner != nil {
			provisioner = item.Provisioner.Name
		}
		window := ""
		if o := item.RenewalInfoOverride; o != nil {
			window = fmt.Sprintf("%s - %s", o.Start.Format(time.RFC3339), o.End.Format(time.RFC3339))
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			item.Serial, item.CommonName, sans,
			item.NotAfter.Format(time.RFC3339), provisioner, item.Status, window)
	}
	return w.Flush()
}

// allSANs returns all subject alternative names of the certificate.
func allSANs(ci *db.CertificateInfo) []string {
	var sans []string
	sans = append(sans, ci.DNSNames...)
	sans = append(sans, ci.IPAddresses...)
	sans = append(sans, ci.EmailAddresses...)
	sans = append(sans, ci.URIs...)
	return sans
}

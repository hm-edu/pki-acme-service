package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/db"
)

func init() {
	command.Register(cli.Command{
		Name:      "renewal-info",
		Usage:     "manage manual ACME renewal info (ARI) windows",
		UsageText: "**step-ca renewal-info** <subcommand> [arguments] [subcommand-flags]",
		Description: `**step-ca renewal-info** manages manual renewal windows for the ACME
renewalInfo endpoint (RFC 9773).

A manual window overrides the default suggested renewal window for a single
certificate, identified by its serial number (decimal). Setting a window that
lies entirely in the past instructs ACME clients to renew immediately.

This command opens the CA database directly. With the badger backend the CA
must be stopped first; with MySQL or PostgreSQL it can run alongside the CA.`,
		Subcommands: cli.Commands{
			{
				Name:      "set",
				Usage:     "set a manual renewal window for one or more certificates",
				UsageText: "**step-ca renewal-info set** <config> [serial...] [**--renew-now**] [**--start**=<time>] [**--end**=<time>] [**--explanation-url**=<url>] [**--all**] [filter-flags]",
				Action:    renewalInfoSetAction,
				Flags: append(certificateFilterFlags(),
					cli.BoolFlag{
						Name:  "renew-now",
						Usage: "mark the certificates for immediate renewal (window in the past)",
					},
					cli.StringFlag{
						Name:  "start",
						Usage: "window start as RFC 3339 timestamp, e.g. 2026-08-01T00:00:00Z",
					},
					cli.StringFlag{
						Name:  "end",
						Usage: "window end as RFC 3339 timestamp",
					},
					cli.StringFlag{
						Name:  "explanation-url",
						Usage: "URL with information on why the certificate should be renewed",
					},
					cli.BoolFlag{
						Name:  "all",
						Usage: "select all active certificates in the database",
					},
				),
				Description: `**step-ca renewal-info set** stores a manual renewal window for one or more
certificates.

The certificates are selected either by listing their serial numbers as
arguments, or by the certificate filter flags (see **step-ca certificates
list**). Filters only select active certificates, i.e. certificates that are
neither expired nor revoked. Use **--all** to select every active certificate
in the database. Serial arguments and filter flags are mutually exclusive.

## EXAMPLES

Mark a certificate for immediate renewal:
'''
$ step-ca renewal-info set $(step path)/config/ca.json 123450987654321 --renew-now
'''

Set an explicit window for two certificates:
'''
$ step-ca renewal-info set $(step path)/config/ca.json 123450987654321 98765432112345 \
    --start 2026-08-01T00:00:00Z --end 2026-08-08T00:00:00Z \
    --explanation-url https://pki.example.com/incident
'''

Mark all active certificates issued by the ACME provisioner before July 2026
for immediate renewal:
'''
$ step-ca renewal-info set $(step path)/config/ca.json --renew-now \
    --provisioner acme --issued-before 2026-07-01T00:00:00Z \
    --explanation-url https://pki.example.com/incident
'''`,
			},
			{
				Name:      "get",
				Usage:     "show the manual renewal window for a certificate serial",
				UsageText: "**step-ca renewal-info get** <config> <serial>",
				Action:    renewalInfoGetAction,
			},
			{
				Name:      "unset",
				Usage:     "remove the manual renewal window for a certificate serial",
				UsageText: "**step-ca renewal-info unset** <config> <serial>",
				Action:    renewalInfoUnsetAction,
			},
		},
	})
}

// renewalInfoWindow parses the --renew-now, --start and --end flags into the
// manual renewal window that is applied to the selected certificates.
func renewalInfoWindow(ctx *cli.Context) (start, end time.Time, err error) {
	switch {
	case ctx.Bool("renew-now"):
		now := time.Now().UTC().Truncate(time.Second)
		return now.Add(-24 * time.Hour), now, nil
	case ctx.String("start") != "" && ctx.String("end") != "":
		if start, err = time.Parse(time.RFC3339, ctx.String("start")); err != nil {
			return start, end, errors.Wrap(err, "error parsing --start")
		}
		if end, err = time.Parse(time.RFC3339, ctx.String("end")); err != nil {
			return start, end, errors.Wrap(err, "error parsing --end")
		}
		if !end.After(start) {
			return start, end, errors.New("--end must be after --start")
		}
		return start, end, nil
	default:
		return start, end, errors.New("either --renew-now or both --start and --end are required")
	}
}

func renewalInfoSetAction(ctx *cli.Context) error {
	if ctx.NArg() < 1 {
		return errs.TooFewArguments(ctx)
	}
	configFile, serials := ctx.Args().Get(0), ctx.Args().Tail()

	filter, filterSet, err := certificateFilterFromFlags(ctx)
	if err != nil {
		return err
	}
	selectAll := ctx.Bool("all")
	switch {
	case len(serials) > 0 && (filterSet || selectAll):
		return errors.New("serial arguments and certificate selection flags are mutually exclusive")
	case len(serials) == 0 && !filterSet && !selectAll:
		return errors.New("provide at least one serial, certificate filter flags, or --all")
	}

	start, end, err := renewalInfoWindow(ctx)
	if err != nil {
		return err
	}

	authDB, acmeDB, shutdown, err := openCADatabase(configFile)
	if err != nil {
		return err
	}
	defer shutdown()

	if len(serials) == 0 {
		lister, ok := authDB.(db.CertificateLister)
		if !ok {
			return errors.New("database does not support listing certificates")
		}
		// Manual renewal windows only make sense for certificates that are
		// neither expired nor revoked.
		filter.Status = db.CertificateStatusActive
		certs, err := lister.ListCertificates(filter)
		if err != nil {
			return err
		}
		if len(certs) == 0 {
			return errors.New("no active certificates match the given filter")
		}
		for _, cert := range certs {
			serials = append(serials, cert.Serial)
		}
	}

	overrides := make([]*acme.RenewalInfoOverride, 0, len(serials))
	for _, serial := range serials {
		override := &acme.RenewalInfoOverride{
			Serial:         serial,
			Start:          start,
			End:            end,
			ExplanationURL: ctx.String("explanation-url"),
		}
		if err := acmeDB.SaveRenewalInfoOverride(context.Background(), override); err != nil {
			return errors.Wrapf(err, "error saving renewal info override for serial %s (%d of %d overrides saved)", serial, len(overrides), len(serials))
		}
		overrides = append(overrides, override)
	}

	if len(overrides) == 1 {
		return printRenewalInfoOverride(overrides[0])
	}
	b, err := json.MarshalIndent(overrides, "", "\t")
	if err != nil {
		return errors.Wrap(err, "error marshaling renewal info overrides")
	}
	fmt.Println(string(b))
	return nil
}

func renewalInfoGetAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}
	configFile, serial := ctx.Args().Get(0), ctx.Args().Get(1)

	_, acmeDB, shutdown, err := openCADatabase(configFile)
	if err != nil {
		return err
	}
	defer shutdown()

	override, err := acmeDB.GetRenewalInfoOverride(context.Background(), serial)
	if err != nil {
		if acme.IsErrNotFound(err) {
			return errors.Errorf("no renewal info override for serial %s", serial)
		}
		return err
	}
	return printRenewalInfoOverride(override)
}

func renewalInfoUnsetAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}
	configFile, serial := ctx.Args().Get(0), ctx.Args().Get(1)

	_, acmeDB, shutdown, err := openCADatabase(configFile)
	if err != nil {
		return err
	}
	defer shutdown()

	if err := acmeDB.DeleteRenewalInfoOverride(context.Background(), serial); err != nil {
		return err
	}
	fmt.Printf("renewal info override for serial %s removed\n", serial)
	return nil
}

func printRenewalInfoOverride(override *acme.RenewalInfoOverride) error {
	b, err := json.MarshalIndent(override, "", "\t")
	if err != nil {
		return errors.Wrap(err, "error marshaling renewal info override")
	}
	fmt.Println(string(b))
	return nil
}

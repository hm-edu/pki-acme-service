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
	"github.com/smallstep/nosql"

	"github.com/smallstep/certificates/acme"
	acmeNoSQL "github.com/smallstep/certificates/acme/db/nosql"
	"github.com/smallstep/certificates/authority/config"
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
				Usage:     "set a manual renewal window for a certificate serial",
				UsageText: "**step-ca renewal-info set** <config> <serial> [**--renew-now**] [**--start**=<time>] [**--end**=<time>] [**--explanation-url**=<url>]",
				Action:    renewalInfoSetAction,
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:  "renew-now",
						Usage: "mark the certificate for immediate renewal (window in the past)",
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
				},
				Description: `**step-ca renewal-info set** stores a manual renewal window.

## EXAMPLES

Mark a certificate for immediate renewal:
'''
$ step-ca renewal-info set $(step path)/config/ca.json 123450987654321 --renew-now
'''

Set an explicit window:
'''
$ step-ca renewal-info set $(step path)/config/ca.json 123450987654321 \
    --start 2026-08-01T00:00:00Z --end 2026-08-08T00:00:00Z \
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

// renewalInfoDB opens the ACME database configured in the given ca.json.
func renewalInfoDB(configFile string) (acme.DB, func() error, error) {
	cfg, err := config.LoadConfiguration(configFile)
	if err != nil {
		return nil, nil, err
	}
	if cfg.DB == nil {
		return nil, nil, errors.New("no database configured in " + configFile)
	}

	database, err := db.New(cfg.DB)
	if err != nil {
		return nil, nil, err
	}
	nosqlDB, ok := database.(nosql.DB)
	if !ok {
		database.Shutdown()
		return nil, nil, errors.Errorf("database type %s does not support ACME", cfg.DB.Type)
	}
	acmeDB, err := acmeNoSQL.New(nosqlDB)
	if err != nil {
		database.Shutdown()
		return nil, nil, errors.Wrap(err, "error configuring ACME DB interface")
	}
	return acmeDB, database.Shutdown, nil
}

func renewalInfoSetAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}
	configFile, serial := ctx.Args().Get(0), ctx.Args().Get(1)

	override := &acme.RenewalInfoOverride{
		Serial:         serial,
		ExplanationURL: ctx.String("explanation-url"),
	}
	switch {
	case ctx.Bool("renew-now"):
		now := time.Now().UTC().Truncate(time.Second)
		override.Start = now.Add(-24 * time.Hour)
		override.End = now
	case ctx.String("start") != "" && ctx.String("end") != "":
		var err error
		if override.Start, err = time.Parse(time.RFC3339, ctx.String("start")); err != nil {
			return errors.Wrap(err, "error parsing --start")
		}
		if override.End, err = time.Parse(time.RFC3339, ctx.String("end")); err != nil {
			return errors.Wrap(err, "error parsing --end")
		}
		if !override.End.After(override.Start) {
			return errors.New("--end must be after --start")
		}
	default:
		return errors.New("either --renew-now or both --start and --end are required")
	}

	acmeDB, shutdown, err := renewalInfoDB(configFile)
	if err != nil {
		return err
	}
	defer shutdown()

	if err := acmeDB.SaveRenewalInfoOverride(context.Background(), override); err != nil {
		return err
	}
	return printRenewalInfoOverride(override)
}

func renewalInfoGetAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}
	configFile, serial := ctx.Args().Get(0), ctx.Args().Get(1)

	acmeDB, shutdown, err := renewalInfoDB(configFile)
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

	acmeDB, shutdown, err := renewalInfoDB(configFile)
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

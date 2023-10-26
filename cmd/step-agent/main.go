package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/sirupsen/logrus"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/acme/validation"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/step"
	"go.step.sm/cli-utils/ui"
)

var agent = cli.Command{
	Name:  "agent",
	Usage: "start the step-ca agent",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "host",
			Usage: "the host of the mqtt broker",
		},
		cli.StringFlag{
			Name:  "user",
			Usage: "the user for the mqtt broker",
		},
		cli.StringFlag{
			Name:  "password",
			Usage: "the password for the mqtt broker",
		},
		cli.StringFlag{
			Name:  "organization",
			Usage: "the organization for the mqtt broker connection",
		},
	},

	Action: func(c *cli.Context) error {
		options := mqtt.NewClientOptions()
		options.SetOrderMatters(false)
		options.ConnectTimeout = time.Second
		options.WriteTimeout = time.Second
		options.KeepAlive = 10
		options.PingTimeout = time.Second
		options.ConnectRetry = true
		options.AutoReconnect = true
		options.ClientID = fmt.Sprintf("acme-agent-%s-%d", c.String("organization"), time.Now().UnixNano())
		options.Username = c.String("user")
		options.Password = c.String("password")
		options.AddBroker(fmt.Sprintf("ssl://%s:8883", c.String("host")))
		logrus.Infof("connecting to mqtt broker")

		// Establish connection to MQTT broker
		options.OnConnectionLost = func(cl mqtt.Client, err error) {
			logrus.Println("mqtt connection lost")
		}
		options.OnConnect = func(mqtt.Client) {
			logrus.Println("mqtt connection established")
		}
		options.OnReconnecting = func(mqtt.Client, *mqtt.ClientOptions) {
			logrus.Println("mqtt reconnecting")
		}

		client := mqtt.NewClient(options)
		if token := client.Connect(); token.WaitTimeout(30*time.Second) && token.Error() != nil {
			logrus.Warn(token.Error())
		}

		// Subscribe to topic
		token := client.Subscribe(fmt.Sprintf("%s/jobs", c.String("organization")), 0, func(client mqtt.Client, msg mqtt.Message) {
			logrus.Infof("received message on topic %s", msg.Topic())
			logrus.Infof("message: %s", msg.Payload())

			var data validation.ValidationRequest

			req := msg.Payload()
			json.Unmarshal(req, &data)

			logger := logrus.WithField("authz", data.Authz).WithField("target", data.Target).WithField("account", data.Challenge)

			http := acme.NewClient()
			resp, err := http.Get(data.Target)
			if err != nil {
				logger.WithError(err).Warn("validating failed")
				return
			}

			defer resp.Body.Close()
			if resp.StatusCode >= 400 {
				logger.Warnf("validation for %s failed with error: %s", data.Target, resp.Status)
				return
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				logger.WithError(err).Warn("parsing body failed")
				return
			}

			keyAuth := strings.TrimSpace(string(body))
			logger.Infof("keyAuth: %s", keyAuth)

			json, err := json.Marshal(&validation.ValidationResponse{
				Authz:     data.Authz,
				Challenge: data.Challenge,
				Content:   keyAuth,
			})
			if err != nil {
				logger.WithError(err).Warn("marshalling failed")
				return
			}
			// Publish to topic
			token := client.Publish(fmt.Sprintf("%s/data", c.String("organization")), 0, false, json)
			if token.WaitTimeout(30*time.Second) && token.Error() != nil {
				logger.WithError(token.Error()).Warn("publishing failed")
			} else {
				logger.Infof("published to topic %s", fmt.Sprintf("%s/data", c.String("organization")))
			}

		})

		if token.WaitTimeout(30*time.Second) && token.Error() != nil {
			logrus.WithError(token.Error()).Warn("subscribing failed")
		} else {
			logrus.Infof("subscribed to topic %s", fmt.Sprintf("%s/jobs", c.String("organization")))
		}

		return nil
	},
}

// commit and buildTime are filled in during build by the Makefile
var (
	BuildTime = "N/A"
	Version   = "N/A"
)

func init() {
	step.Set("Smallstep Agent", Version, BuildTime)
}

func exit(code int) {
	ui.Reset()
	os.Exit(code)
}

func main() {
	ui.Init()
	app := cli.NewApp()
	app.Name = "step-agent"
	app.Usage = "step-agent"
	app.Version = step.Version()
	app.Action = func(c *cli.Context) error {
		return agent.Run(c)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan bool, 1)

	go func() {
		<-sigs
		done <- true
	}()

	if err := app.Run(os.Args); err != nil {
		logrus.Warn(err)
		exit(1)
	}

	<-done
	exit(0)
}

package mqtt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/sirupsen/logrus"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/acme/validation"
)

var clock acme.Clock

func Connect(acmeDB acme.DB, host, user, password, organization string) (validation.MqttClient, error) {
	opts := mqtt.NewClientOptions()
	opts.SetOrderMatters(false)       // Allow out of order messages (use this option unless in order delivery is essential)
	opts.ConnectTimeout = time.Second // Minimal delays on connect
	opts.WriteTimeout = time.Second   // Minimal delays on writes
	opts.KeepAlive = 10               // Keepalive every 10 seconds so we quickly detect network outages
	opts.PingTimeout = time.Second    // local broker so response should be quick
	opts.ConnectRetry = true
	opts.AutoReconnect = true
	opts.ClientID = "acme"
	opts.Username = user
	opts.Password = password
	opts.AddBroker(fmt.Sprintf("ssl://%s:8883", host))
	logrus.Infof("connecting to mqtt broker")
	// Log events
	opts.OnConnectionLost = func(cl mqtt.Client, err error) {
		logrus.Println("mqtt connection lost")
	}
	opts.OnConnect = func(cl mqtt.Client) {
		logrus.Println("mqtt connection established")
		go func() {
			cl.Subscribe(fmt.Sprintf("%s/data", organization), 1, func(client mqtt.Client, msg mqtt.Message) {
				logrus.Printf("Received message on topic: %s\nMessage: %s\n", msg.Topic(), msg.Payload())
				ctx := context.Background()
				data := msg.Payload()
				var payload validation.ValidationResponse
				err := json.Unmarshal(data, &payload)
				if err != nil {
					logrus.Errorf("error unmarshalling payload: %v", err)
					return
				}

				ch, err := acmeDB.GetChallenge(ctx, payload.Challenge, payload.Authz)
				if err != nil {
					logrus.Errorf("error getting challenge: %v", err)
					return
				}

				acc, err := acmeDB.GetAccount(ctx, ch.AccountID)
				if err != nil {
					logrus.Errorf("error getting account: %v", err)
					return
				}
				expected, err := acme.KeyAuthorization(ch.Token, acc.Key)

				if payload.Content != expected || err != nil {
					logrus.Errorf("invalid key authorization: %v", err)
					return
				}
				u := &url.URL{Scheme: "http", Host: ch.Value, Path: fmt.Sprintf("/.well-known/acme-challenge/%s", ch.Token)}
				logrus.Infof("challenge %s validated using mqtt", u.String())

				if ch.Status != acme.StatusPending && ch.Status != acme.StatusValid {
					return
				}

				ch.Status = acme.StatusValid
				ch.Error = nil
				ch.ValidatedAt = clock.Now().Format(time.RFC3339)
				for {
					if err = acmeDB.UpdateChallenge(ctx, ch); err != nil {
						if strings.Contains(err.Error(), "changed since last read") {
							// If the challenge has changed since we read it, then we
							// don't want to overwrite the error.
							logrus.Warn("challenge changed since last read -> retry saving")
							continue
						}
						logrus.Errorf("error updating challenge: %v", err)
					}
					logrus.Infof("challenge %s updated to valid", u.String())
					break
				}

			})
		}()
	}
	opts.OnReconnecting = func(mqtt.Client, *mqtt.ClientOptions) {
		logrus.Println("mqtt attempting to reconnect")
	}

	client := mqtt.NewClient(opts)

	if token := client.Connect(); token.WaitTimeout(30*time.Second) && token.Error() != nil {
		logrus.Warn(token.Error())
		return nil, token.Error()
	}

	connection := validation.BrokerConnection{Client: client, Organization: organization}
	return connection, nil
}

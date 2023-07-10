package validation

import (
	"context"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type ValidationResponse struct {
	Authz     string `json:"authz"`
	Challenge string `json:"challenge"`
	Content   string `json:"content"`
}

type ValidationRequest struct {
	Authz     string `json:"authz"`
	Challenge string `json:"challenge"`
	Target    string `json:"target"`
}

type validationKey struct{}

type MqttClient interface {
	GetClient() mqtt.Client
	GetOrganization() string
}

type BrokerConnection struct {
	Client       mqtt.Client
	Organization string
}

func (b BrokerConnection) GetClient() mqtt.Client {
	return b.Client
}

func (b BrokerConnection) GetOrganization() string {
	return b.Organization
}

// NewContext adds the given validation client  to the context.
func NewContext(ctx context.Context, a MqttClient) context.Context {
	return context.WithValue(ctx, validationKey{}, a)
}

// FromContext returns the validation client from the given context.
func FromContext(ctx context.Context) (a MqttClient, ok bool) {
	a, ok = ctx.Value(validationKey{}).(MqttClient)
	return
}

// MustFromContext returns the validation client from the given context. It will
// panic if no validation client is not in the context.
func MustFromContext(ctx context.Context) MqttClient {
	if a, ok := FromContext(ctx); !ok {
		panic("validation client is not in the context")
	} else {
		return a
	}
}

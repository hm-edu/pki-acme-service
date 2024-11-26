package monitoring

import (
	"context"

	"github.com/getsentry/sentry-go"
)

type sentryTrace struct{}
type sentryBaggage struct{}

func WrapSentryTrace(ctx context.Context) (context.Context, *sentry.Hub) {
	hub := sentry.GetHubFromContext(ctx)
	if hub == nil {
		hub = sentry.CurrentHub().Clone()
	}
	span := sentry.SpanFromContext(ctx)
	ctx = context.Background()
	ctx = sentry.SetHubOnContext(ctx, hub)
	if span != nil {
		ctx = context.WithValue(ctx, sentryTrace{}, span.ToSentryTrace())
		ctx = context.WithValue(ctx, sentryBaggage{}, span.ToBaggage())
	}
	return ctx, hub
}

func GetSpanOptions(ctx context.Context) []sentry.SpanOption {
	var opts []sentry.SpanOption
	trace, okTrace := ctx.Value(sentryTrace{}).(string)
	baggage, okBaggage := ctx.Value(sentryBaggage{}).(string)
	if okTrace && okBaggage {
		opts = append(opts, sentry.ContinueFromHeaders(trace, baggage))
	}
	return opts
}

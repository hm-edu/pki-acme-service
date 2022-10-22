package eab

import (
	"context"

	pb "github.com/hm-edu/portal-apis"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type eabKey struct{}

// NewContext adds the given eab client  to the context.
func NewContext(ctx context.Context, a pb.EABServiceClient) context.Context {
	return context.WithValue(ctx, eabKey{}, a)
}

// FromContext returns the eab client from the given context.
func FromContext(ctx context.Context) (a pb.EABServiceClient, ok bool) {
	a, ok = ctx.Value(eabKey{}).(pb.EABServiceClient)
	return
}

// MustFromContext returns the eab client from the given context. It will
// panic if no eab client is not in the context.
func MustFromContext(ctx context.Context) pb.EABServiceClient {
	if a, ok := FromContext(ctx); !ok {
		panic("eab client is not in the context")
	} else {
		return a
	}
}

func Connect(host string) (pb.EABServiceClient, error) {

	conn, err := grpc.DialContext(
		context.Background(),
		host,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()),
	)
	if err != nil {
		return nil, err
	}

	apiClient := pb.NewEABServiceClient(conn)
	return apiClient, nil

}

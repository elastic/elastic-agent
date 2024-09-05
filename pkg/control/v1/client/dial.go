// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package client

import (
	"context"
	"net"
	"strings"

	"github.com/elastic/elastic-agent/pkg/control"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func dialContext(ctx context.Context) (*grpc.ClientConn, error) {
	return grpc.DialContext(
		ctx,
		strings.TrimPrefix(control.Address(), "unix://"),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
	)
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", addr)
}

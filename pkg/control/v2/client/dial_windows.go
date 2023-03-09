// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows
// +build windows

package client

import (
	"context"
	"net"

	"github.com/elastic/elastic-agent/pkg/control"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/elastic/elastic-agent-libs/api/npipe"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
)

func dialContext(ctx context.Context, grpcConfig *configuration.GRPCConfig) (*grpc.ClientConn, error) {
	return grpc.DialContext(
		ctx,
		control.Address(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(grpcConfig.MaxMsgSize)),
	)
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	return npipe.DialContext(addr)(ctx, "", "")
}

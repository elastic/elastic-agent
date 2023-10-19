// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package client

import (
	"context"
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/elastic/elastic-agent-libs/api/npipe"
)

func dialContext(ctx context.Context, address string, maxMsgSize int, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	opts = append(opts,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsgSize)),
	)
	return grpc.DialContext(ctx, address, opts...)
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	if strings.HasPrefix(addr, "http://") {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", strings.TrimPrefix(addr, "http://"))
	}
	return npipe.DialContext(addr)(ctx, "", "")
}

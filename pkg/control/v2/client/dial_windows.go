// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package client

import (
	"context"
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/elastic/elastic-agent-libs/api/npipe"
)

func dialContext(ctx context.Context, address string, maxMsgSize int, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	opts = append(opts,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsgSize)),
	)
	return dialContextBlocking(ctx, address, opts...)
}

// dialContextBlocking creates a blocking connection equivalent to the deprecated grpc.DialContext
func dialContextBlocking(ctx context.Context, target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	// Create the connection using the new API
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, err
	}

	// Keep waiting until we're connected or context is cancelled
	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			return conn, nil
		}
		if state == connectivity.TransientFailure || state == connectivity.Shutdown {
			conn.Close()
			return nil, ctx.Err()
		}
		if !conn.WaitForStateChange(ctx, state) {
			conn.Close()
			return nil, ctx.Err()
		}
	}
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	if strings.HasPrefix(addr, "http://") {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", strings.TrimPrefix(addr, "http://"))
	}
	return npipe.DialContext(npipe.TransformString(addr))(ctx, "", "")
}

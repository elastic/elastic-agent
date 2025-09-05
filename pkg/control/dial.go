// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package control

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// DialContextBlocking creates a blocking connection equivalent to the deprecated grpc.DialContext.
// It uses the new grpc.NewClient API but waits for the connection to be established before returning,
// maintaining the same blocking behavior as the deprecated function.
func DialContextBlocking(ctx context.Context, target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, err
	}

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

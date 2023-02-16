// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package comp

import (
	"context"
	"crypto/x509"
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func dialContext(ctx context.Context, addr string, cp *x509.CertPool, serverName string) (*grpc.ClientConn, error) {
	return grpc.DialContext(ctx, strings.TrimPrefix(addr, "unix://"), grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(cp, serverName)))
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", addr)
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package agentprovider

import (
	"context"
	"net"
	"strings"
)

func dialSocket(ctx context.Context, address string) (net.Conn, error) {
	path := strings.TrimPrefix(address, "unix://")
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}

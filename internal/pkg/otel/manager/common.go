// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"fmt"
	"net"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
)

// for testing purposes
var netListen = net.Listen

// reportErr sends an error to the provided error channel. It first drains the channel
// to ensure that only the most recent error is kept, as intermediate errors can be safely discarded.
// This ensures the receiver always observes the latest reported error.
func reportErr(ctx context.Context, errCh chan error, err error) {
	select {
	case <-ctx.Done():
		// context is already done
		return
	case <-errCh:
	// drain the error channel first
	default:
	}
	select {
	case errCh <- err:
	case <-ctx.Done():
	}
}

// reportCollectorStatus sends the new status to the status channel.
func reportCollectorStatus(ctx context.Context, statusCh chan *status.AggregateStatus, statuses *status.AggregateStatus) {
	select {
	case <-ctx.Done():
		return
	case statusCh <- statuses:
	}
}

// findRandomTCPPort finds a random available TCP port on the localhost interface.
func findRandomTCPPort() (int, error) {
	l, err := netListen("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	port := l.Addr().(*net.TCPAddr).Port
	err = l.Close()
	if err != nil {
		return 0, err
	}
	if port == 0 {
		return 0, fmt.Errorf("failed to find random port")
	}

	return port, nil
}

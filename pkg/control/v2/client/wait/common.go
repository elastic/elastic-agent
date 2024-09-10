// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package wait

import (
	"context"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
)

const (
	// DefaultDaemonTimeout is the default timeout to use for waiting for the daemon.
	DefaultDaemonTimeout = 30 * time.Second // max amount of for communication to running Agent daemon
)

type waitResult struct {
	err error
}

func getDaemonState(ctx context.Context, timeout time.Duration) (*client.AgentState, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	daemon := client.New()
	err := daemon.Connect(ctx)
	if err != nil {
		return nil, err
	}
	defer daemon.Disconnect()
	return daemon.State(ctx)
}

func expBackoffWithContext(ctx context.Context, init, max time.Duration) backoff.Backoff {
	signal := make(chan struct{})
	bo := backoff.NewExpBackoff(signal, init, max)
	go func() {
		<-ctx.Done()
		close(signal)
	}()
	return bo
}

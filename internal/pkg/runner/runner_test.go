// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runner

import (
	"context"
	"testing"
)

func TestRunnerStartStop(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	runner := Start(ctx, func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	})

	go func() {
		runner.Stop()
	}()

	<-runner.Done()
}

func TestRunnerStartCancel(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	runner := Start(ctx, func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	})

	go func() {
		cn()
	}()

	<-runner.Done()
}

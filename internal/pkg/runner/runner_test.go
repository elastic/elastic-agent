// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runner

import (
	"context"
	"errors"
	"testing"
	"time"
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

func TestRunnerDoneTimedOut(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	runner := Start(ctx, func(ctx context.Context) error {
		time.Sleep(time.Second)
		<-ctx.Done()
		return nil
	})

	go func() {
		runner.Stop()
	}()

	// Should be done much sooner
	select {
	case <-runner.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out")
	}

	// Should have no errors
	err := runner.Err()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want: %v, got: %v", context.DeadlineExceeded, err)
	}
}

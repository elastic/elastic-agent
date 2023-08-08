// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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

func TestRunnerDoneWithTimeout(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	runner := Start(ctx, func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	})

	go func() {
		runner.Stop()
	}()

	// Should be done much sooner
	<-runner.DoneWithTimeout(time.Second)

	// Should have no errors
	if runner.Err() != nil {
		t.Fatal(runner.Err())
	}
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
	<-runner.DoneWithTimeout(500 * time.Millisecond)

	// Should have no errors
	err := runner.Err()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want: %v, got: %v", context.DeadlineExceeded, err)
	}
}

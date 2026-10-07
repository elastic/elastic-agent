// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

// The collector calls Shutdown on every component when startup fails, even on
// components whose Start was never called. Shutdown must not block in that case.
func TestShutdownWithoutStart(t *testing.T) {
	rcv := newTestReceiver(t)
	shutdownWithin(t, rcv, 5*time.Second)
}

func TestStartThenShutdown(t *testing.T) {
	rcv := newTestReceiver(t)
	require.NoError(t, rcv.Start(t.Context(), componenttest.NewNopHost()))
	shutdownWithin(t, rcv, 5*time.Second)

	// The run loop must have exited.
	select {
	case <-rcv.done:
	default:
		t.Fatal("run loop still running after Shutdown")
	}
}

func newTestReceiver(t *testing.T) *monitoringReceiver {
	t.Helper()
	cfg := createDefaultConfig().(*Config)
	cfg.Interval = time.Hour // keep the run loop idle during the test
	rcv, err := createReceiver(t.Context(), receivertest.NewNopSettings(NewFactory().Type()), cfg, consumertest.NewNop())
	require.NoError(t, err)
	return rcv.(*monitoringReceiver)
}

// shutdownWithin fails the test if Shutdown doesn't return within the timeout.
// Shutdown is given a background context so the test verifies that the receiver
// itself unblocks, rather than relying on context cancellation.
func shutdownWithin(t *testing.T, rcv *monitoringReceiver, timeout time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- rcv.Shutdown(context.Background()) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(timeout):
		t.Fatal("Shutdown did not return")
	}
}

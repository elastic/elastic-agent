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

func newTestReceiver(t *testing.T) *monitoringReceiver {
	t.Helper()
	cfg := createDefaultConfig().(*Config)
	cfg.Interval = time.Hour
	r, err := createReceiver(t.Context(), receivertest.NewNopSettings(receivertest.NopType), cfg, consumertest.NewNop())
	require.NoError(t, err)
	return r.(*monitoringReceiver)
}

// Shutdown must return promptly even if Start was never called. The collector
// calls Shutdown on every component in the graph when startup fails, including
// those whose Start was never reached, and it does so with a context that is
// not cancelled.
func TestShutdownWithoutStart(t *testing.T) {
	r := newTestReceiver(t)

	done := make(chan error, 1)
	go func() { done <- r.Shutdown(context.Background()) }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown blocked when Start was never called")
	}
}

func TestStartShutdown(t *testing.T) {
	r := newTestReceiver(t)
	require.NoError(t, r.Start(t.Context(), componenttest.NewNopHost()))

	done := make(chan error, 1)
	go func() { done <- r.Shutdown(context.Background()) }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not complete after Start")
	}

	select {
	case <-r.done:
	default:
		t.Fatal("run loop did not exit after Shutdown")
	}
}

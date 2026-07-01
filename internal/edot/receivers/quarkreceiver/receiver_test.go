// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package quarkreceiver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

func TestReceiverEmitsLogs(t *testing.T) {
	factory := NewFactory()

	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.Interval = 10 * time.Millisecond
	cfg.Message = "hello from quark"

	sink := &consumertest.LogsSink{}
	set := receivertest.NewNopSettings(typ)

	recv, err := factory.CreateLogs(context.Background(), set, cfg, sink)
	require.NoError(t, err)

	require.NoError(t, recv.Start(context.Background(), nil))
	defer func() {
		require.NoError(t, recv.Shutdown(context.Background()))
	}()

	// Wait until at least one log record is received.
	assert.Eventually(t, func() bool {
		return sink.LogRecordCount() >= 1
	}, 2*time.Second, 5*time.Millisecond, "expected at least one log record to be received")

	// Verify the body of the first record.
	all := sink.AllLogs()
	require.NotEmpty(t, all)
	rl := all[0].ResourceLogs().At(0)
	sl := rl.ScopeLogs().At(0)
	lr := sl.LogRecords().At(0)
	assert.Equal(t, "hello from quark", lr.Body().Str())
}

func TestReceiverDefaultConfig(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	assert.Equal(t, time.Second, cfg.Interval)
	assert.Equal(t, "quark", cfg.Message)
	assert.NoError(t, cfg.Validate())
}

func TestReceiverConfigValidation(t *testing.T) {
	cfg := &Config{Interval: 0, Message: "x"}
	assert.Error(t, cfg.Validate())

	cfg.Interval = -time.Second
	assert.Error(t, cfg.Validate())

	cfg.Interval = time.Millisecond
	assert.NoError(t, cfg.Validate())
}

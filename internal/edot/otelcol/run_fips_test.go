// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package otelcol

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/otelcol"

	"github.com/elastic/elastic-agent/internal/edot/otelcol/components"
)

func TestStartCollectorFIPS(t *testing.T) {
	configFiles := getConfigFiles("all-components-fips.yml")
	settings := NewSettings("test", configFiles, WithComponents(components.Default()))

	collector, err := otelcol.NewCollector(*settings)
	require.NoError(t, err)
	require.NotNil(t, collector)

	wg := startCollector(context.Background(), t, collector, "")

	assert.Eventually(t, func() bool {
		return otelcol.StateRunning == collector.GetState()
	}, 10*time.Second, 200*time.Millisecond)
	collector.Shutdown()
	wg.Wait()
	assert.Equal(t, otelcol.StateClosed, collector.GetState())
}

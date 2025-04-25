// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package otel

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/otelcol"
)

func TestStartCollectorFIPS(t *testing.T) {
	configFiles := getConfigFiles("all-components-fips.yml")
	settings := NewSettings("test", configFiles)

	collector, err := otelcol.NewCollector(*settings)
	require.NoError(t, err)
	require.NotNil(t, collector)

	wg := startCollector(context.Background(), t, collector, "")

	collector.Shutdown()
	wg.Wait()
	assert.Equal(t, otelcol.StateClosed, collector.GetState())
}

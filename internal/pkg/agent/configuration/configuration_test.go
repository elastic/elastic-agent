// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/component"
)

// TestNewFromConfig_RuntimeConfigFromFile loads a YAML config file that sets
// runtime manager overrides and verifies the RuntimeConfig is unpacked
// correctly. In particular it exercises the BeatRuntimeConfig inline map +
// "default" struct field combination that triggered go-ucfg bug
// https://github.com/elastic/go-ucfg/issues/215 (the "default" value leaked
// into the inline InputType map). Validate contains a workaround that removes
// the spurious key; this test ensures the final state is correct regardless
// of whether the upstream bug is present.
func TestNewFromConfig_RuntimeConfigFromFile(t *testing.T) {
	cfg, err := config.LoadFile(filepath.Join("testdata", "runtime_config.yaml"))
	require.NoError(t, err)

	c, err := NewFromConfig(cfg)
	require.NoError(t, err)

	runtime := c.Settings.Internal.Runtime
	require.NotNil(t, runtime)

	assert.Equal(t, string(component.OtelRuntimeManager), runtime.Default)

	// filebeat: default + one explicit input type override
	assert.Equal(t, "otel", runtime.Filebeat.Default)
	assert.Equal(t, map[string]string{"log/metrics": "process"}, runtime.Filebeat.InputType,
		"InputType must contain only the explicitly configured keys, no spurious 'default' entry")

	// metricbeat: no default override; system/metrics set in the fixture, rest
	// comes from DefaultRuntimeConfig defaults.
	assert.Equal(t, "", runtime.Metricbeat.Default)
	assert.Equal(t, string(component.OtelRuntimeManager), runtime.Metricbeat.InputType["system/metrics"])
}

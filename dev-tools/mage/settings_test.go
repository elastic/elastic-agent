// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetVersion(t *testing.T) {
	cfg, err := LoadSettings()
	require.NoError(t, err)
	bp, err := BeatQualifiedVersion(cfg)
	assert.NoError(t, err)
	_ = bp
}

func TestAgentPackageVersion(t *testing.T) {
	t.Run("agent package version without env var", func(t *testing.T) {
		cfg, err := LoadSettings()
		require.NoError(t, err)
		expectedPkgVersion, err := BeatQualifiedVersion(cfg)
		require.NoError(t, err)
		actualPkgVersion, err := AgentPackageVersion(cfg)
		require.NoError(t, err)
		assert.Equal(t, expectedPkgVersion, actualPkgVersion)
	})

	t.Run("agent package version env var set", func(t *testing.T) {
		cfg, err := LoadSettings()
		require.NoError(t, err)
		expectedPkgVersion := "1.2.3-specialrelease+abcdef"
		cfg.Packaging.AgentPackageVersion = expectedPkgVersion
		actualPkgVersion, err := AgentPackageVersion(cfg)
		require.NoError(t, err)
		assert.Equal(t, expectedPkgVersion, actualPkgVersion)
	})

	t.Run("agent package version function must be mapped", func(t *testing.T) {
		cfg, err := LoadSettings()
		require.NoError(t, err)
		cfg.Packaging.AgentPackageVersion = "1.2.3-specialrelease+abcdef"
		funcMap := FuncMap(cfg)
		assert.Contains(t, funcMap, agentPackageVersionMappedFunc)
		require.IsType(t, funcMap[agentPackageVersionMappedFunc], func() (string, error) { return "", nil })
		mappedFuncPkgVersion, err := funcMap[agentPackageVersionMappedFunc].(func() (string, error))()
		require.NoError(t, err)
		expectedPkgVersion, err := AgentPackageVersion(cfg)
		require.NoError(t, err)
		assert.Equal(t, expectedPkgVersion, mappedFuncPkgVersion)
	})
}

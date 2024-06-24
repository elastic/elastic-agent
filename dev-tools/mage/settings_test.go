// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package mage

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetVersion(t *testing.T) {
	bp, err := BeatQualifiedVersion()
	assert.NoError(t, err)
	_ = bp
}

func TestAgentPackageVersion(t *testing.T) {
	t.Run("agent package version without env var", func(t *testing.T) {
		os.Unsetenv(agentPackageVersionEnvVar)
		initGlobals()
		expectedPkgVersion, err := BeatQualifiedVersion()
		require.NoError(t, err)
		actualPkgVersion, err := AgentPackageVersion()
		require.NoError(t, err)
		assert.Equal(t, expectedPkgVersion, actualPkgVersion)
	})

	t.Run("agent package version env var set", func(t *testing.T) {
		expectedPkgVersion := "1.2.3-specialrelease+abcdef"
		os.Setenv(agentPackageVersionEnvVar, expectedPkgVersion)
		t.Cleanup(func() { os.Unsetenv(agentPackageVersionEnvVar) })
		initGlobals()
		actualPkgVersion, err := AgentPackageVersion()
		require.NoError(t, err)
		assert.Equal(t, expectedPkgVersion, actualPkgVersion)
	})

	t.Run("agent package version function must be mapped", func(t *testing.T) {
		os.Setenv(agentPackageVersionEnvVar, "1.2.3-specialrelease+abcdef")
		t.Cleanup(func() { os.Unsetenv(agentPackageVersionEnvVar) })
		initGlobals()
		assert.Contains(t, FuncMap, agentPackageVersionMappedFunc)
		require.IsType(t, FuncMap[agentPackageVersionMappedFunc], func() (string, error) { return "", nil })
		mappedFuncPkgVersion, err := FuncMap[agentPackageVersionMappedFunc].(func() (string, error))()
		require.NoError(t, err)
		expectedPkgVersion, err := AgentPackageVersion()
		require.NoError(t, err)
		assert.Equal(t, expectedPkgVersion, mappedFuncPkgVersion)
	})
}

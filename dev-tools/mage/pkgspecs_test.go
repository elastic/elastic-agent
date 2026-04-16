// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadElasticAgentPackageSpecs(t *testing.T) {
	// writeSpecFile writes a packages.yml under the expected relative path
	// inside a temporary directory and returns the directory path.
	writeSpecFile := func(t *testing.T, content string) string {
		t.Helper()
		tmpDir := t.TempDir()
		specDir := filepath.Join(tmpDir, filepath.Dir(packageSpecFile))
		require.NoError(t, os.MkdirAll(specDir, 0o755))
		require.NoError(t, os.WriteFile(
			filepath.Join(tmpDir, packageSpecFile),
			[]byte(content), 0o644,
		))
		return tmpDir
	}

	t.Run("loads core spec successfully", func(t *testing.T) {
		beatsDir := writeSpecFile(t, `
specs:
  elastic_agent_core:
    - os: linux
      types:
        - targz
      spec:
        name: core-pkg
  elastic_agent_packaging:
    - os: windows
      types:
        - zip
      spec:
        name: packaging-pkg
`)
		coreSpec, err := LoadElasticAgentCorePackageSpec(beatsDir)
		require.NoError(t, err)
		require.Len(t, coreSpec, 1)
		assert.Equal(t, "linux", coreSpec[0].OS)
		assert.Equal(t, "core-pkg", coreSpec[0].Spec.Name)
	})

	t.Run("loads packaging spec successfully", func(t *testing.T) {
		beatsDir := writeSpecFile(t, `
specs:
  elastic_agent_core:
    - os: linux
      types:
        - targz
      spec:
        name: core-pkg
  elastic_agent_packaging:
    - os: windows
      types:
        - zip
      spec:
        name: packaging-pkg
`)
		pkgSpec, err := LoadElasticAgentPackageSpec(beatsDir)
		require.NoError(t, err)
		require.Len(t, pkgSpec, 1)
		assert.Equal(t, "windows", pkgSpec[0].OS)
		assert.Equal(t, "packaging-pkg", pkgSpec[0].Spec.Name)
	})

	t.Run("returns error when spec file does not exist", func(t *testing.T) {
		_, err := LoadElasticAgentCorePackageSpec(t.TempDir())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load package specs")
	})

	t.Run("returns error when elastic_agent_core is missing", func(t *testing.T) {
		beatsDir := writeSpecFile(t, `
specs:
  elastic_agent_packaging:
    - os: linux
      types:
        - targz
      spec:
        name: pkg
`)
		_, err := LoadElasticAgentCorePackageSpec(beatsDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "elastic_agent_core")
	})

	t.Run("returns error when elastic_agent_packaging is missing", func(t *testing.T) {
		beatsDir := writeSpecFile(t, `
specs:
  elastic_agent_core:
    - os: linux
      types:
        - targz
      spec:
        name: core
`)
		_, err := LoadElasticAgentPackageSpec(beatsDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "elastic_agent_packaging")
	})
}

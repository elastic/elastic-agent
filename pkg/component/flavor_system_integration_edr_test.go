// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build edr

package component

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
)

// TestEDRFlavorSystemIntegrationInputs verifies that every input type used by the
// System integration (logfile, journald, winlog and system/metrics) is accepted by the
// EDR flavor on every supported platform, using the real EDOT input spec.
func TestEDRFlavorSystemIntegrationInputs(t *testing.T) {
	specContent, err := os.ReadFile(filepath.Join("..", "..", "internal", "edot", "spec.yml"))
	require.NoError(t, err)
	specDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(specDir, "elastic-otel-collector.spec.yml"), specContent, 0o600)) //nolint:gosec // G703: path in test temp dir

	platforms := map[string]PlatformDetail{
		"linux/amd64":   {Platform: Platform{OS: Linux, Arch: AMD64, GOOS: Linux}},
		"linux/arm64":   {Platform: Platform{OS: Linux, Arch: ARM64, GOOS: Linux}},
		"darwin/arm64":  {Platform: Platform{OS: Darwin, Arch: ARM64, GOOS: Darwin}},
		"windows/amd64": {Platform: Platform{OS: Windows, Arch: AMD64, GOOS: Windows}},
		"windows/arm64": {Platform: Platform{OS: Windows, Arch: ARM64, GOOS: Windows}},
	}

	// Input types as they appear in a Fleet policy for the System integration.
	systemInputTypes := []string{"logfile", "journald", "winlog", "system/metrics"}

	for name, platform := range platforms {
		t.Run(name, func(t *testing.T) {
			specs, err := LoadRuntimeSpecs(specDir, platform, SkipBinaryCheck())
			require.NoError(t, err)

			for _, inputType := range systemInputTypes {
				t.Run(inputType, func(t *testing.T) {
					policy := map[string]interface{}{
						"outputs": map[string]interface{}{
							"default": map[string]interface{}{"type": "elasticsearch", "enabled": true},
						},
						"inputs": []interface{}{
							map[string]interface{}{"type": inputType, "id": "system-" + inputType},
						},
					}

					result, err := specs.ToComponents(
						policy, DefaultRuntimeConfig(), nil, nil, logp.InfoLevel, nil, map[string]uint64{}, map[string]bool{})
					require.NoError(t, err)
					require.Len(t, result, 1)
					require.NoError(t, result[0].Err)
					require.Equal(t, OtelRuntimeManager, result[0].RuntimeManager)
				})
			}
		})
	}
}

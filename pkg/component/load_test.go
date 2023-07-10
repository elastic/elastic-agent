// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadRuntimeSpecs(t *testing.T) {
	for _, platform := range GlobalPlatforms {
		t.Run(platform.String(), func(t *testing.T) {
			detail := PlatformDetail{
				Platform: platform,
			}
			runtime, err := LoadRuntimeSpecs(filepath.Join("..", "..", "specs"), detail, SkipBinaryCheck())
			require.NoError(t, err)
			assert.Greater(t, len(runtime.inputTypes), 0)
			assert.Greater(t, len(runtime.inputSpecs), 0)

			// filestream is supported by all platforms
			input, err := runtime.GetInput("filestream")
			require.NoError(t, err)
			assert.NotNil(t, input)

			// unknown input
			_, err = runtime.GetInput("unknown")
			require.ErrorIs(t, err, ErrInputNotSupported)
		})
	}
}

func TestLoadSpec_Components(t *testing.T) {
	scenarios := []struct {
		Name string
		Path string
	}{
		{
			Name: "APM Server",
			Path: "apm-server.spec.yml",
		},
		{
			Name: "Auditbeat",
			Path: "auditbeat.spec.yml",
		},
		{
			Name: "Cloudbeat",
			Path: "cloudbeat.spec.yml",
		},
		{
			Name: "Cloud Defend",
			Path: "cloud-defend.spec.yml",
		},
		{
			Name: "Endpoint Security",
			Path: "endpoint-security.spec.yml",
		},
		{
			Name: "Filebeat",
			Path: "filebeat.spec.yml",
		},
		{
			Name: "Fleet Server",
			Path: "fleet-server.spec.yml",
		},
		{
			Name: "Heartbeat",
			Path: "heartbeat.spec.yml",
		},
		{
			Name: "Metricbeat",
			Path: "metricbeat.spec.yml",
		},
		{
			Name: "Osquerybeat",
			Path: "osquerybeat.spec.yml",
		},
		{
			Name: "Packetbeat",
			Path: "packetbeat.spec.yml",
		},
		{
			Name: "Universal Profiling Collector",
			Path: "pf-elastic-collector.spec.yml",
		},
		{
			Name: "Universal Profiling Symbolizer",
			Path: "pf-elastic-symbolizer.spec.yml",
		},
		{
			Name: "Universal Profiling Agent",
			Path: "pf-host-agent.spec.yml",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			data, err := ioutil.ReadFile(filepath.Join("..", "..", "specs", scenario.Path))
			require.NoError(t, err)
			_, err = LoadSpec(data)
			require.NoError(t, err)
		})
	}
}

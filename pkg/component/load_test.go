// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package component

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseComponentFiles(t *testing.T) {
	binarySuffix := ""
	if runtime.GOOS == "windows" {
		binarySuffix = ".exe"
	}
	tests := []struct {
		name            string
		content         []byte
		filename        string
		includeDefaults bool
		want            []string
		wantErr         bool
	}{
		{
			name:            "empty content with no defaults",
			content:         []byte(`{}`),
			filename:        "test.spec.yml",
			includeDefaults: false,
			want:            []string{},
			wantErr:         false,
		},
		{
			name:            "empty content with defaults",
			content:         []byte(`{}`),
			filename:        "test.spec.yml",
			includeDefaults: true,
			want: []string{
				"test" + binarySuffix, // binary name
				"test.spec.yml",       // spec file
				"test.yml",            // default config
			},
			wantErr: false,
		},
		{
			name:            "empty content with defaults, long name",
			content:         []byte(`{}`),
			filename:        filepath.Join("this", "is", "path", "test.spec.yml"),
			includeDefaults: true,
			want: []string{
				"test" + binarySuffix, // binary name
				"test.spec.yml",       // spec file
				"test.yml",            // default config
			},
			wantErr: false,
		},
		{
			name: "with explicit files",
			content: []byte(`
component_files:
  - "module/config/*"
  - "module/schemas/*"
`),
			filename:        "test.spec.yml",
			includeDefaults: false,
			want: []string{
				"module/config/*",
				"module/schemas/*",
			},
			wantErr: false,
		},
		{
			name: "with explicit files and defaults",
			content: []byte(`
component_files:
  - "module/config/*"
  - "module/schemas/*"
`),
			filename:        "test.spec.yml",
			includeDefaults: true,
			want: []string{
				"module/config/*",
				"module/schemas/*",
				"test" + binarySuffix, // binary name
				"test.spec.yml",       // spec file
				"test.yml",            // default config
			},
			wantErr: false,
		},
		{
			name:            "invalid yaml content",
			content:         []byte(`{invalid`),
			filename:        "test.spec.yml",
			includeDefaults: true,
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseComponentFiles(tt.content, tt.filename, tt.includeDefaults)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

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
			Name: "Cloudbeat",
			Path: "cloudbeat.spec.yml",
		},
		{
			Name: "Endpoint Security",
			Path: "endpoint-security.spec.yml",
		},
		{
			Name: "Filebeat",
			Path: "testbeat.spec.yml",
		},
		{
			Name: "Fleet Server",
			Path: "fleet-server.spec.yml",
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
			data, err := os.ReadFile(filepath.Join("..", "..", "specs", scenario.Path))
			require.NoError(t, err)
			_, err = LoadSpec(data)
			require.NoError(t, err)
		})
	}
}

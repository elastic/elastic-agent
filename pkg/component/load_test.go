// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package component

import (
	"os"
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

func TestInputRuntimeSpec_CommandName(t *testing.T) {
	tests := []struct {
		name string
		spec InputRuntimeSpec
		want string
	}{
		{
			name: "returns Command.Name when set",
			spec: InputRuntimeSpec{
				BinaryName: "mybinary",
				Spec: InputSpec{
					Command: &CommandSpec{
						Name: "custom-command",
					},
				},
			},
			want: "custom-command",
		},
		{
			name: "returns first arg when binary is agentbeat and no Command.Name",
			spec: InputRuntimeSpec{
				BinaryName: "agentbeat",
				Spec: InputSpec{
					Command: &CommandSpec{
						Args: []string{"filebeat", "--some-flag"},
					},
				},
			},
			want: "filebeat",
		},
		{
			name: "returns BinaryName when no Command",
			spec: InputRuntimeSpec{
				BinaryName: "mybinary",
				Spec:       InputSpec{},
			},
			want: "mybinary",
		},
		{
			name: "returns BinaryName when Command has no Name and not agentbeat",
			spec: InputRuntimeSpec{
				BinaryName: "mybinary",
				Spec: InputSpec{
					Command: &CommandSpec{
						Args: []string{"some-arg"},
					},
				},
			},
			want: "mybinary",
		},
		{
			name: "returns BinaryName when agentbeat but no args",
			spec: InputRuntimeSpec{
				BinaryName: "agentbeat",
				Spec: InputSpec{
					Command: &CommandSpec{
						Args: []string{},
					},
				},
			},
			want: "agentbeat",
		},
		{
			name: "prefers Command.Name over agentbeat first arg",
			spec: InputRuntimeSpec{
				BinaryName: "agentbeat",
				Spec: InputSpec{
					Command: &CommandSpec{
						Name: "explicit-name",
						Args: []string{"filebeat"},
					},
				},
			},
			want: "explicit-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.spec.CommandName()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestInputRuntimeSpec_BeatName(t *testing.T) {
	tests := []struct {
		name string
		spec InputRuntimeSpec
		want string
	}{
		{
			name: "returns command name when it ends with beat",
			spec: InputRuntimeSpec{
				BinaryName: "mybinary",
				Spec: InputSpec{
					Command: &CommandSpec{
						Name: "filebeat",
					},
				},
			},
			want: "filebeat",
		},
		{
			name: "returns empty when command name does not end with beat",
			spec: InputRuntimeSpec{
				BinaryName: "mybinary",
				Spec: InputSpec{
					Command: &CommandSpec{
						Name: "apm-server",
					},
				},
			},
			want: "",
		},
		{
			name: "returns first arg when agentbeat and arg ends with beat",
			spec: InputRuntimeSpec{
				BinaryName: "agentbeat",
				Spec: InputSpec{
					Command: &CommandSpec{
						Args: []string{"metricbeat", "--some-flag"},
					},
				},
			},
			want: "metricbeat",
		},
		{
			name: "returns empty when agentbeat but first arg does not end with beat",
			spec: InputRuntimeSpec{
				BinaryName: "agentbeat",
				Spec: InputSpec{
					Command: &CommandSpec{
						Args: []string{"osquerybeat", "--some-flag"},
					},
				},
			},
			want: "osquerybeat",
		},
		{
			name: "returns BinaryName when it ends with beat and no Command",
			spec: InputRuntimeSpec{
				BinaryName: "testbeat",
				Spec:       InputSpec{},
			},
			want: "testbeat",
		},
		{
			name: "returns empty when BinaryName does not end with beat and no Command",
			spec: InputRuntimeSpec{
				BinaryName: "fleet-server",
				Spec:       InputSpec{},
			},
			want: "",
		},
		{
			name: "handles heartbeat correctly",
			spec: InputRuntimeSpec{
				BinaryName: "agentbeat",
				Spec: InputSpec{
					Command: &CommandSpec{
						Args: []string{"heartbeat"},
					},
				},
			},
			want: "heartbeat",
		},
		{
			name: "handles auditbeat correctly",
			spec: InputRuntimeSpec{
				BinaryName: "auditbeat",
				Spec:       InputSpec{},
			},
			want: "auditbeat",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.spec.BeatName()
			assert.Equal(t, tt.want, got)
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

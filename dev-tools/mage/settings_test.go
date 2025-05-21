// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"text/template"

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
		t.Setenv(agentPackageVersionEnvVar, expectedPkgVersion)
		initGlobals()
		actualPkgVersion, err := AgentPackageVersion()
		require.NoError(t, err)
		assert.Equal(t, expectedPkgVersion, actualPkgVersion)
	})

	t.Run("agent package version function must be mapped", func(t *testing.T) {
		t.Setenv(agentPackageVersionEnvVar, "1.2.3-specialrelease+abcdef")
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

func TestGeneratePackageManifest_AgentVersion(t *testing.T) {

	const manifestTemplateString = `
    version: co.elastic.agent/v1
    kind: PackageManifest
    package:
        version: {{ .PackageVersion }}
        hash: {{ .FullHash }}
        {{- if .Snapshot }}
        snapshot: {{ .Snapshot }}
        {{- end }}
        versioned-home: data/elastic-agent-{{ .ShortHash }}
        path-mappings:
            - data/elastic-agent-{{ .ShortHash }}: data/elastic-agent-{{ .PackageVersionWithSnapshot }}-{{ .ShortHash }}
              manifest.yaml: data/elastic-agent-{{ .PackageVersionWithSnapshot }}-{{ .ShortHash }}/manifest.yaml
`

	manifestTemplate, err := template.New("expectedManifest").Parse(manifestTemplateString)
	require.NoError(t, err, "manifest template parsing failed")

	type args struct {
		beatName                   string
		PackageVersion             string
		Snapshot                   bool
		FullHash                   string
		ShortHash                  string
		PackageVersionWithSnapshot string
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "simple major.minor.patch version, no Snapshot",
			args: args{
				beatName:                   "elastic-agent",
				PackageVersion:             "1.2.3",
				Snapshot:                   false,
				FullHash:                   "abcdefghijkl",
				ShortHash:                  "abcdef",
				PackageVersionWithSnapshot: "1.2.3",
			},
			wantErr: assert.NoError,
		},
		{
			name: "simple major.minor.patch version, Snapshot",
			args: args{
				beatName:                   "elastic-agent",
				PackageVersion:             "1.2.3",
				Snapshot:                   true,
				FullHash:                   "abcdefghijkl",
				ShortHash:                  "abcdef",
				PackageVersionWithSnapshot: "1.2.3-SNAPSHOT",
			},
			wantErr: assert.NoError,
		},
		{
			name: "major.minor.patch version with build metadata, no Snapshot",
			args: args{
				beatName:                   "elastic-agent",
				PackageVersion:             "1.2.3+build20240329010101",
				Snapshot:                   false,
				FullHash:                   "abcdefghijkl",
				ShortHash:                  "abcdef",
				PackageVersionWithSnapshot: "1.2.3+build20240329010101",
			},

			wantErr: assert.NoError,
		},
		{
			name: "major.minor.patch version with build metadata, Snapshot",
			args: args{
				beatName:                   "elastic-agent",
				PackageVersion:             "1.2.3+build20240329010101",
				Snapshot:                   true,
				FullHash:                   "abcdefghijkl",
				ShortHash:                  "abcdef",
				PackageVersionWithSnapshot: "1.2.3-SNAPSHOT+build20240329010101",
			},

			wantErr: assert.NoError,
		},
		{
			name: "major.minor.patch version with prerelease and build metadata, no Snapshot",
			args: args{
				beatName:                   "elastic-agent",
				PackageVersion:             "1.2.3-prerelease+build20240329010101",
				Snapshot:                   false,
				FullHash:                   "abcdefghijkl",
				ShortHash:                  "abcdef",
				PackageVersionWithSnapshot: "1.2.3-prerelease+build20240329010101",
			},

			wantErr: assert.NoError,
		},
		{
			name: "major.minor.patch version with prerelease and build metadata, Snapshot",
			args: args{
				beatName:                   "elastic-agent",
				PackageVersion:             "1.2.3-prerelease+build20240329010101",
				Snapshot:                   true,
				FullHash:                   "abcdefghijkl",
				ShortHash:                  "abcdef",
				PackageVersionWithSnapshot: "1.2.3-SNAPSHOT.prerelease+build20240329010101",
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GeneratePackageManifest(tt.args.beatName, tt.args.PackageVersion, tt.args.Snapshot, tt.args.FullHash, tt.args.ShortHash, false, nil)
			if !tt.wantErr(t, err, fmt.Sprintf("GeneratePackageManifest(%v, %v, %v, %v, %v)", tt.args.beatName, tt.args.PackageVersion, tt.args.Snapshot, tt.args.FullHash, tt.args.ShortHash)) {
				return
			}
			buf := new(strings.Builder)
			err = manifestTemplate.Execute(buf, tt.args)
			require.NoError(t, err, "Error rendering expected YAML template")
			assert.YAMLEqf(t, buf.String(), got, "GeneratePackageManifest(%v, %v, %v, %v, %v)", tt.args.beatName, tt.args.PackageVersion, tt.args.Snapshot, tt.args.FullHash, tt.args.ShortHash)
		})
	}
}

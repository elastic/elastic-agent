// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"fmt"
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
	// manifest format string. argument are expected in order:
	// 1: packageVersion
	// 2: snapshot
	// 3: fullHash
	// 4: shortHash
	// 5: version string combining packageVersion and snapshot flag
	const manifestFormat = `
    version: co.elastic.agent/v1
    kind: PackageManifest
    package:
        version: %[1]s
        hash: %[3]s
        snapshot: %[2]t
        versioned-home: data/elastic-agent-%[4]s
        path-mappings:
            - data/elastic-agent-%[4]s: data/elastic-agent-%[5]s-%[4]s
              manifest.yaml: data/elastic-agent-%[5]s-%[4]s/manifest.yaml
`

	type args struct {
		beatName       string
		packageVersion string
		snapshot       bool
		fullHash       string
		shortHash      string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "simple major.minor.patch version, no snapshot",
			args: args{
				beatName:       "elastic-agent",
				packageVersion: "1.2.3",
				snapshot:       false,
				fullHash:       "abcdefghijkl",
				shortHash:      "abcdef",
			},
			want:    "1.2.3",
			wantErr: assert.NoError,
		},
		{
			name: "simple major.minor.patch version, snapshot",
			args: args{
				beatName:       "elastic-agent",
				packageVersion: "1.2.3",
				snapshot:       true,
				fullHash:       "abcdefghijkl",
				shortHash:      "abcdef",
			},
			want:    "1.2.3-SNAPSHOT",
			wantErr: assert.NoError,
		},
		{
			name: "major.minor.patch version with build metadata, no snapshot",
			args: args{
				beatName:       "elastic-agent",
				packageVersion: "1.2.3+build20240329010101",
				snapshot:       false,
				fullHash:       "abcdefghijkl",
				shortHash:      "abcdef",
			},
			want:    "1.2.3+build20240329010101",
			wantErr: assert.NoError,
		},
		{
			name: "major.minor.patch version with build metadata, snapshot",
			args: args{
				beatName:       "elastic-agent",
				packageVersion: "1.2.3+build20240329010101",
				snapshot:       true,
				fullHash:       "abcdefghijkl",
				shortHash:      "abcdef",
			},
			want:    "1.2.3-SNAPSHOT+build20240329010101",
			wantErr: assert.NoError,
		},
		{
			name: "major.minor.patch version with prerelease and build metadata, no snapshot",
			args: args{
				beatName:       "elastic-agent",
				packageVersion: "1.2.3-prerelease+build20240329010101",
				snapshot:       false,
				fullHash:       "abcdefghijkl",
				shortHash:      "abcdef",
			},
			want:    "1.2.3-prerelease+build20240329010101",
			wantErr: assert.NoError,
		},
		{
			name: "major.minor.patch version with prerelease and build metadata, snapshot",
			args: args{
				beatName:       "elastic-agent",
				packageVersion: "1.2.3-prerelease+build20240329010101",
				snapshot:       true,
				fullHash:       "abcdefghijkl",
				shortHash:      "abcdef",
			},
			want:    "1.2.3-SNAPSHOT.prerelease+build20240329010101",
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GeneratePackageManifest(tt.args.beatName, tt.args.packageVersion, tt.args.snapshot, tt.args.fullHash, tt.args.shortHash, false, nil)
			if !tt.wantErr(t, err, fmt.Sprintf("GeneratePackageManifest(%v, %v, %v, %v, %v)", tt.args.beatName, tt.args.packageVersion, tt.args.snapshot, tt.args.fullHash, tt.args.shortHash)) {
				return
			}
			expectedYaml := fmt.Sprintf(manifestFormat, tt.args.packageVersion, tt.args.snapshot, tt.args.fullHash, tt.args.shortHash, tt.want)
			assert.YAMLEqf(t, expectedYaml, got, "GeneratePackageManifest(%v, %v, %v, %v, %v)", tt.args.beatName, tt.args.packageVersion, tt.args.snapshot, tt.args.fullHash, tt.args.shortHash)
		})
	}
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manifest

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/dev-tools/packaging"
)

var (
	//go:embed testdata/manifest-8.14.2.json
	manifest8_14_2 string

	//go:embed testdata/manifest-8.14.2-SNAPSHOT.json
	manifest8_14_2_SNAPSHOT string

	//go:embed testdata/manifest-8.14.0+build202406201002.json
	manifest8_14_0_build202406201002 string
)

func getManifestJsonData(t *testing.T, contents string) Build {
	var response Build

	err := json.NewDecoder(strings.NewReader(contents)).Decode(&response)
	assert.NoError(t, err)

	return response
}

func TestResolveManifestPackage(t *testing.T) {
	tcs := []struct {
		name            string
		file            string
		projectName     string
		binary          string
		platform        string
		expectedUrlList []string
	}{
		{
			name:        "Unified Release Staging 8.14 apm-server",
			file:        manifest8_14_2,
			projectName: "apm-server",
			binary:      "apm-server",
			platform:    "linux/amd64",
			expectedUrlList: []string{
				"https://staging.elastic.co/8.14.2-cfd42f49/downloads/apm-server/apm-server-8.14.2-linux-x86_64.tar.gz",
				"https://staging.elastic.co/8.14.2-cfd42f49/downloads/apm-server/apm-server-8.14.2-linux-x86_64.tar.gz.sha512",
				"https://staging.elastic.co/8.14.2-cfd42f49/downloads/apm-server/apm-server-8.14.2-linux-x86_64.tar.gz.asc",
			},
		},
		{
			name:            "Unified Release Staging 8.14 apm-server unsupported architecture",
			file:            manifest8_14_2,
			projectName:     "apm-server",
			binary:          "apm-server",
			platform:        "darwin/aarch64",
			expectedUrlList: []string{},
		},
		{
			name:        "Unified Release Snapshot 8.14 apm-server",
			file:        manifest8_14_2_SNAPSHOT,
			projectName: "apm-server",
			binary:      "apm-server",
			platform:    "linux/amd64",
			expectedUrlList: []string{
				"https://snapshots.elastic.co/8.14.2-1ceac187/downloads/apm-server/apm-server-8.14.2-SNAPSHOT-linux-x86_64.tar.gz",
				"https://snapshots.elastic.co/8.14.2-1ceac187/downloads/apm-server/apm-server-8.14.2-SNAPSHOT-linux-x86_64.tar.gz.sha512",
				"https://snapshots.elastic.co/8.14.2-1ceac187/downloads/apm-server/apm-server-8.14.2-SNAPSHOT-linux-x86_64.tar.gz.asc",
			},
		},
		{
			name:        "Independent Agent Staging 8.14 apm-server",
			file:        manifest8_14_0_build202406201002,
			projectName: "apm-server",
			binary:      "apm-server",
			platform:    "linux/amd64",
			expectedUrlList: []string{
				"https://staging.elastic.co/8.14.0-fe696c51/downloads/apm-server/apm-server-8.14.0-linux-x86_64.tar.gz",
				"https://staging.elastic.co/8.14.0-fe696c51/downloads/apm-server/apm-server-8.14.0-linux-x86_64.tar.gz.sha512",
				"https://staging.elastic.co/8.14.0-fe696c51/downloads/apm-server/apm-server-8.14.0-linux-x86_64.tar.gz.asc",
			},
		},
		{
			name:        "Unified Release Staging 8.14 endpoint-dev",
			file:        manifest8_14_2,
			projectName: "endpoint-dev",
			binary:      "endpoint-security",
			platform:    "linux/amd64",
			expectedUrlList: []string{
				"https://staging.elastic.co/8.14.2-cfd42f49/downloads/endpoint-dev/endpoint-security-8.14.2-linux-x86_64.tar.gz",
				"https://staging.elastic.co/8.14.2-cfd42f49/downloads/endpoint-dev/endpoint-security-8.14.2-linux-x86_64.tar.gz.sha512",
				"https://staging.elastic.co/8.14.2-cfd42f49/downloads/endpoint-dev/endpoint-security-8.14.2-linux-x86_64.tar.gz.asc",
			},
		},
		{
			name:        "Unified Release Snapshot 8.14 endpoint-dev",
			file:        manifest8_14_2_SNAPSHOT,
			projectName: "endpoint-dev",
			binary:      "endpoint-security",
			platform:    "linux/amd64",
			expectedUrlList: []string{
				"https://snapshots.elastic.co/8.14.2-1ceac187/downloads/endpoint-dev/endpoint-security-8.14.2-SNAPSHOT-linux-x86_64.tar.gz",
				"https://snapshots.elastic.co/8.14.2-1ceac187/downloads/endpoint-dev/endpoint-security-8.14.2-SNAPSHOT-linux-x86_64.tar.gz.sha512",
				"https://snapshots.elastic.co/8.14.2-1ceac187/downloads/endpoint-dev/endpoint-security-8.14.2-SNAPSHOT-linux-x86_64.tar.gz.asc",
			},
		},
		{
			name:        "Independent Agent Staging 8.14 endpoint-dev",
			file:        manifest8_14_0_build202406201002,
			projectName: "endpoint-dev",
			binary:      "endpoint-security",
			platform:    "linux/amd64",
			// Note how the version is one patch release higher than the manifest - this is expected
			expectedUrlList: []string{
				"https://staging.elastic.co/independent-agent/8.14.1+build202406201002/downloads/endpoint-dev/endpoint-security-8.14.1-linux-x86_64.tar.gz",
				"https://staging.elastic.co/independent-agent/8.14.1+build202406201002/downloads/endpoint-dev/endpoint-security-8.14.1-linux-x86_64.tar.gz.sha512",
				"https://staging.elastic.co/independent-agent/8.14.1+build202406201002/downloads/endpoint-dev/endpoint-security-8.14.1-linux-x86_64.tar.gz.asc",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			manifestJson := getManifestJsonData(t, tc.file)
			log.Printf("Manifest Version: [%s]", manifestJson.Version)

			projects := manifestJson.Projects

			// Verify the component name is in the list of expected packages.
			spec, ok := findBinarySpec(tc.binary)
			assert.True(t, ok)

			if !spec.SupportsPlatform(tc.platform) {
				t.Logf("Project %s does not support platform %s", spec.ProjectName, tc.platform)
				return
			}

			resolvedPackage, err := ResolveManifestPackage(projects[tc.projectName], spec, manifestJson.Version, tc.platform)
			require.NoError(t, err)
			require.NotNil(t, resolvedPackage)

			assert.Len(t, resolvedPackage.URLs, 3)
			for _, url := range resolvedPackage.URLs {
				assert.Contains(t, tc.expectedUrlList, url)
			}
		})
	}
}

func findBinarySpec(name string) (packaging.BinarySpec, bool) {
	for _, spec := range packaging.ExpectedBinaries {
		if spec.BinaryName == name {
			return spec, true
		}
	}
	return packaging.BinarySpec{}, false
}

func TestRelaxVersion(t *testing.T) {
	type args struct {
		version string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "major-minor-patch",
			args: args{
				version: "1.2.3",
			},
			want:    `1\.2\.(?:0|[1-9]\d*)`,
			wantErr: assert.NoError,
		},
		{
			name: "major-minor-patch-snapshot",
			args: args{
				version: "1.2.3-SNAPSHOT",
			},
			want:    `1\.2\.(?:0|[1-9]\d*)-SNAPSHOT`,
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := relaxVersion(tt.args.version)
			if !tt.wantErr(t, err, fmt.Sprintf("relaxVersion(%v)", tt.args.version)) {
				return
			}
			assert.Equalf(t, tt.want, got, "relaxVersion(%v)", tt.args.version)
		})
	}
}

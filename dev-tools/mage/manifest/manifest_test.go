// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manifest

import (
	_ "embed"
	"encoding/json"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

			urlList, err := resolveManifestPackage(projects[tc.projectName], spec, manifestJson.Version, tc.platform)
			require.NoError(t, err)

			assert.Len(t, urlList, 3)
			for _, url := range urlList {
				assert.Contains(t, tc.expectedUrlList, url)
			}
		})
	}
}

func findBinarySpec(name string) (BinarySpec, bool) {
	for _, spec := range ExpectedBinaries {
		if spec.BinaryName == name {
			return spec, true
		}
	}
	return BinarySpec{}, false
}

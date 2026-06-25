// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package artifact

import (
	"testing"

	"github.com/stretchr/testify/require"

	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

func TestNewArtifact(t *testing.T) {
	tests := map[string]struct {
		fips         bool
		arch         string
		os           string
		version      *agtversion.ParsedSemVer
		expectedName string
	}{
		"linux_amd386": {
			fips:         false,
			arch:         "386",
			os:           "linux",
			version:      agtversion.NewParsedSemVer(9, 1, 0, "", ""),
			expectedName: "elastic-agent-9.1.0-linux-x86.tar.gz",
		},
		"linux_amd64": {
			fips:         false,
			arch:         "amd64",
			os:           "linux",
			version:      agtversion.NewParsedSemVer(9, 1, 0, "", ""),
			expectedName: "elastic-agent-9.1.0-linux-x86_64.tar.gz",
		},
		"linux_arm64": {
			fips:         false,
			arch:         "arm64",
			os:           "linux",
			version:      agtversion.NewParsedSemVer(9, 1, 0, "", ""),
			expectedName: "elastic-agent-9.1.0-linux-arm64.tar.gz",
		},
		"windows_amd386": {
			fips:         false,
			arch:         "386",
			os:           "windows",
			version:      agtversion.NewParsedSemVer(9, 1, 0, "", ""),
			expectedName: "elastic-agent-9.1.0-windows-x86.zip",
		},
		"windows_amd64": {
			fips:         false,
			arch:         "amd64",
			os:           "windows",
			version:      agtversion.NewParsedSemVer(9, 1, 0, "", ""),
			expectedName: "elastic-agent-9.1.0-windows-x86_64.zip",
		},
		"windows_arm64": {
			fips:         false,
			arch:         "arm64",
			os:           "windows",
			version:      agtversion.NewParsedSemVer(9, 1, 0, "", ""),
			expectedName: "elastic-agent-9.1.0-windows-arm64.zip",
		},
		"darwin_amd64": {
			fips:         false,
			arch:         "amd64",
			os:           "darwin",
			version:      agtversion.NewParsedSemVer(9, 1, 0, "", ""),
			expectedName: "elastic-agent-9.1.0-darwin-x86_64.tar.gz",
		},
		"darwin_arm64": {
			fips:         false,
			arch:         "arm64",
			os:           "darwin",
			version:      agtversion.NewParsedSemVer(9, 1, 0, "", ""),
			expectedName: "elastic-agent-9.1.0-darwin-aarch64.tar.gz",
		},
		"linux_fips_x86": {
			fips:         true,
			arch:         "amd64",
			os:           "linux",
			version:      agtversion.NewParsedSemVer(9, 1, 0, "", ""),
			expectedName: "elastic-agent-fips-9.1.0-linux-x86_64.tar.gz",
		},
		"linux_snapshot_x86": {
			fips:         false,
			arch:         "amd64",
			os:           "linux",
			version:      agtversion.NewParsedSemVer(9, 1, 0, "SNAPSHOT", ""),
			expectedName: "elastic-agent-9.1.0-SNAPSHOT-linux-x86_64.tar.gz",
		},
		"linux_snapshot_x86_no_build": {
			fips:         false,
			arch:         "amd64",
			os:           "linux",
			version:      agtversion.NewParsedSemVer(9, 1, 0, "SNAPSHOT", "b7f97ae0"),
			expectedName: "elastic-agent-9.1.0-SNAPSHOT-linux-x86_64.tar.gz",
		},
		"linux_fips_snapshot_x86": {
			fips:         true,
			arch:         "amd64",
			os:           "linux",
			version:      agtversion.NewParsedSemVer(9, 1, 0, "SNAPSHOT", ""),
			expectedName: "elastic-agent-fips-9.1.0-SNAPSHOT-linux-x86_64.tar.gz",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			a, err := New("elastic-agent", test.fips, test.version, test.os, test.arch)
			require.NoError(t, err)
			require.Equal(t, test.expectedName, a.FileName)
		})
	}
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package artifact

import (
	"testing"

	"github.com/stretchr/testify/require"

	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

func TestGetArtifactName(t *testing.T) {
	version, err := agtversion.ParseVersion("9.1.0")
	require.NoError(t, err)

	tests := map[string]struct {
		a            Artifact
		version      agtversion.ParsedSemVer
		arch         string
		expectedName string
	}{
		"no_fips_arm64": {
			a:            Artifact{Cmd: "elastic-agent"},
			version:      *version,
			arch:         "arm64",
			expectedName: "elastic-agent-9.1.0-linux-arm64.tar.gz",
		},
		"fips_x86": {
			a:            Artifact{Cmd: "elastic-agent-fips"},
			version:      *version,
			arch:         "32",
			expectedName: "elastic-agent-fips-9.1.0-linux-x86.tar.gz",
		},
		"fips_x86_64": {
			a:            Artifact{Cmd: "elastic-agent-fips"},
			version:      *version,
			arch:         "64",
			expectedName: "elastic-agent-fips-9.1.0-linux-x86_64.tar.gz",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			artifactName, err := GetArtifactName(test.a, test.version, "linux", test.arch)
			require.NoError(t, err)
			require.Equal(t, test.expectedName, artifactName)
		})
	}

}

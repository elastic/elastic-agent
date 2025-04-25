// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package artifact

import (
	agtversion "github.com/elastic/elastic-agent/pkg/version"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGetArtifactName(t *testing.T) {
	version, err := agtversion.ParseVersion("9.1.0")
	require.NoError(t, err)

	tests := map[string]struct {
		a               Artifact
		version         agtversion.ParsedSemVer
		operatingSystem string
		arch            string
		expectedName    string
		expectedErr     string
	}{
		"no_fips": {
			a:               Artifact{Cmd: "elastic-agent"},
			version:         *version,
			operatingSystem: "linux",
			arch:            "arm64",
			expectedName:    "elastic-agent-9.1.0-linux-arm64.tar.gz",
		},
		"fips": {
			a:               Artifact{Cmd: "elastic-agent-fips"},
			version:         *version,
			operatingSystem: "linux",
			arch:            "arm64",
			expectedName:    "elastic-agent-fips-9.1.0-linux-arm64.tar.gz",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			artifactName, err := GetArtifactName(test.a, test.version, test.operatingSystem, test.arch)
			if test.expectedErr == "" {
				require.NoError(t, err)
				require.Equal(t, test.expectedName, artifactName)
			} else {
				require.Empty(t, artifactName)
				require.Equal(t, test.expectedErr, err.Error())
			}
		})
	}

}

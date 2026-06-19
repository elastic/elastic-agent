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
	version, err := agtversion.ParseVersion("9.1.0")
	require.NoError(t, err)

	tests := map[string]struct {
		fips         bool
		arch         string
		expectedName string
	}{
		"no_fips_arm64": {
			fips:         false,
			arch:         "arm64",
			expectedName: "elastic-agent-9.1.0-linux-arm64.tar.gz",
		},
		"fips_x86": {
			fips:         true,
			arch:         "386",
			expectedName: "elastic-agent-fips-9.1.0-linux-x86.tar.gz",
		},
		"fips_x86_64": {
			fips:         true,
			arch:         "amd64",
			expectedName: "elastic-agent-fips-9.1.0-linux-x86_64.tar.gz",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			a, err := New(version, "linux", test.arch, test.fips)
			require.NoError(t, err)
			require.Equal(t, test.expectedName, a.FileName)
		})
	}

}

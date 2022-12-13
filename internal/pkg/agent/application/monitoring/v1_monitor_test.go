// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitoring

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEndpointPath(t *testing.T) {
	testCases := []struct {
		Name       string
		OS         string
		ID         string
		ExpectedID string
	}{
		// simple
		{"simple linux", "linux", "simple", "unix:///tmp/elastic-agent/simple.sock"},
		{"simple windows", "windows", "simple", "npipe:///simple"},
		{"simple darwin", "darwin", "simple", "unix:///tmp/elastic-agent/simple.sock"},

		// special chars
		{"simple linux", "linux", "complex43@#$", "unix:///tmp/elastic-agent/complex43@#$.sock"},
		{"simple windows", "windows", "complex43@#$", "npipe:///complex43@#$"},
		{"simple darwin", "darwin", "complex43@#$", "unix:///tmp/elastic-agent/complex43@#$.sock"},

		// slash
		{"simple linux", "linux", "slash/sample", "unix:///tmp/elastic-agent/slash-sample.sock"},
		{"simple windows", "windows", "slash/sample", "npipe:///slash-sample"},
		{"simple darwin", "darwin", "slash/sample", "unix:///tmp/elastic-agent/slash-sample.sock"},

		// backslash
		{"simple linux", "linux", "back\\slash", "unix:///tmp/elastic-agent/back\\slash.sock"},
		{"simple windows", "windows", "back\\slash", "npipe:///back-slash"},
		{"simple darwin", "darwin", "back\\slash", "unix:///tmp/elastic-agent/back\\slash.sock"},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			separator := "/"
			if tc.OS == windowsOS {
				separator = "\\"
			}
			endpointPath := endpointPathWithDir(tc.ID, tc.OS, "/tmp/elastic-agent", separator)
			require.Equal(t, tc.ExpectedID, endpointPath)
		})
	}
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitoring

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEndpointPath(t *testing.T) {
	sep := string(filepath.Separator)
	testCases := []struct {
		Name       string
		OS         string
		ID         string
		ExpectedID string
	}{
		// using filepath join so windows runner is happy, filepath is used internally.
		// simple
		{"simple linux", "linux", "simple", "unix://" + sep + filepath.Join("tmp", "elastic-agent", "simple.sock")},
		{"simple darwin", "darwin", "simple", "unix://" + sep + filepath.Join("tmp", "elastic-agent", "simple.sock")},
		{"simple windows", "windows", "simple", "npipe:///simple"},

		// special chars
		{"simple linux", "linux", "complex43@#$", "unix://" + sep + filepath.Join("tmp", "elastic-agent", "complex43@#$.sock")},
		{"simple darwin", "darwin", "complex43@#$", "unix://" + sep + filepath.Join("tmp", "elastic-agent", "complex43@#$.sock")},
		{"simple windows", "windows", "complex43@#$", "npipe:///complex43@#$"},

		// slash
		{"simple linux", "linux", "slash/sample", "unix://" + sep + filepath.Join("tmp", "elastic-agent", "slash-sample.sock")},
		{"simple darwin", "darwin", "slash/sample", "unix://" + sep + filepath.Join("tmp", "elastic-agent", "slash-sample.sock")},
		{"simple windows", "windows", "slash/sample", "npipe:///slash-sample"},

		// backslash
		{"simple linux", "linux", "back\\slash", "unix://" + sep + filepath.Join("tmp", "elastic-agent", "back\\slash.sock")},
		{"simple darwin", "darwin", "back\\slash", "unix://" + sep + filepath.Join("tmp", "elastic-agent", "back\\slash.sock")},
		{"simple windows", "windows", "back\\slash", "npipe:///back-slash"},
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

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSocketURLWithFallback(t *testing.T) {
	testIDs := map[string]struct {
		id       string
		expected string
	}{
		"simple":  {id: "abcdefg", expected: "fRpUEnsiJQL1t5tfsIAwYRUqRPkrN-I8.sock"},
		"complex": {id: "aA0~!@#$%^&*()_+-=;:<>,.?/|", expected: "OiX5LK4abOM41Y9T1OdJDp5OK_xYFQZ1.sock"},
	}
	testDirs := map[string]struct {
		dir      string
		expected string
	}{
		"shallow": {
			dir:      "/usr/share/elastic-agent/state/data/tmp",
			expected: "unix:///usr/share/elastic-agent/state/data/tmp/",
		},
		"deep": {
			dir:      "/usr/share/elastic-agent/state/data/tmp/aaaaaaaaaa/bbbbbbbbbb/cccccccccc/dddddddddd/eeeeeeeeee/ffffffffff",
			expected: "unix:///tmp/elastic-agent/",
		},
		"spaces": {
			dir:      "/one/dir with space/three/",
			expected: "unix:///one/dir%20with%20space/three/",
		},
	}

	for idCase, idStruct := range testIDs {
		for dirCase, dirStruct := range testDirs {
			t.Run(idCase+"_id_"+dirCase+"_dir", func(t *testing.T) {
				endpointPath := SocketURLWithFallback(idStruct.id, dirStruct.dir)
				require.Equal(t, dirStruct.expected+idStruct.expected, endpointPath)
				require.Less(t, len(endpointPath), SocketMaxLength)
			})
		}
	}
}

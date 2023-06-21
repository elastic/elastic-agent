// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	LongID     = "105_characters_long_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ShallowDir = "/usr/share/elastic-agent/state/data/tmp"
	DeepDir    = "/usr/share/elastic-agent/state/data/tmp/aaaaaaaaaa/bbbbbbbbbb/cccccccccc/dddddddddd/eeeeeeeeee/ffffffffff"
	SpaceDir   = "/one/dir with space/three/"
)

func TestSocketURLWithFallback(t *testing.T) {
	testCases := []struct {
		Name       string
		OS         string
		Dir        string
		ID         string
		ExpectedID string
	}{
		// simple
		{"simple linux", "linux", ShallowDir, "simple", "unix:///usr/share/elastic-agent/state/data/tmp/p6ObcvKXGOZT5zUDIQ-7WXBXt6HHfR_j.sock"},
		{"simple darwin", "darwin", ShallowDir, "simple", "unix:///usr/share/elastic-agent/state/data/tmp/p6ObcvKXGOZT5zUDIQ-7WXBXt6HHfR_j.sock"},
		{"simple windows", "windows", ShallowDir, "simple", "npipe:///p6ObcvKXGOZT5zUDIQ-7WXBXt6HHfR_j.sock"},

		// special chars
		{"special chars linux", "linux", ShallowDir, "complex43@#$ ^*(){}[]", "unix:///usr/share/elastic-agent/state/data/tmp/PE6b2V32MXkTl1rxBNiAwqXTTNCm-D9q.sock"},
		{"special chars darwin", "darwin", ShallowDir, "complex43@#$ ^*(){}[]", "unix:///usr/share/elastic-agent/state/data/tmp/PE6b2V32MXkTl1rxBNiAwqXTTNCm-D9q.sock"},
		{"special chars windows", "windows", ShallowDir, "complex43@#$ ^*(){}[]", "npipe:///PE6b2V32MXkTl1rxBNiAwqXTTNCm-D9q.sock"},

		// slash
		{"slash linux", "linux", ShallowDir, "slash/sample", "unix:///usr/share/elastic-agent/state/data/tmp/3Np2ygRfGEIqmar6kYkBBDmGRBAp6YMG.sock"},
		{"slash darwin", "darwin", ShallowDir, "slash/sample", "unix:///usr/share/elastic-agent/state/data/tmp/3Np2ygRfGEIqmar6kYkBBDmGRBAp6YMG.sock"},
		{"slash windows", "windows", ShallowDir, "slash/sample", "npipe:///3Np2ygRfGEIqmar6kYkBBDmGRBAp6YMG.sock"},

		// backslash
		{"backslash linux", "linux", ShallowDir, "back\\slash", "unix:///usr/share/elastic-agent/state/data/tmp/FJjgtWatfdJl1fLe68gKu3uURsPpQ97L.sock"},
		{"backslash darwin", "darwin", ShallowDir, "back\\slash", "unix:///usr/share/elastic-agent/state/data/tmp/FJjgtWatfdJl1fLe68gKu3uURsPpQ97L.sock"},
		{"backslash windows", "windows", ShallowDir, "back\\slash", "npipe:///FJjgtWatfdJl1fLe68gKu3uURsPpQ97L.sock"},

		// long id
		{"long id linux", "linux", ShallowDir, LongID, "unix:///usr/share/elastic-agent/state/data/tmp/RwNi8dyCwpukvKr2iTmarB9eQuoNAgmg.sock"},
		{"long id darwin", "darwin", ShallowDir, LongID, "unix:///usr/share/elastic-agent/state/data/tmp/RwNi8dyCwpukvKr2iTmarB9eQuoNAgmg.sock"},
		{"long id windows", "windows", ShallowDir, LongID, "npipe:///RwNi8dyCwpukvKr2iTmarB9eQuoNAgmg.sock"},

		// Deep Dir
		{"deep dir linux", "linux", DeepDir, "simple", "unix:///tmp/elastic-agent/p6ObcvKXGOZT5zUDIQ-7WXBXt6HHfR_j.sock"},
		{"deep dir darwin", "darwin", DeepDir, "simple", "unix:///tmp/elastic-agent/p6ObcvKXGOZT5zUDIQ-7WXBXt6HHfR_j.sock"},
		{"deep dir  windows", "windows", DeepDir, "simple", "npipe:///p6ObcvKXGOZT5zUDIQ-7WXBXt6HHfR_j.sock"},

		// Long Dir, Long ID
		{"deep dir, long id, linux", "linux", DeepDir, LongID, "unix:///tmp/elastic-agent/RwNi8dyCwpukvKr2iTmarB9eQuoNAgmg.sock"},
		{"deep dir, long id, darwin", "darwin", DeepDir, LongID, "unix:///tmp/elastic-agent/RwNi8dyCwpukvKr2iTmarB9eQuoNAgmg.sock"},
		{"deep dir, long id, windows", "windows", DeepDir, LongID, "npipe:///RwNi8dyCwpukvKr2iTmarB9eQuoNAgmg.sock"},

		// space in dir
		{"space dir linux", "linux", SpaceDir, "simple", "unix:///one/dir%20with%20space/three/p6ObcvKXGOZT5zUDIQ-7WXBXt6HHfR_j.sock"},
		{"space dir darwin", "darwin", SpaceDir, "simple", "unix:///one/dir%20with%20space/three/p6ObcvKXGOZT5zUDIQ-7WXBXt6HHfR_j.sock"},
		{"space dir windows", "windows", SpaceDir, "simple", "npipe:///p6ObcvKXGOZT5zUDIQ-7WXBXt6HHfR_j.sock"},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			endpointPath := SocketURLWithFallback(tc.ID, tc.OS, tc.Dir)
			require.Equal(t, tc.ExpectedID, endpointPath)
			require.Less(t, len(endpointPath), UnixSocketMaxLength)
		})
	}
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	"testing"

	"github.com/jaypipes/ghw"
	"github.com/jaypipes/ghw/pkg/block"
	"github.com/stretchr/testify/require"
)

func TestHasAllSSDs(t *testing.T) {
	cases := map[string]struct {
		block    ghw.BlockInfo
		expected bool
	}{
		"no_ssds": {
			block: ghw.BlockInfo{Disks: []*block.Disk{
				{DriveType: ghw.DRIVE_TYPE_HDD},
				{DriveType: ghw.DRIVE_TYPE_ODD},
				{DriveType: ghw.DRIVE_TYPE_FDD},
			}},
			expected: false,
		},
		"some_ssds": {
			block: ghw.BlockInfo{Disks: []*block.Disk{
				{DriveType: ghw.DRIVE_TYPE_SSD},
				{DriveType: ghw.DRIVE_TYPE_HDD},
				{DriveType: ghw.DRIVE_TYPE_ODD},
				{DriveType: ghw.DRIVE_TYPE_FDD},
			}},
			expected: false,
		},
		"all_ssds": {
			block: ghw.BlockInfo{Disks: []*block.Disk{
				{DriveType: ghw.DRIVE_TYPE_SSD},
				{DriveType: ghw.DRIVE_TYPE_SSD},
				{DriveType: ghw.DRIVE_TYPE_SSD},
			}},
			expected: true,
		},
		"unknown": {
			block: ghw.BlockInfo{Disks: []*block.Disk{
				{DriveType: ghw.DRIVE_TYPE_UNKNOWN},
			}},
			expected: false,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			actual := HasAllSSDs(test.block)
			require.Equal(t, test.expected, actual)
		})
	}
}

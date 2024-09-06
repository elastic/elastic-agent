// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build kubernetes_inner

package kubernetes_inside

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAgentPathsPermissions(t *testing.T) {

	uid := os.Getuid()
	gid := os.Getgid()

	err := filepath.WalkDir("/usr/share/elastic-agent", func(walkPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("failed to walk path %s: %w", walkPath, err)
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("failed to get info of path %s: %w", walkPath, err)
		}

		sysInfo, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}

		if sysInfo.Gid != uint32(gid) && sysInfo.Uid != uint32(uid) {
			// already owned
			return fmt.Errorf("%s doesn't have correct permissions: has %d:%d (expected %d:%d)", walkPath, sysInfo.Uid, sysInfo.Gid, uid, gid)
		}

		return nil
	})

	require.NoError(t, err)
}

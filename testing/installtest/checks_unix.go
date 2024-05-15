// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package installtest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
)

func checkPlatform(_ *atesting.Fixture, topPath string, unprivileged bool) error {
	if unprivileged {
		// Check that the elastic-agent user/group exist.
		uid, err := install.FindUID(install.ElasticUsername)
		if err != nil {
			return fmt.Errorf("failed to find %s user: %w", install.ElasticUsername, err)
		}
		gid, err := install.FindGID(install.ElasticGroupName)
		if err != nil {
			return fmt.Errorf("failed to find %s group: %w", install.ElasticGroupName, err)
		}

		// Path should now exist as well as be owned by the correct user/group.
		info, err := os.Stat(topPath)
		if err != nil {
			return fmt.Errorf("faield to stat %s: %w", topPath, err)
		}
		fs, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("failed to convert info.Sys() into *syscall.Stat_t")
		}
		if fs.Uid != uint32(uid) {
			return fmt.Errorf("%s not owned by %s user", topPath, install.ElasticUsername)
		}
		if fs.Gid != uint32(gid) {
			return fmt.Errorf("%s not owned by %s group", topPath, install.ElasticGroupName)
		}

		// Check that the socket is created with the correct permissions.
		socketPath := filepath.Join(topPath, paths.ControlSocketName)
		err = waitForNoError(context.Background(), func(_ context.Context) error {
			_, err = os.Stat(socketPath)
			if err != nil {
				return fmt.Errorf("failed to stat socket path %s: %w", socketPath, err)
			}
			return nil
		}, 3*time.Minute, 1*time.Second)
		info, err = os.Stat(socketPath)
		if err != nil {
			return fmt.Errorf("failed to stat socket path %s: %w", socketPath, err)
		}
		fs, ok = info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("failed to convert info.Sys() into *syscall.Stat_t")
		}
		if fs.Uid != uint32(uid) {
			return fmt.Errorf("%s not owned by %s user", socketPath, install.ElasticUsername)
		}
		if fs.Gid != uint32(gid) {
			return fmt.Errorf("%s not owned by %s group", socketPath, install.ElasticGroupName)
		}

		// Executing `elastic-agent status` as the `elastic-agent-user` user should work.
		var output []byte
		err = waitForNoError(context.Background(), func(_ context.Context) error {
			cmd := exec.Command("sudo", "-u", install.ElasticUsername, "elastic-agent", "status")
			output, err = cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("elastic-agent status failed: %w (output: %s)", err, output)
			}
			return nil
		}, 3*time.Minute, 1*time.Second)

		// Executing `elastic-agent status` as the original user should fail, because that
		// user is not in the 'elastic-agent' group.
		originalUser := os.Getenv("SUDO_USER")
		if originalUser != "" {
			cmd := exec.Command("sudo", "-u", originalUser, "elastic-agent", "status")
			output, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("sudo -u %s elastic-agent status failed: %w (output: %s)", originalUser, err, output)
			}
		}
	} else {
		// Ensure that the top path is owned by root:root.
		info, err := os.Stat(topPath)
		if err != nil {
			return fmt.Errorf("faield to stat %s: %w", topPath, err)
		}
		fs, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("failed to convert info.Sys() into *syscall.Stat_t")
		}
		if fs.Uid != 0 {
			return fmt.Errorf("%s not owned by root user", topPath)
		}
		if fs.Gid != 0 {
			return fmt.Errorf("%s not owned by root group", topPath)
		}
		if fs.Mode&0007 == 0 {
			return fmt.Errorf("%s has world access", topPath)
		}
	}
	return nil
}

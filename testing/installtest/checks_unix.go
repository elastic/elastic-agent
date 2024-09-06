// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package installtest

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
)

func checkPlatform(ctx context.Context, _ *atesting.Fixture, topPath string, opts *CheckOpts) error {
	if !opts.Privileged {
		// Check that the elastic-agent user/group exist.
		uid, err := install.FindUID(install.ElasticUsername)
		if err != nil {
			return fmt.Errorf("failed to find %s user: %w", install.ElasticUsername, err)
		}
		gid, err := install.FindGID(install.ElasticGroupName)
		if err != nil {
			return fmt.Errorf("failed to find %s group: %w", install.ElasticGroupName, err)
		}

		// Ensure entire installation tree has the correct permissions.
		err = validateFileTree(topPath, uint32(uid), uint32(gid))
		if err != nil {
			// context already added
			return err
		}

		// Check that the socket is created with the correct permissions.
		socketPath := filepath.Join(topPath, paths.ControlSocketName)
		err = waitForNoError(ctx, func(_ context.Context) error {
			_, err = os.Stat(socketPath)
			if err != nil {
				return fmt.Errorf("failed to stat socket path %s: %w", socketPath, err)
			}
			return nil
		}, 3*time.Minute, 1*time.Second)
		info, err := os.Stat(socketPath)
		if err != nil {
			return fmt.Errorf("failed to stat socket path %s: %w", socketPath, err)
		}
		fs, ok := info.Sys().(*syscall.Stat_t)
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
		shellWrapperName := "elastic-agent"
		if opts.Namespace != "" {
			shellWrapperName = paths.ShellWrapperPathForNamespace(opts.Namespace)
		}

		var output []byte
		err = waitForNoError(ctx, func(_ context.Context) error {
			// #nosec G204 -- user cannot inject any parameters to this command
			cmd := exec.Command("sudo", "-u", install.ElasticUsername, shellWrapperName, "status")
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
			// #nosec G204 -- user cannot inject any parameters to this command
			cmd := exec.Command("sudo", "-u", originalUser, shellWrapperName, "status")
			output, err := cmd.CombinedOutput()
			if err == nil {
				return fmt.Errorf("sudo -u %s elastic-agent didn't fail: got output: %s", originalUser, output)
			}
		}
	} else {
		// Ensure entire installation tree has the correct permissions.
		err := validateFileTree(topPath, 0, 0)
		if err != nil {
			// context already added
			return err
		}
	}
	return nil
}

func validateFileTree(dir string, uid uint32, gid uint32) error {
	return filepath.WalkDir(dir, func(file string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error traversing the file tree: %w", err)
		}
		if d.Type() == os.ModeSymlink {
			// symlink don't check permissions
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("error caling info: %w", err)
		}
		fs, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("failed to convert info.Sys() into *syscall.Stat_t")
		}
		if fs.Uid != uid {
			return fmt.Errorf("%s doesn't have correct uid: has %d (expected %d)", file, fs.Uid, uid)
		}
		if fs.Gid != gid {
			return fmt.Errorf("%s doesn't have correct gid: has %d (expected %d)", file, fs.Gid, gid)
		}
		if fs.Mode&0007 != 0 {
			return fmt.Errorf("%s has world access", file)
		}
		return nil
	})
}

func waitForNoError(ctx context.Context, fun func(ctx context.Context) error, timeout time.Duration, interval time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	t := time.NewTicker(interval)
	defer t.Stop()

	var lastErr error
	for {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return lastErr
			}
			return ctx.Err()
		case <-t.C:
			err := fun(ctx)
			if err == nil {
				return nil
			}
			lastErr = err
		}
	}
}

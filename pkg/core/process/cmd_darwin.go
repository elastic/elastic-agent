// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build darwin

package process

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// Cmd returns an *exec.Cmd with the current environment variables set in the
// returned Cmd and it also sets Pdeathsig to syscall.SIGKILL, so if caller
// process dies, the child process is also killed. The child process has its
// GID and UID set to match the caller, no other groups are set.
// An error is only returned if the current GID or UID are nit Int32.
func Cmd(ctx context.Context, path string, arg ...string) (*exec.Cmd, error) {
	return getCmd(ctx, path, []string{}, os.Geteuid(), os.Getgid(), arg...)
}

func getCmd(ctx context.Context, path string, env []string, uid, gid int, arg ...string) (*exec.Cmd, error) {
	var cmd *exec.Cmd
	if ctx == nil {
		cmd = exec.Command(path, arg...)
	} else {
		cmd = exec.CommandContext(ctx, path, arg...)
	}
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, env...)
	cmd.Dir = filepath.Dir(path)
	if isInt32(uid) && isInt32(gid) {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid:         uint32(uid),
				Gid:         uint32(gid),
				NoSetGroups: true,
			},
		}
	} else {
		return nil, fmt.Errorf("invalid uid: '%d' or gid: '%d'", uid, gid)
	}

	return cmd, nil
}

func isInt32(val int) bool {
	return val >= 0 && val <= math.MaxInt32
}

// killCmd calls Process.Kill
func killCmd(proc *os.Process) error {
	return proc.Kill()
}

// terminateCmd sends SIGTERM to the process
func terminateCmd(proc *os.Process) error {
	return proc.Signal(syscall.SIGTERM)
}

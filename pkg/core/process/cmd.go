// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !linux && !darwin

package process

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
)

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

	return cmd, nil
}

func killCmd(proc *os.Process) error {
	return proc.Kill()
}

func terminateCmd(proc *os.Process) error {
	return proc.Kill()
}

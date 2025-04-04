// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux

package process

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/elastic/elastic-agent-libs/logp"
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
	if isInt32(uid) && isInt32(gid) {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			// on shutdown all sub-processes are sent SIGTERM, in the case that the Agent dies or is -9 killed
			// then also kill the children (only supported on linux)
			Pdeathsig: syscall.SIGKILL,
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
	fmt.Println("==================== Sending CTRL_BREAK_EVENT to PID:", proc.Pid)
	logp.L().Named("trace-debug").Info("==================== Sending CTRL_BREAK_EVENT to PID:", proc.Pid)
	fmt.Println("++++++++++++++++++++ TRACE 00 ", proc.Pid)
	logp.L().Named("trace-debug").Info("++++++++++++++++++++ TRACE 00 ", proc.Pid)
	return proc.Signal(syscall.SIGTERM)
}

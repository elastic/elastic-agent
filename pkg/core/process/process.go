// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package process

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// Info groups information about fresh new process
type Info struct {
	PID     int
	Process *os.Process
	Stdin   io.WriteCloser
	Stderr  io.ReadCloser
}

// CmdOption is an option func to change the underlying command
type CmdOption func(c *exec.Cmd) error

type StartConfig struct {
	ctx       context.Context
	uid, gid  int
	args, env []string
	cmdOpts   []CmdOption
}

type StartOptionFunc func(cfg *StartConfig)

// Start starts a new process
func Start(path string, opts ...StartOptionFunc) (proc *Info, err error) {
	// Apply options
	c := StartConfig{
		uid: os.Geteuid(),
		gid: os.Getegid(),
	}

	for _, opt := range opts {
		opt(&c)
	}

	return startContext(c.ctx, path, c.uid, c.gid, c.args, c.env, c.cmdOpts...)
}

func WithCmdOptions(cmdOpts ...CmdOption) StartOptionFunc {
	return func(cfg *StartConfig) {
		cfg.cmdOpts = cmdOpts
	}
}

func WithContext(ctx context.Context) StartOptionFunc {
	return func(cfg *StartConfig) {
		cfg.ctx = ctx
	}
}

func WithUID(uid int) StartOptionFunc {
	return func(cfg *StartConfig) {
		cfg.uid = uid
	}
}

func WithGID(gid int) StartOptionFunc {
	return func(cfg *StartConfig) {
		cfg.gid = gid
	}
}

func WithArgs(args []string) StartOptionFunc {
	return func(cfg *StartConfig) {
		cfg.args = args
	}
}

func WithEnv(env []string) StartOptionFunc {
	return func(cfg *StartConfig) {
		cfg.env = env
	}
}

// startContext starts a new process with context.
func startContext(ctx context.Context, path string, uid, gid int, args []string, env []string, opts ...CmdOption) (*Info, error) {
	cmd, err := getCmd(ctx, path, env, uid, gid, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to create command for %q: %w", path, err)
	}
	for _, o := range opts {
		if err := o(cmd); err != nil {
			return nil, fmt.Errorf("failed to set option command for %q: %w", path, err)
		}
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin for %q: %w", path, err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr for %q: %w", path, err)
	}

	// start process
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %q: %w", path, err)
	}

	// Hook to JobObject on windows, noop on other platforms.
	// This ties the application processes lifespan to the agent's.
	// Fixes the orphaned beats processes left behind situation
	// after the agent process gets killed.
	if err := JobObject.Assign(cmd.Process); err != nil {
		_ = killCmd(cmd.Process)
		return nil, fmt.Errorf("failed job assignment %q: %w", path, err)
	}

	return &Info{
		PID:     cmd.Process.Pid,
		Process: cmd.Process,
		Stdin:   stdin,
		Stderr:  stderr,
	}, err
}

// Kill kills the process.
func (i *Info) Kill() error {
	return killCmd(i.Process)
}

// Stop stops the process cleanly.
func (i *Info) Stop() error {
	return terminateCmd(i.Process)
}

// StopWait stops the process and waits for it to exit.
func (i *Info) StopWait() error {
	err := i.Stop()
	if err != nil {
		return err
	}
	_, err = i.Process.Wait()
	return err
}

// Wait returns a channel that will send process state once it exits.
func (i *Info) Wait() <-chan *os.ProcessState {
	ch := make(chan *os.ProcessState)

	go func() {
		procState, err := i.Process.Wait()
		if err != nil {
			// process is not a child - some OSs requires process to be child
			externalProcess(i.Process)
		}
		ch <- procState
	}()

	return ch
}

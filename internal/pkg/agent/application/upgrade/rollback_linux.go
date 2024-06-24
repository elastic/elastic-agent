// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux

package upgrade

import (
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

const (
	// delay after agent restart is performed to allow agent to tear down all the processes
	// important mainly for windows, as it prevents removing files which are in use
	afterRestartDelay = 2 * time.Second
)

func invokeCmd(agentExecutable string) *exec.Cmd {
	// #nosec G204 -- user cannot inject any parameters to this command
	cmd := exec.Command(agentExecutable, watcherSubcommand,
		"--path.config", paths.Config(),
		"--path.home", paths.Top(),
	)

	var cred = &syscall.Credential{
		Uid:         uint32(os.Getuid()),
		Gid:         uint32(os.Getgid()),
		Groups:      nil,
		NoSetGroups: true,
	}
	var sysproc = &syscall.SysProcAttr{
		Credential: cred,
		Setsid:     true,
		// propagate sigint instead of sigkill so we can ignore it
		Pdeathsig: syscall.SIGINT,
	}
	cmd.SysProcAttr = sysproc
	return cmd
}

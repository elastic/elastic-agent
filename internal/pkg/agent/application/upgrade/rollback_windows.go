// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package upgrade

import (
	"os/exec"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

const (
	// delay after agent restart is performed to allow agent to tear down all the processes
	// important mainly for windows, as it prevents removing files which are in use
	afterRestartDelay = 15 * time.Second
)

func invokeCmd() *exec.Cmd {
	// #nosec G204 -- user cannot inject any parameters to this command
	cmd := exec.Command(paths.TopBinaryPath(), watcherSubcommand,
		"--path.config", paths.Config(),
		"--path.home", paths.Top(),
	)
	return cmd
}

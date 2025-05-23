// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package upgrade

import (
	"os/exec"
	"time"
)

const (
	// delay after agent restart is performed to allow agent to tear down all the processes
	// important mainly for windows, as it prevents removing files which are in use
	afterRestartDelay = 20 * time.Second
)

func makeOSWatchCmd(baseWatchCmd *exec.Cmd) *exec.Cmd {
	return baseWatchCmd
}

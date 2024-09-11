// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package process

import (
	"os"
	"syscall"
	"time"
)

// externalProcess is a watch mechanism used in cases where OS requires  a process to be a child
// for waiting for process. We need to be able to await any process.
func externalProcess(proc *os.Process) {
	if proc == nil {
		return
	}

	for {
		<-time.After(1 * time.Second)
		if proc.Signal(syscall.Signal(0)) != nil {
			// failed to contact process, return
			return
		}
	}
}

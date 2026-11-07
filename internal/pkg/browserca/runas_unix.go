// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package browserca

import (
	"os/exec"
	"syscall"
)

// runAs makes cmd run as o. Like Heartbeat for the browser, it adds the root group,
// so that cmd has exactly the browser's access.
func runAs(cmd *exec.Cmd, o *owner) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: o.uid, Gid: o.gid, Groups: []uint32{0}},
	}
}

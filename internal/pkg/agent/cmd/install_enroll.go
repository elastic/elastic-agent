// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package cmd

import (
	"fmt"
	"os/exec"
	"strconv"
	"syscall"
)

func enrollCmdExtras(cmd *exec.Cmd, uidStr string, gidStr string) error {
	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		return fmt.Errorf("failed to convert uid(%s) to int: %w", uidStr, err)
	}
	gid, err := strconv.Atoi(gidStr)
	if err != nil {
		return fmt.Errorf("failed to convert gid(%s) to int: %w", gidStr, err)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
	}
	return nil
}

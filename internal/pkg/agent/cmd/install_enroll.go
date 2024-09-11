// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package cmd

import (
	"fmt"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/elastic/elastic-agent/pkg/utils"
)

func enrollCmdExtras(cmd *exec.Cmd, ownership utils.FileOwner) error {
	if ownership.UID > 0 {
		cmd.Args = append(
			cmd.Args,
			fmt.Sprintf("--%s", fromInstallUserArg),
			strconv.Itoa(ownership.UID),
		)
	}
	if ownership.GID > 0 {
		cmd.Args = append(
			cmd.Args,
			fmt.Sprintf("--%s", fromInstallGroupArg),
			strconv.Itoa(ownership.GID),
		)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(ownership.UID),
			Gid: uint32(ownership.GID),
		},
	}
	return nil
}

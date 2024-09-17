// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package cmd

import (
	"fmt"
	"os/exec"

	"github.com/elastic/elastic-agent/pkg/utils"
)

func enrollCmdExtras(cmd *exec.Cmd, ownership utils.FileOwner) error {
	if ownership.UID != "" {
		cmd.Args = append(
			cmd.Args,
			fmt.Sprintf("--%s", fromInstallUserArg),
			ownership.UID,
		)
	}
	if ownership.GID != "" {
		cmd.Args = append(
			cmd.Args,
			fmt.Sprintf("--%s", fromInstallGroupArg),
			ownership.GID,
		)
	}
	return nil
}

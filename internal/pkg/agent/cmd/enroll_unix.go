// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/pkg/utils"
)

func addPlatformFlags(cmd *cobra.Command) {
	cmd.Flags().Int32(fromInstallUserArg, -1, "UID of the elastic-agent-user user when enrolling from installer")
	_ = cmd.Flags().MarkHidden(fromInstallUserArg)

	cmd.Flags().Int32(fromInstallGroupArg, -1, "GID of the elastic-agent group when enrolling from installer")
	_ = cmd.Flags().MarkHidden(fromInstallGroupArg)
}

func getFileOwnerFromCmd(cmd *cobra.Command) (utils.FileOwner, error) {
	uid, err := getIDFromCmd(cmd, fromInstallUserArg)
	if err != nil {
		return utils.FileOwner{}, err
	}
	gid, err := getIDFromCmd(cmd, fromInstallGroupArg)
	if err != nil {
		return utils.FileOwner{}, err
	}
	ownership, err := utils.CurrentFileOwner()
	if err != nil {
		return utils.FileOwner{}, err
	}
	if uid != -1 {
		ownership.UID = uid
	}
	if gid != -1 {
		ownership.GID = gid
	}
	return ownership, nil
}

func getIDFromCmd(cmd *cobra.Command, param string) (int, error) {
	id, _ := cmd.Flags().GetInt32(param)
	if id < -1 {
		return -1, fmt.Errorf("--%s has an invalid value of: %d", param, id)
	}
	return int(id), nil
}

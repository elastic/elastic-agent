// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/pkg/utils"
)

func addPlatformFlags(cmd *cobra.Command) {
	cmd.Flags().String(fromInstallUserArg, "", "UID of the elastic-agent-user user when enrolling from installer")
	_ = cmd.Flags().MarkHidden(fromInstallUserArg)

	cmd.Flags().String(fromInstallGroupArg, "", "GID of the elastic-agent group when enrolling from installer")
	_ = cmd.Flags().MarkHidden(fromInstallGroupArg)
}

func getFileOwnerFromCmd(cmd *cobra.Command) (utils.FileOwner, error) {
	userSID, err := getSIDFromCmd(cmd, fromInstallUserArg)
	if err != nil {
		return utils.FileOwner{}, err
	}
	groupSID, err := getSIDFromCmd(cmd, fromInstallGroupArg)
	if err != nil {
		return utils.FileOwner{}, err
	}
	var ownership utils.FileOwner
	if userSID != nil {
		ownership.UID = userSID.String()
	}
	if groupSID != nil {
		ownership.GID = groupSID.String()
	}
	return ownership, nil
}

func getSIDFromCmd(cmd *cobra.Command, param string) (*windows.SID, error) {
	sidStr, _ := cmd.Flags().GetString(param)
	if sidStr != "" {
		sid, err := windows.StringToSid(sidStr)
		if err != nil {
			return nil, fmt.Errorf("--%s has an invalid SID: %s", param, sidStr)
		}
		return sid, nil
	}
	return nil, nil
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/internal/pkg/acl"
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

// getOwnerFromPath calls getOwnerFromPathWindows for testability. This way we
// can inject the windows specific functions.
func getOwnerFromPath(path string) (utils.FileOwner, error) {
	return getOwnerFromPathWindows(path, acl.GetNamedSecurityInfo, windows.LocalFree)
}

type getNamedSecurityInfo func(objectName string, objectType int32, secInfo uint32, owner, group **windows.SID, dacl, sacl, secDesc *windows.Handle) error
type localFree func(handle windows.Handle) (windows.Handle, error)

func getOwnerFromPathWindows(path string, getNamedSecurityInfo getNamedSecurityInfo, localFree localFree) (utils.FileOwner, error) {
	var ownerSID *windows.SID
	var groupSID *windows.SID
	var secDesc windows.Handle

	if err := getNamedSecurityInfo(
		path,
		acl.SE_FILE_OBJECT,
		acl.OWNER_SECURITY_INFORMATION|acl.GROUP_SECURITY_INFORMATION,
		&ownerSID,
		&groupSID,
		nil,
		nil,
		&secDesc,
	); err != nil {
		return utils.FileOwner{}, fmt.Errorf("failed to get security info for %s: %w", path, err)
	}

	defer localFree(secDesc) //nolint:errcheck // not much we can do

	var ownership utils.FileOwner
	if ownerSID == nil || groupSID == nil {
		return utils.FileOwner{}, fmt.Errorf("failed to get owner or group SID for %s", path)
	}

	ownership.UID = ownerSID.String()
	ownership.GID = groupSID.String()

	return ownership, nil
}

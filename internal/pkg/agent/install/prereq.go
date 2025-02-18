// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"errors"
	"fmt"

	"github.com/schollz/progressbar/v3"

	"github.com/elastic/elastic-agent/pkg/utils"
)

// EnsureUserAndGroup creates the given username and group returning the file ownership information for that
// user and group.
func EnsureUserAndGroup(username string, groupName string, pt *progressbar.ProgressBar, forceCreate bool) (utils.FileOwner, error) {
	var err error
	var ownership utils.FileOwner

	// ensure required group
	ownership.GID, err = FindGID(groupName)
	if err != nil && !errors.Is(err, ErrGroupNotFound) {
		return utils.FileOwner{}, fmt.Errorf("failed finding group %s: %w", groupName, err)
	}
	if forceCreate && errors.Is(err, ErrGroupNotFound) {
		pt.Describe(fmt.Sprintf("Creating group %s", groupName))
		ownership.GID, err = CreateGroup(groupName)
		if err != nil {
			pt.Describe(fmt.Sprintf("Failed to create group %s", groupName))
			return utils.FileOwner{}, fmt.Errorf("failed to create group %s: %w", groupName, err)
		}
		pt.Describe(fmt.Sprintf("Successfully created group %s", groupName))
	}

	// ensure required user
	ownership.UID, err = FindUID(username)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return utils.FileOwner{}, fmt.Errorf("failed finding username %s: %w", username, err)
	}
	if forceCreate && errors.Is(err, ErrUserNotFound) {
		pt.Describe(fmt.Sprintf("Creating user %s", username))
		ownership.UID, err = CreateUser(username, ownership.GID)
		if err != nil {
			pt.Describe(fmt.Sprintf("Failed to create user %s", username))
			return utils.FileOwner{}, fmt.Errorf("failed to create user %s: %w", username, err)
		}
		err = AddUserToGroup(username, groupName)
		if err != nil {
			pt.Describe(fmt.Sprintf("Failed to add user %s to group %s", username, groupName))
			return utils.FileOwner{}, fmt.Errorf("failed to add user %s to group %s: %w", username, groupName, err)
		}
		pt.Describe(fmt.Sprintf("Successfully created user %s", username))
	}

	if err := EnsureRights(username); err != nil {
		pt.Describe(fmt.Sprintf("Failed to assign rights to user %s", username))
		return utils.FileOwner{}, fmt.Errorf("failed to set proper rights to user %s: %w", username, err)
	}
	return ownership, nil
}

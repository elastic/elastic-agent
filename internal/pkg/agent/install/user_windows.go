// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package install

import "errors"

// FindGID returns the group's GID on the machine.
func FindGID(name string) (string, error) {
	return "", errors.New("not implemented")
}

// CreateGroup creates a group on the machine.
func CreateGroup(name string) (string, error) {
	return "", errors.New("not implemented")
}

// FindUID returns the user's UID on the machine.
func FindUID(name string) (string, error) {
	return "", errors.New("not implemented")
}

// CreateUser creates a user on the machine.
func CreateUser(name string, gid string) (string, error) {
	return "", errors.New("not implemented")
}

// AddUserToGroup adds a user to  a group.
func AddUserToGroup(username string, groupName string) error {
	return errors.New("not implemented")
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import "errors"

var (
	// ErrGroupNotFound returned when group is not found.
	ErrGroupNotFound = errors.New("group not found")
	// ErrUserNotFound returned when user is not found.
	ErrUserNotFound = errors.New("user not found")
)

// FindGID returns the group's GID on the machine.
func FindGID(name string) (string, error) {
	return findGID(name)
}

// CreateGroup creates a group on the machine.
func CreateGroup(name string) (string, error) {
	return createGroup(name)
}

// FindUID returns the user's UID on the machine.
func FindUID(name string) (string, error) {
	return findUID(name)
}

// CreateUser creates a user on the machine.
func CreateUser(name string, gid string) (string, error) {
	return createUser(name, gid)
}

// AddUserToGroup adds a user to  a group.
func AddUserToGroup(username string, groupName string) error {
	return addUserToGroup(username, groupName)
}

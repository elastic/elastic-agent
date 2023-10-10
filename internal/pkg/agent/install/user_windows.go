// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package install

import "errors"

func findGID(name string) (string, error) {
	return "", errors.New("not implemented")
}

func createGroup(name string) (string, error) {
	return "", errors.New("not implemented")
}

func findUID(name string) (string, error) {
	return "", errors.New("not implemented")
}

func createUser(name string, gid string) (string, error) {
	return "", errors.New("not implemented")
}

func addUserToGroup(username string, groupName string) error {
	return errors.New("not implemented")
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux

package install

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// FindGID returns the group's GID on the machine.
func FindGID(name string) (int, error) {
	id, err := getentGetID("group", name)
	if e := (&exec.ExitError{}); errors.As(err, &e) {
		if e.ExitCode() == 2 {
			// exit code 2 is the key doesn't exist in the database
			return -1, ErrGroupNotFound
		}
	}
	return id, err
}

// CreateGroup creates a group on the machine.
func CreateGroup(name string) (int, error) {
	cmd := exec.Command("groupadd", "-f", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return -1, fmt.Errorf("groupadd -f %s failed: %w (output: %s)", name, err, output)
	}
	return FindGID(name)
}

// FindUID returns the user's UID on the machine.
func FindUID(name string) (int, error) {
	id, err := getentGetID("passwd", name)
	if e := (&exec.ExitError{}); errors.As(err, &e) {
		if e.ExitCode() == 2 {
			// exit code 2 is the key doesn't exist in the database
			return -1, ErrUserNotFound
		}
	}
	return id, err
}

// CreateUser creates a user on the machine.
func CreateUser(name string, gid int) (int, error) {
	args := []string{
		"--gid", strconv.Itoa(gid),
		"--system",
		"--no-user-group",
		"--shell", "/usr/bin/false",
		name,
	}
	cmd := exec.Command("useradd", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		command := fmt.Sprintf("useradd %s", strings.Join(args, " "))
		return -1, fmt.Errorf("%s failed: %w (output: %s)", command, err, output)
	}
	return FindUID(name)
}

// AddUserToGroup adds a user to  a group.
func AddUserToGroup(username string, groupName string) error {
	cmd := exec.Command("usermod", "-a", "-G", groupName, username)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("usermod -a -G %s %s failed: %w (output: %s)", groupName, username, err, output)
	}
	return nil
}

func getentGetID(database string, key string) (int, error) {
	cmd := exec.Command("getent", database, key)
	output, err := cmd.Output()
	if err != nil {
		return -1, fmt.Errorf("getent %s %s failed: %w (output: %s)", database, key, err, output)
	}
	split := strings.Split(string(output), ":")
	if len(split) < 3 {
		return -1, fmt.Errorf("unexpected format: %s", output)
	}
	val, err := strconv.Atoi(split[2])
	if err != nil {
		return -1, fmt.Errorf("failed to convert %s to int: %w", split[2], err)
	}
	return val, nil
}

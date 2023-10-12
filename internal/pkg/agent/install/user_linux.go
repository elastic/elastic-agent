// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux

package install

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func findGID(name string) (string, error) {
	id, err := getentGetID("group", name)
	if e := (&exec.ExitError{}); errors.As(err, &e) {
		if e.ExitCode() == 2 {
			// exit code 2 is the key doesn't exist in the database
			return "", ErrGroupNotFound
		}
	}
	return id, err
}

func createGroup(name string) (string, error) {
	cmd := exec.Command("groupadd", "-f", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("groupadd -f %s failed: %w (output: %s)", name, err, output)
	}
	return findGID(name)
}

func findUID(name string) (string, error) {
	id, err := getentGetID("passwd", name)
	if e := (&exec.ExitError{}); errors.As(err, &e) {
		if e.ExitCode() == 2 {
			// exit code 2 is the key doesn't exist in the database
			return "", ErrUserNotFound
		}
	}
	return id, err
}

func createUser(name string, gid string) (string, error) {
	args := []string{
		"--gid", gid,
		"--system",
		"--no-user-group",
		"--shell", "/usr/bin/false",
		name,
	}
	cmd := exec.Command("useradd", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		command := fmt.Sprintf("useradd %s", strings.Join(args, " "))
		return "", fmt.Errorf("%s failed: %w (output: %s)", command, err, output)
	}
	return findUID(name)
}

func addUserToGroup(username string, groupName string) error {
	cmd := exec.Command("usermod", "-a", "-G", groupName, username)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("usermod -a -G %s %s failed: %w (output: %s)", groupName, username, err, output)
	}
	return nil
}

func getentGetID(database string, key string) (string, error) {
	cmd := exec.Command("getent", database, key)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("getent %s %s failed: %w (output: %s)", database, key, err, output)
	}
	split := strings.Split(string(output), ":")
	if len(split) < 3 {
		return "", fmt.Errorf("unexpected format: %s", output)
	}
	return split[2], nil
}

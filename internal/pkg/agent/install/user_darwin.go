// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin

package install

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// FindGID returns the group's GID on the machine.
func FindGID(name string) (int, error) {
	records, err := dsclList("/Groups", "PrimaryGroupID")
	if err != nil {
		return -1, fmt.Errorf("failed listing: %w", err)
	}
	for _, record := range records {
		if record[0] == name {
			val, err := strconv.Atoi(record[1])
			if err != nil {
				return -1, fmt.Errorf("failed to convert %s to int: %w", record[1], err)
			}
			return val, nil
		}
	}
	return -1, ErrGroupNotFound
}

// CreateGroup creates a group on the machine.
func CreateGroup(name string) (int, error) {
	// find the next available ID
	nextId, err := dsclNextID("/Groups", "PrimaryGroupID")
	if err != nil {
		return -1, fmt.Errorf("failed getting next gid: %w", err)
	}
	path := fmt.Sprintf("/Groups/%s", name)

	// create the group entry
	err = dsclExec("-create", path, "PrimaryGroupID", strconv.Itoa(nextId))
	if err != nil {
		return -1, err
	}

	return nextId, nil
}

// FindUID returns the user's UID on the machine.
func FindUID(name string) (int, error) {
	records, err := dsclList("/Users", "UniqueID")
	if err != nil {
		return -1, fmt.Errorf("failed listing: %w", err)
	}
	for _, record := range records {
		if record[0] == name {
			val, err := strconv.Atoi(record[1])
			if err != nil {
				return -1, fmt.Errorf("failed to convert %s to int: %w", record[1], err)
			}
			return val, nil
		}
	}
	return -1, ErrUserNotFound
}

// CreateUser creates a user on the machine.
func CreateUser(name string, gid int) (int, error) {
	// find the next available ID
	nextId, err := dsclNextID("/Users", "UniqueID")
	if err != nil {
		return -1, fmt.Errorf("failed getting next uid: %w", err)
	}
	path := fmt.Sprintf("/Users/%s", name)

	// create the user entry
	err = dsclExec("-create", path, "UniqueID", strconv.Itoa(nextId))
	if err != nil {
		return -1, err
	}

	// set primary group to gid
	err = dsclExec("-create", path, "PrimaryGroupID", strconv.Itoa(gid))
	if err != nil {
		return -1, err
	}

	// set home directory to empty
	err = dsclExec("-create", path, "NFSHomeDirectory", "/var/empty")
	if err != nil {
		return -1, err
	}

	// set to no shell
	err = dsclExec("-create", path, "UserShell", "/usr/bin/false")
	if err != nil {
		return -1, err
	}

	// set to no password (aka. cannot authenticate)
	err = dsclExec("-create", path, "Password", "*")
	if err != nil {
		return -1, err
	}

	return nextId, nil
}

// AddUserToGroup adds a user to  a group.
func AddUserToGroup(username string, groupName string) error {
	// #nosec G204 -- user cannot set the groupName or username (hard coded in caller)
	cmd := exec.Command("dscl", ".", "-append", fmt.Sprintf("/Groups/%s", groupName), "GroupMembership", username)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("dscl . -append failed: %w (output: %s)", err, output)
	}
	return nil
}

func dsclNextID(path, field string) (int, error) {
	records, err := dsclList(path, field)
	if err != nil {
		return -1, fmt.Errorf("failed listing: %w", err)
	}
	var ids []int
	for _, record := range records {
		id, err := strconv.Atoi(record[1])
		if err != nil {
			return -1, fmt.Errorf("failed atoi for %s: %w", record[1], err)
		}
		ids = append(ids, id)
	}
	// largest id first
	sort.Slice(ids, func(i, j int) bool {
		return ids[j] < ids[i]
	})
	if len(ids) == 0 {
		// never going to happen, just be defensive
		return 1, nil
	}
	return ids[0] + 1, nil
}

func dsclList(path, field string) ([][]string, error) {
	cmd := exec.Command("dscl", ".", "-list", path, field)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dscl . -list failed: %w", err)
	}
	var records [][]string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("got more than 2 fields reading line %q", line)
		}
		records = append(records, fields)
	}
	return records, nil
}

func dsclExec(args ...string) error {
	args = append([]string{"."}, args...)
	cmd := exec.Command("dscl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		command := fmt.Sprintf("dscl %s", strings.Join(args, " "))
		return fmt.Errorf("%s failed: %w (output: %s)", command, err, output)
	}
	return nil
}

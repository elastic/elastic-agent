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

func findGID(name string) (string, error) {
	records, err := dsclList("/Groups", "PrimaryGroupID")
	if err != nil {
		return "", fmt.Errorf("failed listing: %w", err)
	}
	for _, record := range records {
		if record[0] == name {
			return record[1], nil
		}
	}
	return "", ErrGroupNotFound
}

func createGroup(name string) (string, error) {
	// find the next available ID
	nextId, err := dsclNextID("/Groups", "PrimaryGroupID")
	if err != nil {
		return "", fmt.Errorf("failed getting next gid: %w", err)
	}
	gid := strconv.Itoa(nextId)

	// create the group entry
	cmd := exec.Command("dscl", ".", "-create", fmt.Sprintf("/Groups/%s", name), "PrimaryGroupID", gid)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("dscl . -create failed: %w (output: %s)", err, output)
	}

	return gid, nil
}

func findUID(name string) (string, error) {
	records, err := dsclList("/Users", "UniqueID")
	if err != nil {
		return "", fmt.Errorf("failed listing: %w", err)
	}
	for _, record := range records {
		if record[0] == name {
			return record[1], nil
		}
	}
	return "", ErrUserNotFound
}

func createUser(name string, gid string) (string, error) {
	// find the next available ID
	nextId, err := dsclNextID("/Users", "UniqueID")
	if err != nil {
		return "", fmt.Errorf("failed getting next uid: %w", err)
	}
	uid := strconv.Itoa(nextId)
	path := fmt.Sprintf("/Users/%s", name)

	// create the user entry
	cmd := exec.Command("dscl", ".", "-create", path, "UniqueID", uid)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("dscl . -create failed: %w (output: %s)", err, output)
	}

	// set primary group to gid
	cmd = exec.Command("dscl", ".", "-create", path, "PrimaryGroupID", gid)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("dscl . -create failed: %w (output: %s)", err, output)
	}

	return uid, nil
}

func addUserToGroup(username string, groupName string) error {
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

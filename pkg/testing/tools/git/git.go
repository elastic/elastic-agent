// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package git

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
)

var (
	releaseBranchRegexp = regexp.MustCompile(`.*(\d+\.\d+)$`)
)

// GetReleaseBranches returns a list of release branches of the
// current repository ordered descending by creation date.
// e.g. 8.13, 8.12, etc.
func GetReleaseBranches(ctx context.Context) ([]string, error) {
	var seen = map[string]struct{}{}
	branchList := []string{}

	c := exec.CommandContext(ctx, "git", "branch", "-r", "--list", "*/[0-9]*.*[0-9]", "--sort=-creatordate")

	r, err := c.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create the stdout pipe: %w", err)
	}
	defer r.Close()

	err = c.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start git command: %w", err)
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		branch := scanner.Text()
		if !releaseBranchRegexp.MatchString(branch) {
			continue
		}

		matches := releaseBranchRegexp.FindStringSubmatch(branch)
		if len(matches) != 2 {
			continue
		}
		branch = matches[1]
		_, exists := seen[branch]
		if exists {
			continue
		}
		seen[branch] = struct{}{}
		// appending to the list right away instead of
		// collecting from the map later preserves the order
		branchList = append(branchList, branch)
	}
	if scanner.Err() != nil {
		return nil, fmt.Errorf("failed to scan the output: %w", err)
	}

	err = c.Wait()
	if err != nil {
		return nil, fmt.Errorf("failed to wait for the git command to finish: %w", err)
	}

	return branchList, nil
}

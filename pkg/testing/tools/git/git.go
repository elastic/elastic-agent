// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package git

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
)

var (
	ErrNotReleaseBranch = errors.New("this is not a release branch")
	releaseBranchRegexp = regexp.MustCompile(`.*(\d+\.\d+)$`)
)

type outputReader func(io.Reader) error

// GetReleaseBranches returns a list of release branches of the
// current repository ordered descending by creation date.
// e.g. 8.13, 8.12, etc.
func GetReleaseBranches(ctx context.Context) ([]string, error) {
	c := exec.CommandContext(ctx, "git", "branch", "-r", "--list", "*/[0-9]*.*[0-9]", "--sort=-creatordate")

	branchList := []string{}
	err := runCommand(c, releaseBranchReader(&branchList))
	if err != nil {
		return nil, err
	}

	return branchList, nil
}

// GetCurrentReleaseBranch returns the current branch of the repository
func GetCurrentReleaseBranch(ctx context.Context) (string, error) {
	c := exec.CommandContext(ctx, "git", "symbolic-ref", "--short", "HEAD")

	var branch string
	err := runCommand(c, fullOutputReader(&branch))
	if err != nil {
		return "", err
	}

	// in the APIs the release branch is still called `master`
	if branch == "main" {
		return "master", nil
	}

	return extractReleaseBranch(branch)
}

func fullOutputReader(out *string) outputReader {
	return func(r io.Reader) error {
		b, err := io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("failed to read the entire output: %w", err)
		}
		*out = string(bytes.TrimSpace(b))
		return nil
	}
}

func releaseBranchReader(out *[]string) outputReader {
	return func(r io.Reader) error {
		var seen = map[string]struct{}{}
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			branch := scanner.Text()
			branch, err := extractReleaseBranch(branch)
			if err != nil {
				continue
			}
			_, exists := seen[branch]
			if exists {
				continue
			}
			seen[branch] = struct{}{}
			// appending to the list right away instead of
			// collecting from the map later preserves the order
			*out = append(*out, branch)
		}
		if scanner.Err() != nil {
			return fmt.Errorf("failed to scan the output: %w", scanner.Err())
		}

		return nil
	}
}

func extractReleaseBranch(branch string) (string, error) {
	if !releaseBranchRegexp.MatchString(branch) {
		return "", fmt.Errorf("failed to process branch %q: %w", branch, ErrNotReleaseBranch)
	}

	matches := releaseBranchRegexp.FindStringSubmatch(branch)
	if len(matches) != 2 {
		return "", fmt.Errorf("failed to process branch %q: expected 2 matches, got %d", branch, len(matches))
	}
	return matches[1], nil
}

func runCommand(c *exec.Cmd, or outputReader) error {
	r, err := c.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create the stdout pipe: %w", err)
	}
	defer r.Close()

	err = c.Start()
	if err != nil {
		return fmt.Errorf("failed to start git command: %w", err)
	}

	err = or(r)
	if err != nil {
		return fmt.Errorf("failed to process the git command output: %w", err)
	}

	err = c.Wait()
	if err != nil {
		return fmt.Errorf("failed to wait for the git command to finish: %w", err)
	}

	return nil
}

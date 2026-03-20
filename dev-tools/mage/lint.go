// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/magefile/mage/sh"

	"github.com/elastic/elastic-agent/pkg/testing/tools/git"
)

// ParseToolVersions parses a .tool-versions file and returns a map of tool
// names to their versions. See https://asdf-vm.com/manage/configuration.html#tool-versions.
func ParseToolVersions(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	versions := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			versions[fields[0]] = fields[1]
		}
	}
	return versions, scanner.Err()
}

// GolangciLintVersion reads the golangci-lint version from .tool-versions and
// returns it prefixed with "v" (e.g. "v2.5.0").
func GolangciLintVersion() (string, error) {
	versions, err := ParseToolVersions(".tool-versions")
	if err != nil {
		return "", err
	}
	ver, ok := versions["golangci-lint"]
	if !ok {
		return "", fmt.Errorf("golangci-lint version not found in .tool-versions")
	}
	return "v" + ver, nil
}

// InstallGolangciLint downloads and installs golangci-lint using the version
// specified in .tool-versions.
func InstallGolangciLint() error {
	ver, err := GolangciLintVersion()
	if err != nil {
		return err
	}
	fmt.Printf(">> install golangci-lint %s\n", ver)
	return sh.RunV("bash", "-c",
		fmt.Sprintf("curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s %s", ver))
}

// Lint runs golangci-lint on new issues only, comparing against the closest
// release branch (main or N.M). This matches the CI behavior where
// only-new-issues is set on pull requests.
func Lint(ctx context.Context) error {
	base, err := detectBaseBranch(ctx)
	if err != nil {
		return err
	}
	fmt.Printf(">> lint: using base branch %s\n", base)
	return sh.RunV("./bin/golangci-lint", "run", "-v", "--timeout=30m",
		"--whole-files", "--new-from-merge-base="+base)
}

// LintAll runs golangci-lint on the whole codebase.
func LintAll() error {
	return sh.RunV("./bin/golangci-lint", "run", "-v", "--timeout=30m")
}

// detectBaseBranch finds the closest release branch by choosing the one whose
// merge-base with HEAD is the most recent (i.e. fewest commits away). This is
// the branch a PR would typically target.
func detectBaseBranch(ctx context.Context) (string, error) {
	branches, err := git.GetReleaseBranches(ctx)
	if err != nil {
		return "", fmt.Errorf("listing release branches: %w", err)
	}
	// Also consider main as a candidate.
	candidates := append([]string{"origin/main"}, prefixAll("origin/", branches)...)

	best := ""
	bestDist := -1
	for _, branch := range candidates {
		mb, err := sh.Output("git", "merge-base", branch, "HEAD")
		if err != nil {
			continue
		}
		countStr, err := sh.Output("git", "rev-list", "--count", strings.TrimSpace(mb)+"..HEAD")
		if err != nil {
			continue
		}
		dist := 0
		if _, err := fmt.Sscanf(strings.TrimSpace(countStr), "%d", &dist); err != nil {
			continue
		}
		if bestDist < 0 || dist < bestDist {
			best = branch
			bestDist = dist
		}
	}
	if best == "" {
		return "", fmt.Errorf("could not determine merge-base for any release branch")
	}
	return best, nil
}

func prefixAll(prefix string, ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = prefix + s
	}
	return out
}

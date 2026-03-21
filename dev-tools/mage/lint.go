// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/magefile/mage/sh"

	"github.com/elastic/elastic-agent/pkg/testing/tools/git"
)

// GolangciLintVersion reads the golangci-lint version from
// .golangci-lint-version and returns it prefixed with "v" (e.g. "v2.5.0").
func GolangciLintVersion() (string, error) {
	data, err := os.ReadFile(".golangci-lint-version")
	if err != nil {
		return "", fmt.Errorf("reading .golangci-lint-version: %w", err)
	}
	ver := strings.TrimSpace(string(data))
	if ver == "" {
		return "", fmt.Errorf(".golangci-lint-version is empty")
	}
	return "v" + ver, nil
}

// InstallGolangciLint ensures ./bin/golangci-lint is present and matches the
// version specified in .golangci-lint-version. It skips the download if the installed
// binary is already the correct version.
func InstallGolangciLint() error {
	wantVer, err := GolangciLintVersion()
	if err != nil {
		return err
	}
	if installedVer, err := golangciLintInstalledVersion(); err == nil && installedVer == wantVer {
		fmt.Printf(">> golangci-lint %s already installed, skipping download\n", wantVer)
		return nil
	}
	fmt.Printf(">> install golangci-lint %s\n", wantVer)
	return sh.RunV("bash", "-c",
		fmt.Sprintf("curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s %s", wantVer))
}

// golangciLintInstalledVersion returns the version of the locally installed
// golangci-lint binary (e.g. "v2.5.0"), or an error if the binary is missing
// or its output cannot be parsed.
func golangciLintInstalledVersion() (string, error) {
	out, err := sh.Output("./bin/golangci-lint", "version")
	if err != nil {
		return "", err
	}
	// Output format: "golangci-lint has version 2.5.0 built with ..."
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "version" && i+1 < len(fields) {
			return "v" + fields[i+1], nil
		}
	}
	return "", fmt.Errorf("could not parse version from: %s", out)
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

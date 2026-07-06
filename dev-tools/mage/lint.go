// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
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

// buildTagSet is one build-tag combination we lint with, plus the name the CI
// matrix uses for it.
type buildTagSet struct {
	Name string `json:"name"`
	Tags string `json:"tags"`
}

// buildTagSets are the build-tag combinations we lint with so that files
// behind a //go:build tag are actually checked. "local" and "define" are
// mutually exclusive, hence two sets.
var buildTagSets = []buildTagSet{
	{Name: "default", Tags: ""},
	{Name: "local", Tags: "integration,requirefips,kubernetes_inner,mage,local"},
	{Name: "define", Tags: "integration,requirefips,kubernetes_inner,mage,define"},
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

	changed, err := changedFiles(base)
	if err != nil {
		return err
	}
	sets := tagSetsNeeded(changed)
	fmt.Printf(">> lint: build-tag sets to run: %+v\n", sets)

	for _, set := range sets {
		args := []string{"run", "-v", "--timeout=30m", "--whole-files", "--new-from-merge-base=" + base}
		if set.Tags != "" {
			args = append(args, "--build-tags="+set.Tags)
		}
		fmt.Printf(">> lint: build-tags=%q\n", set.Tags)
		if err := sh.RunV("./bin/golangci-lint", args...); err != nil {
			return err
		}
	}
	return nil
}

// LintPlan prints the lint tag-set plan as JSON for CI and runs golangci-lint
// zero times. LINT_PLAN_BASE selects the diff base; unset (pushes) plans all sets.
func LintPlan() error {
	sets := buildTagSets
	if base := os.Getenv("LINT_PLAN_BASE"); base != "" {
		changed, err := changedFiles(base)
		if err != nil {
			return err
		}
		sets = tagSetsNeeded(changed)
	}
	out, err := json.Marshal(sets)
	if err != nil {
		return fmt.Errorf("marshaling tag sets: %w", err)
	}
	fmt.Println(string(out))
	return nil
}

// changedFiles lists the files changed between the merge-base of base and
// HEAD, and HEAD itself.
func changedFiles(base string) ([]string, error) {
	out, err := sh.Output("git", "diff", "--name-only", base+"...HEAD")
	if err != nil {
		return nil, fmt.Errorf("listing changed files against %s: %w", base, err)
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, nil
	}
	return strings.Split(out, "\n"), nil
}

// riskFiles affect every tag set when changed, so all of them must run.
var riskFiles = map[string]bool{
	"go.mod":                              true,
	"go.sum":                              true,
	".golangci.yml":                       true,
	".golangci-lint-version":              true,
	".github/workflows/golangci-lint.yml": true,
}

var (
	sharedTagWords = regexp.MustCompile(`\b(integration|requirefips|kubernetes_inner|mage)\b`)
	localTagWord   = regexp.MustCompile(`\blocal\b`)
	defineTagWord  = regexp.MustCompile(`\bdefine\b`)
)

// tagSetsNeeded picks which tag sets to lint for the given changed files, so
// we skip runs that couldn't report anything new. The untagged set always
// runs; a tagged set is added only when a changed file could belong to it.
// It may over-select but never under-selects.
func tagSetsNeeded(changed []string) []buildTagSet {
	needLocal, needDefine := false, false
	for _, f := range changed {
		if riskFiles[f] {
			needLocal, needDefine = true, true
			continue
		}
		if !strings.HasSuffix(f, ".go") {
			continue
		}
		tagLine, ok := buildTagLine(f)
		if !ok {
			continue
		}
		if sharedTagWords.MatchString(tagLine) {
			needLocal, needDefine = true, true
		}
		if localTagWord.MatchString(tagLine) {
			needLocal = true
		}
		if defineTagWord.MatchString(tagLine) {
			needDefine = true
		}
	}

	sets := []buildTagSet{buildTagSets[0]}
	if needLocal {
		sets = append(sets, buildTagSets[1])
	}
	if needDefine {
		sets = append(sets, buildTagSets[2])
	}
	return sets
}

// buildTagLine returns the file's "//go:build" line, or false if it has none
// or can't be read (e.g. deleted).
func buildTagLine(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "//go:build") {
			return line, true
		}
	}
	return "", false
}

// LintAll runs golangci-lint on the whole codebase.
func LintAll() error {
	for _, set := range buildTagSets {
		args := []string{"run", "-v", "--timeout=30m"}
		if set.Tags != "" {
			args = append(args, "--build-tags="+set.Tags)
		}
		fmt.Printf(">> lint-all: build-tags=%q\n", set.Tags)
		if err := sh.RunV("./bin/golangci-lint", args...); err != nil {
			return err
		}
	}
	return nil
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

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Command agent-release runs Elastic Agent release automation from a nested Go
// module so tooling dependencies stay out of the root module.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/elastic/elastic-agent/dev-tools/mage/release"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "agent-release: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if err := chdirAgentRoot(); err != nil {
		return err
	}

	if len(args) < 1 {
		return fmt.Errorf("usage: agent-release <command> [args...]\n\n%s", usage())
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "update-version":
		if len(rest) != 1 {
			return fmt.Errorf("usage: agent-release update-version <version>")
		}
		return release.UpdateVersion(rest[0])
	case "update-docs":
		if len(rest) != 1 {
			return fmt.Errorf("usage: agent-release update-docs <version>")
		}
		return release.UpdateDocs(rest[0])
	case "update-patch-docs":
		if len(rest) != 1 {
			return fmt.Errorf("usage: agent-release update-patch-docs <version>")
		}
		return release.UpdatePatchDocs(rest[0])
	case "update-mergify":
		if len(rest) != 1 {
			return fmt.Errorf("usage: agent-release update-mergify <version>")
		}
		return release.UpdateMergify(rest[0])
	case "run-major-minor":
		if len(rest) != 0 {
			return fmt.Errorf("usage: agent-release run-major-minor")
		}
		cfg, err := release.LoadConfigFromEnv()
		if err != nil {
			return err
		}
		return release.RunMajorMinorRelease(cfg)
	case "run-patch":
		if len(rest) != 0 {
			return fmt.Errorf("usage: agent-release run-patch")
		}
		cfg, err := release.LoadConfigFromEnv()
		if err != nil {
			return err
		}
		return release.RunPatchRelease(cfg)
	case "ensure-issue-tracker":
		if len(rest) != 0 {
			return fmt.Errorf("usage: agent-release ensure-issue-tracker")
		}
		cfg, err := release.LoadConfigFromEnv()
		if err != nil {
			return err
		}
		return release.EnsureReleaseIssueTracker(cfg, nil)
	case "help", "-h", "--help":
		fmt.Print(usage())
		return nil
	default:
		return fmt.Errorf("unknown command %q\n\n%s", cmd, usage())
	}
}

func usage() string {
	return strings.TrimSpace(`
Commands:
  update-version <version>
  update-docs <version>
  update-patch-docs <version>
  update-mergify <version>
  run-major-minor
  run-patch
  ensure-issue-tracker

Environment for run-major-minor / run-patch / ensure-issue-tracker: see RELEASE.md and
dev-tools/mage/release/README.md (CURRENT_RELEASE, DRY_RUN, GITHUB_TOKEN, …).
`) + "\n"
}

// chdirAgentRoot finds the Elastic Agent repository root and makes it the working
// directory. go run -C leaves cwd in the nested module, but release workflows
// expect to run from the repo root (OpenRepo("."), relative paths, mage update).
func chdirAgentRoot() error {
	if root := os.Getenv("ELASTIC_AGENT_REPO_ROOT"); root != "" {
		return os.Chdir(root)
	}

	start, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	dir := start
	for {
		modPath := filepath.Join(dir, "go.mod")
		data, err := os.ReadFile(modPath)
		if err == nil && isAgentRootModule(string(data)) {
			return os.Chdir(dir)
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return fmt.Errorf("elastic-agent repository root not found from %s (set ELASTIC_AGENT_REPO_ROOT)", start)
		}
		dir = parent
	}
}

func isAgentRootModule(goMod string) bool {
	for _, line := range strings.Split(goMod, "\n") {
		line = strings.TrimSpace(line)
		if line == "module github.com/elastic/elastic-agent" {
			return true
		}
	}
	return false
}

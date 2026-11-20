// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// This file was contributed to by generative AI

//go:build mage

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/elastic/elastic-agent/dev-tools/mage/dra"
	"github.com/elastic/elastic-agent/version"
)

// Dra holds the parts of the elastic-agent-package DRA flow that are packaging
// logic rather than CI plumbing: which products the package is assembled from,
// which DRA build of each is current, and what the merged manifest that drives
// `mage package` looks like.
//
// Running the two targets below is enough to reproduce a full DRA packaging run
// locally on any branch:
//
//	mage dra:mergeManifests
//	MANIFEST_PATH=build/dra/agent-artifacts-merged.json AGENT_CORE_SOURCE=manifest mage package
//
// The surrounding Buildkite and GCS calls stay in .buildkite/scripts; see
// dev-tools/mage/dra/README.md for how the two halves fit together.
type Dra mg.Namespace

// DefaultMergedManifestPath is where dra:mergeManifests writes by default.
const DefaultMergedManifestPath = "build/dra/agent-artifacts-merged.json"

// Dependencies prints the DRA products elastic-agent-package consumes, one per
// line, as derived from dev-tools/packaging/packages.yml.
//
// It is the single source of truth for the dependency poller and for the
// --dependency flags passed to dractl prep.
func (Dra) Dependencies() error {
	deps, err := dra.Dependencies()
	if err != nil {
		return err
	}
	for _, dep := range deps {
		fmt.Fprintln(os.Stdout, dep)
	}
	return nil
}

// MergeManifests resolves the current DRA build of every dependency, downloads
// their manifests and writes a single merged manifest that `mage package`
// consumes through MANIFEST_PATH (locally) or MANIFEST_URL (in CI).
//
// The merged manifest's build_id is a content hash of the dependency builds, so
// merging the same inputs twice produces the same id. The poller script uses
// that to decide whether these inputs have already been built. Its version is
// the one the dependencies themselves report, which is what the pipeline then
// passes on as DRA_VERSION.
//
// Environment:
//
//	DRA_WORKFLOW     snapshot (default) or staging
//	DRA_VERSION      resolve this exact stack version instead of the branch's
//	                 current build
//	BUILDKITE_BRANCH branch to resolve, defaults to this checkout's branch
//	DRA_MERGED_MANIFEST_OUT
//	                 output path, defaults to build/dra/agent-artifacts-merged.json
//	DRA_ALLOW_MISSING_DEPS
//	                 merge even when a product has published no matching build
func (Dra) MergeManifests(ctx context.Context) error {
	workflow, err := dra.ParseWorkflow(envOrDefault("DRA_WORKFLOW", string(dra.WorkflowSnapshot)))
	if err != nil {
		return err
	}
	allowMissing, err := envBool("DRA_ALLOW_MISSING_DEPS")
	if err != nil {
		return err
	}

	branch := draBranch()
	key, keySource := draPointerKey(workflow, branch)
	outputPath := envOrDefault("DRA_MERGED_MANIFEST_OUT", DefaultMergedManifestPath)

	projects, err := dra.Dependencies()
	if err != nil {
		return err
	}

	logger := log.New(os.Stdout, "", 0)
	logger.Printf("resolving %s dependencies of branch %s from latest/%s.json (%s): %s",
		workflow, branch, key, keySource, strings.Join(projects, ", "))

	client := dra.NewArtifactsClient(workflow)
	resolved, missing, err := dra.ResolveDependencies(ctx, client, key, projects)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		if !allowMissing {
			return fmt.Errorf("no %s build published for: %s (set DRA_ALLOW_MISSING_DEPS=true to merge anyway)",
				key, strings.Join(missing, ", "))
		}
		logger.Printf("warning: no %s build published for %s; packaging will not find their artifacts",
			key, strings.Join(missing, ", "))
	}

	stackVersion, disagreeing, err := dra.StackVersion(resolved)
	if err != nil {
		return err
	}
	if len(disagreeing) > 0 {
		// Normal for a while after a version bump. Worth saying out loud,
		// because it is also what a stuck dependency looks like.
		logger.Printf("warning: packaging at %s, but these dependencies report another version: %s",
			stackVersion, strings.Join(disagreeing, ", "))
	}

	merged, err := dra.BuildMergedManifest(ctx, client, workflow, branch, stackVersion, resolved)
	if err != nil {
		return err
	}
	if err := merged.Validate(projectNamesOf(resolved)); err != nil {
		return err
	}
	merged.LogSummary(logger)

	content, err := merged.MarshalIndent()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("creating output directory for %s: %w", outputPath, err)
	}
	if err := os.WriteFile(outputPath, content, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", outputPath, err)
	}

	logger.Printf("merged manifest written to %s", outputPath)
	logger.Printf("package from it with: MANIFEST_PATH=%s AGENT_CORE_SOURCE=manifest mage package", outputPath)
	return nil
}

func projectNamesOf(deps []dra.DependencyBuild) []string {
	names := make([]string, 0, len(deps))
	for _, dep := range deps {
		names = append(names, dep.Project)
	}
	return names
}

// draPointerKey picks which "latest" pointer to read, and says why.
//
// The branch's own pointer is preferred: it follows the branch across version
// bumps without this repository having to agree with DRA about the version. A
// branch DRA does not publish — every feature branch — falls back to the
// version in the checkout, so a local run on one resolves what CI would. An
// explicit DRA_VERSION overrides both.
func draPointerKey(workflow dra.Workflow, branch string) (dra.LatestPointerKey, string) {
	if v := os.Getenv("DRA_VERSION"); v != "" {
		return workflow.VersionPointerKey(v), "from DRA_VERSION"
	}
	if key, published := dra.BranchPointerKey(branch); published {
		return key, "branch pointer"
	}
	return workflow.VersionPointerKey(version.Agent), "no DRA pointer for this branch, using the checkout's version"
}

// draBranch is the branch to resolve dependencies for, and is recorded in the
// merged manifest.
func draBranch() string {
	if v := os.Getenv("BUILDKITE_BRANCH"); v != "" {
		return v
	}
	if out, err := sh.Output("git", "rev-parse", "--abbrev-ref", "HEAD"); err == nil {
		if branch := strings.TrimSpace(out); branch != "" && branch != "HEAD" {
			return branch
		}
	}
	return "unknown"
}

func envOrDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func envBool(name string) (bool, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean, got %q", name, raw)
	}
	return value, nil
}

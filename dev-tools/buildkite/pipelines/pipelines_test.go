// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipelines

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gotest.tools/v3/golden"

	"github.com/elastic/elastic-agent/dev-tools/buildkite/pipeline"
)

// findRepoRoot finds the repository root by looking for go.mod.
func findRepoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repository root (go.mod)")
		}
		dir = parent
	}
}

func TestGCECleanup(t *testing.T) {
	p := GCECleanup()

	yaml, err := p.MarshalYAML()
	if err != nil {
		t.Fatalf("failed to marshal pipeline: %v", err)
	}

	// Golden file test - update with: go test -update
	golden.AssertBytes(t, yaml, "pipeline.elastic-agent-gce-cleanup.yml")
}

func TestGCECleanupMatchesActual(t *testing.T) {
	repoRoot := findRepoRoot(t)
	actualPath := filepath.Join(repoRoot, ".buildkite", "pipeline.elastic-agent-gce-cleanup.yml")

	p := GCECleanup()
	result, err := pipeline.SemanticCompareWithFile(p, actualPath)
	if err != nil {
		t.Fatalf("failed to compare: %v", err)
	}

	if result.ParseError != nil {
		t.Fatalf("failed to parse YAML: %v", result.ParseError)
	}

	if !result.Equal {
		t.Errorf("Generated pipeline does not match %s:\n%s",
			actualPath, strings.Join(result.Differences, "\n"))
	}
}

func TestAgentlessAppRelease(t *testing.T) {
	p := AgentlessAppRelease()

	yaml, err := p.MarshalYAML()
	if err != nil {
		t.Fatalf("failed to marshal pipeline: %v", err)
	}

	// Golden file test - update with: go test -update
	golden.AssertBytes(t, yaml, "pipeline.agentless-app-release.yaml")
}

func TestAgentlessAppReleaseMatchesActual(t *testing.T) {
	repoRoot := findRepoRoot(t)
	actualPath := filepath.Join(repoRoot, ".buildkite", "pipeline.agentless-app-release.yaml")

	p := AgentlessAppRelease()
	result, err := pipeline.SemanticCompareWithFile(p, actualPath)
	if err != nil {
		t.Fatalf("failed to compare: %v", err)
	}

	if result.ParseError != nil {
		t.Fatalf("failed to parse YAML: %v", result.ParseError)
	}

	if !result.Equal {
		t.Errorf("Generated pipeline does not match %s:\n%s",
			actualPath, strings.Join(result.Differences, "\n"))
	}
}

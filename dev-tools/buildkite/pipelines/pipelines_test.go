// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipelines

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gotest.tools/v3/golden"

	"github.com/elastic/elastic-agent/dev-tools/buildkite/pipeline"
)

// pipelineTestCase defines a test case for pipeline generation.
type pipelineTestCase struct {
	name       string
	generator  func() *pipeline.Pipeline
	goldenFile string
	actualFile string
	// dynamic indicates the pipeline has been migrated to dynamic upload.
	// Dynamic pipelines have a stub in .buildkite/ that calls mage, so we
	// skip the actual file comparison for them.
	dynamic bool
}

var pipelineTestCases = []pipelineTestCase{
	{
		name:       "GCECleanup",
		generator:  GCECleanup,
		goldenFile: "pipeline.elastic-agent-gce-cleanup.yml",
		actualFile: "pipeline.elastic-agent-gce-cleanup.yml",
		dynamic:    true,
	},
	{
		name:       "AgentlessAppRelease",
		generator:  AgentlessAppRelease,
		goldenFile: "pipeline.agentless-app-release.yaml",
		actualFile: "pipeline.agentless-app-release.yaml",
	},
	{
		name:       "Pipeline",
		generator:  Pipeline,
		goldenFile: "pipeline.yml",
		actualFile: "pipeline.yml",
		dynamic:    true,
	},
	{
		name:       "IntegrationPipeline",
		generator:  IntegrationPipeline,
		goldenFile: "integration.pipeline.yml",
		actualFile: "integration.pipeline.yml",
		dynamic:    true,
	},
	{
		name:       "ElasticAgentPackage",
		generator:  ElasticAgentPackage,
		goldenFile: "pipeline.elastic-agent-package.yml",
		actualFile: "pipeline.elastic-agent-package.yml",
	},
	{
		name:       "BKIntegrationPipeline",
		generator:  BKIntegrationPipeline,
		goldenFile: "bk.integration.pipeline.yml",
		actualFile: "bk.integration.pipeline.yml",
	},
	{
		name:       "BKIntegrationFIPSPipeline",
		generator:  BKIntegrationFIPSPipeline,
		goldenFile: "bk.integration-fips.pipeline.yml",
		actualFile: "bk.integration-fips.pipeline.yml",
	},
}

// findRepoRoot finds the repository root by looking for go.mod.
func findRepoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err, "failed to get working directory")

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "could not find repository root (go.mod)")
		dir = parent
	}
}

func TestPipelines(t *testing.T) {
	for _, tc := range pipelineTestCases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.generator()

			yaml, err := p.MarshalYAML()
			require.NoError(t, err, "failed to marshal pipeline")

			// Golden file test - update with: go test -update
			golden.AssertBytes(t, yaml, tc.goldenFile)
		})
	}
}

func TestPipelinesMatchActual(t *testing.T) {
	repoRoot := findRepoRoot(t)

	for _, tc := range pipelineTestCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.dynamic {
				t.Skip("Skipping actual file comparison for dynamic pipeline (uses mage for upload)")
			}

			actualPath := filepath.Join(repoRoot, ".buildkite", tc.actualFile)

			p := tc.generator()
			result, err := pipeline.SemanticCompareWithFile(p, actualPath)
			require.NoError(t, err, "failed to compare")
			require.NoError(t, result.ParseError, "failed to parse YAML")

			assert.True(t, result.Equal,
				"Generated pipeline does not match %s:\n%s",
				actualPath, strings.Join(result.Differences, "\n"))
		})
	}
}

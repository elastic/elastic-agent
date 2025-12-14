// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestBuildkitePipelinesRegistered(t *testing.T) {
	// Verify that all expected pipelines are registered
	expectedPipelines := []string{
		"GCECleanup",
		"AgentlessAppRelease",
		"Pipeline",
		"IntegrationPipeline",
		"ElasticAgentPackage",
		"BKIntegrationPipeline",
		"BKIntegrationFIPSPipeline",
	}

	actualNames := make([]string, len(BuildkitePipelines))
	for i, p := range BuildkitePipelines {
		actualNames[i] = p.Name
	}

	assert.Equal(t, expectedPipelines, actualNames, "pipeline registry mismatch")
}

func TestBuildkitePipelineGoldenFiles(t *testing.T) {
	// Verify that all pipeline golden files are in the testdata directory
	for _, p := range BuildkitePipelines {
		assert.True(t, strings.HasPrefix(p.GoldenFile, "dev-tools/buildkite/pipelines/testdata/"),
			"pipeline %s golden file %q should be in testdata/", p.Name, p.GoldenFile)
	}
}

func TestBuildkitePipelineGenerators(t *testing.T) {
	// Verify that all pipeline generators return non-nil pipelines
	for _, p := range BuildkitePipelines {
		t.Run(p.Name, func(t *testing.T) {
			pl := p.Generator()
			require.NotNil(t, pl, "generator for %s returned nil pipeline", p.Name)
		})
	}
}

func TestBuildkiteGeneratePipeline(t *testing.T) {
	// Test generating a known pipeline (outputs to stdout)
	err := BuildkiteGeneratePipeline("GCECleanup")
	require.NoError(t, err, "should generate GCECleanup pipeline")
}

func TestBuildkiteGeneratePipelineNotFound(t *testing.T) {
	// Test generating a non-existent pipeline
	err := BuildkiteGeneratePipeline("NonExistentPipeline")
	require.Error(t, err, "should error for non-existent pipeline")
	assert.Contains(t, err.Error(), "not found")
}

func TestBuildkiteIndividualPipelineFunctions(t *testing.T) {
	// Test each individual pipeline function
	tests := []struct {
		name string
		fn   func() error
	}{
		{"BuildkitePipeline", BuildkitePipeline},
		{"BuildkiteIntegration", BuildkiteIntegration},
		{"BuildkiteIntegrationFull", BuildkiteIntegrationFull},
		{"BuildkiteIntegrationFIPS", BuildkiteIntegrationFIPS},
		{"BuildkitePackage", BuildkitePackage},
		{"BuildkiteAgentlessRelease", BuildkiteAgentlessRelease},
		{"BuildkiteGCECleanup", BuildkiteGCECleanup},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			require.NoError(t, err, "%s should succeed", tt.name)
		})
	}
}

func TestBuildkiteValidatePipeline(t *testing.T) {
	// Change to repo root so relative paths work
	repoRoot := findRepoRoot(t)
	originalDir, err := os.Getwd()
	require.NoError(t, err)
	err = os.Chdir(repoRoot)
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(originalDir)
	}()

	// Test validating a known pipeline
	result, err := BuildkiteValidatePipeline("GCECleanup")
	require.NoError(t, err, "GCECleanup validation should succeed")
	assert.True(t, result.Valid, "GCECleanup should be valid")
	assert.Equal(t, "GCECleanup", result.Name)
	assert.Equal(t, "dev-tools/buildkite/pipelines/testdata/pipeline.elastic-agent-gce-cleanup.yml", result.GoldenFile)
}

func TestBuildkiteValidatePipelineNotFound(t *testing.T) {
	// Test validating a non-existent pipeline
	result, err := BuildkiteValidatePipeline("NonExistentPipeline")
	require.Error(t, err, "should error for non-existent pipeline")
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "not found")
}

func TestBuildkiteValidateAllPipelines(t *testing.T) {
	// Change to repo root so relative paths work
	repoRoot := findRepoRoot(t)
	originalDir, err := os.Getwd()
	require.NoError(t, err)
	err = os.Chdir(repoRoot)
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(originalDir)
	}()

	// Test validating all pipelines
	results, err := BuildkiteValidate()
	require.NoError(t, err, "all pipeline validations should succeed")

	// Verify we got results for all pipelines
	assert.Len(t, results, len(BuildkitePipelines), "should have results for all pipelines")

	// Verify all results are valid
	for _, r := range results {
		assert.True(t, r.Valid, "pipeline %s should be valid", r.Name)
		assert.Nil(t, r.Error, "pipeline %s should have no error", r.Name)
		assert.Empty(t, r.Differences, "pipeline %s should have no differences", r.Name)
	}
}

func TestBuildkiteDiff(t *testing.T) {
	// Change to repo root so relative paths work
	repoRoot := findRepoRoot(t)
	originalDir, err := os.Getwd()
	require.NoError(t, err)
	err = os.Chdir(repoRoot)
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(originalDir)
	}()

	// Test diff for all pipelines
	results := BuildkiteDiff()

	// Verify we got results for all pipelines
	assert.Len(t, results, len(BuildkitePipelines), "should have results for all pipelines")

	// Verify all results have no errors
	for _, r := range results {
		assert.Nil(t, r.Error, "pipeline %s should have no error", r.Name)
	}
}

func TestPipelineDefinitionFields(t *testing.T) {
	// Verify that all pipeline definitions have required fields
	for _, p := range BuildkitePipelines {
		t.Run(p.Name, func(t *testing.T) {
			assert.NotEmpty(t, p.Name, "pipeline should have a name")
			assert.NotNil(t, p.Generator, "pipeline should have a generator")
			assert.NotEmpty(t, p.GoldenFile, "pipeline should have a golden file path")
		})
	}
}

func TestDynamicPipelines(t *testing.T) {
	// Verify that GCECleanup is marked as dynamic
	for _, p := range BuildkitePipelines {
		if p.Name == "GCECleanup" {
			assert.True(t, p.Dynamic, "GCECleanup should be marked as dynamic")
		}
	}
}

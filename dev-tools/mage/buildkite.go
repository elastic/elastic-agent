// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"fmt"
	"strings"

	"github.com/elastic/elastic-agent/dev-tools/buildkite/pipeline"
	"github.com/elastic/elastic-agent/dev-tools/buildkite/pipelines"
)

// PipelineDefinition defines a Buildkite pipeline that can be generated.
type PipelineDefinition struct {
	Name      string
	Generator func() *pipeline.Pipeline
	// GoldenFile is the path to the golden file for validation/comparison.
	// This is used to verify the generated pipeline matches expected output.
	GoldenFile string
	// Dynamic indicates whether this pipeline has been migrated to dynamic upload.
	// Dynamic pipelines use a stub in .buildkite/ that calls mage to generate the pipeline.
	Dynamic bool
}

// goldenFileDir is the directory containing golden files for pipeline validation.
const goldenFileDir = "dev-tools/buildkite/pipelines/testdata"

// BuildkitePipelines is the list of all pipelines that can be generated.
// The GoldenFile field points to the golden file for validation.
var BuildkitePipelines = []PipelineDefinition{
	{"GCECleanup", pipelines.GCECleanup, goldenFileDir + "/pipeline.elastic-agent-gce-cleanup.yml", true},
	{"AgentlessAppRelease", pipelines.AgentlessAppRelease, goldenFileDir + "/pipeline.agentless-app-release.yaml", false},
	{"Pipeline", pipelines.Pipeline, goldenFileDir + "/pipeline.yml", false},
	{"IntegrationPipeline", pipelines.IntegrationPipeline, goldenFileDir + "/integration.pipeline.yml", true},
	{"ElasticAgentPackage", pipelines.ElasticAgentPackage, goldenFileDir + "/pipeline.elastic-agent-package.yml", false},
	{"BKIntegrationPipeline", pipelines.BKIntegrationPipeline, goldenFileDir + "/bk.integration.pipeline.yml", false},
	{"BKIntegrationFIPSPipeline", pipelines.BKIntegrationFIPSPipeline, goldenFileDir + "/bk.integration-fips.pipeline.yml", false},
}

// BuildkiteGeneratePipeline generates a pipeline by name and outputs YAML to stdout.
// This is designed to be piped to `buildkite-agent pipeline upload`.
func BuildkiteGeneratePipeline(name string) error {
	for _, p := range BuildkitePipelines {
		if p.Name == name {
			pl := p.Generator()
			yaml, err := pl.MarshalYAML()
			if err != nil {
				return fmt.Errorf("failed to marshal %s: %w", p.Name, err)
			}
			fmt.Print(string(yaml))
			return nil
		}
	}
	return fmt.Errorf("pipeline %q not found", name)
}

// Individual pipeline generators - each outputs YAML to stdout.
// These are designed to be piped to `buildkite-agent pipeline upload`.

// BuildkitePipeline outputs the main pipeline YAML to stdout.
func BuildkitePipeline() error {
	return BuildkiteGeneratePipeline("Pipeline")
}

// BuildkiteIntegration outputs the integration pipeline YAML to stdout.
func BuildkiteIntegration() error {
	return BuildkiteGeneratePipeline("IntegrationPipeline")
}

// BuildkiteIntegrationFull outputs the full integration tests pipeline YAML to stdout.
func BuildkiteIntegrationFull() error {
	return BuildkiteGeneratePipeline("BKIntegrationPipeline")
}

// BuildkiteIntegrationFIPS outputs the FIPS integration tests pipeline YAML to stdout.
func BuildkiteIntegrationFIPS() error {
	return BuildkiteGeneratePipeline("BKIntegrationFIPSPipeline")
}

// BuildkitePackage outputs the Elastic Agent package pipeline YAML to stdout.
func BuildkitePackage() error {
	return BuildkiteGeneratePipeline("ElasticAgentPackage")
}

// BuildkiteAgentlessRelease outputs the agentless app release pipeline YAML to stdout.
func BuildkiteAgentlessRelease() error {
	return BuildkiteGeneratePipeline("AgentlessAppRelease")
}

// BuildkiteGCECleanup outputs the GCE cleanup pipeline YAML to stdout.
func BuildkiteGCECleanup() error {
	return BuildkiteGeneratePipeline("GCECleanup")
}

// BuildkiteValidateResult contains the result of validating a single pipeline.
type BuildkiteValidateResult struct {
	Name        string
	GoldenFile  string
	Valid       bool
	Error       error
	Differences []string
}

// BuildkiteValidate validates that generated pipelines match the golden files.
// Returns the validation results and an error if any pipeline doesn't match.
func BuildkiteValidate() ([]BuildkiteValidateResult, error) {
	fmt.Println(">> buildkite:validate - Validating Buildkite pipelines against golden files...")

	var results []BuildkiteValidateResult
	var errs []string

	for _, p := range BuildkitePipelines {
		result := BuildkiteValidateResult{
			Name:       p.Name,
			GoldenFile: p.GoldenFile,
		}

		pl := p.Generator()
		compareResult, err := pipeline.SemanticCompareWithFile(pl, p.GoldenFile)
		if err != nil {
			result.Error = err
			errs = append(errs, fmt.Sprintf("%s: %v", p.Name, err))
			results = append(results, result)
			continue
		}
		if compareResult.ParseError != nil {
			result.Error = compareResult.ParseError
			errs = append(errs, fmt.Sprintf("%s: parse error: %v", p.Name, compareResult.ParseError))
			results = append(results, result)
			continue
		}
		if !compareResult.Equal {
			result.Differences = compareResult.Differences
			errs = append(errs, fmt.Sprintf("%s: generated pipeline does not match %s:\n%s",
				p.Name, p.GoldenFile, strings.Join(compareResult.Differences, "\n")))
		} else {
			result.Valid = true
			fmt.Printf("  ✓ %s matches %s\n", p.Name, p.GoldenFile)
		}
		results = append(results, result)
	}

	if len(errs) > 0 {
		fmt.Println("\n>> buildkite:validate - FAILED!")
		for _, e := range errs {
			fmt.Printf("  ✗ %s\n", e)
		}
		return results, fmt.Errorf("pipeline validation failed: %d errors", len(errs))
	}

	fmt.Println(">> buildkite:validate - Done! All pipelines match.")
	return results, nil
}

// BuildkiteValidatePipeline validates a single pipeline by name.
// Returns the validation result.
func BuildkiteValidatePipeline(name string) (*BuildkiteValidateResult, error) {
	for _, p := range BuildkitePipelines {
		if p.Name == name {
			result := &BuildkiteValidateResult{
				Name:       p.Name,
				GoldenFile: p.GoldenFile,
			}

			pl := p.Generator()
			compareResult, err := pipeline.SemanticCompareWithFile(pl, p.GoldenFile)
			if err != nil {
				result.Error = err
				return result, err
			}
			if compareResult.ParseError != nil {
				result.Error = compareResult.ParseError
				return result, compareResult.ParseError
			}
			if !compareResult.Equal {
				result.Differences = compareResult.Differences
				return result, fmt.Errorf("generated pipeline does not match %s", p.GoldenFile)
			}
			result.Valid = true
			return result, nil
		}
	}
	return nil, fmt.Errorf("pipeline %q not found", name)
}

// BuildkiteDiffResult contains the diff result for a single pipeline.
type BuildkiteDiffResult struct {
	Name       string
	GoldenFile string
	Equal      bool
	Diff       string
	Error      error
}

// BuildkiteDiff compares generated pipelines with golden files.
// Returns the diff results for each pipeline.
func BuildkiteDiff() []BuildkiteDiffResult {
	fmt.Println(">> buildkite:diff - Comparing generated pipelines with golden files...")

	var results []BuildkiteDiffResult
	anyDiff := false

	for _, p := range BuildkitePipelines {
		result := BuildkiteDiffResult{
			Name:       p.Name,
			GoldenFile: p.GoldenFile,
		}

		pl := p.Generator()
		compareResult, err := pipeline.CompareWithFile(pl, p.GoldenFile)
		if err != nil {
			result.Error = err
			fmt.Printf("\n--- %s ---\nError: %v\n", p.Name, err)
			anyDiff = true
			results = append(results, result)
			continue
		}

		result.Equal = compareResult.Equal
		if !compareResult.Equal {
			result.Diff = compareResult.Diff
			anyDiff = true
			fmt.Printf("\n--- %s (%s) ---\n", p.Name, p.GoldenFile)
			fmt.Println(compareResult.Diff)
		}
		results = append(results, result)
	}

	if !anyDiff {
		fmt.Println(">> buildkite:diff - No differences found!")
	}

	return results
}

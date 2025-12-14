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
	// YAMLFile is the path to the existing YAML file for validation/comparison.
	YAMLFile string
}

// BuildkitePipelines is the list of all pipelines that can be generated.
// The YAMLFile field points to the existing static YAML file for validation.
var BuildkitePipelines = []PipelineDefinition{
	{"GCECleanup", pipelines.GCECleanup, ".buildkite/pipeline.elastic-agent-gce-cleanup.yml"},
	{"AgentlessAppRelease", pipelines.AgentlessAppRelease, ".buildkite/pipeline.agentless-app-release.yaml"},
	{"Pipeline", pipelines.Pipeline, ".buildkite/pipeline.yml"},
	{"IntegrationPipeline", pipelines.IntegrationPipeline, ".buildkite/integration.pipeline.yml"},
	{"ElasticAgentPackage", pipelines.ElasticAgentPackage, ".buildkite/pipeline.elastic-agent-package.yml"},
	{"BKIntegrationPipeline", pipelines.BKIntegrationPipeline, ".buildkite/bk.integration.pipeline.yml"},
	{"BKIntegrationFIPSPipeline", pipelines.BKIntegrationFIPSPipeline, ".buildkite/bk.integration-fips.pipeline.yml"},
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
	YAMLFile    string
	Valid       bool
	Error       error
	Differences []string
}

// BuildkiteValidate validates that generated pipelines match the existing YAML files.
// Returns the validation results and an error if any pipeline doesn't match.
func BuildkiteValidate() ([]BuildkiteValidateResult, error) {
	fmt.Println(">> buildkite:validate - Validating Buildkite pipelines against YAML files...")

	var results []BuildkiteValidateResult
	var errs []string

	for _, p := range BuildkitePipelines {
		result := BuildkiteValidateResult{
			Name:     p.Name,
			YAMLFile: p.YAMLFile,
		}

		pl := p.Generator()
		compareResult, err := pipeline.SemanticCompareWithFile(pl, p.YAMLFile)
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
				p.Name, p.YAMLFile, strings.Join(compareResult.Differences, "\n")))
		} else {
			result.Valid = true
			fmt.Printf("  ✓ %s matches %s\n", p.Name, p.YAMLFile)
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
				Name:     p.Name,
				YAMLFile: p.YAMLFile,
			}

			pl := p.Generator()
			compareResult, err := pipeline.SemanticCompareWithFile(pl, p.YAMLFile)
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
				return result, fmt.Errorf("generated pipeline does not match %s", p.YAMLFile)
			}
			result.Valid = true
			return result, nil
		}
	}
	return nil, fmt.Errorf("pipeline %q not found", name)
}

// BuildkiteDiffResult contains the diff result for a single pipeline.
type BuildkiteDiffResult struct {
	Name     string
	YAMLFile string
	Equal    bool
	Diff     string
	Error    error
}

// BuildkiteDiff compares generated pipelines with existing YAML files.
// Returns the diff results for each pipeline.
func BuildkiteDiff() []BuildkiteDiffResult {
	fmt.Println(">> buildkite:diff - Comparing generated pipelines with YAML files...")

	var results []BuildkiteDiffResult
	anyDiff := false

	for _, p := range BuildkitePipelines {
		result := BuildkiteDiffResult{
			Name:     p.Name,
			YAMLFile: p.YAMLFile,
		}

		pl := p.Generator()
		compareResult, err := pipeline.CompareWithFile(pl, p.YAMLFile)
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
			fmt.Printf("\n--- %s (%s) ---\n", p.Name, p.YAMLFile)
			fmt.Println(compareResult.Diff)
		}
		results = append(results, result)
	}

	if !anyDiff {
		fmt.Println(">> buildkite:diff - No differences found!")
	}

	return results
}

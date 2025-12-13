// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipeline

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/buildkite/buildkite-sdk/sdk/go/sdk/buildkite"
)

// Pipeline wraps the buildkite.Pipeline with additional helper methods.
type Pipeline struct {
	*buildkite.Pipeline
}

// New creates a new pipeline.
func New() *Pipeline {
	return &Pipeline{
		Pipeline: buildkite.NewPipeline(),
	}
}

// Env adds an environment variable to the pipeline.
func (p *Pipeline) Env(key, value string) *Pipeline {
	p.AddEnvironmentVariable(key, value)
	return p
}

// EnvMap adds multiple environment variables to the pipeline.
func (p *Pipeline) EnvMap(env map[string]string) *Pipeline {
	for k, v := range env {
		p.AddEnvironmentVariable(k, v)
	}
	return p
}

// WithImageEnvVars adds all standard image environment variables to the pipeline.
func (p *Pipeline) WithImageEnvVars() *Pipeline {
	for k, v := range ImageEnvVars() {
		p.AddEnvironmentVariable(k, v)
	}
	return p
}

// Add adds a step to the pipeline. It accepts CommandStep, GroupStep, TriggerStep,
// InputStep, BlockStep, or WaitStep.
func (p *Pipeline) Add(step any) *Pipeline {
	switch s := step.(type) {
	case *buildkite.CommandStep:
		p.AddStep(s)
	case *buildkite.GroupStep:
		p.AddStep(s)
	case *buildkite.TriggerStep:
		p.AddStep(s)
	case *buildkite.InputStep:
		p.AddStep(s)
	case *buildkite.BlockStep:
		p.AddStep(s)
	case *buildkite.WaitStep:
		p.AddStep(s)
	default:
		panic(fmt.Sprintf("unsupported step type: %T", step))
	}
	return p
}

// Wait adds a wait step to the pipeline.
func (p *Pipeline) Wait() *Pipeline {
	p.AddStep(&buildkite.WaitStep{
		Wait: Ptr(""),
	})
	return p
}

// MarshalYAML marshals the pipeline to YAML bytes with the schema comment.
func (p *Pipeline) MarshalYAML() ([]byte, error) {
	yaml, err := p.ToYAML()
	if err != nil {
		return nil, fmt.Errorf("marshaling pipeline to YAML: %w", err)
	}

	var buf bytes.Buffer
	buf.WriteString("# yaml-language-server: $schema=https://raw.githubusercontent.com/buildkite/pipeline-schema/main/schema.json\n")
	buf.WriteString(yaml)

	return buf.Bytes(), nil
}

// WriteYAML writes the pipeline to a file.
func (p *Pipeline) WriteYAML(path string) error {
	data, err := p.MarshalYAML()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Ptr is a helper to convert a value to a pointer.
// This is useful when setting fields that require pointers.
func Ptr[T any](v T) *T {
	return &v
}

// CompareResult contains the result of comparing two pipelines.
type CompareResult struct {
	Equal      bool
	Diff       string
	Generated  string
	Expected   string
	ParseError error
}

// CompareWithFile compares a generated pipeline with an existing YAML file.
func CompareWithFile(p *Pipeline, path string) (*CompareResult, error) {
	generated, err := p.MarshalYAML()
	if err != nil {
		return nil, fmt.Errorf("marshaling generated pipeline: %w", err)
	}

	expected, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading expected file %s: %w", path, err)
	}

	return Compare(generated, expected)
}

// Compare compares two YAML representations of pipelines.
func Compare(generated, expected []byte) (*CompareResult, error) {
	result := &CompareResult{
		Generated: string(generated),
		Expected:  string(expected),
	}

	// Normalize both by trimming whitespace and comparing
	genNorm := strings.TrimSpace(string(generated))
	expNorm := strings.TrimSpace(string(expected))

	result.Equal = genNorm == expNorm

	if !result.Equal {
		result.Diff = computeDiff(genNorm, expNorm)
	}

	return result, nil
}

// computeDiff creates a simple line-by-line diff.
func computeDiff(generated, expected string) string {
	genLines := strings.Split(generated, "\n")
	expLines := strings.Split(expected, "\n")

	var diff strings.Builder
	diff.WriteString("--- expected\n+++ generated\n")

	maxLen := len(genLines)
	if len(expLines) > maxLen {
		maxLen = len(expLines)
	}

	for i := 0; i < maxLen; i++ {
		var genLine, expLine string
		if i < len(genLines) {
			genLine = genLines[i]
		}
		if i < len(expLines) {
			expLine = expLines[i]
		}

		if genLine != expLine {
			if expLine != "" {
				diff.WriteString(fmt.Sprintf("-%d: %s\n", i+1, expLine))
			}
			if genLine != "" {
				diff.WriteString(fmt.Sprintf("+%d: %s\n", i+1, genLine))
			}
		}
	}

	return diff.String()
}

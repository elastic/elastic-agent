// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipeline

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/buildkite/buildkite-sdk/sdk/go/sdk/buildkite"
	"gopkg.in/yaml.v3"
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

// SemanticCompareResult contains the result of semantic comparison.
type SemanticCompareResult struct {
	Equal       bool
	Differences []string
	ParseError  error
}

// SemanticCompareWithFile compares a generated pipeline with an existing YAML file semantically.
// This handles differences in comments, field ordering, and YAML anchor expansion.
func SemanticCompareWithFile(p *Pipeline, path string) (*SemanticCompareResult, error) {
	generated, err := p.MarshalYAML()
	if err != nil {
		return nil, fmt.Errorf("marshaling generated pipeline: %w", err)
	}

	expected, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading expected file %s: %w", path, err)
	}

	return SemanticCompare(generated, expected)
}

// SemanticCompare compares two YAML representations semantically by parsing them
// into maps and comparing the data structures. This ignores comments, field ordering,
// and handles YAML anchor expansion.
func SemanticCompare(generated, expected []byte) (*SemanticCompareResult, error) {
	result := &SemanticCompareResult{}

	var genData, expData map[string]any
	if err := yaml.Unmarshal(generated, &genData); err != nil {
		result.ParseError = fmt.Errorf("parsing generated YAML: %w", err)
		return result, nil
	}
	if err := yaml.Unmarshal(expected, &expData); err != nil {
		result.ParseError = fmt.Errorf("parsing expected YAML: %w", err)
		return result, nil
	}

	// Remove the 'common' key used for YAML anchors (not part of actual pipeline)
	delete(expData, "common")

	result.Differences = compareValues("", genData, expData)
	result.Equal = len(result.Differences) == 0

	return result, nil
}

// compareValues recursively compares two values and returns differences.
func compareValues(path string, generated, expected any) []string {
	var diffs []string

	if generated == nil && expected == nil {
		return nil
	}

	// Handle wait step equivalence: wait: ~ (null) == wait: "" (empty string)
	if path == "wait" || strings.HasSuffix(path, ".wait") {
		genStr, genIsStr := generated.(string)
		if expected == nil && genIsStr && genStr == "" {
			return nil
		}
		expStr, expIsStr := expected.(string)
		if generated == nil && expIsStr && expStr == "" {
			return nil
		}
	}

	if generated == nil {
		return []string{fmt.Sprintf("%s: missing in generated (expected: %v)", path, expected)}
	}
	if expected == nil {
		return []string{fmt.Sprintf("%s: extra in generated (value: %v)", path, generated)}
	}

	// Normalize types for comparison
	generated = normalizeValue(generated)
	expected = normalizeValue(expected)

	switch exp := expected.(type) {
	case map[string]any:
		gen, ok := generated.(map[string]any)
		if !ok {
			return []string{fmt.Sprintf("%s: type mismatch (generated: %T, expected: map)", path, generated)}
		}
		// Check all expected keys
		for k, v := range exp {
			newPath := k
			if path != "" {
				newPath = path + "." + k
			}
			diffs = append(diffs, compareValues(newPath, gen[k], v)...)
		}
		// Check for extra keys in generated
		for k, v := range gen {
			if _, exists := exp[k]; !exists {
				newPath := k
				if path != "" {
					newPath = path + "." + k
				}
				diffs = append(diffs, fmt.Sprintf("%s: extra in generated (value: %v)", newPath, v))
			}
		}

	case []any:
		gen, ok := generated.([]any)
		if !ok {
			return []string{fmt.Sprintf("%s: type mismatch (generated: %T, expected: array)", path, generated)}
		}
		if len(gen) != len(exp) {
			return []string{fmt.Sprintf("%s: array length mismatch (generated: %d, expected: %d)", path, len(gen), len(exp))}
		}
		for i := range exp {
			newPath := fmt.Sprintf("%s[%d]", path, i)
			diffs = append(diffs, compareValues(newPath, gen[i], exp[i])...)
		}

	default:
		if !reflect.DeepEqual(generated, expected) {
			return []string{fmt.Sprintf("%s: value mismatch (generated: %v, expected: %v)", path, generated, expected)}
		}
	}

	return diffs
}

// normalizeValue normalizes values for comparison (e.g., int to int64, trim trailing newlines).
func normalizeValue(v any) any {
	switch val := v.(type) {
	case string:
		// Normalize trailing newlines (YAML block scalars add trailing newline)
		trimmed := strings.TrimRight(val, "\n")
		// Normalize boolean strings to actual booleans
		if trimmed == "true" {
			return true
		}
		if trimmed == "false" {
			return false
		}
		return trimmed
	case int:
		return int64(val)
	case int32:
		return int64(val)
	case float64:
		// YAML often parses integers as float64
		if val == float64(int64(val)) {
			return int64(val)
		}
		return val
	case map[any]any:
		// Convert map[any]any to map[string]any
		result := make(map[string]any)
		for k, v := range val {
			result[fmt.Sprintf("%v", k)] = normalizeValue(v)
		}
		return result
	case map[string]any:
		result := make(map[string]any)
		for k, v := range val {
			result[k] = normalizeValue(v)
		}
		return result
	case []any:
		result := make([]any, len(val))
		for i, v := range val {
			result[i] = normalizeValue(v)
		}
		return result
	default:
		return v
	}
}

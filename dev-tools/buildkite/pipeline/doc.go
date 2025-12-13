// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package pipeline provides types and helpers for generating Buildkite pipeline
// YAML files programmatically using Go.
//
// This package wraps github.com/buildkite/buildkite-sdk with additional helpers
// specific to the Elastic Agent project, including predefined agent configurations,
// plugin helpers, and shared constants for VM images.
//
// # Basic Usage
//
//	step := pipeline.CommandWithKey("Unit tests", "unit-tests", ".buildkite/scripts/steps/unit-tests.sh")
//	pipeline.SetAgent(step, pipeline.GCPAgent(pipeline.ImageUbuntu2204X86, pipeline.MachineTypeN2Standard8))
//	pipeline.SetArtifactPaths(step, "build/TEST-*.xml")
//	pipeline.SetRetry(step, 1, true)
//
//	p := pipeline.New().
//		Env("VAULT_PATH", pipeline.VaultPathGCP).
//		Add(step)
//
//	yaml, err := p.MarshalYAML()
//
// # Agent Configuration
//
// The package provides helpers for common agent configurations:
//
//	// GCP agent
//	pipeline.GCPAgent(pipeline.ImageUbuntu2204X86, pipeline.MachineTypeN2Standard8)
//
//	// AWS agent
//	pipeline.AWSAgent(pipeline.ImageUbuntu2204ARM, pipeline.InstanceTypeM6gXLarge)
//
//	// Orka agent (macOS)
//	pipeline.OrkaAgent("generic-base-15-arm-002")
//
// # Plugin Configuration
//
// Common plugins are available as helper functions:
//
//	step := pipeline.Command("Build", "make build")
//	pipeline.WithVaultDockerLogin(step)
//	pipeline.AddPlugin(step, source, config)
//
// # Testing
//
// The package includes utilities for comparing generated YAML with existing files
// to ensure migration parity:
//
//	result, err := pipeline.CompareWithFile(p, ".buildkite/pipeline.yml")
//	if !result.Equal {
//		fmt.Println(result.Diff)
//	}
package pipeline

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestCoreComponentsInGoMod verifies that all components listed in components.yml
// are present in the project dependencies.
func TestCoreComponentsInGoMod(t *testing.T) {
	// Extract components from project dependencies
	moduleComponents, err := extractComponentsFromDeps()
	require.NoError(t, err, "Failed to extract components from dependencies")

	// Print found components for debugging
	t.Logf("Found components in dependencies: %v", moduleComponents)

	// Load components from components.yml
	yamlComponents, err := loadCoreComponentsYAML()
	require.NoError(t, err, "Failed to load components.yml")

	// Verify all components in YAML are present in dependencies
	for _, component := range yamlComponents {
		assert.Contains(t, moduleComponents, component)
	}
}

// GoListModule represents the relevant parts of the `go list -json` output
type GoListModule struct {
	Deps []string `json:"Deps"`
}

// extractComponentsFromDeps extracts component names from the project dependencies
// by running `go list -json` and parsing the output
func extractComponentsFromDeps() ([]string, error) {
	// Run go list -json to get the dependencies
	cmd := exec.Command("go", "list", "-json", "github.com/elastic/elastic-agent")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run go list command: %w", err)
	}

	// Parse the JSON output
	var module GoListModule
	if err := json.Unmarshal(output, &module); err != nil {
		return nil, fmt.Errorf("failed to parse go list output: %w", err)
	}

	// Component types to look for in dependency paths
	componentTypes := []string{
		"processor",
		"receiver",
		"extension",
		"exporter",
		"connector",
		"confmap/provider",
		"storage",
	}

	// Extract component names from dependency paths
	var components []string
	for _, dep := range module.Deps {
		for _, cType := range componentTypes {
			// Check if the dependency path contains the component type
			if strings.Contains(dep, "/"+cType+"/") {
				// Extract the component name (last part of the path)
				parts := strings.Split(dep, "/")
				if len(parts) > 0 {
					componentName := parts[len(parts)-1]
					components = append(components, componentName)
				}
			}
		}

		// Special case for filestorage which is under extension/storage/
		if strings.Contains(dep, "/extension/storage/") {
			parts := strings.Split(dep, "/")
			if len(parts) > 0 {
				componentName := parts[len(parts)-1]
				components = append(components, componentName)
			}
		}
	}

	return components, nil
}

// loadCoreComponentsYAML loads the components from components.yml
func loadCoreComponentsYAML() ([]string, error) {
	// Get the directory of the current file
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return nil, fmt.Errorf("failed to get current file path")
	}
	dir := filepath.Dir(filename)
	yamlPath := filepath.Join(dir, "components.yml")

	yamlFile, err := os.ReadFile(yamlPath)
	if err != nil {
		return nil, err
	}

	var data struct {
		Components []string `yaml:"core_components"`
	}

	err = yaml.Unmarshal(yamlFile, &data)
	if err != nil {
		return nil, err
	}

	// Filter out any empty strings or comments
	var filteredComponents []string
	for _, comp := range data.Components {
		comp = strings.TrimSpace(comp)
		if comp != "" && !strings.HasPrefix(comp, "#") {
			filteredComponents = append(filteredComponents, comp)
		}
	}

	return filteredComponents, nil
}

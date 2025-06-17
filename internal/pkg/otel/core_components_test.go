// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestCoreComponentsInGoMod verifies that all components listed in core-components.yaml
// are present in the go.mod file.
func TestCoreComponentsInGoMod(t *testing.T) {
	// Find the go.mod file (starting from the current directory and going up)
	goModPath, err := findGoModFile()
	if err != nil {
		t.Fatalf("Failed to find go.mod file: %v", err)
	}

	// Extract components from go.mod
	goModComponents, err := extractComponentsFromGoMod(goModPath)
	if err != nil {
		t.Fatalf("Failed to extract components from go.mod: %v", err)
	}

	// Print found components for debugging
	t.Logf("Found components in go.mod: %v", goModComponents)

	// Load components from core-components.yaml
	yamlComponents, err := loadCoreComponentsYAML()
	if err != nil {
		t.Fatalf("Failed to load core-components.yaml: %v", err)
	}

	// Verify all components in YAML are present in go.mod
	for _, component := range yamlComponents {
		assert.Contains(t, goModComponents, component)
	}
}

// findGoModFile locates the go.mod file by traversing up from the current directory
func findGoModFile() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return goModPath, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break // Reached the root directory
		}
		dir = parent
	}

	return "", fmt.Errorf("go.mod file not found in any parent directory")
}

// extractComponentsFromGoMod extracts component names from go.mod file
// by looking for paths containing /processor/, /receiver/, /extension/, /exporter/, /connector/, and /provider/
func extractComponentsFromGoMod(goModPath string) ([]string, error) {
	file, err := os.Open(goModPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var components []string
	// Match both standard paths and special cases like storage/filestorage
	componentRegex := regexp.MustCompile(`(?:github\.com/[^/]+/[^/]+/|go\.opentelemetry\.io/collector/)(?:processor|receiver|extension|exporter|connector|confmap/provider|storage)/([a-zA-Z0-9]+)`)

	// Special case for filestorage which is under extension/storage/
	storageRegex := regexp.MustCompile(`extension/storage/([a-zA-Z0-9]+)`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Match standard components
		matches := componentRegex.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				components = append(components, match[1])
			}
		}

		// Match special case for filestorage
		storageMatches := storageRegex.FindAllStringSubmatch(line, -1)
		for _, match := range storageMatches {
			if len(match) >= 2 {
				components = append(components, match[1])
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return components, nil
}

// loadCoreComponentsYAML loads the components from core-components.yaml
func loadCoreComponentsYAML() ([]string, error) {
	// Get the directory of the current file
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return nil, fmt.Errorf("failed to get current file path")
	}
	dir := filepath.Dir(filename)
	yamlPath := filepath.Join(dir, "core-components.yaml")

	yamlFile, err := os.ReadFile(yamlPath)
	if err != nil {
		return nil, err
	}

	var data struct {
		Components []string `yaml:"components"`
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

// contains checks if a string is present in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

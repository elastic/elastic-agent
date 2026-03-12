// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// UpdateVersion updates the version in version/version.go
func UpdateVersion(newVersion string) error {
	versionFile := "version/version.go"

	content, err := os.ReadFile(versionFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", versionFile, err)
	}

	// Replace the version string
	// Pattern: const defaultBeatVersion = "X.Y.Z"
	re := regexp.MustCompile(`(const\s+defaultBeatVersion\s*=\s*)"[^"]+"`)
	newContent := re.ReplaceAllString(string(content), `${1}"`+newVersion+`"`)

	if newContent == string(content) {
		return fmt.Errorf("version pattern not found in %s", versionFile)
	}

	err = os.WriteFile(versionFile, []byte(newContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", versionFile, err)
	}

	fmt.Printf("✓ Updated version to %s in %s\n", newVersion, versionFile)
	return nil
}

// UpdateDocs updates version references in documentation and K8s manifests
func UpdateDocs(newVersion string) error {
	// Update K8s manifests
	k8sFiles := []string{
		"deploy/kubernetes/elastic-agent-managed-kubernetes.yaml",
		"deploy/kubernetes/elastic-agent-standalone-kubernetes.yaml",
	}

	for _, file := range k8sFiles {
		if err := updateVersionInFile(file, newVersion); err != nil {
			return err
		}
	}

	return nil
}

// updateVersionInFile updates version references in a file
func updateVersionInFile(filePath, newVersion string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", filePath, err)
	}

	// Pattern: docker.elastic.co/elastic-agent/elastic-agent:X.Y.Z
	re := regexp.MustCompile(`(docker\.elastic\.co/elastic-agent/elastic-agent:)[0-9]+\.[0-9]+\.[0-9]+`)
	newContent := re.ReplaceAllString(string(content), `${1}`+newVersion)

	if newContent == string(content) {
		// No changes needed
		fmt.Printf("  No version changes needed in %s\n", filePath)
		return nil
	}

	err = os.WriteFile(filePath, []byte(newContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", filePath, err)
	}

	fmt.Printf("✓ Updated version to %s in %s\n", newVersion, filePath)
	return nil
}

// UpdateMergify adds a new backport rule to .mergify.yml
func UpdateMergify(version string) error {
	mergifyFile := ".mergify.yml"

	// Read the YAML file
	content, err := os.ReadFile(mergifyFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", mergifyFile, err)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("failed to parse %s: %w", mergifyFile, err)
	}

	// Extract major.minor from version (e.g., "9.4.0" -> "9.4")
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid version format: %s (expected X.Y.Z)", version)
	}
	branchVersion := fmt.Sprintf("%s.%s", parts[0], parts[1])

	// Get pull_request_rules array
	rules, ok := config["pull_request_rules"].([]interface{})
	if !ok {
		return fmt.Errorf("pull_request_rules not found or invalid format")
	}

	// Check if rule already exists
	label := fmt.Sprintf("backport-%s", branchVersion)
	for _, rule := range rules {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}
		name, ok := ruleMap["name"].(string)
		if ok && strings.Contains(name, branchVersion) {
			fmt.Printf("  Backport rule for %s already exists\n", branchVersion)
			return nil
		}
	}

	// Create new backport rule
	newRule := map[string]interface{}{
		"name": fmt.Sprintf("backport patches to %s branch", branchVersion),
		"conditions": []interface{}{
			"merged",
			fmt.Sprintf("label=%s", label),
		},
		"actions": map[string]interface{}{
			"backport": map[string]interface{}{
				"branches": []interface{}{branchVersion},
			},
		},
	}

	// Add the new rule to the end of pull_request_rules
	rules = append(rules, newRule)
	config["pull_request_rules"] = rules

	// Marshal back to YAML
	output, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	// Write back to file
	err = os.WriteFile(mergifyFile, output, 0644)
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", mergifyFile, err)
	}

	fmt.Printf("✓ Added backport rule for %s to %s\n", branchVersion, mergifyFile)
	return nil
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// UpdateMergify adds a new backport rule to .mergify.yml.
func UpdateMergify(version string) error {
	mergifyFile := ".mergify.yml"

	content, err := os.ReadFile(mergifyFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", mergifyFile, err)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("failed to parse %s: %w", mergifyFile, err)
	}

	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid version format: %s (expected X.Y.Z)", version)
	}
	branchVersion := fmt.Sprintf("%s.%s", parts[0], parts[1])

	rules, ok := config["pull_request_rules"].([]interface{})
	if !ok {
		return fmt.Errorf("pull_request_rules not found or invalid format")
	}

	label := fmt.Sprintf("backport-%s", branchVersion)
	for _, rule := range rules {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}
		name, ok := ruleMap["name"].(string)
		if ok && strings.Contains(name, branchVersion) {
			fmt.Printf("Backport rule for %s already exists\n", branchVersion)
			return nil
		}
	}

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

	rules = append(rules, newRule)
	config["pull_request_rules"] = rules

	output, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	err = writeRepoFile(mergifyFile, output)
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", mergifyFile, err)
	}

	fmt.Printf("Added backport rule for %s to %s\n", branchVersion, mergifyFile)
	return nil
}

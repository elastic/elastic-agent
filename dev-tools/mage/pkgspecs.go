// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// --- Packaging spec loading ---

const packageSpecFile = "dev-tools/packaging/packages.yml"

// LoadElasticAgentCorePackageSpec loads and returns the elastic_agent_core
// package spec from packages.yml under beatsDir.
func LoadElasticAgentCorePackageSpec(beatsDir string) ([]OSPackageArgs, error) {
	return loadPackageSpec(beatsDir, "elastic_agent_core")
}

// LoadElasticAgentPackageSpec loads and returns the elastic_agent_packaging
// package spec from packages.yml under beatsDir.
func LoadElasticAgentPackageSpec(beatsDir string) ([]OSPackageArgs, error) {
	return loadPackageSpec(beatsDir, "elastic_agent_packaging")
}

// loadPackageSpec loads the named spec from packages.yml under beatsDir.
func loadPackageSpec(beatsDir, specName string) ([]OSPackageArgs, error) {
	pkgSpecFile := filepath.Join(beatsDir, packageSpecFile)
	packageSpecs, err := LoadSpecs(pkgSpecFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load package specs: %w", err)
	}

	spec, ok := packageSpecs[specName]
	if !ok {
		return nil, fmt.Errorf("%v not found in package specs", specName)
	}
	return spec, nil
}

// LoadSpecs loads the packaging specifications from the specified YAML files.
func LoadSpecs(files ...string) (map[string][]OSPackageArgs, error) {
	var data [][]byte
	for _, file := range files {
		d, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read from spec file: %w", err)
		}
		data = append(data, d)
	}

	// Parse into yaml.Node first to allow custom extra_vars deep-merge.
	var root yaml.Node
	if err := yaml.Unmarshal(bytes.Join(data, []byte{'\n'}), &root); err != nil {
		return nil, fmt.Errorf("failed to parse spec YAML: %w", err)
	}

	// yaml.v3 performs a shallow merge for <<: keys: when multiple anchors each
	// define extra_vars, only the first anchor's extra_vars map survives. packages.yml
	// relies on yaml.v2's deep-merge behavior, where individual sub-keys from multiple
	// anchors are combined. We replicate that here by walking the node tree and
	// prepending a fully-merged extra_vars node before decoding.
	fixExtraVarsMerge(&root, make(map[*yaml.Node]bool))

	type PackageYAML struct {
		Specs map[string][]OSPackageArgs `yaml:"specs"`
	}

	var packages PackageYAML
	if err := root.Decode(&packages); err != nil {
		return nil, fmt.Errorf("failed to unmarshal spec data: %w", err)
	}

	// verify that the package specification sets the docker variant
	for specName, specs := range packages.Specs {
		for _, spec := range specs {
			for _, pkgType := range spec.Types {
				if pkgType == Docker && spec.Spec.DockerVariant == Undefined {
					return nil, fmt.Errorf("%s defined a package spec for docker without a docker_variant set", specName)
				}
			}
		}
	}

	return packages.Specs, nil
}

// fixExtraVarsMerge walks the YAML node tree and, for each mapping node that has
// merge keys (<<:), collects extra_vars sub-keys from all merge sources and
// prepends a unified extra_vars node. The prepended node takes priority during
// Decode, emulating yaml.v2's deep-merge behavior for the extra_vars map.
func fixExtraVarsMerge(node *yaml.Node, visited map[*yaml.Node]bool) {
	if node == nil || visited[node] {
		return
	}
	visited[node] = true

	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			fixExtraVarsMerge(child, visited)
		}
	case yaml.AliasNode:
		fixExtraVarsMerge(node.Alias, visited)
	case yaml.MappingNode:
		// Recurse into children first so nested merge keys are resolved before
		// we collect extra_vars from anchor references.
		for _, child := range node.Content {
			fixExtraVarsMerge(child, visited)
		}

		// Only act on mappings that have at least one merge key.
		hasMerge := false
		for i := 0; i < len(node.Content)-1; i += 2 {
			if node.Content[i].Tag == "!!merge" {
				hasMerge = true
				break
			}
		}
		if !hasMerge {
			return
		}

		merged := collectAllExtraVars(node)
		if len(merged) == 0 {
			return
		}

		// Build a sorted yaml.Node for the merged extra_vars map.
		keys := make([]string, 0, len(merged))
		for k := range merged {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		valNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for _, k := range keys {
			valNode.Content = append(valNode.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: merged[k]},
			)
		}

		// If the node already has an explicit extra_vars key, replace its value with
		// the merged result to avoid duplicate key errors in yaml.v3.
		// Otherwise prepend a new key so it takes priority over merge-key values.
		existingIdx := -1
		for i := 0; i < len(node.Content)-1; i += 2 {
			if node.Content[i].Value == "extra_vars" && node.Content[i].Tag != "!!merge" {
				existingIdx = i
				break
			}
		}
		if existingIdx >= 0 {
			node.Content[existingIdx+1] = valNode
		} else {
			keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "extra_vars"}
			node.Content = append([]*yaml.Node{keyNode, valNode}, node.Content...)
		}
	}
}

// collectAllExtraVars collects extra_vars sub-keys from a mapping node and all
// its merge sources. Among merge sources, "first anchor wins" semantics apply.
// The node's own inline extra_vars (if any) take the highest priority.
func collectAllExtraVars(node *yaml.Node) map[string]string {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode {
		return collectAllExtraVars(node.Alias)
	}
	if node.Kind != yaml.MappingNode {
		return nil
	}

	merged := make(map[string]string)
	var own map[string]string

	for i := 0; i < len(node.Content)-1; i += 2 {
		keyNode := node.Content[i]
		valNode := node.Content[i+1]

		switch {
		case keyNode.Value == "extra_vars" && keyNode.Tag != "!!merge":
			own = extraVarsFromNode(valNode)
		case keyNode.Tag == "!!merge":
			var sources []*yaml.Node
			switch valNode.Kind {
			case yaml.AliasNode:
				sources = []*yaml.Node{valNode.Alias}
			case yaml.SequenceNode:
				for _, item := range valNode.Content {
					if item.Kind == yaml.AliasNode {
						sources = append(sources, item.Alias)
					}
				}
			}
			for _, src := range sources {
				for k, v := range collectAllExtraVars(src) {
					if _, exists := merged[k]; !exists {
						merged[k] = v
					}
				}
			}
		}
	}

	for k, v := range own {
		merged[k] = v
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

// extraVarsFromNode decodes a yaml.MappingNode into a map[string]string.
func extraVarsFromNode(node *yaml.Node) map[string]string {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode {
		return extraVarsFromNode(node.Alias)
	}
	if node.Kind != yaml.MappingNode {
		return nil
	}
	result := make(map[string]string)
	for i := 0; i < len(node.Content)-1; i += 2 {
		result[node.Content[i].Value] = node.Content[i+1].Value
	}
	return result
}

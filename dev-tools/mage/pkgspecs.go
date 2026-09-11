// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

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

	// Parse into yaml.Node first to allow custom deep-merge.
	var root yaml.Node
	if err := yaml.Unmarshal(bytes.Join(data, []byte{'\n'}), &root); err != nil {
		return nil, fmt.Errorf("failed to parse spec YAML: %w", err)
	}

	// yaml.v3 performs a shallow merge for <<: keys: when multiple anchors each
	// define the same map-typed key (e.g. extra_vars or files), only the first
	// anchor's value survives. packages.yml relies on yaml.v2's deep-merge
	// behavior, where sub-keys from multiple anchors are combined. We replicate
	// that here by walking the node tree and, for every mapping-valued key that
	// appears across multiple merge sources, prepending (or replacing) a fully-
	// merged version so yaml.v3's decode sees the complete merged map.
	fixDeepMerge(&root, make(map[*yaml.Node]bool))

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

// fixDeepMerge walks the YAML node tree and, for each mapping node that has
// merge keys (<<:), deep-merges any mapping-valued keys (e.g. extra_vars,
// files) across all merge sources. This replicates yaml.v2's behavior where
// map sub-keys from multiple anchors are combined, rather than yaml.v3's
// shallow "first anchor wins" merge.
func fixDeepMerge(node *yaml.Node, visited map[*yaml.Node]bool) {
	if node == nil || visited[node] {
		return
	}
	visited[node] = true

	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			fixDeepMerge(child, visited)
		}
	case yaml.AliasNode:
		fixDeepMerge(node.Alias, visited)
	case yaml.MappingNode:
		// Recurse into children first so nested merge keys are resolved before
		// we collect values from anchor references.
		for _, child := range node.Content {
			fixDeepMerge(child, visited)
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

		// Collect, for each key that has a mapping-valued result across all
		// merge sources, the combined sub-keys (first-occurrence wins).
		mergedMaps := collectMergedMappingKeys(node)
		for key, mergedVal := range mergedMaps {
			// Find the existing explicit value for this key in the node (if any).
			existingIdx := -1
			for i := 0; i < len(node.Content)-1; i += 2 {
				if node.Content[i].Value == key && node.Content[i].Tag != "!!merge" {
					existingIdx = i
					break
				}
			}
			if existingIdx >= 0 {
				// Replace existing value with the deep-merged one.
				node.Content[existingIdx+1] = mergedVal
			} else {
				// Prepend a new key-value pair so it takes priority over
				// merge-key values during yaml.v3 Decode.
				keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
				node.Content = append([]*yaml.Node{keyNode, mergedVal}, node.Content...)
			}
		}
	}
}

// collectMergedMappingKeys returns, for each key that has a mapping-typed value
// in the given node or in any of its merge sources, a yaml.MappingNode whose
// content is the union of all sub-keys from all sources (first occurrence wins
// per sub-key). Only keys whose values are mapping nodes are returned; scalar
// and sequence values are handled correctly by yaml.v3's native first-wins rule.
//
// The returned map only contains keys where the merged result has more sub-keys
// than the node's own explicit value (i.e. where extra sub-keys come from merge
// sources). Keys where the node already has a complete value are excluded.
func collectMergedMappingKeys(node *yaml.Node) map[string]*yaml.Node {
	// result maps a key name to its merged MappingNode.
	result := make(map[string]*yaml.Node)
	// seenSubKeys tracks which sub-keys have been added for each outer key.
	seenSubKeys := make(map[string]map[string]bool)

	// collectExplicit collects mapping-valued keys from src's own explicit
	// (non-merge) entries only. visitMerges handles merge key recursion.
	collectExplicit := func(src *yaml.Node) {
		if src == nil || src.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i < len(src.Content)-1; i += 2 {
			keyNode := src.Content[i]
			valNode := src.Content[i+1]
			if keyNode.Tag == "!!merge" {
				continue
			}
			if valNode.Kind != yaml.MappingNode {
				continue
			}
			resolvedVal := valNode
			if resolvedVal.Kind == yaml.AliasNode {
				resolvedVal = resolvedVal.Alias
			}
			if resolvedVal.Kind != yaml.MappingNode {
				continue
			}
			k := keyNode.Value
			if _, exists := result[k]; !exists {
				result[k] = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
				seenSubKeys[k] = make(map[string]bool)
			}
			for j := 0; j < len(resolvedVal.Content)-1; j += 2 {
				sk := resolvedVal.Content[j].Value
				if !seenSubKeys[k][sk] {
					seenSubKeys[k][sk] = true
					result[k].Content = append(result[k].Content,
						resolvedVal.Content[j],
						resolvedVal.Content[j+1],
					)
				}
			}
		}
	}

	// visit processes a merge-source mapping node and all of its nested merge
	// sources, collecting mapping-valued keys (first occurrence wins).
	var visit func(src *yaml.Node, offset int)
	visit = func(src *yaml.Node, offset int) {
		if src == nil {
			return
		}
		if src.Kind == yaml.AliasNode {
			visit(src.Alias, offset)
			return
		}
		if src.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i < len(src.Content)-1; i += 2 {
			keyNode := src.Content[i]
			valNode := src.Content[i+1]

			if keyNode.Tag == "!!merge" {
				// Recurse into merge key sources.
				switch valNode.Kind {
				case yaml.AliasNode:
					visit(valNode.Alias, offset+1)
				case yaml.SequenceNode:
					for idx, item := range valNode.Content {
						if item.Kind == yaml.AliasNode {
							visit(item.Alias, offset+idx+1)
						}
					}
				}
				continue
			}

			if valNode.Kind != yaml.MappingNode {
				continue // scalar and sequence keys: native yaml.v3 behavior is correct
			}

			// Resolve alias values.
			resolvedVal := valNode
			if resolvedVal.Kind == yaml.AliasNode {
				resolvedVal = resolvedVal.Alias
			}
			if resolvedVal.Kind != yaml.MappingNode {
				continue
			}

			k := keyNode.Value
			if _, exists := result[k]; !exists {
				result[k] = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
				seenSubKeys[k] = make(map[string]bool)
			}
			// Merge sub-keys from this source; first occurrence wins.
			for j := 0; j < len(resolvedVal.Content)-1; j += 2 {
				sk := resolvedVal.Content[j].Value
				if !seenSubKeys[k][sk] {
					seenSubKeys[k][sk] = true
					result[k].Content = append(result[k].Content,
						resolvedVal.Content[j],
						resolvedVal.Content[j+1],
					)
				}
			}
		}
	}

	// Process node's own explicit keys first so they take priority over merge
	// sources — mirrors yaml.v2's behavior where explicit keys always win.
	collectExplicit(node)
	// Then visit merge sources to collect additional sub-keys.
	for i := 0; i < len(node.Content)-1; i += 2 {
		keyNode := node.Content[i]
		valNode := node.Content[i+1]
		if keyNode.Tag != "!!merge" {
			continue
		}
		switch valNode.Kind {
		case yaml.AliasNode:
			visit(valNode.Alias, 1)
		case yaml.SequenceNode:
			for idx, item := range valNode.Content {
				if item.Kind == yaml.AliasNode {
					visit(item.Alias, idx+1)
				}
			}
		}
	}

	// Drop entries where the merge produced no more sub-keys than what the
	// node already has explicitly — no fix needed in those cases.
	for k, mergedVal := range result {
		if len(mergedVal.Content) == 0 {
			delete(result, k)
			continue
		}
		ownLen := 0
		for i := 0; i < len(node.Content)-1; i += 2 {
			if node.Content[i].Value == k && node.Content[i].Tag != "!!merge" {
				ownLen = len(node.Content[i+1].Content)
				break
			}
		}
		if len(mergedVal.Content) <= ownLen {
			delete(result, k)
		}
	}

	return result
}

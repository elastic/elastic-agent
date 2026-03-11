// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

// --- Packaging spec loading ---

const packageSpecFile = "dev-tools/packaging/packages.yml"

// LoadElasticAgentCorePackageSpec loads and returns the elastic_agent_core
// package spec from packages.yml under beatsDir.
func LoadElasticAgentCorePackageSpec(beatsDir string) ([]OSPackageArgs, error) {
	return loadPackageSpec(beatsDir, "elastic_agent_core")
}

// LoadElasticAgentPackageSpec loads and returns the elastic_beat_agent_binaries
// package spec from packages.yml under beatsDir.
func LoadElasticAgentPackageSpec(beatsDir string) ([]OSPackageArgs, error) {
	return loadPackageSpec(beatsDir, "elastic_beat_agent_binaries")
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

	type PackageYAML struct {
		Specs map[string][]OSPackageArgs `yaml:"specs"`
	}

	var packages PackageYAML
	if err := yaml.Unmarshal(bytes.Join(data, []byte{'\n'}), &packages); err != nil {
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

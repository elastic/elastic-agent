// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

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

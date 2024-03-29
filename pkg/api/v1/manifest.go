// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package v1

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v2"
)

const ManifestKind = "PackageManifest"
const ManifestFileName = "manifest.yaml"

type PackageDesc struct {
	Version       string              `yaml:"version" json:"version"`
	Snapshot      bool                `yaml:"snapshot" json:"snapshot"`
	Hash          string              `yaml:"hash" json:"hash"`
	VersionedHome string              `yaml:"versioned-home" json:"versionedHome"`
	PathMappings  []map[string]string `yaml:"path-mappings" json:"pathMappings"`
}

type PackageManifest struct {
	apiObject `yaml:",inline"`
	Package   PackageDesc `yaml:"package" json:"package"`
}

func NewManifest() *PackageManifest {
	return &PackageManifest{
		apiObject: apiObject{
			Version: VERSION,
			Kind:    ManifestKind,
		},
	}
}

func ParseManifest(r io.Reader) (*PackageManifest, error) {
	m := new(PackageManifest)
	err := yaml.NewDecoder(r).Decode(m)
	if err != nil {
		return nil, fmt.Errorf("decoding package manifest: %w", err)
	}

	return m, nil
}

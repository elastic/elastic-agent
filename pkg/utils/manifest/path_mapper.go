// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manifest

import (
	"path"
	"strings"
)

// PathMapper is a utility object that will help with File mappings specified in a v1/Manifest
type PathMapper struct {
	mappings []map[string]string
}

func (pm PathMapper) Map(packagePath string) string {
	for _, mapping := range pm.mappings {
		for pkgPath, mappedPath := range mapping {
			if strings.HasPrefix(packagePath, pkgPath) {
				return path.Join(mappedPath, packagePath[len(pkgPath):])
			}
		}
	}
	return packagePath
}

func NewPathMapper(mappings []map[string]string) *PathMapper {
	return &PathMapper{mappings}
}

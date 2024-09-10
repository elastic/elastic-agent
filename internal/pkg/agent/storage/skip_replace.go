// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package storage

import (
	"strings"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
)

// This is a temporary solution to avoid replacing the target file if the content of the replacement is contained in the target file.
// It only works for YAML files, since the only use case is for the default agent fleet config.
// Returns true only if the replacement configuration is already contained in the original.
func shouldSkipReplace(original []byte, replacement []byte) bool {
	replacementYaml := map[string]interface{}{}
	originalYaml := map[string]interface{}{}

	err := yaml.Unmarshal(replacement, &replacementYaml)
	if err != nil {
		return false
	}

	err = yaml.Unmarshal(original, &originalYaml)
	if err != nil {
		return false
	}

	diff := cmp.Diff(replacementYaml, originalYaml)
	if strings.HasPrefix(diff, "-") || strings.Contains(diff, "\n-") {
		// Lines starting with - represent values in the replacement that are not present in the original
		return false
	}

	return true
}

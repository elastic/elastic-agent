// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dir

import (
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

// DiscoverFiles takes a slices of wildcards patterns and try to discover all the matching files
// recursively and will stop on any errors.
func DiscoverFiles(patterns ...string) ([]string, error) {
	files := make([]string, 0)
	for _, pattern := range patterns {
		f, err := filepath.Glob(pattern)
		if err != nil {
			return files, errors.New(err,
				"error while reading the glob pattern",
				errors.TypeFilesystem,
				errors.M(errors.MetaKeyPath, pattern))
		}

		if len(f) > 0 {
			files = append(files, f...)
		}
	}

	return files, nil
}

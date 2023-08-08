// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"errors"

	"github.com/elastic/elastic-agent/internal/pkg/dir"
)

// ErrNoConfiguration is returned when no configuration are found.
var ErrNoConfiguration = errors.New("no configuration found")

// DiscoverFunc is a function that discovers a list of files to load.
type DiscoverFunc func() ([]string, error)

// Discoverer returns a DiscoverFunc that discovers all files that match the given patterns.
func Discoverer(patterns ...string) DiscoverFunc {
	p := make([]string, 0, len(patterns))
	for _, newP := range patterns {
		if len(newP) == 0 {
			continue
		}

		p = append(p, newP)
	}

	if len(p) == 0 {
		return func() ([]string, error) {
			return []string{}, ErrNoConfiguration
		}
	}

	return func() ([]string, error) {
		return dir.DiscoverFiles(p...)
	}
}

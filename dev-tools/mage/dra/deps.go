// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dra

import (
	"fmt"
	"maps"
	"slices"

	"github.com/elastic/elastic-agent/dev-tools/packaging"
)

// Dependencies returns the DRA projects elastic-agent-package consumes, sorted
// and de-duplicated.
//
// The list is derived from dev-tools/packaging/packages.yml rather than kept in
// a second file next to the pipeline: packages.yml is what the packaging code
// itself reads to decide which archives to pull out of MANIFEST_URL, so any
// other list can only ever drift from it. Adding a component to packages.yml is
// enough to make the poller watch its product.
//
// Note that this is deliberately *not* the same as "every product whose source
// ends up in the package". agentbeat is compiled from the beats submodule of
// this checkout, so the beats DRA build is not an input here; a beats bump
// reaches elastic-agent-package as a new elastic-agent-core build instead.
func Dependencies() ([]string, error) {
	components, err := packaging.Components()
	if err != nil {
		return nil, fmt.Errorf("loading packaging components: %w", err)
	}

	projects := map[string]struct{}{}
	for _, component := range components {
		if component.ProjectName == "" {
			continue
		}
		projects[component.ProjectName] = struct{}{}
	}

	if len(projects) == 0 {
		return nil, fmt.Errorf("no component in packages.yml declares a projectName")
	}

	return slices.Sorted(maps.Keys(projects)), nil
}

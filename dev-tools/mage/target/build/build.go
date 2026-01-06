// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package build

import (
	"context"

	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
)

// Build builds the Beat binary.
func Build(ctx context.Context) error {
	cfg := devtools.ConfigFromContext(ctx)
	return devtools.BuildWithConfig(cfg, devtools.DefaultBuildArgsWithConfig(cfg))
}

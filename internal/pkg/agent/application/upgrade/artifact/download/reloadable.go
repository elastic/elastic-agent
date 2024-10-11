// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package download

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
)

// Reloader is an interface allowing to reload artifact config
type Reloader interface {
	Reload(*artifact.Config) error
}

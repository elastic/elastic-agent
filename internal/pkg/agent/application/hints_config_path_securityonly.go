// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build securityonly

package application

import (
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// hintsInputConfigPath returns an empty string in the security-only variant; Kubernetes
// hints-based config discovery is not available in this build.
func hintsInputConfigPath(_ *logger.Logger, _ map[string]interface{}) string {
	return ""
}

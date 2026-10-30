// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import "github.com/elastic/elastic-agent/internal/pkg/browserca"

// SyntheticsConfig configures the Synthetics monitors the agent runs.
type SyntheticsConfig struct {
	// Browser configures the browser of browser monitors: the CAs it trusts.
	Browser browserca.Config `yaml:"browser,omitempty" config:"browser,omitempty" json:"browser,omitempty"`
}

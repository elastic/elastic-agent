// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package common

import "github.com/elastic/elastic-agent/pkg/testing/define"

// SupportedOS maps a OS definition to a OSRunner.
type SupportedOS struct {
	define.OS

	// Runner is the runner to use for the OS.
	Runner OSRunner
}

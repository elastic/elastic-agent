// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !linux

package cmd

import (
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

func initContainer(streams *cli.IOStreams, skipFileCapabilities bool) (shouldExit bool, err error) {
	return false, nil
}

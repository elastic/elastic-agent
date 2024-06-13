// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !linux

package cmd

import (
	"os/exec"

	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

func initContainer(_ *cli.IOStreams) (cmd *exec.Cmd, err error) {
	return nil, nil
}

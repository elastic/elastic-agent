// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package gotool

import (
	"fmt"

	"github.com/magefile/mage/sh"
)

type goLinkCheck func(opts ...ArgOpt) error

// LinkCheck runs a tool to verify that links in a file are live.
var LinkCheck goLinkCheck = runGoLinkCheck

func runGoLinkCheck(opts ...ArgOpt) error {
	args := buildArgs(opts).build()
	output, err := sh.Output("link-patrol", args...)
	if err != nil {
		fmt.Println(output)
		return err
	}

	return nil
}

func (goLinkCheck) Path(path string) ArgOpt { return flagArgIf("-f", path) }

func (goLinkCheck) MaxRetries(retries uint) ArgOpt {
	return flagArgIf("--max-retries", fmt.Sprintf("%d", retries))
}

func (goLinkCheck) MaxBackoff(seconds uint) ArgOpt {
	return flagArgIf("--max-backoff", fmt.Sprintf("%ds", seconds))
}

func (goLinkCheck) StartBackoff(seconds uint) ArgOpt {
	return flagArgIf("--start-backoff", fmt.Sprintf("%ds", seconds))
}

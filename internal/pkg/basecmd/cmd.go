// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package basecmd

import (
	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/basecmd/restart"
	"github.com/elastic/elastic-agent/internal/pkg/basecmd/version"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

// NewDefaultCommandsWithArgs returns a list of default commands to executes.
func NewDefaultCommandsWithArgs(args []string, streams *cli.IOStreams) []*cobra.Command {
	return []*cobra.Command{
		restart.NewCommandWithArgs(streams),
		version.NewCommandWithArgs(streams),
	}
}

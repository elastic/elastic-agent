// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package restart

import (
	"context"

	"github.com/elastic/elastic-agent/pkg/control"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

// NewCommandWithArgs returns a new version command.
func NewCommandWithArgs(streams *cli.IOStreams) *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "Restart the currently running Elastic Agent daemon",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c := client.New()
			err := c.Connect(context.Background())
			if err != nil {
				return errors.New(err, "Failed communicating to running daemon", errors.TypeNetwork, errors.M("socket", control.Address()))
			}
			defer c.Disconnect()
			err = c.Restart(context.Background())
			if err != nil {
				return errors.New(err, "Failed trigger restart of daemon")
			}
			return nil
		},
	}
}

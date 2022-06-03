// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"fmt"
	"io/ioutil"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/pkg/component"

	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

func newComponentSpecCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "spec [file]",
		Short: "Validates a component specification",
		Long:  "Validates a component specification that instructs the Elastic Agent how it should be ran.",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			data, err := ioutil.ReadFile(args[0])
			if err != nil {
				return err
			}
			_, err = component.LoadSpec(data)
			if err != nil {
				return err
			}
			fmt.Fprintln(streams.Out, "Component specification is valid")
			return nil
		},
	}

	return cmd
}

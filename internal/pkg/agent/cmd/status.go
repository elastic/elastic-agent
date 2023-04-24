// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"

	"gopkg.in/yaml.v2"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

type outputter func(io.Writer, interface{}) error

var statusOutputs = map[string]outputter{
	"human": humanStateOutput,
	"json":  jsonOutput,
	"yaml":  yamlOutput,
}

func newStatusCommand(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the current status of the running Elastic Agent daemon",
		Long:  `This command shows the current status of the running Elastic Agent daemon.`,
		Run: func(c *cobra.Command, args []string) {
			if err := statusCmd(streams, c, args); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
		},
	}

	cmd.Flags().String("output", "human", "Output the status information in either human, json, or yaml (default: human)")

	return cmd
}

func statusCmd(streams *cli.IOStreams, cmd *cobra.Command, args []string) error {
	output, _ := cmd.Flags().GetString("output")
	outputFunc, ok := statusOutputs[output]
	if !ok {
		return fmt.Errorf("unsupported output: %s", output)
	}

	ctx := handleSignal(context.Background())
	innerCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	state, err := getDaemonState(innerCtx)
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("timed out after 30 seconds trying to connect to Elastic Agent daemon")
	} else if errors.Is(err, context.Canceled) {
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to communicate with Elastic Agent daemon: %w", err)
	}

	err = outputFunc(streams.Out, state)
	if err != nil {
		return err
	}
	// exit 0 only if the Elastic Agent daemon is healthy
	if state.State == client.Healthy {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
	return nil
}

func humanStateOutput(w io.Writer, obj interface{}) error {
	status, ok := obj.(*client.AgentState)
	if !ok {
		return fmt.Errorf("unable to cast %T as *client.AgentStatus", obj)
	}
	return outputState(w, status)
}

func outputState(w io.Writer, state *client.AgentState) error {
	fmt.Fprintf(w, "State: %s\n", state.State)
	if state.Message == "" {
		fmt.Fprint(w, "Message: (no message)\n")
	} else {
		fmt.Fprintf(w, "Message: %s\n", state.Message)
	}
	fmt.Fprintf(w, "Fleet State: %s\n", state.FleetState)
	if state.FleetMessage == "" {
		fmt.Fprint(w, "Fleet Message: (no message)\n")
	} else {
		fmt.Fprintf(w, "Fleet Message: %s\n", state.FleetMessage)
	}
	if len(state.Components) == 0 {
		fmt.Fprint(w, "Components: (none)\n")
	} else {
		fmt.Fprint(w, "Components:\n")
		tw := tabwriter.NewWriter(w, 4, 1, 2, ' ', 0)
		for _, comp := range state.Components {
			fmt.Fprintf(tw, "  * %s\t(%s)\n", comp.Name, comp.State)
			if comp.Message == "" {
				fmt.Fprint(tw, "\t(no message)\n")
			} else {
				fmt.Fprintf(tw, "\t%s\n", comp.Message)
			}
		}
		tw.Flush()
	}
	return nil
}

func jsonOutput(w io.Writer, out interface{}) error {
	bytes, err := json.MarshalIndent(out, "", "    ")
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "%s\n", bytes)
	return nil
}

func yamlOutput(w io.Writer, out interface{}) error {
	bytes, err := yaml.Marshal(out)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "%s\n", bytes)
	return nil
}

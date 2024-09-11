// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/control"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"

	"gopkg.in/yaml.v2"

	"github.com/spf13/cobra"

	"github.com/jedib0t/go-pretty/v6/list"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

type outputter func(io.Writer, interface{}) error

var statusOutputs = map[string]outputter{
	"human": humanOutput,
	"full":  humanFullOutput,
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

	cmd.Flags().String("output", "human", "Output the status information in either 'human', 'full', 'json', or 'yaml'.  'human' only shows non-healthy details, others show full details. (default: human)")

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

	sort.SliceStable(state.Components, func(i, j int) bool { return state.Components[i].ID < state.Components[j].ID })
	for _, c := range state.Components {
		sort.SliceStable(c.Units, func(i, j int) bool { return c.Units[i].UnitID < c.Units[j].UnitID })
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

func formatStatus(state client.State, message string) string {
	return fmt.Sprintf("status: (%s) %s", state, message)
}

func listComponentState(l list.Writer, components []client.ComponentState, all bool) {
	for _, c := range components {
		// see if any unit is not Healthy because component
		// can be healthy with failed units
		units_healthy := true
		for _, u := range c.Units {
			if u.State != client.Healthy {
				units_healthy = false
				break
			}
		}
		if !all && units_healthy && (c.State == client.Healthy) {
			continue
		}
		l.Indent()
		l.AppendItem(c.ID)
		l.Indent()
		l.AppendItem(formatStatus(c.State, c.Message))
		l.UnIndent()
		for _, u := range c.Units {
			if !all && (u.State == client.Healthy) {
				continue
			}
			l.Indent()
			l.AppendItem(u.UnitID)
			l.Indent()
			l.AppendItem(formatStatus(u.State, u.Message))
			if all {
				l.AppendItem(fmt.Sprintf("type: %s", u.UnitType))
			}
			l.UnIndent()
			l.UnIndent()
		}
		l.UnIndent()
		l.UnIndent()
	}
}

func listAgentState(l list.Writer, state *client.AgentState, all bool) {
	l.AppendItem("elastic-agent")
	l.Indent()
	l.AppendItem(formatStatus(state.State, state.Message))
	if all {
		l.AppendItem("info")
		l.Indent()
		l.AppendItem("id: " + state.Info.ID)
		l.AppendItem("version: " + state.Info.Version)
		l.AppendItem("commit: " + state.Info.Commit)
		l.UnIndent()
	}
	l.UnIndent()
	listComponentState(l, state.Components, all)

	// Upgrade details
	listUpgradeDetails(l, state.UpgradeDetails)
}

func listUpgradeDetails(l list.Writer, upgradeDetails *cproto.UpgradeDetails) {
	if upgradeDetails == nil {
		return
	}

	l.AppendItem("upgrade_details")
	l.Indent()
	l.AppendItem("target_version: " + upgradeDetails.TargetVersion)
	l.AppendItem("state: " + upgradeDetails.State)
	if upgradeDetails.ActionId != "" {
		l.AppendItem("action_id: " + upgradeDetails.ActionId)
	}

	if upgradeDetails.Metadata != nil {
		l.AppendItem("metadata")
		l.Indent()
		if upgradeDetails.Metadata.ScheduledAt != "" {
			l.AppendItem("scheduled_at: " + upgradeDetails.Metadata.ScheduledAt)
		}
		if upgradeDetails.Metadata.FailedState != "" {
			l.AppendItem("failed_state: " + upgradeDetails.Metadata.FailedState)
		}
		if upgradeDetails.Metadata.ErrorMsg != "" {
			l.AppendItem("error_msg: " + upgradeDetails.Metadata.ErrorMsg)
		}
		if upgradeDetails.State == string(details.StateDownloading) {
			l.AppendItem(fmt.Sprintf("download_percent: %.2f%%", upgradeDetails.Metadata.DownloadPercent*100))
		}
		if upgradeDetails.Metadata.RetryUntil != "" {
			l.AppendItem("retry_until: " + humanDurationUntil(upgradeDetails.Metadata.RetryUntil, time.Now()))
		}
		if upgradeDetails.Metadata.RetryErrorMsg != "" {
			l.AppendItem("retry_error_msg: " + upgradeDetails.Metadata.RetryErrorMsg)
		}
		l.UnIndent()
	}

	l.UnIndent()
}

func listFleetState(l list.Writer, state *client.AgentState, all bool) {
	l.AppendItem("fleet")
	l.Indent()
	l.AppendItem(formatStatus(state.FleetState, state.FleetMessage))
	l.UnIndent()
}

func humanListOutput(w io.Writer, state *client.AgentState, all bool) error {
	l := list.NewWriter()
	l.SetStyle(list.StyleConnectedLight)
	l.SetOutputMirror(w)
	listFleetState(l, state, all)
	listAgentState(l, state, all)
	_ = l.Render()
	return nil
}

func humanFullOutput(w io.Writer, obj interface{}) error {
	status, ok := obj.(*client.AgentState)
	if !ok {
		return fmt.Errorf("unable to cast %T as *client.AgentStatus", obj)
	}
	return humanListOutput(w, status, true)
}

func humanOutput(w io.Writer, obj interface{}) error {
	status, ok := obj.(*client.AgentState)
	if !ok {
		return fmt.Errorf("unable to cast %T as *client.AgentStatus", obj)
	}
	return humanListOutput(w, status, false)
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

func humanDurationUntil(targetTime string, from time.Time) string {
	target, err := time.Parse(control.TimeFormat(), targetTime)
	if err != nil {
		return targetTime
	}

	until := target.Sub(from)
	return until.String()
}

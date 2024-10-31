// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/elastic/elastic-agent/pkg/control"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/utils"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

const (
	flagSourceURI      = "source-uri"
	flagSkipVerify     = "skip-verify"
	flagSkipDefaultPgp = "skip-default-pgp"
	flagPGPBytes       = "pgp"
	flagPGPBytesPath   = "pgp-path"
	flagPGPBytesURI    = "pgp-uri"
	flagForce          = "force"
)

var unsupportedUpgrade error = errors.New("upgrading fleet managed agents is not supported")

func newUpgradeCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upgrade <version>",
		Short: "Upgrade the currently installed Elastic Agent to the specified version",
		Long:  "This command upgrades the currently installed Elastic Agent to the specified version.",
		Args:  cobra.ExactArgs(1),
		Run: func(c *cobra.Command, args []string) {
			c.SetContext(context.Background())
			if err := upgradeCmd(streams, c, args); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringP(flagSourceURI, "s", "", "Source URI to download the new version from")
	cmd.Flags().BoolP(flagSkipVerify, "", false, "Skips package verification")
	cmd.Flags().BoolP(flagSkipDefaultPgp, "", false, "Skips package verification with embedded key")
	cmd.Flags().String(flagPGPBytes, "", "PGP to use for package verification")
	cmd.Flags().String(flagPGPBytesURI, "", "Path to a web location containing PGP to use for package verification")
	cmd.Flags().String(flagPGPBytesPath, "", "Path to a file containing PGP to use for package verification")
	cmd.Flags().BoolP(flagForce, "", false, "Advanced option to force an upgrade on a fleet managed agent")
	err := cmd.Flags().MarkHidden(flagForce)
	if err != nil {
		fmt.Fprintf(streams.Err, "error while setting upgrade force flag attributes: %s", err.Error())
		os.Exit(1)
	}

	return cmd
}

type upgradeInput struct {
	streams   *cli.IOStreams
	cmd       *cobra.Command
	args      []string
	c         client.Client
	agentInfo info.Agent
}

func upgradeCmd(streams *cli.IOStreams, cmd *cobra.Command, args []string) error {
	c := client.New()
	agentInfo, err := info.NewAgentInfoWithLog(cmd.Context(), "error", false)
	if err != nil {
		return fmt.Errorf("failed to retrieve agent info while tring to upgrade the agent: %w", err)
	}
	input := &upgradeInput{
		streams,
		cmd,
		args,
		c,
		agentInfo,
	}
	return upgradeCmdWithClient(input)
}

func checkUpgradable(force bool, agentInfo info.Agent) error {
	if agentInfo.IsStandalone() {
		return nil
	}

	if agentInfo.Unprivileged() {
		return fmt.Errorf("upgrade command needs to be executed as root for fleet managed agents")
	}

	if !force {
		return unsupportedUpgrade
	}

	return nil
}

func upgradeCmdWithClient(input *upgradeInput) error {
	cmd := input.cmd
	c := input.c
	version := input.args[0]
	sourceURI, _ := cmd.Flags().GetString(flagSourceURI)

	force, err := cmd.Flags().GetBool(flagForce)
	if err != nil {
		return fmt.Errorf("failed to retrieve command flag information while trying to upgrade the agent: %w", err)
	}

	err = checkUpgradable(force, input.agentInfo)
	if err != nil {
		return fmt.Errorf("aborting upgrade: %w", err)
	}

	err = c.Connect(cmd.Context())
	if err != nil {
		return errors.New(err, "Failed communicating to running daemon", errors.TypeNetwork, errors.M("socket", control.Address()))
	}
	defer c.Disconnect()

	isBeingUpgraded, err := upgrade.IsInProgress(c, utils.GetWatcherPIDs)
	if err != nil {
		return fmt.Errorf("failed to check if upgrade is already in progress: %w", err)
	}
	if isBeingUpgraded {
		return errors.New("an upgrade is already in progress; please try again later.")
	}

	skipVerification, _ := cmd.Flags().GetBool(flagSkipVerify)
	var pgpChecks []string
	if !skipVerification {
		// get local PGP
		pgpPath, _ := cmd.Flags().GetString(flagPGPBytesPath)
		if len(pgpPath) > 0 {
			content, err := os.ReadFile(pgpPath)
			if err != nil {
				return errors.New(err, "failed to read pgp file")
			}
			if len(content) > 0 {
				pgpChecks = append(pgpChecks, download.PgpSourceRawPrefix+string(content))
			}
		}

		pgpBytes, _ := cmd.Flags().GetString(flagPGPBytes)
		if len(pgpBytes) > 0 {
			pgpChecks = append(pgpChecks, download.PgpSourceRawPrefix+pgpBytes)
		}

		pgpUri, _ := cmd.Flags().GetString(flagPGPBytesURI)
		if len(pgpUri) > 0 {
			if uriErr := download.CheckValidDownloadUri(pgpUri); uriErr != nil {
				return uriErr
			}

			// URI is parsed later with proper TLS and Proxy config within downloader
			pgpChecks = append(pgpChecks, download.PgpSourceURIPrefix+pgpUri)
		}
	}
	skipDefaultPgp, _ := cmd.Flags().GetBool(flagSkipDefaultPgp)
	version, err = c.Upgrade(context.Background(), version, sourceURI, skipVerification, skipDefaultPgp, pgpChecks...)
	if err != nil {
		s, ok := status.FromError(err)
		// Sometimes the gRPC server shuts down before replying to the command which is expected
		// we can determine this state by the EOF error coming from the server.
		// If the server is just unavailable/not running, we should not succeed.
		isConnectionInterrupted := ok && s.Code() == codes.Unavailable && strings.Contains(s.Message(), "EOF")
		if !isConnectionInterrupted {
			return errors.New(err, "Failed trigger upgrade of daemon")
		}
	}
	fmt.Fprintf(input.streams.Out, "Upgrade triggered to version %s, Elastic Agent is currently restarting\n", version)
	return nil
}

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

	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/control"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/utils"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install/pkgmgr"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

const (
	flagSourceURI      = "source-uri"
	flagSkipVerify     = "skip-verify"
	flagSkipDefaultPgp = "skip-default-pgp"
	flagPGPBytes       = "pgp"
	flagPGPBytesPath   = "pgp-path"
	flagPGPBytesURI    = "pgp-uri"
)

func newUpgradeCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upgrade <version>",
		Short: "Upgrade the currently installed Elastic Agent to the specified version",
		Long:  "This command upgrades the currently installed Elastic Agent to the specified version.",
		Args:  cobra.ExactArgs(1),
		Run: func(c *cobra.Command, args []string) {
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

	return cmd
}

func upgradeCmd(streams *cli.IOStreams, cmd *cobra.Command, args []string) error {
	c := client.New()
	return upgradeCmdWithClient(streams, cmd, args, c)
}
func shouldUpgrade(ctx context.Context, cmd *cobra.Command) (bool, error) {
  // Check if the agent is installed by dpkg or rpm
  if pkgmgr.InstalledViaExternalPkgMgr() {
    return false, fmt.Errorf("upgrading the elastic-agent is not support if the agent is installed using dpkg or rpm")
  }

  // Check if the agent is running in a container
  details, err  := component.LoadPlatformDetail()
  if err != nil {
    return false, fmt.Errorf("failed to load platform details while trying to upgrade the agent")
  }

  if details.OS == component.Container {
    return false, fmt.Errorf("upgrading an elastic-agent running in a container is not supported")
  }

  agentInfo, err := info.NewAgentInfoWithLog(ctx, "error", false)
  if err != nil {
    return false, fmt.Errorf("failed to retrieve agent info while tring to upgrade the agent")
  }

  isAdmin, err := utils.HasRoot()
  if err != nil {
    return false, fmt.Errorf("failed checking root/Administrator rights while trying to upgrade the agent")
  }

  // Check if the agent is fleet managed
  if !agentInfo.IsStandalone() {
    // Check if the upgrade command is executed as root
    if !isAdmin {
      return false, fmt.Errorf("need to execute the \"upgrade\" command as root if the agent is fleet managed")
    }

    force, err := cmd.Flags().GetBool("force")
    if err != nil {
      return false, fmt.Errorf("failed to retrieve command flag information while trying to upgrade the agent")
    }

    if !force {
      return false, fmt.Errorf("upgrading a fleet managed agent is not supported")
    }

    cf, err := cli.Confirm("Upgrading a fleet managed agent is not supported. Would you still like to proceed?", false)
    if err != nil {
      return false, fmt.Errorf("failed while confirming action")
    }

    if !cf {
      return false, fmt.Errorf("upgrade not confirmed")
    }
  }

  return true, nil
}

func upgradeCmdWithClient(streams *cli.IOStreams, cmd *cobra.Command, args []string, c client.Client) error {
// agentInfo, err := info.NewAgentInfo(ctx context.Context, createAgentID bool)
	version := args[0]
	sourceURI, _ := cmd.Flags().GetString(flagSourceURI)

  ctx := context.Background()

  err := c.Connect(ctx)
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
	fmt.Fprintf(streams.Out, "Upgrade triggered to version %s, Elastic Agent is currently restarting\n", version)
	return nil
}

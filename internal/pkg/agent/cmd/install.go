// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const (
	flagInstallBasePath     = "base-path"
	flagInstallUnprivileged = "unprivileged"
)

func newInstallCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install Elastic Agent permanently on this system",
		Long: `This command installs Elastic Agent permanently on this system. The system's service manager then manages the installed Elastic agent.

Unless all the require command-line parameters are provided or -f is used this command will ask questions on how you
would like the Agent to operate.
`,
		Run: func(c *cobra.Command, _ []string) {
			if err := installCmd(streams, c); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
		},
	}

	cmd.Flags().BoolP("force", "f", false, "Force overwrite the current installation and do not prompt for confirmation")
	cmd.Flags().BoolP("non-interactive", "n", false, "Install Elastic Agent in non-interactive mode which will not prompt on missing parameters but fails instead.")
	cmd.Flags().String(flagInstallBasePath, paths.DefaultBasePath, "The path where the Elastic Agent will be installed. It must be an absolute path.")
	cmd.Flags().Bool(flagInstallUnprivileged, false, "Installed Elastic Agent will create an 'elastic-agent' user and run as that user. (experimental)")
	_ = cmd.Flags().MarkHidden(flagInstallUnprivileged) // Hidden until fully supported
	addEnrollFlags(cmd)

	return cmd
}

func installCmd(streams *cli.IOStreams, cmd *cobra.Command) error {
	var err error

	err = validateEnrollFlags(cmd)
	if err != nil {
		return fmt.Errorf("could not validate flags: %w", err)
	}

	basePath, _ := cmd.Flags().GetString(flagInstallBasePath)
	if !filepath.IsAbs(basePath) {
		return fmt.Errorf("base path [%s] is not absolute", basePath)
	}

	isAdmin, err := utils.HasRoot()
	if err != nil {
		return fmt.Errorf("unable to perform install command while checking for administrator rights, %w", err)
	}
	if !isAdmin {
		return fmt.Errorf("unable to perform install command, not executed with %s permissions", utils.PermissionUser)
	}

	// only support Linux and MacOS at the moment
	unprivileged, _ := cmd.Flags().GetBool(flagInstallUnprivileged)
	if unprivileged && (runtime.GOOS != "linux" && runtime.GOOS != "darwin") {
		return fmt.Errorf("unable to perform install command, unprivileged is currently only supported on Linux and MacOSß")
	}
	if unprivileged {
		fmt.Fprintln(streams.Out, "Unprivileged installation mode enabled; this is an experimental and currently unsupported feature.")
	}

	topPath := paths.InstallPath(basePath)

	status, reason := install.Status(topPath)
	force, _ := cmd.Flags().GetBool("force")
	if status == install.Installed && !force {
		return fmt.Errorf("already installed at: %s", topPath)
	}

	nonInteractive, _ := cmd.Flags().GetBool("non-interactive")
	if nonInteractive {
		fmt.Fprintln(streams.Out, "Installing in non-interactive mode.")
	}

	if status == install.PackageInstall {
		fmt.Fprintf(streams.Out, "Installed as a system package, installation will not be altered.\n")
	}

	// check the lock to ensure that elastic-agent is not already running in this directory
	locker := filelock.NewAppLocker(paths.Data(), paths.AgentLockFileName)
	if err := locker.TryLock(); err != nil {
		if errors.Is(err, filelock.ErrAppAlreadyRunning) {
			return fmt.Errorf("cannot perform installation as Elastic Agent is already running from this directory")
		}
		return fmt.Errorf("error obtaining lock: %w", err)
	}
	_ = locker.Unlock()

	if status == install.Broken {
		if !force && !nonInteractive {
			fmt.Fprintf(streams.Out, "Elastic Agent is installed but currently broken: %s\n", reason)
			confirm, err := cli.Confirm(fmt.Sprintf("Continuing will re-install Elastic Agent over the current installation at %s. Do you want to continue?", topPath), true)
			if err != nil {
				return fmt.Errorf("problem reading prompt response")
			}
			if !confirm {
				return fmt.Errorf("installation was cancelled by the user")
			}
		}
	} else if status != install.PackageInstall {
		if !force && !nonInteractive {
			confirm, err := cli.Confirm(fmt.Sprintf("Elastic Agent will be installed at %s and will run as a service. Do you want to continue?", topPath), true)
			if err != nil {
				return fmt.Errorf("problem reading prompt response")
			}
			if !confirm {
				return fmt.Errorf("installation was cancelled by the user")
			}
		}
	}

	enroll := true
	askEnroll := true
	url, _ := cmd.Flags().GetString("url")
	token, _ := cmd.Flags().GetString("enrollment-token")
	delayEnroll, _ := cmd.Flags().GetBool("delay-enroll")
	if url != "" && token != "" {
		askEnroll = false
	}
	fleetServer, _ := cmd.Flags().GetString("fleet-server-es")
	if fleetServer != "" || force || delayEnroll || nonInteractive {
		askEnroll = false
	}
	if askEnroll {
		confirm, err := cli.Confirm("Do you want to enroll this Agent into Fleet?", true)
		if err != nil {
			return fmt.Errorf("problem reading prompt response")
		}
		if !confirm {
			// not enrolling
			enroll = false
		}
	}
	if !askEnroll && (url == "" || token == "") && fleetServer == "" {
		// force was performed without required enrollment arguments, all done (standalone mode)
		enroll = false
	}

	if enroll && fleetServer == "" {
		if url == "" {
			if nonInteractive {
				return fmt.Errorf("missing required --url argument used to enroll the agent")
			}
			url, err = cli.ReadInput("URL you want to enroll this Agent into:")
			if err != nil {
				return fmt.Errorf("problem reading prompt response")
			}
			if url == "" {
				fmt.Fprintln(streams.Out, "Enrollment cancelled because no URL was provided.")
				return nil
			}
		}
		if token == "" {
			if nonInteractive {
				return fmt.Errorf("missing required --enrollment-token argument used to enroll the agent")
			}
			token, err = cli.ReadInput("Fleet enrollment token:")
			if err != nil {
				return fmt.Errorf("problem reading prompt response")
			}
			if token == "" {
				fmt.Fprintf(streams.Out, "Enrollment cancelled because no enrollment token was provided.\n")
				return nil
			}
		}
	}

	progBar := install.CreateAndStartNewSpinner(streams.Out, "Installing Elastic Agent...")

	logCfg := logp.DefaultConfig(logp.DefaultEnvironment)
	logCfg.Level = logp.DebugLevel
	// Using in memory logger, so we don't write logs to the
	// directory we are trying to delete
	logp.ToObserverOutput()(&logCfg)

	err = logp.Configure(logCfg)
	if err != nil {
		return fmt.Errorf("error creating logging config: %w", err)
	}

	log := logger.NewWithoutConfig("")

	defer func() {
		if err == nil {
			return
		}
		oLogs := logp.ObserverLogs().TakeAll()
		fmt.Fprintf(os.Stderr, "Error uninstalling.  Printing logs\n")
		for _, oLog := range oLogs {
			fmt.Fprintf(os.Stderr, "%v\n", oLog.Entry)
		}
	}()

	var ownership utils.FileOwner
	cfgFile := paths.ConfigFile()
	if status != install.PackageInstall {
		ownership, err = install.Install(cfgFile, topPath, unprivileged, log, progBar, streams)
		if err != nil {
			return fmt.Errorf("error installing package: %w", err)
		}

		defer func() {
			if err != nil {
				progBar.Describe("Uninstalling")
				innerErr := install.Uninstall(cfgFile, topPath, "", log, progBar, unprivileged)
				if innerErr != nil {
					progBar.Describe("Failed to Uninstall")
				} else {
					progBar.Describe("Uninstalled")
				}
			}
		}()

		if !delayEnroll {
			progBar.Describe("Starting Service")
			err = install.StartService(topPath)
			if err != nil {
				progBar.Describe("Start Service failed, exiting...")
				fmt.Fprintf(streams.Out, "Installation failed to start Elastic Agent service.\n")
				return fmt.Errorf("error starting service: %w", err)
			}
			progBar.Describe("Service Started")

			defer func() {
				if err != nil {
					progBar.Describe("Stopping Service")
					innerErr := install.StopService(topPath)
					if innerErr != nil {
						progBar.Describe("Failed to Stop Service")
					} else {
						progBar.Describe("Successfully Stopped Service")
					}
				}
			}()
		}

		fmt.Fprintln(streams.Out, "Elastic Agent successfully installed, starting enrollment.")
	}

	if enroll {
		enrollArgs := []string{"enroll", "--from-install"}
		enrollArgs = append(enrollArgs, buildEnrollmentFlags(cmd, url, token)...)
		enrollCmd := exec.Command(install.ExecutablePath(topPath), enrollArgs...) //nolint:gosec // it's not tainted
		enrollCmd.Stdin = os.Stdin
		enrollCmd.Stdout = os.Stdout
		enrollCmd.Stderr = os.Stderr
		err = enrollCmdExtras(enrollCmd, ownership)
		if err != nil {
			return err
		}

		progBar.Describe("Enrolling Elastic Agent with Fleet")
		err = enrollCmd.Start()
		if err != nil {
			progBar.Describe("Failed to Enroll")
			return fmt.Errorf("failed to execute enroll command: %w", err)
		}
		progBar.Describe("Waiting For Enroll...")
		err = enrollCmd.Wait()
		if err != nil {
			progBar.Describe("Failed to Enroll")
			// uninstall doesn't need to be performed here the defer above will
			// catch the error and perform the uninstall
			return fmt.Errorf("enroll command failed for unknown reason: %w", err)
		}
		progBar.Describe("Enroll Completed")
	}

	progBar.Describe("Done")
	_ = progBar.Finish()
	_ = progBar.Exit()
	fmt.Fprint(streams.Out, "\nElastic Agent has been successfully installed.\n")
	return nil
}

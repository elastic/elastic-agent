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
	"strconv"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const (
	flagInstallBasePath = "base-path"
	flagInstallNonRoot  = "non-root"
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
	cmd.Flags().Bool(flagInstallNonRoot, false, "Installed Elastic Agent will create an 'elastic-agent' user and run as that user, instead of running as root.")
	addEnrollFlags(cmd)

	return cmd
}

func installCmd(streams *cli.IOStreams, cmd *cobra.Command) error {
	err := validateEnrollFlags(cmd)
	if err != nil {
		return err
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

	// only support Linux at the moment
	nonRoot, _ := cmd.Flags().GetBool(flagInstallNonRoot)
	if runtime.GOOS != "linux" {
		return fmt.Errorf("unable to perform install command, non-root is currently only supported on Linux")
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
		return err
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
				fmt.Fprintf(streams.Out, "Enrollment cancelled because no URL was provided.\n")
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

	pt := install.NewProgressTracker(streams.Out)
	s := pt.Start()
	defer func() {
		if err != nil {
			s.Failed()
		} else {
			s.Succeeded()
		}
	}()

	uidStr := "0"
	gidStr := "0"
	cfgFile := paths.ConfigFile()
	if status != install.PackageInstall {
		uidStr, gidStr, err = install.Install(cfgFile, topPath, nonRoot, s)
		if err != nil {
			return err
		}

		defer func() {
			if err != nil {
				uninstallStep := s.StepStart("Uninstalling")
				innerErr := install.Uninstall(cfgFile, topPath, "", uninstallStep)
				if innerErr != nil {
					uninstallStep.Failed()
				} else {
					uninstallStep.Succeeded()
				}
			}
		}()

		if !delayEnroll {
			startServiceStep := s.StepStart("Starting service")
			err = install.StartService(topPath)
			if err != nil {
				startServiceStep.Failed()
				fmt.Fprintf(streams.Out, "Installation failed to start Elastic Agent service.\n")
				return err
			}
			startServiceStep.Succeeded()

			defer func() {
				if err != nil {
					stoppingServiceStep := s.StepStart("Stopping service")
					innerErr := install.StopService(topPath)
					if innerErr != nil {
						stoppingServiceStep.Failed()
					} else {
						stoppingServiceStep.Succeeded()
					}
				}
			}()
		}
	}

	if enroll {
		enrollArgs := []string{"enroll", "--from-install"}
		enrollArgs = append(enrollArgs, buildEnrollmentFlags(cmd, url, token)...)
		enrollCmd := exec.Command(install.ExecutablePath(topPath), enrollArgs...) //nolint:gosec // it's not tainted
		enrollCmd.Stdin = os.Stdin
		enrollCmd.Stdout = os.Stdout
		enrollCmd.Stderr = os.Stderr

		if runtime.GOOS != "windows" {
			uid, err := strconv.Atoi(uidStr)
			if err != nil {
				return fmt.Errorf("failed to convert uid(%s) to int: %w", uidStr, err)
			}
			gid, err := strconv.Atoi(gidStr)
			if err != nil {
				return fmt.Errorf("failed to convert gid(%s) to int: %w", gidStr, err)
			}
			enrollCmd.SysProcAttr = &syscall.SysProcAttr{
				Credential: &syscall.Credential{
					Uid: uint32(uid),
					Gid: uint32(gid),
				},
			}
		}

		enrollStep := s.StepStart("Enrolling Elastic Agent with Fleet")
		err = enrollCmd.Start()
		if err != nil {
			enrollStep.Failed()
			return fmt.Errorf("failed to execute enroll command: %w", err)
		}
		err = enrollCmd.Wait()
		if err != nil {
			enrollStep.Failed()
			// uninstall doesn't need to be performed here the defer above will
			// catch the error and perform the uninstall
			return fmt.Errorf("enroll command failed for unknown reason: %w", err)
		}
		enrollStep.Succeeded()
	}

	if err := info.CreateInstallMarker(topPath, uidStr, gidStr); err != nil {
		return fmt.Errorf("failed to create install marker: %w", err)
	}

	fmt.Fprint(streams.Out, "Elastic Agent has been successfully installed.\n")
	return nil
}

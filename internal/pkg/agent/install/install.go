// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jaypipes/ghw"
	"github.com/kardianos/service"
	"github.com/otiai10/copy"
	"github.com/schollz/progressbar/v3"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

const (
	darwin = "darwin"
)

// Install installs Elastic Agent persistently on the system including creating and starting its service.
func Install(cfgFile, topPath string, pt *progressbar.ProgressBar, streams *cli.IOStreams) error {
	dir, err := findDirectory()
	if err != nil {
		return errors.New(err, "failed to discover the source directory for installation", errors.TypeFilesystem)
	}

	// We only uninstall Agent if it is currently installed.
	status, _ := Status(topPath)
	if status == Installed {
		// Uninstall current installation
		//
		// There is no uninstall token for "install" command.
		// Uninstall will fail on protected agent.
		// The protected Agent will need to be uninstalled first before it can be installed.
		pt.Describe("Uninstalling current Elastic Agent")
		err = Uninstall(cfgFile, topPath, "", pt)
		if err != nil {
			pt.Describe("Failed to uninstall current Elastic Agent")
			return errors.New(
				err,
				fmt.Sprintf("failed to uninstall Agent at (%s)", filepath.Dir(topPath)),
				errors.M("directory", filepath.Dir(topPath)))
		}
		pt.Describe("Successfully uninstalled current Elastic Agent")
	}

	// ensure parent directory exists
	err = os.MkdirAll(filepath.Dir(topPath), 0755)
	if err != nil {
		return errors.New(
			err,
			fmt.Sprintf("failed to create installation parent directory (%s)", filepath.Dir(topPath)),
			errors.M("directory", filepath.Dir(topPath)))
	}

	// copy source into install path
	//
	// Try to detect if we are running with SSDs. If we are increase the copy concurrency,
	// otherwise fall back to the default.
	copyConcurrency := 1
	hasSSDs, detectHWErr := HasAllSSDs()
	if detectHWErr != nil {
		fmt.Fprintf(streams.Out, "Could not determine block hardware type, disabling copy concurrency: %s\n", detectHWErr)
	}
	if hasSSDs {
		copyConcurrency = runtime.NumCPU() * 4
	}

	pt.Describe("Copying install files")
	err = copy.Copy(dir, topPath, copy.Options{
		OnSymlink: func(_ string) copy.SymlinkAction {
			return copy.Shallow
		},
		Sync:         true,
		NumOfWorkers: int64(copyConcurrency),
	})
	if err != nil {
		pt.Describe("Error copying files")
		return errors.New(
			err,
			fmt.Sprintf("failed to copy source directory (%s) to destination (%s)", dir, topPath),
			errors.M("source", dir), errors.M("destination", topPath),
		)
	}
	pt.Describe("Successfully copied files")

	// place shell wrapper, if present on platform
	if paths.ShellWrapperPath != "" {
		pathDir := filepath.Dir(paths.ShellWrapperPath)
		err = os.MkdirAll(pathDir, 0755)
		if err != nil {
			return errors.New(
				err,
				fmt.Sprintf("failed to create directory (%s) for shell wrapper (%s)", pathDir, paths.ShellWrapperPath),
				errors.M("directory", pathDir))
		}
		// Install symlink for darwin instead of the wrapper script.
		// Elastic-agent should be first process that launchd starts in order to be able to grant
		// the Full-Disk Access (FDA) to the agent and it's child processes.
		// This is specifically important for osquery FDA permissions at the moment.
		if runtime.GOOS == darwin {
			// Check if previous shell wrapper or symlink exists and remove it so it can be overwritten
			if _, err := os.Lstat(paths.ShellWrapperPath); err == nil {
				if err := os.Remove(paths.ShellWrapperPath); err != nil {
					return errors.New(
						err,
						fmt.Sprintf("failed to remove (%s)", paths.ShellWrapperPath),
						errors.M("destination", paths.ShellWrapperPath))
				}
			}
			err = os.Symlink(filepath.Join(topPath, paths.BinaryName), paths.ShellWrapperPath)
			if err != nil {
				return errors.New(
					err,
					fmt.Sprintf("failed to create elastic-agent symlink (%s)", paths.ShellWrapperPath),
					errors.M("destination", paths.ShellWrapperPath))
			}
		} else {
			// We use strings.Replace instead of fmt.Sprintf here because, with the
			// latter, govet throws a false positive error here: "fmt.Sprintf call has
			// arguments but no formatting directives".
			shellWrapper := strings.Replace(paths.ShellWrapper, "%s", topPath, -1)
			err = os.WriteFile(paths.ShellWrapperPath, []byte(shellWrapper), 0755)
			if err != nil {
				return errors.New(
					err,
					fmt.Sprintf("failed to write shell wrapper (%s)", paths.ShellWrapperPath),
					errors.M("destination", paths.ShellWrapperPath))
			}
		}
	}

	// post install (per platform)
	err = postInstall(topPath)
	if err != nil {
		return fmt.Errorf("error running post-install steps: %w", err)
	}

	// fix permissions
	err = FixPermissions(topPath)
	if err != nil {
		return errors.New(
			err,
			"failed to perform permission changes",
			errors.M("destination", topPath))
	}

	// install service
	pt.Describe("Installing service")
	svc, err := newService(topPath)
	if err != nil {
		pt.Describe("Failed to install service")
		return fmt.Errorf("error installing new service: %w", err)
	}
	err = svc.Install()
	if err != nil {
		pt.Describe("Failed to install service")
		return errors.New(
			err,
			fmt.Sprintf("failed to install service (%s)", paths.ServiceName),
			errors.M("service", paths.ServiceName))
	}
	pt.Describe("Installed service")

	return nil
}

// StartService starts the installed service.
//
// This should only be called after Install is successful.
func StartService(topPath string) error {
	svc, err := newService(topPath)
	if err != nil {
		return fmt.Errorf("error creating new service handler: %w", err)
	}
	err = svc.Start()
	if err != nil {
		return errors.New(
			err,
			fmt.Sprintf("failed to start service (%s)", paths.ServiceName),
			errors.M("service", paths.ServiceName))
	}
	return nil
}

// StopService stops the installed service.
func StopService(topPath string) error {
	svc, err := newService(topPath)
	if err != nil {
		return fmt.Errorf("error creating new service handler: %w", err)
	}
	err = svc.Stop()
	if err != nil {
		return errors.New(
			err,
			fmt.Sprintf("failed to stop service (%s)", paths.ServiceName),
			errors.M("service", paths.ServiceName))
	}
	return nil
}

// RestartService restarts the installed service.
func RestartService(topPath string) error {
	svc, err := newService(topPath)
	if err != nil {
		return fmt.Errorf("error creating new service handler: %w", err)
	}
	err = svc.Restart()
	if err != nil {
		return errors.New(
			err,
			fmt.Sprintf("failed to restart service (%s)", paths.ServiceName),
			errors.M("service", paths.ServiceName))
	}
	return nil
}

// StatusService returns the status of the service.
func StatusService(topPath string) (service.Status, error) {
	svc, err := newService(topPath)
	if err != nil {
		return service.StatusUnknown, err
	}
	return svc.Status()
}

// FixPermissions fixes the permissions on the installed system.
func FixPermissions(topPath string) error {
	return fixPermissions(topPath)
}

// findDirectory returns the directory to copy into the installation location.
//
// This also verifies that the discovered directory is a valid directory for installation.
func findDirectory() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("error fetching executable of current process: %w", err)
	}
	execPath, err = filepath.Abs(execPath)
	if err != nil {
		return "", fmt.Errorf("error fetching absolute file path: %w", err)
	}
	sourceDir := paths.ExecDir(filepath.Dir(execPath))
	err = verifyDirectory(sourceDir)
	if err != nil {
		return "", fmt.Errorf("error verifying directory: %w", err)
	}
	return sourceDir, nil
}

// verifyDirectory ensures that the directory includes the executable.
func verifyDirectory(dir string) error {
	_, err := os.Stat(filepath.Join(dir, paths.BinaryName))
	if os.IsNotExist(err) {
		return fmt.Errorf("missing %s", paths.BinaryName)
	}
	return nil
}

// HasAllSSDs returns true if the host we are on uses SSDs for
// all its persistent storage; false otherwise. Returns any error
// encountered detecting the hardware type for informational purposes.
// Errors from this function are not fatal. Note that errors may be
// returned on some Mac hardware configurations as the ghw package
// does not fully support MacOS.
func HasAllSSDs() (bool, error) {
	block, err := ghw.Block()
	if err != nil {
		return false, err
	}

	return hasAllSSDs(*block), nil
}

// Internal version of HasAllSSDs for testing.
func hasAllSSDs(block ghw.BlockInfo) bool {
	for _, disk := range block.Disks {
		switch disk.DriveType {
		case ghw.DRIVE_TYPE_FDD, ghw.DRIVE_TYPE_ODD:
			// Floppy or optical drive; we don't care about these
			continue
		case ghw.DRIVE_TYPE_SSD:
			// SSDs
			continue
		case ghw.DRIVE_TYPE_HDD:
			// HDD (spinning hard disk)
			return false
		default:
			return false
		}
	}

	return true
}

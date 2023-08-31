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

	"github.com/otiai10/copy"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

const (
	darwin = "darwin"
)

// Install installs Elastic Agent persistently on the system including creating and starting its service.
func Install(cfgFile, topPath string, pt ProgressTrackerStep) error {
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
		s := pt.StepStart("Uninstalling current Elastic Agent")
		err = Uninstall(cfgFile, topPath, "", s)
		if err != nil {
			s.Failed()
			return errors.New(
				err,
				fmt.Sprintf("failed to uninstall Agent at (%s)", filepath.Dir(topPath)),
				errors.M("directory", filepath.Dir(topPath)))
		}
		s.Succeeded()
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
	s := pt.StepStart("Copying files")
	err = copy.Copy(dir, topPath, copy.Options{
		OnSymlink: func(_ string) copy.SymlinkAction {
			return copy.Shallow
		},
		Sync:        true,
		Concurrency: uint(runtime.NumCPU()), // TODO: account for SSDs
	})
	if err != nil {
		s.Failed()
		return errors.New(
			err,
			fmt.Sprintf("failed to copy source directory (%s) to destination (%s)", dir, topPath),
			errors.M("source", dir), errors.M("destination", topPath))
	}
	s.Succeeded()

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
		return err
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
	s = pt.StepStart("Installing service")
	svc, err := newService(topPath)
	if err != nil {
		s.Failed()
		return err
	}
	err = svc.Install()
	if err != nil {
		s.Failed()
		return errors.New(
			err,
			fmt.Sprintf("failed to install service (%s)", paths.ServiceName),
			errors.M("service", paths.ServiceName))
	}
	s.Succeeded()

	return nil
}

// StartService starts the installed service.
//
// This should only be called after Install is successful.
func StartService(topPath string) error {
	svc, err := newService(topPath)
	if err != nil {
		return err
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
		return err
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
		return err
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
		return "", err
	}
	execPath, err = filepath.Abs(execPath)
	if err != nil {
		return "", err
	}
	sourceDir := paths.ExecDir(filepath.Dir(execPath))
	err = verifyDirectory(sourceDir)
	if err != nil {
		return "", err
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

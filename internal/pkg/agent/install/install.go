// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	goerrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jaypipes/ghw"
	"github.com/kardianos/service"
	"github.com/otiai10/copy"
	"github.com/schollz/progressbar/v3"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const (
	darwin = "darwin"

	elasticUsername  = "elastic-agent"
	elasticGroupName = "elastic-agent"
)

// Install installs Elastic Agent persistently on the system including creating and starting its service.
func Install(cfgFile, topPath string, unprivileged bool, log *logp.Logger, pt *progressbar.ProgressBar, streams *cli.IOStreams) (utils.FileOwner, error) {
	dir, err := findDirectory()
	if err != nil {
		return utils.FileOwner{}, errors.New(err, "failed to discover the source directory for installation", errors.TypeFilesystem)
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
		err = Uninstall(cfgFile, topPath, "", log, pt, unprivileged)
		if err != nil {
			pt.Describe("Failed to uninstall current Elastic Agent")
			return utils.FileOwner{}, errors.New(
				err,
				fmt.Sprintf("failed to uninstall Agent at (%s)", filepath.Dir(topPath)),
				errors.M("directory", filepath.Dir(topPath)))
		}
		pt.Describe("Successfully uninstalled current Elastic Agent")
	}

	var ownership utils.FileOwner
	username := ""
	groupName := ""
	if unprivileged {
		username = elasticUsername
		groupName = elasticGroupName

		// ensure required group
		ownership.GID, err = FindGID(groupName)
		if err != nil && !errors.Is(err, ErrGroupNotFound) {
			return utils.FileOwner{}, fmt.Errorf("failed finding group %s: %w", groupName, err)
		}
		if errors.Is(err, ErrGroupNotFound) {
			pt.Describe(fmt.Sprintf("Creating group %s", groupName))
			ownership.GID, err = CreateGroup(groupName)
			if err != nil {
				pt.Describe(fmt.Sprintf("Failed to create group %s", groupName))
				return utils.FileOwner{}, fmt.Errorf("failed to create group %s: %w", groupName, err)
			}
			pt.Describe(fmt.Sprintf("Successfully created group %s", groupName))
		}

		// ensure required user
		ownership.UID, err = FindUID(username)
		if err != nil && !errors.Is(err, ErrUserNotFound) {
			return utils.FileOwner{}, fmt.Errorf("failed finding username %s: %w", username, err)
		}
		if errors.Is(err, ErrUserNotFound) {
			pt.Describe(fmt.Sprintf("Creating user %s", username))
			ownership.UID, err = CreateUser(username, ownership.GID)
			if err != nil {
				pt.Describe(fmt.Sprintf("Failed to create user %s", username))
				return utils.FileOwner{}, fmt.Errorf("failed to create user %s: %w", username, err)
			}
			err = AddUserToGroup(username, groupName)
			if err != nil {
				pt.Describe(fmt.Sprintf("Failed to add user %s to group %s", username, groupName))
				return utils.FileOwner{}, fmt.Errorf("failed to add user %s to group %s: %w", username, groupName, err)
			}
			pt.Describe(fmt.Sprintf("Successfully created user %s", username))
		}
	}

	err = setupInstallPath(topPath, ownership)
	if err != nil {
		return utils.FileOwner{}, fmt.Errorf("error setting up install path: %w", err)
	}

	manifest, err := readPackageManifest(dir)
	if err != nil {
		return utils.FileOwner{}, fmt.Errorf("reading package manifest: %w", err)
	}

	pathMappings := manifest.Package.PathMappings

	pt.Describe("Copying install files")
	copyConcurrency := calculateCopyConcurrency(streams)
	err = copyFiles(copyConcurrency, pathMappings, dir, topPath)
	if err != nil {
		pt.Describe("Error copying files")
		return utils.FileOwner{}, err
	}

	pt.Describe("Successfully copied files")

	// place shell wrapper, if present on platform
	if paths.ShellWrapperPath != "" {
		pathDir := filepath.Dir(paths.ShellWrapperPath)
		err = os.MkdirAll(pathDir, 0755)
		if err != nil {
			return utils.FileOwner{}, errors.New(
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
					return utils.FileOwner{}, errors.New(
						err,
						fmt.Sprintf("failed to remove (%s)", paths.ShellWrapperPath),
						errors.M("destination", paths.ShellWrapperPath))
				}
			}
			err = os.Symlink(filepath.Join(topPath, paths.BinaryName), paths.ShellWrapperPath)
			if err != nil {
				return utils.FileOwner{}, errors.New(
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
				return utils.FileOwner{}, errors.New(
					err,
					fmt.Sprintf("failed to write shell wrapper (%s)", paths.ShellWrapperPath),
					errors.M("destination", paths.ShellWrapperPath))
			}
		}
	}

	// post install (per platform)
	err = postInstall(topPath)
	if err != nil {
		return ownership, fmt.Errorf("error running post-install steps: %w", err)
	}

	// fix permissions
	err = FixPermissions(topPath, ownership)
	if err != nil {
		return ownership, fmt.Errorf("failed to perform permission changes on path %s: %w", topPath, err)
	}
	if paths.ShellWrapperPath != "" {
		err = FixPermissions(paths.ShellWrapperPath, ownership)
		if err != nil {
			return ownership, fmt.Errorf("failed to perform permission changes on path %s: %w", paths.ShellWrapperPath, err)
		}
	}

	// install service
	pt.Describe("Installing service")
	svc, err := newService(topPath, withUserGroup(username, groupName))
	if err != nil {
		pt.Describe("Failed to install service")
		return ownership, fmt.Errorf("error installing new service: %w", err)
	}
	err = svc.Install()
	if err != nil {
		pt.Describe("Failed to install service")
		return ownership, errors.New(
			err,
			fmt.Sprintf("failed to install service (%s)", paths.ServiceName),
			errors.M("service", paths.ServiceName))
	}
	pt.Describe("Installed service")

	return ownership, nil
}

// setup the basic topPath, and the .installed file
func setupInstallPath(topPath string, ownership utils.FileOwner) error {
	// ensure parent directory exists
	err := os.MkdirAll(filepath.Dir(topPath), 0755)
	if err != nil {
		return errors.New(err, fmt.Sprintf("failed to create installation parent directory (%s)", filepath.Dir(topPath)), errors.M("directory", filepath.Dir(topPath)))
	}

	// create Agent/ directory with more locked-down permissions
	err = os.MkdirAll(topPath, 0750)
	if err != nil {
		return errors.New(err, fmt.Sprintf("failed to create top path (%s)", topPath), errors.M("directory", topPath))
	}

	// create the install marker
	if err := CreateInstallMarker(topPath, ownership); err != nil {
		return fmt.Errorf("failed to create install marker: %w", err)
	}
	return nil
}

func readPackageManifest(extractedPackageDir string) (*v1.PackageManifest, error) {
	manifestFilePath := filepath.Join(extractedPackageDir, v1.ManifestFileName)
	manifestFile, err := os.Open(manifestFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open package manifest file (%s): %w", manifestFilePath, err)
	}
	defer manifestFile.Close()
	manifest, err := v1.ParseManifest(manifestFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse package manifest file %q contents: %w", manifestFilePath, err)
	}

	return manifest, nil
}

func calculateCopyConcurrency(streams *cli.IOStreams) int {
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

	return copyConcurrency
}

func copyFiles(copyConcurrency int, pathMappings []map[string]string, srcDir string, topPath string) error {
	// copy source into install path

	// these are needed to keep track of what we already copied
	copiedFiles := map[string]struct{}{}
	// collect any symlink we found that need remapping
	symlinks := map[string]string{}

	var copyErrors []error

	// Start copying the remapped paths first
	for _, pathMapping := range pathMappings {
		for packagePath, installedPath := range pathMapping {
			// flag the original path as handled
			copiedFiles[packagePath] = struct{}{}
			srcPath := filepath.Join(srcDir, packagePath)
			dstPath := filepath.Join(topPath, installedPath)
			err := copy.Copy(srcPath, dstPath, copy.Options{
				OnSymlink: func(_ string) copy.SymlinkAction {
					return copy.Shallow
				},
				Sync:         true,
				NumOfWorkers: int64(copyConcurrency),
			})
			if err != nil {
				return errors.New(
					err,
					fmt.Sprintf("failed to copy source directory (%s) to destination (%s)", packagePath, installedPath),
					errors.M("source", packagePath), errors.M("destination", installedPath),
				)
			}
		}
	}

	// copy the remaining files excluding overlaps with the mapped paths
	err := copy.Copy(srcDir, topPath, copy.Options{
		OnSymlink: func(source string) copy.SymlinkAction {
			target, err := os.Readlink(source)
			if err != nil {
				// error reading the link, not much choice to leave it unchanged and collect the error
				copyErrors = append(copyErrors, fmt.Errorf("unable to read link %q for remapping", source))
				return copy.Skip
			}

			// if we find a link, check if its target need to be remapped, in which case skip it for now and save it for
			// later creation with the remapped target
			for _, pathMapping := range pathMappings {
				for srcPath, dstPath := range pathMapping {
					srcPathLocal := filepath.FromSlash(srcPath)
					dstPathLocal := filepath.FromSlash(dstPath)
					if strings.HasPrefix(target, srcPathLocal) {
						newTarget := strings.Replace(target, srcPathLocal, dstPathLocal, 1)
						rel, err := filepath.Rel(srcDir, source)
						if err != nil {
							copyErrors = append(copyErrors, fmt.Errorf("extracting relative path for %q using %q as base: %w", source, srcDir, err))
							return copy.Skip
						}
						symlinks[rel] = newTarget
						return copy.Skip
					}
				}
			}

			return copy.Shallow
		},
		Skip: func(srcinfo os.FileInfo, src, dest string) (bool, error) {
			relPath, err := filepath.Rel(srcDir, src)
			if err != nil {
				return false, fmt.Errorf("calculating relative path for %s: %w", src, err)
			}
			// check if we already handled this path as part of the mappings: if we did, skip it
			relPath = filepath.ToSlash(relPath)
			_, ok := copiedFiles[relPath]
			return ok, nil
		},
		Sync:         true,
		NumOfWorkers: int64(copyConcurrency),
	})
	if err != nil {
		return errors.New(
			err,
			fmt.Sprintf("failed to copy source directory (%s) to destination (%s)", srcDir, topPath),
			errors.M("source", srcDir), errors.M("destination", topPath),
		)
	}

	if len(copyErrors) > 0 {
		return fmt.Errorf("errors encountered during copy from %q to %q: %w", srcDir, topPath, goerrors.Join(copyErrors...))
	}

	// Create the remapped symlinks
	for src, target := range symlinks {
		absSrcPath := filepath.Join(topPath, src)
		err := os.Symlink(target, absSrcPath)
		if err != nil {
			return errors.New(
				err,
				fmt.Sprintf("failed to link source %q to destination %q", absSrcPath, target),
			)
		}
	}
	return nil
}

// StartService starts the installed service.
//
// This should only be called after Install is successful.
func StartService(topPath string) error {
	// only starting the service, so no need to set the username and group to any value
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
	// only stopping the service, so no need to set the username and group to any value
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
	// only restarting the service, so no need to set the username and group to any value
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

// CreateInstallMarker creates a `.installed` file at the given install path,
// and then calls fixInstallMarkerPermissions to set the ownership provided by `ownership`
func CreateInstallMarker(topPath string, ownership utils.FileOwner) error {
	markerFilePath := filepath.Join(topPath, paths.MarkerFileName)
	handle, err := os.Create(markerFilePath)
	if err != nil {
		return err
	}
	_ = handle.Close()
	return fixInstallMarkerPermissions(markerFilePath, ownership)
}

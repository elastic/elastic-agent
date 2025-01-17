// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	goerrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jaypipes/ghw"
	"github.com/kardianos/service"
	"github.com/otiai10/copy"
	"github.com/schollz/progressbar/v3"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/perms"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const (
	darwin = "darwin"

	ElasticUsername  = "elastic-agent-user"
	ElasticGroupName = "elastic-agent"

	// DefaultStopTimeout is the default stop timeout that can be used to stop a running daemon.
	DefaultStopTimeout = 30 * time.Second
	// DefaultStopInterval is the check interval to determine if the service has stopped.
	DefaultStopInterval = 250 * time.Millisecond
)

// Install installs Elastic Agent persistently on the system including creating and starting its service.
func Install(cfgFile, topPath string, unprivileged bool, log *logp.Logger, pt *progressbar.ProgressBar, streams *cli.IOStreams, customUser, customGroup, userPassword string, flavor string) (utils.FileOwner, error) {
	dir, err := findDirectory()
	if err != nil {
		return utils.FileOwner{}, errors.New(err, "failed to discover the source directory for installation", errors.TypeFilesystem)
	}

	var ownership utils.FileOwner
	username := ""
	groupName := ""
	password := ""
	if unprivileged {
		username, password = UnprivilegedUser(customUser, userPassword)
		groupName = UnprivilegedGroup(customGroup)
		ownership, err = EnsureUserAndGroup(username, groupName, pt, username == ElasticUsername && password == "") // force create only elastic user
		if err != nil {
			// error context already added by EnsureUserAndGroup
			return utils.FileOwner{}, err

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

	skipFn := func(relPath string) bool { return false }
	if flavor != "" {
		flavorDefinition, err := Flavor(flavor, RegistryFilePath(dir), nil)
		if err != nil {
			return utils.FileOwner{}, err
		}
		skipFn, err = SkipComponentsPathFn(paths.VersionedHome(dir), flavorDefinition)
		if err != nil {
			return utils.FileOwner{}, err
		}
	}

	err = copyFiles(copyConcurrency, pathMappings, dir, topPath, skipFn)
	if err != nil {
		pt.Describe("Error copying files")
		return utils.FileOwner{}, err
	}

	if err := markFlavor(topPath, flavor); err != nil {
		return utils.FileOwner{}, err
	}

	pt.Describe("Successfully copied files")

	// place shell wrapper, if present on platform
	if paths.ShellWrapperPath() != "" {
		pathDir := filepath.Dir(paths.ShellWrapperPath())
		err = os.MkdirAll(pathDir, 0755)
		if err != nil {
			return utils.FileOwner{}, errors.New(
				err,
				fmt.Sprintf("failed to create directory (%s) for shell wrapper (%s)", pathDir, paths.ShellWrapperPath()),
				errors.M("directory", pathDir))
		}
		// Install symlink for darwin instead of the wrapper script.
		// Elastic-agent should be first process that launchd starts in order to be able to grant
		// the Full-Disk Access (FDA) to the agent and it's child processes.
		// This is specifically important for osquery FDA permissions at the moment.
		if runtime.GOOS == darwin {
			// Check if previous shell wrapper or symlink exists and remove it so it can be overwritten
			if _, err := os.Lstat(paths.ShellWrapperPath()); err == nil {
				if err := os.Remove(paths.ShellWrapperPath()); err != nil {
					return utils.FileOwner{}, errors.New(
						err,
						fmt.Sprintf("failed to remove (%s)", paths.ShellWrapperPath()),
						errors.M("destination", paths.ShellWrapperPath()))
				}
			}
			err = os.Symlink(filepath.Join(topPath, paths.BinaryName), paths.ShellWrapperPath())
			if err != nil {
				return utils.FileOwner{}, errors.New(
					err,
					fmt.Sprintf("failed to create elastic-agent symlink (%s)", paths.ShellWrapperPath()),
					errors.M("destination", paths.ShellWrapperPath()))
			}
		} else {
			// We use strings.Replace instead of fmt.Sprintf here because, with the
			// latter, govet throws a false positive error here: "fmt.Sprintf call has
			// arguments but no formatting directives".
			shellWrapper := strings.Replace(paths.ShellWrapperFmt, "%s", topPath, -1)
			err = os.WriteFile(paths.ShellWrapperPath(), []byte(shellWrapper), 0755)
			if err != nil {
				return utils.FileOwner{}, errors.New(
					err,
					fmt.Sprintf("failed to write shell wrapper (%s)", paths.ShellWrapperPath()),
					errors.M("destination", paths.ShellWrapperPath()))
			}
		}
	}

	// post install (per platform)
	err = postInstall(topPath)
	if err != nil {
		return ownership, fmt.Errorf("error running post-install steps: %w", err)
	}

	// fix permissions
	err = perms.FixPermissions(topPath, perms.WithOwnership(ownership))
	if err != nil {
		return ownership, fmt.Errorf("failed to perform permission changes on path %s: %w", topPath, err)
	}
	if paths.ShellWrapperPath() != "" {
		err = perms.FixPermissions(paths.ShellWrapperPath(), perms.WithOwnership(ownership))
		if err != nil {
			return ownership, fmt.Errorf("failed to perform permission changes on path %s: %w", paths.ShellWrapperPath(), err)
		}
	}

	// install service
	pt.Describe("Installing service")
	err = InstallService(topPath, ownership, username, groupName, password)
	if err != nil {
		pt.Describe("Failed to install service")
		// error context already added by InstallService
		return ownership, err
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

func copyFiles(copyConcurrency int, pathMappings []map[string]string, srcDir string, topPath string, skipFn func(string) bool) error {
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
				Skip: func(srcinfo os.FileInfo, src, dest string) (bool, error) {
					relPath, err := filepath.Rel(srcDir, src)
					if err != nil {
						return false, fmt.Errorf("calculating relative path for %s: %w", src, err)
					}

					if skipFn != nil && skipFn(relPath) {
						return true, nil
					}

					return false, nil
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

			if skipFn != nil && skipFn(relPath) {
				return true, nil
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
		return fmt.Errorf("error creating new service handler for start: %w", err)
	}
	err = svc.Start()
	if err != nil {
		return fmt.Errorf("failed to start service (%s): %w", paths.ServiceName(), err)
	}
	return nil
}

// StopService stops the installed service.
func StopService(topPath string, timeout time.Duration, interval time.Duration) error {
	// only stopping the service, so no need to set the username and group to any value
	svc, err := newService(topPath)
	if err != nil {
		return fmt.Errorf("error creating new service handler for stop: %w", err)
	}
	err = svc.Stop()
	if err != nil {
		return fmt.Errorf("failed to stop service (%s): %w", paths.ServiceName(), err)
	}
	err = isStopped(timeout, interval, paths.ServiceName())
	if err != nil {
		return fmt.Errorf("failed to stop service (%s): %w", paths.ServiceName(), err)
	}
	return nil
}

// RestartService restarts the installed service.
func RestartService(topPath string) error {
	// only restarting the service, so no need to set the username and group to any value
	svc, err := newService(topPath)
	if err != nil {
		return fmt.Errorf("error creating new service handler for restart: %w", err)
	}
	err = svc.Restart()
	if err != nil {
		return fmt.Errorf("failed to restart service (%s): %w", paths.ServiceName(), err)
	}
	return nil
}

// StatusService returns the status of the service.
func StatusService(topPath string) (service.Status, error) {
	svc, err := newService(topPath)
	if err != nil {
		return service.StatusUnknown, fmt.Errorf("error creating new service handler for status: %w", err)
	}
	return svc.Status()
}

// InstallService installs the service.
func InstallService(topPath string, ownership utils.FileOwner, username string, groupName string, password string) error {
	opts, err := withServiceOptions(username, groupName, password)
	if err != nil {
		return fmt.Errorf("error getting service installation options: %w", err)
	}

	svc, err := newService(topPath, opts...)
	if err != nil {
		return fmt.Errorf("error creating new service handler for install: %w", err)
	}
	err = svc.Install()
	if err != nil {
		return fmt.Errorf("failed to install service (%s): %w", paths.ServiceName(), err)
	}
	err = serviceConfigure(ownership)
	if err != nil {
		// ignore error
		_ = svc.Uninstall()
		return fmt.Errorf("failed to configure service (%s): %w", paths.ServiceName(), err)
	}
	return nil
}

// UninstallService uninstalls the service.
func UninstallService(topPath string) error {
	svc, err := newService(topPath)
	if err != nil {
		return fmt.Errorf("error creating new service handler for uninstall: %w", err)
	}
	err = svc.Uninstall()
	if err != nil {
		return fmt.Errorf("failed to uninstall service (%s): %w", paths.ServiceName(), err)
	}
	return nil
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

func UnprivilegedUser(username, password string) (string, string) {
	if username != "" {
		return username, password
	}

	return ElasticUsername, password
}

func UnprivilegedGroup(groupName string) string {
	if groupName != "" {
		return groupName
	}

	return ElasticGroupName
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/pkg/utils"
)

var (
	// for unit-testing
	capBound   = cap.GetBound
	capGetFile = cap.GetFile
	capProc    = cap.GetProc
)

// initContainer applies the following container initialisation steps:
// - set any missing capabilities of Effective set based on the Bounding set at elastic-agent binary
// - raise capabilities of the Ambient set to match the Effective set
// - chown all agent-related paths if DAC_OVERRIDE capability is not in the Effective set
// If new binary capabilities are set then the returned cmd will be not nil. Note that it is up to caller to invoke
// the returned cmd and spawn an agent instance with all the capabilities.
func initContainer(streams *cli.IOStreams) (shouldExit bool, err error) {
	isRoot, err := utils.HasRoot()
	if err != nil {
		return true, err
	}
	if !skipFileCapabilities && !isRoot {
		executable, err := os.Executable()
		if err != nil {
			return true, err
		}

		logInfo(streams, "agent container initialisation - file capabilities")
		updated, err := updateFileCapsFromBoundingSet(executable)
		if err != nil {
			return true, err
		}

		if updated {
			// new capabilities were added thus we need to re-exec agent to pick them up
			args := []string{filepath.Base(executable)}
			if len(os.Args) > 1 {
				args = append(args, os.Args[1:]...)
			}
			// add skipFileCapabilitiesFlag flag to skip reapplying the file capabilities
			args = append(args, fmt.Sprintf("--%s", skipFileCapabilitiesFlag))

			return true, unix.Exec(executable, args, os.Environ())
		}
	}

	if !isRoot {
		// if we are not root, we need to raise the ambient capabilities
		logInfo(streams, "agent container initialisation - ambient capabilities")
		if err := raiseAmbientCapabilities(); err != nil {
			return true, err
		}
	}

	// check if we have DAC_OVERRIDE
	// Note: that even if we running under root (uid = 0), we may not have DAC_OVERRIDE which is there by default
	// ( e.g. with cap-drop: ALL). Thus, we won't be able to read/write any file that doesn't belong to us
	procSet := capProc()
	hasOverride, err := procSet.GetFlag(cap.Effective, cap.DAC_OVERRIDE)
	if err != nil {
		return true, err
	}
	if !hasOverride {
		// we need to chown all paths
		logInfo(streams, "agent container initialisation - chown paths")

		if err = chownPaths(); err != nil {
			return true, err
		}
	}

	return false, nil
}

// raiseAmbientCapabilities will attempt to raise all capabilities present in the Effective set of the running process
// to the Ambient set. Note that for security reasons CAP_CHOWN, CAP_SETPCAP, CAP_SETFCAP are excluded.
func raiseAmbientCapabilities() error {
	caps, err := getAmbientCapabilitiesFromEffectiveSet()
	if err != nil {
		return err
	}

	iab := cap.NewIAB()
	for _, capVal := range caps {
		err = iab.SetVector(cap.Inh, true, capVal)
		if err != nil {
			return fmt.Errorf("failed to set inheritable vector: %w", err)
		}
		err = iab.SetVector(cap.Amb, true, capVal)
		if err != nil {
			return fmt.Errorf("failed to set ambient vector: %w", err)
		}
	}

	return iab.SetProc()
}

// getAmbientCapabilitiesFromEffectiveSet returns the capabilities that are in the Effective set of the running process
// excluding CAP_CHOWN, CAP_SETPCAP, and CAP_SETFCAP.
func getAmbientCapabilitiesFromEffectiveSet() ([]cap.Value, error) {
	set := capProc()
	var caps []cap.Value

	for capVal := cap.Value(0); capVal < cap.MaxBits(); capVal++ {

		switch capVal {
		case cap.CHOWN, cap.SETPCAP, cap.SETFCAP:
			// don't set these as they shouldn't be required by any exec'ed child process
			continue
		default:
		}

		exists, err := set.GetFlag(cap.Effective, capVal)
		if err != nil {
			return nil, fmt.Errorf("failed to get proc effective flag: %w", err)
		}

		if !exists {
			continue
		}

		caps = append(caps, capVal)
	}

	return caps, nil
}

// updateFileCapsFromBoundingSet writes the capabilities that are missing from the given executable and are in the Bounding
// set. updated is true if the capabilities were updated. err is non-nil if an error occurred.
func updateFileCapsFromBoundingSet(executablePath string) (updated bool, err error) {
	capsText, err := getMissingBoundingCapsText(executablePath)
	if err != nil {
		return false, err
	}

	if capsText == "" {
		return false, nil
	}

	// always chown to reset S_ISUID and S_ISGID mode bits. Otherwise the setFile might get stuck.
	if err := os.Chown(executablePath, os.Getuid(), os.Getgid()); err != nil {
		return false, fmt.Errorf("failed to chown %s: %w", executablePath, err)
	}

	// create a new set based on the capabilities of Bounding set
	fileSet, err := cap.FromText(capsText)
	if err != nil {
		return false, fmt.Errorf("failed to parse caps text: %w", err)
	}

	// set the capabilities of the executable
	err = fileSet.SetFile(executablePath)
	if err != nil {
		return false, fmt.Errorf("failed to set file %s caps: %w", executablePath, err)
	}

	return true, nil
}

// getMissingBoundingCapsText returns in text representation the missing capabilities that are in the Bounding set
// and not in the Effective set.
func getMissingBoundingCapsText(executablePath string) (string, error) {
	boundCapsText := strings.Builder{}
	missingCapabilities := false

	fileCapabilities, err := capGetFile(executablePath)
	if err != nil {
		if errors.Is(err, syscall.ENODATA) {
			// no capabilities set at file level start with an empty set
			fileCapabilities = cap.NewSet()
		} else {
			return "", fmt.Errorf("failed to get file %s capabilities: %w", executablePath, err)
		}
	}

	// check all capabilities
	for capVal := cap.Value(0); capVal < cap.MaxBits(); capVal++ {

		inBound, err := capBound(capVal)
		if err != nil {
			return "", fmt.Errorf("failed to check bounding set capability: %w", err)
		}

		if !inBound {
			// not in Bounding set so skip
			continue
		}

		if boundCapsText.Len() > 0 {
			boundCapsText.WriteString(",")
		}
		boundCapsText.WriteString(capVal.String())

		inFile, err := fileCapabilities.GetFlag(cap.Effective, capVal)
		if err != nil {
			return "", fmt.Errorf("failed to check file capability: %w", err)
		}

		if !inFile {
			missingCapabilities = true
		}
	}

	if !missingCapabilities {
		// all capabilities of Bounding set are already set
		return "", nil
	}

	// eip = effective, inherited, permitted
	boundCapsText.WriteString("=eip")
	return boundCapsText.String(), nil
}

// chownPaths will chown all agent related paths to the current uid and gid.
func chownPaths() error {
	uid := os.Getuid()
	gid := os.Getgid()

	pathsToChown := distinctPaths{
		agentBaseDirectory: {},
	}

	pathsToChown.addPath(envWithDefault("", "LOGS_PATH"))
	pathsToChown.addPath(envWithDefault("", "STATE_PATH"))
	pathsToChown.addPath(envWithDefault("", "CONFIG_PATH"))
	pathsToChown.addPath(envWithDefault("", "DATA_PATH"))
	pathsToChown.addPath(envWithDefault("", "HOME_PATH"))
	return pathsToChown.chown(uid, gid)
}

// distinctPaths represents a set of paths that do not overlap.
type distinctPaths map[string]struct{}

// addPath will add the given path to the set if a parent path is not already present.
// Also, if the given path is the parent of existing entries these will be removed.
func (u distinctPaths) addPath(path string) {
	if u == nil || path == "" {
		return
	}
	for entry := range u {
		if strings.HasPrefix(path, entry) {
			// parent included in paths
			return
		}

		if strings.HasPrefix(entry, path) {
			// entry is a child of path to add so remove it
			delete(u, entry)
		}
	}

	u[path] = struct{}{}
}

// chown will chown all paths in the set to the given uid and gid.
func (u distinctPaths) chown(uid int, gid int) error {
	if u == nil {
		return nil
	}
	for entry := range u {
		err := filepath.WalkDir(entry, func(walkPath string, d fs.DirEntry, err error) error {
			if err != nil {
				return fmt.Errorf("failed to walk path %s: %w", walkPath, err)
			}

			info, err := d.Info()
			if err != nil {
				return fmt.Errorf("failed to get info of path %s: %w", walkPath, err)
			}

			sysInfo, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}

			if sysInfo.Gid == uint32(gid) && sysInfo.Uid == uint32(uid) {
				// already owned
				return nil
			}

			if err = os.Chown(walkPath, uid, gid); err != nil {
				return fmt.Errorf("failed to chown path %s: %w", walkPath, err)
			}

			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}

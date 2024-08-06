// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

// The initialization steps in this file are specifically for the elastic-agent running inside a container.
// They aim to adjust the ownership of agent-related paths to match the elastic-agent process's uid
// and elevate the process capabilities to those allowed for the container when the agent runs as non-root.
// Refer to initContainer for more details.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/elastic/elastic-agent/pkg/utils"

	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

type capProc interface {
	GetFlag(vec cap.Flag, val cap.Value) (bool, error)
	SetFlag(vec cap.Flag, enable bool, val ...cap.Value) error
	SetProc() error
}

type capBound interface {
	SetVector(vec cap.Vector, raised bool, vals ...cap.Value) error
	SetProc() error
}

var (
	// for unit-testing
	capBoundFunc = func() capBound {
		return cap.NewIAB()
	}
	// for unit-testing
	capProcFunc = func() capProc {
		return cap.GetProc()
	}
)

func logWarning(streams *cli.IOStreams, err error) {
	fmt.Fprintf(streams.Err, "Warning: %v\n", err)
}

// initContainer applies the following container initialisation steps:
//   - raises the capabilities of the Effective and Inheritable sets to match the ones in the Permitted set
//   - raises the capabilities of the Ambient set to match the ones in Effective set
//   - chown all agent-related paths
//
// Note that to avoid disrupting effects, any error is logged as a warning, but not returned.
func initContainer(streams *cli.IOStreams) {
	isRoot, err := utils.HasRoot()
	if err != nil {
		logWarning(streams, err)
		return
	}
	if !isRoot {
		// if the agent runs as a non-root user, elevate the Effective capabilities to match the Bounding set.
		// This is necessary because transitioning from the CRI process (uid 0) to the current process (non-zero uid)
		// in Linux results in an empty Effective capabilities set.
		logInfo(streams, "agent container initialisation - effective capabilities")
		if err := raiseEffectiveCapabilities(); err != nil {
			logWarning(streams, err)
			return
		}

		logInfo(streams, "agent container initialisation - ambient capabilities")
		if err := raiseAmbientCapabilities(); err != nil {
			logWarning(streams, err)
		}
	}

	// ensure all agent-related paths match the process's uid and gid to prevent access errors and
	// meet required ownership checks of underlying Beats.
	logInfo(streams, "agent container initialisation - chown paths")
	if err := chownPaths(agentBaseDirectory); err != nil {
		logWarning(streams, err)
	}
}

// raiseEffectiveCapabilities raises the capabilities of the Effective and Inheritable sets to match
// the ones in the Permitted set. Note that any capabilities that are not part of the Bounding set
// are exclude by the OS from the Permitted set.
func raiseEffectiveCapabilities() error {
	procCaps := capProcFunc()

	setProc := false

	for val := cap.Value(0); val < cap.MaxBits(); val++ {
		permittedHasCap, err := procCaps.GetFlag(cap.Permitted, val)
		if err != nil {
			return fmt.Errorf("get cap from permitted failed: %w", err)
		}
		if !permittedHasCap {
			continue
		}

		effectiveHasCap, err := procCaps.GetFlag(cap.Effective, val)
		if err != nil {
			return fmt.Errorf("get cap from effective failed: %w", err)
		}
		if !effectiveHasCap {
			err = procCaps.SetFlag(cap.Effective, true, val)
			if err != nil {
				return fmt.Errorf("set cap to permitted failed: %w", err)
			}
			setProc = true
		}

		inheritableHasCap, err := procCaps.GetFlag(cap.Inheritable, val)
		if err != nil {
			return fmt.Errorf("get cap from effective failed: %w", err)
		}
		if !inheritableHasCap {
			err = procCaps.SetFlag(cap.Inheritable, true, val)
			if err != nil {
				return fmt.Errorf("set cap to inheritable failed: %w", err)
			}
			setProc = true
		}
	}

	if !setProc {
		return nil
	}

	if err := procCaps.SetProc(); err != nil {
		return fmt.Errorf("set proc failed: %w", err)
	}

	return nil
}

// raiseAmbientCapabilities raises all capabilities present in the Effective set of the current process
// to the Ambient set excluding CAP_SETPCAP, and CAP_SETFCAP.
func raiseAmbientCapabilities() error {
	var caps []cap.Value
	procCaps := capProcFunc()

	effectiveHasSETPCAP := false

	for capVal := cap.Value(0); capVal < cap.MaxBits(); capVal++ {

		exists, err := procCaps.GetFlag(cap.Effective, capVal)
		if err != nil {
			return fmt.Errorf("failed to get proc effective flag: %w", err)
		}

		if !exists {
			continue
		}

		if capVal == cap.SETPCAP {
			effectiveHasSETPCAP = true
		}

		switch capVal {
		case cap.SETPCAP, cap.SETFCAP:
			// don't set these as they shouldn't be required by any spawned child process
			continue
		default:
		}

		caps = append(caps, capVal)
	}

	if len(caps) == 0 {
		return nil
	}

	if !effectiveHasSETPCAP {
		return errors.New("failed to set ambient vector: missing SETPCAP capability")
	}

	iab := capBoundFunc()
	for _, capVal := range caps {
		if err := iab.SetVector(cap.Amb, true, capVal); err != nil {
			return fmt.Errorf("failed to set ambient vector: %w", err)
		}

		if err := iab.SetVector(cap.Inh, true, capVal); err != nil {
			return fmt.Errorf("failed to set ambient vector: %w", err)
		}
	}

	return iab.SetProc()
}

// chownPaths will chown all agent related paths to the current uid and gid.
func chownPaths(agentBaseDirectory string) error {
	uid := os.Getuid()
	gid := os.Getgid()

	procCaps := capProcFunc()
	hasChown, err := procCaps.GetFlag(cap.Effective, cap.CHOWN)
	if err != nil {
		return fmt.Errorf("failed to get chown flag: %w", err)
	}
	if !hasChown {
		hasDacOverride, err := procCaps.GetFlag(cap.Effective, cap.DAC_OVERRIDE)
		if err != nil {
			return fmt.Errorf("failed to get dac_override flag: %w", err)
		}
		if !hasDacOverride {
			return errors.New("cannot chown agent paths without CAP_CHOWN or CAP_DAC_OVERRIDE capabilities")
		}
	}

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

			if info.Mode()&fs.ModeSymlink != 0 {
				if err = os.Lchown(walkPath, uid, gid); err != nil {
					return fmt.Errorf("failed to chown path %s: %w", walkPath, err)
				}
			}

			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}

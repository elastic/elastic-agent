// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package reexec

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// The following are overridable in tests so the re-exec preconditions can be
// exercised without manipulating the real process/installation state.
var (
	runningInstalled       = paths.RunningInstalled
	runningUnderSupervisor = info.RunningUnderSupervisor
	releaseUpgradeable     = release.Upgradeable
)

// CanReExec reports the checks shared by every action that re-executes the agent
// process (RESTART, UPGRADE): the process must be running under the control of
// the system supervisor (systemd/launchd/Windows service) so the re-execution is
// recovered. It is composed by CanRestart and CanUpgrade rather than used
// directly, so that action-specific preconditions live next to the shared one.
func CanReExec() bool {
	return runningUnderSupervisor()
}

// CanRestart reports whether a RESTART action can be performed. A restart has no
// preconditions beyond the shared ones (CanReExec): it re-executes the current
// binary in place without touching the installation layout, so a supervised
// agent can be restarted regardless of how it was deployed — the install
// sub-command, a DEB or an RPM package. Unsupervised processes (a bare
// interactive binary, or an agent running as PID 1 in a container) are excluded
// because a re-execution there would not be recovered by a supervisor.
func CanRestart() bool {
	return CanReExec()
}

// CanUpgrade reports whether an UPGRADE action can be performed. In addition to
// the shared re-exec checks, an upgrade needs the installed layout (the
// versioned directories, top-level symlink and upgrade watcher) created by the
// install sub-command, so it is restricted to agents installed that way. A build
// compiled specifically with upgrading enabled is always considered upgradeable.
func CanUpgrade() bool {
	return releaseUpgradeable() || (runningInstalled() && CanReExec())
}

// ExecManager is the interface that the global reexec manager implements.
type ExecManager interface {
	// ReExec asynchronously re-executes command in the same PID and memory address
	// as the currently running application.
	ReExec(callback ShutdownCallbackFn, argOverrides ...string)

	// ShutdownChan returns the shutdown channel the main function should use to
	// handle shutdown of the current running application.
	ShutdownChan() <-chan bool

	// ShutdownComplete gets called from the main function once ShutdownChan channel
	// has been closed and the running application has completely shutdown.
	ShutdownComplete()
}

type manager struct {
	logger   *logger.Logger
	exec     string
	trigger  chan bool
	shutdown chan bool
	complete chan bool
}

// ShutdownCallbackFn is called once everything is shutdown and allows cleanup during reexec process.
type ShutdownCallbackFn func() error

// NewManager returns the reexec manager.
func NewManager(log *logger.Logger, exec string) ExecManager {
	return &manager{
		logger:   log,
		exec:     exec,
		trigger:  make(chan bool),
		shutdown: make(chan bool),
		complete: make(chan bool),
	}
}

func (m *manager) ReExec(shutdownCallback ShutdownCallbackFn, argOverrides ...string) {
	go func() {
		m.logger.Debug("Triggering manager shutdown")
		close(m.trigger)
		<-m.shutdown
		m.logger.Debug("Manager shutdown complete")

		if shutdownCallback != nil {
			if err := shutdownCallback(); err != nil {
				// panic; because there is no going back, everything is shutdown
				panic(errors.New(errors.TypeUnexpected, err, "failure occurred during shutdown cleanup"))
			}
		}

		if err := reexec(m.logger, m.exec, argOverrides...); err != nil {
			// panic; because there is no going back, everything is shutdown
			panic(err)
		}

		close(m.complete)
	}()
}

func (m *manager) ShutdownChan() <-chan bool {
	return m.trigger
}

func (m *manager) ShutdownComplete() {
	close(m.shutdown)
	<-m.complete
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

var (
	// ErrAgentUninstall error for when the Elastic Agent has been uninstalled
	ErrAgentUninstall = errors.New("Elastic Agent was uninstalled")
)

// InstallChecker checks for removal of the Elastic Agent.
type InstallChecker struct {
	notifyChan    chan error
	log           *logger.Logger
	checkInterval time.Duration
}

// NewInstallChecker creates a new install checker.
func NewInstallChecker(ch chan error, log *logger.Logger, checkInterval time.Duration) (*InstallChecker, error) {
	c := &InstallChecker{
		notifyChan:    ch,
		log:           log,
		checkInterval: checkInterval,
	}
	return c, nil
}

// Run runs the checking loop.
func (ch *InstallChecker) Run(ctx context.Context) {
	ch.log.Debug("Install checker started")
	for {
		t := time.NewTimer(ch.checkInterval)

		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
			status, reason := install.Status(paths.Top())
			if status == install.Installed {
				ch.log.Debug("retrieve service status: installed")
				continue
			}
			ch.notifyChan <- fmt.Errorf("%w: %s", ErrAgentUninstall, reason)
			t.Stop()
			return
		}
	}
}

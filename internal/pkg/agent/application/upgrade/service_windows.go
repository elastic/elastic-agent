// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package upgrade

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	winsvc "golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

const (
	// delay after agent restart is performed to allow agent to tear down all the processes
	// important mainly for windows, as it prevents removing files which are in use
	afterRestartDelay = 15 * time.Second
)

func newServiceHandler() (serviceHandler, error) {
	mgr, err := mgr.Connect()
	if err != nil {
		return nil, errors.New("failed to initiate service manager", err)
	}

	return &pidProvider{
		winManager: mgr,
	}, nil
}

type pidProvider struct {
	winManager *mgr.Mgr
}

func (p *pidProvider) Close() {}

func (p *pidProvider) Name() string { return "Windows Service Manager" }

func (p *pidProvider) PID(ctx context.Context) (int, error) {
	svc, err := p.winManager.OpenService(paths.ServiceName)
	if err != nil {
		return 0, errors.New("failed to read windows service", err)
	}

	status, err := svc.Query()
	if err != nil {
		return 0, errors.New("failed to read windows service PID: %v", err)
	}

	return int(status.ProcessId), nil
}

func (p *pidProvider) Restart(ctx context.Context) error {
	svc, err := p.winManager.OpenService(paths.ServiceName)
	if err != nil {
		return fmt.Errorf("failed to read windows service: %w", err)
	}

	// AFAICT, there's no way to directly/atomically restart a windows service.
	// So we do a stop followed by a start instead.
	if _, err := svc.Control(winsvc.Stop); err != nil {
		return fmt.Errorf(
			"failed to stop service %s using %s as part of restarting it: %w",
			paths.ServiceName, p.Name(), err,
		)
	}

	if err := svc.Start(); err != nil {
		return fmt.Errorf(
			"failed to start service %s using %s as part of restarting it: %w",
			paths.ServiceName, p.Name(), err,
		)
	}

	return nil
}

func invokeCmd() *exec.Cmd {
	// #nosec G204 -- user cannot inject any parameters to this command
	cmd := exec.Command(paths.TopBinaryPath(), watcherSubcommand,
		"--path.config", paths.Config(),
		"--path.home", paths.Top(),
	)
	return cmd
}

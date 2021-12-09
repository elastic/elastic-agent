// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// +build windows

package upgrade

import (
	"context"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc/mgr"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/errors"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/logger"
)

const (
	// delay after agent restart is performed to allow agent to tear down all the processes
	// important mainly for windows, as it prevents removing files which are in use
	afterRestartDelay = 15 * time.Second
)

// Init initializes os dependent properties.
func (ch *CrashChecker) Init(ctx context.Context, _ *logger.Logger) error {
	mgr, err := mgr.Connect()
	if err != nil {
		return errors.New("failed to initiate service manager", err)
	}

	ch.sc = &pidProvider{
		winManager: mgr,
	}

	return nil
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

func invokeCmd(topPath string) *exec.Cmd {
	homeExePath := filepath.Join(topPath, agentName)

	cmd := exec.Command(homeExePath, watcherSubcommand,
		"--path.config", paths.Config(),
		"--path.home", paths.Top(),
	)

	return cmd
}

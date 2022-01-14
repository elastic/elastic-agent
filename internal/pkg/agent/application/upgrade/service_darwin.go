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

// +build darwin

package upgrade

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/go-multierror"

	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent-poc/internal/pkg/core/logger"
	"github.com/elastic/elastic-agent-poc/internal/pkg/release"
)

const (
	// delay after agent restart is performed to allow agent to tear down all the processes
	// important mainly for windows, as it prevents removing files which are in use
	afterRestartDelay = 2 * time.Second
)

// Init initializes os dependent properties.
func (ch *CrashChecker) Init(ctx context.Context, _ *logger.Logger) error {
	ch.sc = &darwinPidProvider{}

	return nil
}

type darwinPidProvider struct{}

func (p *darwinPidProvider) Name() string { return "launchd" }

func (p *darwinPidProvider) Close() {}

func (p *darwinPidProvider) PID(ctx context.Context) (int, error) {
	piders := []func(context.Context) (int, error){
		p.piderFromCmd(ctx, "launchctl", "list", paths.ServiceName),
	}

	// if release is specifically built to be upgradeable (using DEV flag)
	// we dont require to run as a service and will need sudo fallback
	if release.Upgradeable() {
		piders = append(piders, p.piderFromCmd(ctx, "sudo", "launchctl", "list", paths.ServiceName))
	}

	var pidErrors error
	for _, pider := range piders {
		pid, err := pider(ctx)
		if err == nil {
			return pid, nil
		}

		pidErrors = multierror.Append(pidErrors, err)
	}

	return 0, pidErrors
}

func (p *darwinPidProvider) piderFromCmd(ctx context.Context, name string, args ...string) func(context.Context) (int, error) {
	return func(context.Context) (int, error) {
		listCmd := exec.Command(name, args...)
		listCmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: 0, Gid: 0},
		}
		out, err := listCmd.Output()
		if err != nil {
			return 0, errors.New("failed to read process id", err)
		}

		// find line
		pidLine := ""
		reader := bufio.NewReader(bytes.NewReader(out))
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, `"PID" = `) {
				pidLine = strings.TrimSpace(line)
				break
			}
		}

		if pidLine == "" {
			return 0, errors.New(fmt.Sprintf("service process not found for service '%v'", paths.ServiceName))
		}

		re := regexp.MustCompile(`"PID" = ([0-9]+);`)
		matches := re.FindStringSubmatch(pidLine)
		if len(matches) != 2 {
			return 0, errors.New("could not detect pid of process", pidLine, matches)
		}

		pid, err := strconv.Atoi(matches[1])
		if err != nil {
			return 0, errors.New(fmt.Sprintf("failed to get process id[%v]", matches[1]), err)
		}

		return pid, nil
	}
}

func invokeCmd(topPath string) *exec.Cmd {
	homeExePath := filepath.Join(topPath, agentName)

	cmd := exec.Command(homeExePath, watcherSubcommand,
		"--path.config", paths.Config(),
		"--path.home", paths.Top(),
	)

	var cred = &syscall.Credential{
		Uid:         uint32(os.Getuid()),
		Gid:         uint32(os.Getgid()),
		Groups:      nil,
		NoSetGroups: true,
	}
	var sysproc = &syscall.SysProcAttr{
		Credential: cred,
		Setsid:     true,
	}
	cmd.SysProcAttr = sysproc
	return cmd
}

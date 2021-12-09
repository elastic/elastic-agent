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

package cmd

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/errors"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/cli"
)

func newReExecWindowsCommand(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Hidden: true,
		Use:    "reexec_windows <service_name> <pid>",
		Short:  "ReExec the windows service",
		Long:   "This waits for the windows service to stop then restarts it to allow self-upgrading.",
		Args:   cobra.ExactArgs(2),
		Run: func(c *cobra.Command, args []string) {
			serviceName := args[0]
			servicePid, err := strconv.Atoi(args[1])
			if err != nil {
				fmt.Fprintf(streams.Err, "%v\n", err)
				os.Exit(1)
			}
			err = reExec(serviceName, servicePid)
			if err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
		},
	}

	return cmd
}

func reExec(serviceName string, servicePid int) error {
	manager, err := mgr.Connect()
	if err != nil {
		return errors.New(err, "failed to connect to service manager")
	}
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return errors.New(err, "failed to open service")
	}
	for {
		status, err := service.Query()
		if err != nil {
			return errors.New(err, "failed to query service")
		}
		if status.State == svc.Stopped {
			err = service.Start()
			if err != nil {
				return errors.New(err, "failed to start service")
			}
			// triggered restart; done
			return nil
		}
		if int(status.ProcessId) != servicePid {
			// already restarted; has different PID, done!
			return nil
		}
		<-time.After(300 * time.Millisecond)
	}
}

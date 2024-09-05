// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package cmd

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

const (
	reexecName = "elastic-agent-reexec"
)

func newReExecWindowsCommand(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Hidden: true,
		Use:    "reexec_windows <service_name> <pid>",
		Short:  "ReExec the windows service",
		Long:   "This waits for the windows service to stop then restarts it to allow self-upgrading.",
		Args:   cobra.ExactArgs(2),
		Run: func(c *cobra.Command, args []string) {
			cfg := getConfig(streams)
			log, err := configuredLogger(cfg, reexecName)
			if err != nil {
				fmt.Fprintf(streams.Err, "Error configuring logger: %v\n%s\n", err, troubleshootMessage())
				os.Exit(3)
			}

			// Make sure to flush any buffered logs before we're done.
			defer log.Sync() //nolint:errcheck // flushing buffered logs is best effort.

			serviceName := args[0]
			servicePid, err := strconv.Atoi(args[1])
			if err != nil {
				log.Errorw("reexec failed", "error.message", err)
				fmt.Fprintf(streams.Err, "reexec failed: %v\n", err)
				os.Exit(1)
			}
			reExec(log, serviceName, servicePid, streams.Err)
		},
	}

	return cmd
}

func reExec(log *logp.Logger, serviceName string, servicePid int, writer io.Writer) {
	for {
		ready, err := ensureAnotherProcess(log, serviceName, servicePid)
		if err == nil && ready {
			// all done
			// success is logged in the ensureAnotherProcess with more detail
			return
		}
		if err != nil {
			log.Errorw("failed to ensure another service process was spawned; will retry in 0.3 seconds", "error.message", err)
			_, _ = fmt.Fprintf(writer, "failed to ensure another service process was spawned; will retry in 0.3 seconds: %s", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func ensureAnotherProcess(log *logp.Logger, serviceName string, servicePid int) (bool, error) {
	status, err := getServiceState(serviceName)
	if err != nil {
		return false, err
	}
	log.Infof("current state for service(%s); state: %d [pid: %d]", serviceName, status.State, status.ProcessId)

	if status.State == svc.Running && status.ProcessId != 0 && int(status.ProcessId) != servicePid {
		// running and it's a different process
		log.Infof("reexec complete; running and with a different PID (%d != %d)", servicePid, status.ProcessId)
		return true, nil
	}

	if status.State == svc.Stopped {
		// fully stopped
		log.Infof("service is completely stopped; starting the service")
		err = startService(serviceName)
		return false, err
	}

	// not stopped and not running as a different PID, just wait
	return false, nil
}

// getServiceState gets the current state from the service manager.
//
// Connects to the manager on every check to ensure that the correct ACL's are applied at the time.
func getServiceState(serviceName string) (svc.Status, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return svc.Status{}, fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer func() {
		_ = manager.Disconnect()
	}()

	service, err := manager.OpenService(serviceName)
	if err != nil {
		return svc.Status{}, fmt.Errorf("failed to open service: %w", err)
	}
	defer service.Close()

	status, err := service.Query()
	if err != nil {
		return svc.Status{}, fmt.Errorf("failed to query service: %w", err)
	}
	return status, nil
}

// startService starts the service.
//
// Connects to the manager on every check to ensure that the correct ACL's are applied at the time.
func startService(serviceName string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer func() {
		_ = manager.Disconnect()
	}()

	service, err := manager.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("failed to open service: %w", err)
	}
	defer service.Close()

	err = service.Start()
	if err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}
	return nil
}

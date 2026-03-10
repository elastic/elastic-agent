// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/elastic/elastic-agent-libs/logp"
)

// isStopped queries the Windows service manager to see if the state
// of the service is stopped.  It will repeat the query every
// 'interval' until the 'timeout' is reached.  It returns nil if the
// system is stopped within the timeout period.  An error is returned
// if the service doesn't stop before the timeout or if there are
// errors communicating with the service manager.
func isStopped(log *logp.Logger, timeout time.Duration, interval time.Duration, service string) error {
	var err error
	var status svc.Status

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer func() {
		_ = m.Disconnect()
	}()

	s, err := m.OpenService(service)
	if err != nil {
		return fmt.Errorf("failed to open service (%s): %w", service, err)
	}
	defer s.Close()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var pid uint32
	startTime := time.Now()
	for {
		select {
		case <-ticker.C:
			status, err = s.Query()
			if err != nil {
				return fmt.Errorf("error querying service (%s): %w", service, err)
			}
			if status.ProcessId != 0 {
				pid = status.ProcessId
			}
			if status.State == svc.Stopped {
				timeElapsed := time.Since(startTime)
				remainingTimeout := timeout - timeElapsed
				return waitForProcessExit(log, pid, remainingTimeout)
			}
		case <-timer.C:
			return fmt.Errorf("timed out after %s waiting for service (%s) to stop, last state was: %d", timeout, service, status.State)
		}
	}
}

// waitForProcessExit waits for the process with the given PID to exit.
// On Windows, the service can report as stopped while the process is still
// alive (the SCM marks it stopped when the service handler returns, but the
// process may still be running cleanup code). This ensures the process has
// fully exited before we attempt to remove its files.
func waitForProcessExit(log *logp.Logger, pid uint32, timeout time.Duration) error {
	if pid == 0 {
		return nil
	}

	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		// Process is already gone or we can't open it — either way, proceed.
		log.Debugf("could not open process %d to wait for exit (likely already exited): %v", pid, err)
		return nil
	}
	defer func() {
		if closeErr := windows.CloseHandle(h); closeErr != nil {
			log.Infof("failed to close process handle: %v", closeErr)
		}
	}()

	log.Infof("service stopped but process %d is still alive, waiting for it to exit", pid)

	timeoutMs := uint32(timeout.Milliseconds()) //nolint: gosec // this timeout is around a minute in practice
	event, err := windows.WaitForSingleObject(h, timeoutMs)
	if err != nil {
		return fmt.Errorf("error waiting for process %d: %w", pid, err)
	}
	switch event {
	case windows.WAIT_ABANDONED, windows.WAIT_FAILED:
		return fmt.Errorf("waiting for process %d to exit failed", pid)
	case windows.WAIT_OBJECT_0:
	default:
		return fmt.Errorf("unexpected return value from WaitForSingleObject on process %d: %d", pid, event)
	}

	return nil
}

// EnsureServiceRemoved opens the Windows service manager and checks if the
// service is removed. It will repeat this check every 'interval'
// until the 'timeout' is reached.  It returns nil if the service
// is removed within the timeout period.  An error is returned if
// the service is not removed before the timeout or if there are
// errors communicating with the service manager.
func EnsureServiceRemoved(timeout time.Duration, interval time.Duration, service string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer func() {
		_ = m.Disconnect()
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-ticker.C:
			s, err := m.OpenService(service)
			if s != nil {
				_ = s.Close()
			}
			switch {
			case err == nil:
				// The service is still installed continue waiting
				continue
			case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
				// The service is no longer installed
				return nil
			default:
				// An unknown error occurred trying to open the service
				return fmt.Errorf("error opening service (%s): %w", service, err)
			}
		case <-timer.C:
			return fmt.Errorf("timed out after %s waiting for service (%s) to uninstall", timeout, service)
		}
	}
}

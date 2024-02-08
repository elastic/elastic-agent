// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package install

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// isStopped queries the Windows service manager to see if the state of the service is stopped.
// it will repeat the query every every 'interval' until the 'timeout' is reached.  It returns
// nil if the system is stopped within the timeout period, and an error if it isn't.
func isStopped(timeout time.Duration, interval time.Duration, service string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer func() {
		err := m.Disconnect()
		if err != nil {
			return fmt.Errorf("failed to disconnect from service manager: %w", err)
		}
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

	for {
		select {
		case <-ticker.C:
			status, err := s.Query()
			if err != nil {
				return fmt.Errorf("error querying service (%s): %w", service, err)
			}
			if status.State == svc.Stopped {
				return nil
			}
		case <-timer.C:
			return fmt.Errorf("timed out waiting for service (%s) to stop", service)
		}
	}
}

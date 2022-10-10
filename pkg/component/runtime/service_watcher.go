// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"errors"
	"time"

	"github.com/kardianos/service"
)

const (
	defaultCheckInterval = 10 * time.Second
	defaultCheckDuration = 3 * time.Minute
)

type statusCheckResult struct {
	Status service.Status
	Err    error
}

type serviceWatcher struct {
	svc           service.Service
	statusCh      chan statusCheckResult
	checkInterval time.Duration
	checkDuration time.Duration
	stopOnError   bool

	lastStatusCheckResult statusCheckResult

	// The github.com/kardianos/service library sometimes returns service.ErrNotInstalled error
	// while the service transitioning from running to stopped, found during testing on linux
	// Capture the last error separately in order to perform another watch loop pass if this happens
	lastStatusCheckError error
}

func getService(name string) (service.Service, error) {
	svcConfig := &service.Config{
		Name: name,
	}

	return service.New(nil, svcConfig)
}

func newServiceWatcher(name string) (*serviceWatcher, error) {
	svc, err := getService(name)
	if err != nil {
		return nil, err
	}

	return &serviceWatcher{
		svc:           svc,
		statusCh:      make(chan statusCheckResult),
		checkInterval: defaultCheckInterval,
		checkDuration: defaultCheckDuration,
		stopOnError:   true,
	}, nil
}

func (s *serviceWatcher) run(ctx context.Context) {
	start := time.Now()
	t := time.NewTicker(s.checkInterval)
	defer t.Stop()
	defer close(s.statusCh)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if time.Since(start) > s.checkDuration {
				return
			}

			status, err := s.svc.Status()

			if err != nil {
				if s.lastStatusCheckError == nil && errors.Is(err, service.ErrNotInstalled) {
					s.lastStatusCheckError = err
					break
				}
			}
			s.lastStatusCheckError = err

			// Send status check result if it changed
			if s.lastStatusCheckResult.Status != status || !errors.Is(err, s.lastStatusCheckResult.Err) {
				res := statusCheckResult{
					Status: status,
					Err:    err,
				}
				select {
				case s.statusCh <- res:
				case <-ctx.Done():
					return
				}
				s.lastStatusCheckResult = res
			}
			if err != nil && s.stopOnError {
				return
			}
		}
	}
}

func (s *serviceWatcher) status() <-chan statusCheckResult {
	return s.statusCh
}

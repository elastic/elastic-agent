// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package service

import (
	"context"
	"time"

	"github.com/kardianos/service"
)

const (
	defaultCheckInterval = 10 * time.Second
	defaultCheckDuration = 3 * time.Minute
)

type statusCheckResult struct {
	status service.Status
	err    error
}

type serviceWatcher struct {
	svc           service.Service
	statusCh      chan statusCheckResult
	checkInterval time.Duration
	checkDuration time.Duration
	stopOnError   bool
}

func newServiceWatcher(name string) (*serviceWatcher, error) {
	svcConfig := &service.Config{
		Name: name,
	}

	svc, err := service.New(nil, svcConfig)
	if err != nil {
		return nil, err
	}

	return &serviceWatcher{
		svc:           svc,
		statusCh:      make(chan statusCheckResult),
		checkInterval: defaultCheckInterval,
		checkDuration: defaultCheckDuration,
		stopOnError:   false,
	}, nil
}

func (s *serviceWatcher) run(ctx context.Context) {
	start := time.Now()
	t := time.NewTimer(s.checkInterval)
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

			select {
			case s.statusCh <- statusCheckResult{
				status: status,
				err:    err,
			}:
			case <-ctx.Done():
				return
			}

			if s.stopOnError {
				return
			}
			t.Reset(s.checkInterval)
		}
	}
}

func (s *serviceWatcher) status() <-chan statusCheckResult {
	return s.statusCh
}

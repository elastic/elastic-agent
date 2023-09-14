// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	evaluatedPeriods = 6 // with 10s period this means we evaluate 60s of agent run
	crashesAllowed   = 2 // means that within 60s one restart is allowed, additional one is considered crash
)

type serviceHandler interface {
	PID(ctx context.Context) (int, error)
	Name() string
	Close()
}

// CrashChecker checks agent for crash pattern in Elastic Agent lifecycle.
type CrashChecker struct {
	notifyChan    chan error
	q             *disctintQueue
	log           *logger.Logger
	sc            serviceHandler
	checkInterval time.Duration
}

// NewCrashChecker creates a new crash checker.
func NewCrashChecker(ctx context.Context, ch chan error, log *logger.Logger, checkInterval time.Duration) (*CrashChecker, error) {
	q, err := newDistinctQueue(evaluatedPeriods)
	if err != nil {
		return nil, err
	}

	c := &CrashChecker{
		notifyChan:    ch,
		q:             q,
		log:           log,
		checkInterval: checkInterval,
	}

	if err := c.Init(ctx, log); err != nil {
		return nil, err
	}

	log.Infof("running checks using '%s' controller", c.sc.Name())

	return c, nil
}

// Run runs the checking loop.
func (ch *CrashChecker) Run(ctx context.Context) {
	defer ch.sc.Close()

	ch.log.Info("Crash checker started")
	for {
		t := time.NewTimer(ch.checkInterval)

		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
			pid, err := ch.sc.PID(ctx)
			if err != nil {
				ch.log.Error(err)
			}

			ch.q.Push(pid)
			restarts := ch.q.Distinct()
			ch.log.Infof("retrieved service PID [%d] changed %d times within %d", pid, restarts, evaluatedPeriods)
			if restarts > crashesAllowed {
				ch.notifyChan <- errors.New(fmt.Sprintf("service restarted '%d' times within '%v' seconds", restarts, ch.checkInterval.Seconds()))
			}
		}
	}
}

type disctintQueue struct {
	q    []int
	size int
	lock sync.Mutex
}

func newDistinctQueue(size int) (*disctintQueue, error) {
	if size < 1 {
		return nil, errors.New("invalid size", errors.TypeUnexpected)
	}
	return &disctintQueue{
		q:    make([]int, 0, size),
		size: size,
	}, nil
}

func (dq *disctintQueue) Push(id int) {
	dq.lock.Lock()
	defer dq.lock.Unlock()

	cutIdx := len(dq.q)
	if dq.size-1 < len(dq.q) {
		cutIdx = dq.size - 1
	}
	dq.q = append([]int{id}, dq.q[:cutIdx]...)
}

func (dq *disctintQueue) Distinct() int {
	dq.lock.Lock()
	defer dq.lock.Unlock()

	dm := make(map[int]int)

	for _, id := range dq.q {
		dm[id] = 1
	}

	return len(dm)
}

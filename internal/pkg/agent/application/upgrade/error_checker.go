// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/elastic/elastic-agent/pkg/control"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"

	"github.com/hashicorp/go-multierror"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	statusCheckMissesAllowed = 4 // enable 2 minute start
	evaluatedPeriods         = 2 // with 30s period this means we evaluate 60s of agent run
	crashesAllowed           = 2 // means that within 60s one restart is allowed, additional one is considered crash
)

// ErrAgentStatusFailed is returned when agent reports FAILED status.
var ErrAgentStatusFailed = errors.New("agent in a failed state", errors.TypeApplication)

// ErrorChecker checks agent for status change and sends an error to a channel if found.
type ErrorChecker struct {
	failuresCounter int
	notifyChan      chan error
	log             *logger.Logger
	agentClient     client.Client
	checkInterval   time.Duration
	pidQueue        *distinctQueue
}

// NewErrorChecker creates a new error checker.
func NewErrorChecker(ch chan error, log *logger.Logger, checkInterval time.Duration) (*ErrorChecker, error) {
	q, err := newDistinctQueue(evaluatedPeriods)
	if err != nil {
		return nil, err
	}

	c := client.New()
	ec := &ErrorChecker{
		notifyChan:    ch,
		agentClient:   c,
		log:           log,
		checkInterval: checkInterval,
		pidQueue:      q,
	}

	return ec, nil
}

// Run runs the checking loop.
func (ch *ErrorChecker) Run(ctx context.Context) {
	ch.log.Info("Error checker started")
	for {
		t := time.NewTimer(ch.checkInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
			err := ch.agentClient.Connect(ctx)
			if err != nil {
				ch.failuresCounter++
				ch.log.Error(err, "Failed communicating to running daemon", errors.TypeNetwork, errors.M("socket", control.Address()))
				ch.checkFailures()

				continue
			}

			state, err := ch.agentClient.State(ctx)
			ch.agentClient.Disconnect()
			if err != nil {
				ch.log.Error("failed retrieving agent status", err)
				ch.failuresCounter++
				ch.checkFailures()

				// agent is probably not running and this will be detected by pid watcher
				continue
			}

			// call was successful, reset counter
			ch.failuresCounter = 0

			if state.State == client.Failed {
				ch.log.Error("error checker notifying failure of agent")
				ch.notifyChan <- ErrAgentStatusFailed
			}

			for _, comp := range state.Components {
				if comp.State == client.Failed {
					err = multierror.Append(err, errors.New(fmt.Sprintf("component %s[%v] failed: %s", comp.Name, comp.ID, comp.Message)))
				}
			}

			if err != nil {
				ch.log.Error("error checker notifying failure of applications")
				ch.notifyChan <- errors.New(err, "applications in a failed state", errors.TypeApplication)
			}

			// add PID to queue
			ch.pidQueue.Push(state.Info.PID)
			ch.checkRestarted()
		}
	}
}

func (ch *ErrorChecker) checkFailures() {
	if failures := ch.failuresCounter; failures > statusCheckMissesAllowed {
		ch.notifyChan <- errors.New(fmt.Sprintf("service failed to fetch agent status '%d' times in a row", failures))
	}
}

// checkRestarted checks if the PID reported for the Agent process has
// changed more than crashesAllowed times. If so, it decides that the service
// has crashed.
func (ch *ErrorChecker) checkRestarted() {
	restarts := ch.pidQueue.Distinct()
	ch.log.Debugf("PID changed %d times within %d evaluations", restarts, evaluatedPeriods)

	if restarts > crashesAllowed {
		msg := fmt.Sprintf("restarted '%d' times within '%v' seconds", restarts, ch.checkInterval.Seconds())
		ch.notifyChan <- errors.New(msg)
	}
}

type distinctQueue struct {
	q    []int
	size int
	lock sync.Mutex
}

func newDistinctQueue(size int) (*distinctQueue, error) {
	if size < 1 {
		return nil, errors.New("invalid size", errors.TypeUnexpected)
	}
	return &distinctQueue{
		q:    make([]int, 0, size),
		size: size,
	}, nil
}

func (dq *distinctQueue) Push(id int) {
	dq.lock.Lock()
	defer dq.lock.Unlock()

	cutIdx := len(dq.q)
	if dq.size-1 < len(dq.q) {
		cutIdx = dq.size - 1
	}
	dq.q = append([]int{id}, dq.q[:cutIdx]...)
}

func (dq *distinctQueue) Distinct() int {
	dq.lock.Lock()
	defer dq.lock.Unlock()

	dm := make(map[int]int)

	for _, id := range dq.q {
		dm[id] = 1
	}

	return len(dm)
}

func (dq *distinctQueue) Len() int {
	return len(dq.q)
}

func (dq *distinctQueue) Peek(size int) []int {
	if size > len(dq.q) {
		size = len(dq.q)
	}

	return dq.q[:size]
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"
	"time"

	"github.com/elastic/elastic-agent/pkg/control"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"

	"github.com/hashicorp/go-multierror"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	statusCheckMissesAllowed = 4 // enable 2 minute start
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
}

// NewErrorChecker creates a new error checker.
func NewErrorChecker(ch chan error, log *logger.Logger, checkInterval time.Duration) (*ErrorChecker, error) {
	c := client.New()
	ec := &ErrorChecker{
		notifyChan:    ch,
		agentClient:   c,
		log:           log,
		checkInterval: checkInterval,
	}

	return ec, nil
}

// Run runs the checking loop.
func (ch *ErrorChecker) Run(ctx context.Context) {
	ch.log.Debug("Error checker started")
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
		}
	}
}

func (ch *ErrorChecker) checkFailures() {
	if failures := ch.failuresCounter; failures > statusCheckMissesAllowed {
		ch.notifyChan <- errors.New(fmt.Sprintf("service failed to fetch agent status '%d' times in a row", failures))
	}
}

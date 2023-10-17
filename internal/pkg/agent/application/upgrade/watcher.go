// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	statusCheckMissesAllowed      = 4 // enable 2 minute start (30 second periods)
	statusLossesAllowed           = 2 // enable connection lost to agent twice
	statusFailureFlipFlopsAllowed = 3 // no more than three failure flip-flops allowed
)

var (
	// ErrCannotConnect is returned when connection cannot be made to the agent.
	ErrCannotConnect = errors.New("failed to connect to agent daemon")
	// ErrLostConnection is returned when connection is lost to the agent daemon.
	ErrLostConnection = errors.New("lost connection to agent daemon")
	// ErrAgentStatusFailed is returned when agent reports FAILED status.
	ErrAgentStatusFailed = errors.New("agent reported failed state")
	// ErrAgentComponentFailed is returned when agent reports FAILED status for a component
	ErrAgentComponentFailed = errors.New("agent reported failed component(s) state")
	// ErrAgentFlipFlopFailed is returned when agent flip-flops between failed and healthy.
	ErrAgentFlipFlopFailed = errors.New("agent reported on and off failures ")
)

// AgentWatcher watches for the ability to connect to the running Elastic Agent, if it reports any errors
// and how many times it disconnects from the Elastic Agent while running.
type AgentWatcher struct {
	connectCounter int
	lostCounter    int

	notifyChan    chan error
	log           *logger.Logger
	agentClient   client.Client
	checkInterval time.Duration
}

// NewAgentWatcher creates a new agent watcher.
func NewAgentWatcher(ch chan error, log *logger.Logger, checkInterval time.Duration) *AgentWatcher {
	c := client.New()
	ec := &AgentWatcher{
		notifyChan:    ch,
		agentClient:   c,
		log:           log,
		checkInterval: checkInterval,
	}
	return ec
}

// Run runs the checking loop.
func (ch *AgentWatcher) Run(ctx context.Context) {
	ch.log.Info("Agent watcher started")

	ch.connectCounter = 0
	ch.lostCounter = 0

	// tracking of an error runs in a separate goroutine, because
	// the call to `watch.Recv` blocks and a timer is needed
	// to determine if an error last longer than the checkInterval.
	failedReset := make(chan bool)
	failedCh := make(chan error)
	go func() {
		failedTimer := time.NewTimer(ch.checkInterval)
		failedTimer.Stop()       // starts stopped
		defer failedTimer.Stop() // stopped on exit always

		var failedCount int
		var failedErr error
		for {
			select {
			case <-ctx.Done():
				return
			case reset := <-failedReset:
				if reset {
					failedCount = 0
					failedTimer.Stop()
				}
			case err := <-failedCh:
				if err != nil {
					if failedErr == nil {
						failedCount++
						failedTimer.Reset(ch.checkInterval)
						ch.log.Error("Agent reported failure (starting failed timer): %s", err)
					} else {
						ch.log.Error("Agent reported failure (failed timer already started): %s", err)
					}
				} else {
					if failedErr != nil {
						failedTimer.Stop()
						ch.log.Error("Agent reported healthy (failed timer stopped): %s", err)
					}
				}
				failedErr = err
				if failedCount > statusFailureFlipFlopsAllowed {
					err := fmt.Errorf("%w '%d' times in a row", ErrAgentFlipFlopFailed, failedCount)
					ch.log.Error(err)
					ch.notifyChan <- err
				}
			case <-failedTimer.C:
				if failedErr == nil {
					// error was cleared; do nothing
					continue
				}
				// error lasted longer than the checkInterval, notify!
				ch.notifyChan <- failedErr
			}
		}
	}()

LOOP:
	for {
		connectTimer := time.NewTimer(ch.checkInterval)
		select {
		case <-ctx.Done():
			connectTimer.Stop()
			return
		case <-connectTimer.C:
			ch.log.Info("Trying to connect to agent")
			err := ch.agentClient.Connect(ctx)
			if err != nil {
				ch.connectCounter++
				ch.log.Error("Failed connecting to running daemon: %s", err)
				if ch.checkFailures() {
					return
				}
				// agent is probably not running
				continue
			}
			watch, err := ch.agentClient.StateWatch(ctx)
			if err != nil {
				// considered a connect error
				ch.agentClient.Disconnect()
				ch.log.Error("Failed to start state watch: %s", err)
				ch.connectCounter++
				if ch.checkFailures() {
					return
				}
				// agent is probably not running
				continue
			}

			ch.log.Info("Connected to agent")

			// clear the connectCounter as connection was successfully made
			// we don't want a disconnect and a reconnect to be counted with
			// the connectCounter that is tracked with the lostCounter
			ch.connectCounter = 0

			// failure is tracked only for the life of the connection to
			// the watch streaming protocol. either an error that last longer
			// than the checkInterval or to many flopping of error/non-error
			// will trigger a reported failure
			failedReset <- true
			failedCh <- nil

			for {
				state, err := watch.Recv()
				if err != nil {
					// agent has crashed or exited
					ch.agentClient.Disconnect()
					ch.log.Error("Failed reading next state: %s", err)
					ch.lostCounter++
					if ch.checkFailures() {
						return
					}
					continue LOOP
				}

				if state.State == client.Failed {
					// top-level failure (something is really wrong)
					failedCh <- fmt.Errorf("%w: %s", ErrAgentStatusFailed, state.Message)
					continue
				} else {
					// agent is healthy; but a component might not be healthy
					// upgrade tracks unhealthy component as an issue with the upgrade
					var compErr error
					for _, comp := range state.Components {
						if comp.State == client.Failed {
							compErr = multierror.Append(compErr, fmt.Errorf("component %s[%v] failed: %s", comp.Name, comp.ID, comp.Message))
						}
					}
					if compErr != nil {
						failedCh <- fmt.Errorf("%w: %w", ErrAgentComponentFailed, compErr)
						continue
					}
				}

				// nothing is failed
				failedCh <- nil
			}
		}
	}
}

func (ch *AgentWatcher) checkFailures() bool {
	if failures := ch.connectCounter; failures > statusCheckMissesAllowed {
		ch.notifyChan <- fmt.Errorf("%w '%d' times in a row", ErrCannotConnect, failures)
		return true
	}
	if failures := ch.lostCounter; failures > statusLossesAllowed {
		ch.notifyChan <- fmt.Errorf("%w '%d' times in a row", ErrLostConnection, failures)
		return true
	}
	return false
}

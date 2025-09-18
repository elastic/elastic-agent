// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"google.golang.org/grpc"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	statusCheckMissesAllowed      = 4 // enable 2 minute start (30 second periods)
	statusLossesAllowed           = 2 // enable connection lost to agent twice
	statusFailureFlipFlopsAllowed = 3 // no more than three failure flip-flops allowed

	watcherApplockerFileName = "watcher.lock"

	// Takeover constants
	// defaultTakeoverWatcherTimeout defines the global timeout for the takeover operation before giving up
	defaultTakeoverWatcherTimeout = 30 * time.Second
	// watcherSweepInterval defines the interval for searching for other watcher processes and signaling them for graceful termination
	watcherSweepInterval = 500 * time.Millisecond
	// takeoverAttemptInterval defines the interval between filelock takeover attempts
	takeoverAttemptInterval = 100 * time.Millisecond
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
	lastPid        int32

	notifyChan    chan error
	log           *logger.Logger
	agentClient   client.Client
	checkInterval time.Duration
}

// NewAgentWatcher creates a new agent watcher.
func NewAgentWatcher(ch chan error, log *logger.Logger, checkInterval time.Duration) *AgentWatcher {
	// when starting watcher from pre 8.8 version of agent control socket is evaluated incorrectly and upgrade fails.
	// resolving control socket updates it to a proper value before client is initiated
	// upgrade is only available for installed agent so we can assume
	paths.ResolveControlSocket(true)

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

		var flipFlopCount int
		var failedErr error
		for {
			select {
			case <-ctx.Done():
				return
			case reset := <-failedReset:
				if reset {
					flipFlopCount = 0
					failedTimer.Stop()
				}
			case err := <-failedCh:
				if err != nil {
					if failedErr == nil {
						flipFlopCount++
						failedTimer.Reset(ch.checkInterval)
						ch.log.Errorf("Agent reported failure (starting failed timer): %s", err)
					} else {
						ch.log.Errorf("Agent reported failure (failed timer already started): %s", err)
					}
				} else {
					if failedErr != nil {
						failedTimer.Stop()
						ch.log.Info("Agent reported healthy (failed timer stopped)")
					}
				}
				failedErr = err
				if flipFlopCount > statusFailureFlipFlopsAllowed {
					err := fmt.Errorf("%w '%d' times in a row", ErrAgentFlipFlopFailed, flipFlopCount)
					ch.log.Error(err)
					ch.notifyChan <- err
				}
			case <-failedTimer.C:
				if failedErr == nil {
					// error was cleared; do nothing
					continue
				}
				// error lasted longer than the checkInterval, notify!
				ch.notifyChan <- fmt.Errorf("last error was not cleared before checkInterval (%s) elapsed: %w",
					ch.checkInterval, failedErr)
			}
		}
	}()

LOOP:
	for {
		ch.lastPid = -1
		connectTimer := time.NewTimer(ch.checkInterval)
		select {
		case <-ctx.Done():
			connectTimer.Stop()
			return
		case <-connectTimer.C:
			ch.log.Info("Trying to connect to agent")
			// block on connection, don't retry connection, and fail on temp dial errors
			// always a local connection it should connect quickly so the timeout is only 1 second
			connectCtx, connectCancel := context.WithTimeout(ctx, 1*time.Second)
			//nolint:staticcheck // requires changing client signature
			err := ch.agentClient.Connect(connectCtx, grpc.WithBlock(), grpc.WithDisableRetry(), grpc.FailOnNonTempDialError(true))
			connectCancel()
			if err != nil {
				ch.connectCounter++
				ch.log.Errorf("Failed connecting to running daemon: %s", err)
				if ch.checkFailures() {
					return
				}
				// agent is probably not running
				continue
			}

			stateCtx, stateCancel := context.WithCancel(ctx)
			watch, err := ch.agentClient.StateWatch(stateCtx)
			if err != nil {
				// considered a connect error
				stateCancel()
				ch.agentClient.Disconnect()
				ch.log.Errorf("Failed to start state watch: %s", err)
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
					ch.log.Debugf("received state: error: %s",
						err)

					// agent has crashed or exited
					stateCancel()
					ch.agentClient.Disconnect()
					ch.log.Errorf("Lost connection: failed reading next state: %s", err)
					ch.lostCounter++
					if ch.checkFailures() {
						return
					}
					continue LOOP
				}
				ch.log.Debugf("received state: %s:%s",
					state.State, state.Message)

				// gRPC is good at hiding the fact that connection was lost
				// to ensure that we don't miss a restart a changed PID means
				// we are now talking to a different spawned Elastic Agent
				if ch.lastPid == -1 {
					ch.lastPid = state.Info.PID
					ch.log.Infof("Communicating with PID %d", ch.lastPid)
				} else if ch.lastPid != state.Info.PID {
					ch.log.Errorf("Communication with PID %d lost, now communicating with PID %d", ch.lastPid, state.Info.PID)
					ch.lastPid = state.Info.PID
					// count the PID change as a lost connection, but allow
					// the communication to continue unless has become a failure
					ch.lostCounter++
					if ch.checkFailures() {
						stateCancel()
						ch.agentClient.Disconnect()
						return
					}
				}

				if state.State == client.Failed {
					// top-level failure (something is really wrong)
					failedCh <- fmt.Errorf("%w: %s", ErrAgentStatusFailed, state.Message)
					continue
				} else {
					// agent is healthy; but a component might not be healthy
					// upgrade tracks unhealthy component as an issue with the upgrade
					var errs []error
					for _, comp := range state.Components {
						if comp.State == client.Failed {
							errs = append(errs, fmt.Errorf("component %s[%v] failed: %s", comp.Name, comp.ID, comp.Message))
						}
					}
					if len(errs) != 0 {
						failedCh <- fmt.Errorf("%w: %w", ErrAgentComponentFailed, errors.Join(errs...))
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

// Ensure that AgentWatcherHelper implements the WatcherHelper interface
var _ WatcherHelper = &AgentWatcherHelper{}

type AgentWatcherHelper struct {
}

func (a AgentWatcherHelper) InvokeWatcher(log *logger.Logger, agentExecutable string, additionalWatchArgs ...string) (*exec.Cmd, error) {
	return InvokeWatcher(log, agentExecutable, additionalWatchArgs...)
}

func (a AgentWatcherHelper) SelectWatcherExecutable(topDir string, previous agentInstall, current agentInstall) string {
	return selectWatcherExecutable(topDir, previous, current)
}

func (a AgentWatcherHelper) WaitForWatcher(ctx context.Context, log *logger.Logger, markerFilePath string, waitTime time.Duration) error {
	return waitForWatcher(ctx, log, markerFilePath, waitTime)
}

func (a AgentWatcherHelper) TakeOverWatcher(ctx context.Context, log *logger.Logger, topDir string) (*filelock.AppLocker, error) {
	return takeOverWatcher(ctx, log, new(commandWatcherGrappler), topDir, defaultTakeoverWatcherTimeout, watcherSweepInterval, takeoverAttemptInterval)
}

// watcherGrappler is an abstraction over the way elastic-agent main process should take down (stop, gracefully if possible) a watcher process
type watcherGrappler interface {
	TakeDownWatcher(ctx context.Context, log *logger.Logger) error
}

type commandWatcherGrappler struct{}

func (c commandWatcherGrappler) TakeDownWatcher(ctx context.Context, log *logger.Logger) error {
	cmd := createTakeDownWatcherCommand(ctx)
	log.Debugf("launching takedown with %v", cmd.Args)
	output, err := cmd.CombinedOutput()
	log.Debugf("takedown output: %s", string(output))
	if err != nil {
		return fmt.Errorf("watcher command takedown failed: %w", err)
	}
	return nil
}

// Private functions providing implementation of AgentWatcherHelper
func takeOverWatcher(ctx context.Context, log *logger.Logger, watcherGrappler watcherGrappler, topDir string, timeout time.Duration, watcherSweepInterval time.Duration, takeOverInterval time.Duration) (*filelock.AppLocker, error) {
	takeoverCtx, takeoverCancel := context.WithTimeout(ctx, timeout)
	defer takeoverCancel()

	go func() {
		sweepTicker := time.NewTicker(watcherSweepInterval)
		defer sweepTicker.Stop()
		for {
			select {
			case <-takeoverCtx.Done():
				return
			case <-sweepTicker.C:
				err := watcherGrappler.TakeDownWatcher(takeoverCtx, log)
				if err != nil {
					log.Errorf("error taking down watcher: %s", err)
					continue
				}

			}
		}
	}()

	// we should retry to take over the AppLocker for 30s, but AppLocker interface is limited
	takeOverTicker := time.NewTicker(takeOverInterval)
	defer takeOverTicker.Stop()
	for {
		select {
		case <-takeoverCtx.Done():
			return nil, fmt.Errorf("timed out taking over watcher applocker")
		case <-takeOverTicker.C:
			locker := filelock.NewAppLocker(topDir, watcherApplockerFileName)
			err := locker.TryLock()
			if err != nil {
				log.Errorf("error locking watcher applocker: %s", err)
				continue
			}
			return locker, nil
		}
	}
}

func selectWatcherExecutable(topDir string, previous agentInstall, current agentInstall) string {
	// check if the upgraded version is less than the previous (currently installed) version
	if current.parsedVersion.Less(*previous.parsedVersion) {
		// use the current agent executable for watch, if downgrading the old agent doesn't understand the current agent's path structure.
		return paths.BinaryPath(filepath.Join(topDir, previous.versionedHome), agentName)
	} else {
		// use the new agent executable as it should be able to parse the new update marker
		return paths.BinaryPath(filepath.Join(topDir, current.versionedHome), agentName)
	}
}

func waitForWatcher(ctx context.Context, log *logger.Logger, markerFilePath string, waitTime time.Duration) error {
	return waitForWatcherWithTimeoutCreationFunc(ctx, log, markerFilePath, waitTime, context.WithTimeout)
}

type createContextWithTimeout func(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc)

func waitForWatcherWithTimeoutCreationFunc(ctx context.Context, log *logger.Logger, markerFilePath string, waitTime time.Duration, createTimeoutContext createContextWithTimeout) error {
	// Wait for the watcher to be up and running
	watcherContext, cancel := createTimeoutContext(ctx, waitTime)
	defer cancel()

	markerWatcher := newMarkerFileWatcher(markerFilePath, log)
	err := markerWatcher.Run(watcherContext)
	if err != nil {
		return fmt.Errorf("error starting update marker watcher: %w", err)
	}

	log.Infof("waiting up to %s for upgrade watcher to set %s state in upgrade marker", waitTime, details.StateWatching)

	for {
		select {
		case updMarker := <-markerWatcher.Watch():
			if updMarker.Details != nil && updMarker.Details.State == details.StateWatching {
				// watcher started and it is watching, all good
				log.Infof("upgrade watcher set %s state in upgrade marker: exiting wait loop", details.StateWatching)
				return nil
			}

		case <-watcherContext.Done():
			log.Errorf("upgrade watcher did not start watching within %s or context has expired", waitTime)
			return errors.Join(ErrWatcherNotStarted, watcherContext.Err())
		}
	}
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package process

import (
	"context"
	"fmt"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/internal/pkg/core/process"
	"github.com/elastic/elastic-agent/internal/pkg/core/state"
	"github.com/elastic/elastic-agent/pkg/core/server"
)

// OnStatusChange is the handler called by the GRPC server code.
//
// It updates the status of the application and handles restarting the application if needed.
func (a *Application) OnStatusChange(s *server.ApplicationState, status proto.StateObserved_Status, msg string, payload map[string]interface{}) {
	a.appLock.Lock()
	defer a.appLock.Unlock()

	// If the application is stopped, do not update the state. Stopped is a final state
	// and should not be overridden.
	if a.state.Status == state.Stopped {
		return
	}

	a.setState(state.FromProto(status), msg, payload)
	if status == proto.StateObserved_FAILED {
		// ignore when expected state is stopping
		if s.Expected() == proto.StateExpected_STOPPING {
			return
		}

		// it was marshalled to pass into the state, so unmarshall will always succeed
		var cfg map[string]interface{}
		_ = yaml.Unmarshal([]byte(s.Config()), &cfg)

		// start the failed timer
		// pass process info to avoid killing new process spun up in a meantime
		a.startFailedTimer(cfg, a.state.ProcessInfo)
	} else {
		a.stopFailedTimer()
	}
}

// startFailedTimer starts a timer that will restart the application if it doesn't exit failed after a period of time.
//
// This does not grab the appLock, that must be managed by the caller.
func (a *Application) startFailedTimer(cfg map[string]interface{}, proc *process.Info) {
	if a.restartCanceller != nil {
		// already have running failed timer; just update config
		a.restartConfig = cfg
		return
	}

	// (AndersonQ) the context is getting cancelled, a.restart is never called.
	// After putting the log below I can see it being logged on the 2nd failure.
	// This context is cancelled, it should not be reused. However, I'm not seeing
	// a.restartCanceller() being called. I added a log before it and the log does not appear.
	// Perhaps a.startContext parent's context gets cancelled...
	if err := a.startContext.Err(); err != nil {
		a.logger.Warnf("a.startContext is done: %v. %s will never restart",
			err, a.Name())
	}
	ctx, cancel := context.WithCancel(a.startContext)
	a.restartCanceller = cancel
	a.restartConfig = cfg
	t := time.NewTimer(a.processConfig.FailureTimeout)
	a.logger.Warnf("started a %s failed timer for %s, PID: %d",
		a.processConfig.FailureTimeout, a.name, proc.PID)
	go func() {
		defer func() {
			a.appLock.Lock()
			a.restartCanceller = nil
			a.restartConfig = nil
			a.appLock.Unlock()
		}()

		a.logger.Infof("waiting on failed timer for %s, PID: %d", a.name, proc.PID)
		select {
		case <-ctx.Done():
			a.logger.Infof("%s: failed timer cancelled, PID: %d. ctx: %v",
				a.name, proc.PID, ctx.Err())
			return
		case <-t.C:
			a.logger.Warnf("invoking a.restart for %s, PID: %d",
				a.name, proc.PID)
			a.restart(proc)
		}
	}()
}

// stopFailedTimer stops the timer that would restart the application from reporting failure.
//
// This does not grab the appLock, that must be managed by the caller.
func (a *Application) stopFailedTimer() {
	if a.restartCanceller == nil {
		return
	}
	a.logger.Infof("cancelling %s failed timer", a.Name())
	a.restartCanceller()
	a.restartCanceller = nil
}

// restart restarts the application
func (a *Application) restart(proc *process.Info) {
	a.appLock.Lock()
	defer a.appLock.Unlock()

	a.logger.Warnf("restarting %s, PID %d", a.Name(), proc.PID)
	// stop the watcher
	a.stopWatcher(proc)

	// kill the process
	if proc != nil && proc.Process != nil {
		if err := proc.Process.Kill(); err != nil {
			a.logger.Infof("could not kill %s:%d: %v", a.name, proc.PID, err)
		}
	}

	if proc != a.state.ProcessInfo {
		// we're restarting different process than actually running
		// no need to start another one
		return
	}

	a.state.ProcessInfo = nil

	ctx := a.startContext
	tag := a.tag

	a.setState(state.Restarting, "", nil)
	err := a.start(ctx, tag, a.restartConfig, true)
	if err != nil {
		a.setState(state.Crashed, fmt.Sprintf("failed to restart: %s", err), nil)
	}
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.uber.org/zap/zapcore"
	"golang.org/x/time/rate"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/process"
	"github.com/elastic/elastic-agent/pkg/utils"
)

type actionMode int

const (
	actionTeardown = actionMode(-1)
	actionStop     = actionMode(0)
	actionStart    = actionMode(1)

	runDirMod = 0770

	envAgentComponentID   = "AGENT_COMPONENT_ID"
	envAgentComponentType = "AGENT_COMPONENT_TYPE"

	stateUnknownMessage = "Unknown"
)

func (m actionMode) String() string {
	switch m {
	case actionTeardown:
		return "teardown"
	case actionStop:
		return "stop"
	case actionStart:
		return "start"
	}
	return ""
}

type MonitoringManager interface {
	EnrichArgs(string, string, []string) []string
	Prepare(string) error
	Cleanup(string) error
}

type procState struct {
	proc  *process.Info
	state *os.ProcessState
}

// commandRuntime provides the command runtime for running a component as a subprocess.
type commandRuntime struct {
	logStd *logWriter
	logErr *logWriter

	current component.Component
	monitor MonitoringManager

	// ch is the reporting channel for the current state. When a policy change
	// or client checkin affects the component state, its new value is sent
	// here and handled by (componentRuntimeState).runLoop.
	ch chan ComponentState

	// When the managed process closes, its termination status is sent on procCh
	// by the watching goroutine, and handled by (*commandRuntime).Run.
	procCh chan procState

	// compCh forwards new component metadata from the runtime manager to
	// the command runtime. It is written by calls to (*commandRuntime).Update
	// and read by the run loop in (*commandRuntime).Run.
	compCh chan component.Component

	// The most recent mode received on actionCh. The mode will be either
	// actionStart (indicating the process should be running, and should be
	// created if it is not), or actionStop or actionTeardown (indicating that
	// it should terminate).
	actionState actionMode

	// actionState is changed by sending its new value on actionCh, where it is
	// handled by (*commandRuntime).Run.
	actionCh chan actionMode

	proc *process.Info

	state          ComponentState
	lastCheckin    time.Time
	missedCheckins int
	restartBucket  *rate.Limiter
}

// newCommandRuntime creates a new command runtime for the provided component.
func newCommandRuntime(comp component.Component, log *logger.Logger, monitor MonitoringManager) (*commandRuntime, error) {
	c := &commandRuntime{
		current:     comp,
		monitor:     monitor,
		ch:          make(chan ComponentState),
		actionCh:    make(chan actionMode, 1),
		procCh:      make(chan procState),
		compCh:      make(chan component.Component, 1),
		actionState: actionStop,
		state:       newComponentState(&comp),
	}
	cmdSpec := c.getCommandSpec()
	if cmdSpec == nil {
		return nil, errors.New("must have command defined in specification")
	}
	ll, unitLevels := getLogLevels(comp)
	c.logStd = createLogWriter(c.current, log, c.getCommandSpec(), c.getSpecType(), c.getSpecBinaryName(), ll, unitLevels, logSourceStdout)
	ll, unitLevels = getLogLevels(comp) // don't want to share mapping of units (so new map is generated)
	c.logErr = createLogWriter(c.current, log, c.getCommandSpec(), c.getSpecType(), c.getSpecBinaryName(), ll, unitLevels, logSourceStderr)

	c.restartBucket = newRateLimiter(cmdSpec.RestartMonitoringPeriod, cmdSpec.MaxRestartsPerPeriod)

	return c, nil
}

// Run starts the runtime for the component.
//
// Called by Manager inside a goroutine. Run does not return until the passed in context is done. Run is always
// called before any of the other methods in the interface and once the context is done none of those methods should
// ever be called again.
func (c *commandRuntime) Run(ctx context.Context, comm Communicator) error {
	cmdSpec := c.getCommandSpec()
	checkinPeriod := cmdSpec.Timeouts.Checkin
	restartPeriod := cmdSpec.Timeouts.Restart
	c.forceCompState(client.UnitStateStarting, "Starting")
	t := time.NewTicker(checkinPeriod)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case as := <-c.actionCh:
			c.actionState = as
			switch as {
			case actionStart:
				if err := c.start(comm); err != nil {
					c.forceCompState(client.UnitStateFailed, fmt.Sprintf("Failed: %s", err))
				}
				t.Reset(checkinPeriod)
			case actionStop, actionTeardown:
				if err := c.stop(ctx); err != nil {
					c.forceCompState(client.UnitStateFailed, fmt.Sprintf("Failed: %s", err))
				}
			}
		case ps := <-c.procCh:
			// ignores old processes
			if ps.proc == c.proc {
				c.proc = nil
				if c.handleProc(ps.state) {
					// start again after restart period
					t.Reset(restartPeriod)
				}
			}
		case newComp := <-c.compCh:
			c.current = newComp
			c.syncLogLevels()

			sendExpected := c.state.syncExpected(&newComp)
			changed := c.state.syncUnits(&newComp)
			if sendExpected || c.state.unsettled() {
				comm.CheckinExpected(c.state.toCheckinExpected(), nil)
			}

			if changed {
				c.sendObserved()
			}
		case checkin := <-comm.CheckinObserved():
			sendExpected := false
			changed := false
			if c.state.State == client.UnitStateStarting {
				// first observation after start set component to healthy
				c.state.State = client.UnitStateHealthy
				c.state.Message = fmt.Sprintf("Healthy: communicating with pid '%d'", c.proc.PID)
				changed = true
			}
			if c.lastCheckin.IsZero() {
				// first check-in
				sendExpected = true
			}
			c.lastCheckin = time.Now().UTC()
			if c.state.syncCheckin(checkin) {
				changed = true
			}
			if c.state.unsettled() {
				sendExpected = true
			}
			if sendExpected {
				checkinExpected := c.state.toCheckinExpected()
				comm.CheckinExpected(checkinExpected, checkin)
			}
			if changed {
				c.sendObserved()
			}
			if c.state.cleanupStopped() {
				c.sendObserved()
			}
		case <-t.C:
			t.Reset(checkinPeriod)
			if c.actionState == actionStart {
				if c.proc == nil {
					// not running, but should be running
					if err := c.start(comm); err != nil {
						c.forceCompState(client.UnitStateFailed, fmt.Sprintf("Failed: %s", err))
					}
				} else {
					// running and should be running
					now := time.Now().UTC()
					if now.Sub(c.lastCheckin) <= checkinPeriod {
						c.missedCheckins = 0
					} else {
						c.missedCheckins++
					}
					if c.missedCheckins == 0 {
						c.compState(client.UnitStateHealthy)
					} else if c.missedCheckins > 0 && c.missedCheckins < maxCheckinMisses {
						c.compState(client.UnitStateDegraded)
					} else if c.missedCheckins >= maxCheckinMisses {
						// something is wrong; the command should be checking in
						//
						// at this point it is assumed the sub-process has locked up and will not respond to a nice
						// termination signal, so we jump directly to killing the process
						msg := fmt.Sprintf("Failed: pid '%d' missed %d check-ins and will be killed", c.proc.PID, maxCheckinMisses)
						c.forceCompState(client.UnitStateFailed, msg)
						_ = c.proc.Kill() // watcher will handle it from here
					}
				}
			}
		}
	}
}

// Watch returns the channel that sends component state.
//
// Channel should send a new state anytime a state for a unit or the whole component changes.
func (c *commandRuntime) Watch() <-chan ComponentState {
	return c.ch
}

// Start starts the component.
//
// Non-blocking and never returns an error.
func (c *commandRuntime) Start() error {
	// clear channel so it's the latest action
	select {
	case <-c.actionCh:
	default:
	}
	c.actionCh <- actionStart
	return nil
}

// Update updates the currComp runtime with a new-revision for the component definition.
//
// Non-blocking and never returns an error.
func (c *commandRuntime) Update(comp component.Component) error {
	// clear channel so it's the latest component
	select {
	case <-c.compCh:
	default:
	}
	c.compCh <- comp
	return nil
}

// Stop stops the component.
//
// Non-blocking and never returns an error.
func (c *commandRuntime) Stop() error {
	// clear channel so it's the latest action
	select {
	case <-c.actionCh:
	default:
	}
	c.actionCh <- actionStop
	return nil
}

// Teardown tears down the component.
//
// Non-blocking and never returns an error.
func (c *commandRuntime) Teardown(_ *component.Signed) error {
	// clear channel so it's the latest action
	select {
	case <-c.actionCh:
	default:
	}
	c.actionCh <- actionTeardown
	return nil
}

// forceCompState force updates the state for the entire component, forcing that state on all units.
func (c *commandRuntime) forceCompState(state client.UnitState, msg string) {
	if c.state.forceState(state, msg) {
		c.sendObserved()
	}
}

// compState updates just the component state not all the units.
func (c *commandRuntime) compState(state client.UnitState) {
	msg := stateUnknownMessage
	if state == client.UnitStateHealthy {
		msg = fmt.Sprintf("Healthy: communicating with pid '%d'", c.proc.PID)
	} else if state == client.UnitStateDegraded {
		if c.missedCheckins == 1 {
			msg = fmt.Sprintf("Degraded: pid '%d' missed 1 check-in", c.proc.PID)
		} else {
			msg = fmt.Sprintf("Degraded: pid '%d' missed %d check-ins", c.proc.PID, c.missedCheckins)
		}
	}
	if c.state.compState(state, msg) {
		c.sendObserved()
	}
}

func (c *commandRuntime) sendObserved() {
	c.ch <- c.state.Copy()
}

func (c *commandRuntime) start(comm Communicator) error {
	if c.proc != nil {
		// already running
		return nil
	}
	cmdSpec := c.getCommandSpec()
	env := make([]string, 0, len(cmdSpec.Env)+2)
	for _, e := range cmdSpec.Env {
		env = append(env, fmt.Sprintf("%s=%s", e.Name, e.Value))
	}
	env = append(env, fmt.Sprintf("%s=%s", envAgentComponentID, c.current.ID))
	env = append(env, fmt.Sprintf("%s=%s", envAgentComponentType, c.getSpecType()))
	uid, gid := os.Geteuid(), os.Getegid()
	workDir, err := c.workDir(uid, gid)
	if err != nil {
		return err
	}
	path, err := filepath.Abs(c.getSpecBinaryPath())
	if err != nil {
		return fmt.Errorf("failed to determine absolute path: %w", err)
	}
	err = utils.HasStrictExecPerms(path, uid)
	if err != nil {
		return fmt.Errorf("execution of component prevented: %w", err)
	}

	if err := c.monitor.Prepare(c.current.ID); err != nil {
		return err
	}
	args := c.monitor.EnrichArgs(c.current.ID, c.getSpecBinaryName(), cmdSpec.Args)

	// differentiate data paths
	dataPath := filepath.Join(paths.Home(), "run", c.current.ID)
	_ = os.MkdirAll(dataPath, 0755)
	args = append(args, "-E", "path.data="+dataPath)

	// reset checkin state before starting the process.
	c.lastCheckin = time.Time{}
	c.missedCheckins = 0

	proc, err := process.Start(path,
		process.WithArgs(args),
		process.WithEnv(env),
		process.WithCmdOptions(attachOutErr(c.logStd, c.logErr), dirPath(workDir)))
	if err != nil {
		return err
	}

	c.proc = proc
	c.forceCompState(client.UnitStateStarting, fmt.Sprintf("Starting: spawned pid '%d'", c.proc.PID))
	c.startWatcher(proc, comm)
	return nil
}

func (c *commandRuntime) stop(ctx context.Context) error {
	if c.proc == nil {
		// already stopped, ensure that state of the component is also stopped
		if c.state.State != client.UnitStateStopped {
			if c.state.State == client.UnitStateFailed {
				c.forceCompState(client.UnitStateStopped, "Stopped: never started successfully")
			} else {
				c.forceCompState(client.UnitStateStopped, "Stopped: already stopped")
			}
		}
		return nil
	}

	// cleanup reserved resources related to monitoring
	defer c.monitor.Cleanup(c.current.ID) //nolint:errcheck // this is ok
	cmdSpec := c.getCommandSpec()
	go func(info *process.Info, timeout time.Duration) {
		t := time.NewTimer(timeout)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// kill no matter what (might already be stopped)
			_ = info.Kill()
		}
	}(c.proc, cmdSpec.Timeouts.Stop)
	return c.proc.Stop()
}

func (c *commandRuntime) startWatcher(info *process.Info, comm Communicator) {
	go func() {
		err := comm.WriteConnInfo(info.Stdin)
		if err != nil {
			_, _ = c.logErr.Write([]byte(fmt.Sprintf("Failed: failed to provide connection information to spawned pid '%d': %s", info.PID, err)))
			// kill instantly
			_ = info.Kill()
		} else {
			_ = info.Stdin.Close()
		}

		ch := info.Wait()
		s := <-ch
		c.procCh <- procState{
			proc:  info,
			state: s,
		}
	}()
}

func (c *commandRuntime) handleProc(state *os.ProcessState) bool {
	switch c.actionState {
	case actionStart:
		if c.restartBucket != nil && c.restartBucket.Allow() {
			stopMsg := fmt.Sprintf("Suppressing FAILED state due to restart for '%d' exited with code '%d'", state.Pid(), state.ExitCode())
			c.forceCompState(client.UnitStateStopped, stopMsg)
		} else {
			// report failure only if bucket is full of restart events
			stopMsg := fmt.Sprintf("Failed: pid '%d' exited with code '%d'", state.Pid(), state.ExitCode())
			c.forceCompState(client.UnitStateFailed, stopMsg)
		}
		return true
	case actionStop, actionTeardown:
		// stopping (should have exited)
		if c.actionState == actionTeardown {
			// teardown so the entire component has been removed (cleanup work directory)
			_ = os.RemoveAll(c.workDirPath())
		}
		stopMsg := fmt.Sprintf("Stopped: pid '%d' exited with code '%d'", state.Pid(), state.ExitCode())
		c.forceCompState(client.UnitStateStopped, stopMsg)
	}
	return false
}

func (c *commandRuntime) workDirPath() string {
	return filepath.Join(paths.Run(), c.current.ID)
}

func (c *commandRuntime) workDir(uid int, gid int) (string, error) {
	path := c.workDirPath()
	err := os.MkdirAll(path, runDirMod)
	if err != nil {
		return "", fmt.Errorf("failed to create path %q: %w", path, err)
	}
	if runtime.GOOS == component.Windows {
		return path, nil
	}
	err = os.Chown(path, uid, gid)
	if err != nil {
		return "", fmt.Errorf("failed to chown %q: %w", path, err)
	}
	err = os.Chmod(path, runDirMod)
	if err != nil {
		return "", fmt.Errorf("failed to chmod %q: %w", path, err)
	}
	return path, nil
}

func (c *commandRuntime) getSpecType() string {
	if c.current.InputSpec != nil {
		return c.current.InputSpec.InputType
	}
	if c.current.ShipperSpec != nil {
		return c.current.ShipperSpec.ShipperType
	}
	return ""
}

func (c *commandRuntime) getSpecBinaryName() string {
	if c.current.InputSpec != nil {
		return c.current.InputSpec.BinaryName
	}
	if c.current.ShipperSpec != nil {
		return c.current.ShipperSpec.BinaryName
	}
	return ""
}

func (c *commandRuntime) getSpecBinaryPath() string {
	if c.current.InputSpec != nil {
		return c.current.InputSpec.BinaryPath
	}
	if c.current.ShipperSpec != nil {
		return c.current.ShipperSpec.BinaryPath
	}
	return ""
}

func (c *commandRuntime) getCommandSpec() *component.CommandSpec {
	if c.current.InputSpec != nil {
		return c.current.InputSpec.Spec.Command
	}
	if c.current.ShipperSpec != nil {
		return c.current.ShipperSpec.Spec.Command
	}
	return nil
}

func (c *commandRuntime) syncLogLevels() {
	ll, unitLevels := getLogLevels(c.current)
	c.logStd.SetLevels(ll, unitLevels)
	ll, unitLevels = getLogLevels(c.current) // don't want to share mapping of units (so new map is generated)
	c.logErr.SetLevels(ll, unitLevels)
}

func attachOutErr(stdOut *logWriter, stdErr *logWriter) process.CmdOption {
	return func(cmd *exec.Cmd) error {
		cmd.Stdout = stdOut
		cmd.Stderr = stdErr
		return nil
	}
}

func createLogWriter(comp component.Component, baseLog *logger.Logger, cmdSpec *component.CommandSpec, typeStr string, binaryName string, ll zapcore.Level, unitLevels map[string]zapcore.Level, src logSource) *logWriter {
	dataset := fmt.Sprintf("elastic_agent.%s", strings.ReplaceAll(strings.ReplaceAll(binaryName, "-", "_"), "/", "_"))
	logger := baseLog.With(
		"component", map[string]interface{}{
			"id":      comp.ID,
			"type":    typeStr,
			"binary":  binaryName,
			"dataset": dataset,
		},
		"log", map[string]interface{}{
			"source": comp.ID,
		},
	)
	return newLogWriter(logger.Core(), cmdSpec.Log, ll, unitLevels, src)
}

// getLogLevels returns the lowest log level and a mapping between each unit and its defined log level.
func getLogLevels(comp component.Component) (zapcore.Level, map[string]zapcore.Level) {
	baseLevel := zapcore.ErrorLevel
	unitLevels := make(map[string]zapcore.Level)
	for _, unit := range comp.Units {
		ll := toZapcoreLevel(unit.LogLevel)
		unitLevels[unit.ID] = ll
		if ll < baseLevel {
			baseLevel = ll
		}
	}
	return baseLevel, unitLevels
}

func toZapcoreLevel(unitLevel client.UnitLogLevel) zapcore.Level {
	switch unitLevel {
	case client.UnitLogLevelError:
		return zapcore.ErrorLevel
	case client.UnitLogLevelWarn:
		return zapcore.WarnLevel
	case client.UnitLogLevelInfo:
		return zapcore.InfoLevel
	case client.UnitLogLevelDebug:
		return zapcore.DebugLevel
	case client.UnitLogLevelTrace:
		// zap doesn't support trace
		return zapcore.DebugLevel
	}
	// unknown level (default to info)
	return zapcore.InfoLevel
}

func dirPath(path string) process.CmdOption {
	return func(cmd *exec.Cmd) error {
		cmd.Dir = path
		return nil
	}
}

func newRateLimiter(restartMonitoringPeriod time.Duration, maxEventsPerPeriod int) *rate.Limiter {
	if restartMonitoringPeriod <= 0 || maxEventsPerPeriod <= 0 {
		return nil
	}

	period := restartMonitoringPeriod.Seconds()
	events := float64(maxEventsPerPeriod)
	frequency := events / period
	if frequency > 0 {
		bucketSize := rate.Limit(frequency)
		return rate.NewLimiter(bucketSize, maxEventsPerPeriod)
	}

	return nil
}

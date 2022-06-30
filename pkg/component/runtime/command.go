package runtime

import (
	"context"
	"errors"
	"fmt"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"gopkg.in/yaml.v2"
	"os"
	"os/exec"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"

	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

const (
	actionStart = 0
	actionStop  = 1
)

type procState struct {
	proc  *process.Info
	state *os.ProcessState
}

type CommandRuntime struct {
	current component.Component

	ch       chan ComponentState
	actionCh chan int
	procCh   chan procState
	compCh   chan component.Component

	actionState int
	proc        *process.Info

	expected       ComponentState
	observed       ComponentState
	lastCheckin    time.Time
	missedCheckins int
}

func NewCommandRuntime(comp component.Component) (ComponentRuntime, error) {
	if comp.Spec.Spec.Command == nil {
		return nil, errors.New("must have command defined in input specification")
	}
	expected := newComponentState(&comp, client.UnitStateHealthy, "", 1)
	observed := newComponentState(&comp, client.UnitStateStarting, "Starting", 0)
	return &CommandRuntime{
		current:     comp,
		ch:          make(chan ComponentState),
		actionCh:    make(chan int),
		procCh:      make(chan procState),
		compCh:      make(chan component.Component),
		actionState: actionStart,
		expected:    expected,
		observed:    observed,
	}, nil
}

func (c *CommandRuntime) Run(ctx context.Context, comm Communicator) {
	checkinPeriod := c.current.Spec.Spec.Command.Timeouts.Checkin
	c.forceCompState(client.UnitStateStarting, "Starting")
	t := time.NewTicker(checkinPeriod)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case as := <-c.actionCh:
			c.actionState = as
			switch as {
			case actionStart:
				if err := c.start(comm); err != nil {
					c.forceCompState(client.UnitStateFailed, err.Error())
				}
				t.Reset(checkinPeriod)
			case actionStop:
				if err := c.stop(ctx); err != nil {
					c.forceCompState(client.UnitStateFailed, err.Error())
				}
			}
		case ps := <-c.procCh:
			// ignores old processes
			if ps.proc == c.proc {
				c.proc = nil
				if c.handleProc(ps.state) {
					// start again
					if err := c.start(comm); err != nil {
						c.forceCompState(client.UnitStateFailed, err.Error())
					}
				}
				t.Reset(checkinPeriod)
			}
		case newComp := <-c.compCh:
			c.expected.syncComponent(&newComp, client.UnitStateHealthy, "Healthy", 1)
			if c.mustSendExpected() {
				c.sendExpected(comm)
			}
		case checkin := <-comm.CheckinObserved():
			sendExpected := false
			changed := false
			if c.observed.State == client.UnitStateStarting {
				// first observation after start set component to healthy
				c.observed.State = client.UnitStateHealthy
				c.observed.Message = fmt.Sprintf("Healthy: communicating with pid '%d'", c.proc.PID)
				changed = true
			}
			if c.lastCheckin.IsZero() {
				// first check-in
				sendExpected = true
			}
			c.lastCheckin = time.Now().UTC()
			if c.observed.syncCheckin(checkin) {
				changed = true
			}
			if c.mustSendExpected() {
				sendExpected = true
			}
			if sendExpected {
				c.sendExpected(comm)
			}
			if changed {
				c.sendObserved()
			}
			if c.cleanupStopped() {
				c.sendObserved()
			}
		case <-t.C:
			if c.proc != nil && c.actionState == actionStart {
				// running and should be running
				now := time.Now().UTC()
				if c.lastCheckin.IsZero() {
					// never checked-in
					c.missedCheckins += 1
				} else if now.Sub(c.lastCheckin) > checkinPeriod {
					// missed check-in during required period
					c.missedCheckins += 1
				} else if now.Sub(c.lastCheckin) <= checkinPeriod {
					c.missedCheckins = 0
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

func (c *CommandRuntime) Watch() <-chan ComponentState {
	return c.ch
}

func (c *CommandRuntime) Start() error {
	c.actionCh <- actionStart
	return nil
}

func (c *CommandRuntime) Update(comp component.Component) error {
	c.compCh <- comp
	return nil
}

func (c *CommandRuntime) Stop() error {
	c.actionCh <- actionStop
	return nil
}

func (c *CommandRuntime) Teardown() error {
	// teardown is not different from stop for command runtime
	return c.Stop()
}

// forceCompState force updates the state for the entire component, forcing that state on all units.
func (c *CommandRuntime) forceCompState(state client.UnitState, msg string) {
	c.observed.State = state
	c.observed.Message = msg
	for k, unit := range c.observed.Units {
		unit.State = state
		unit.Message = msg
		unit.Payload = nil
		unit.configStateIdx = 0

		// unit is a copy and must be set back into the map
		c.observed.Units[k] = unit
	}
	c.sendObserved()
}

// compState updates just the component state not all the units.
func (c *CommandRuntime) compState(state client.UnitState) {
	msg := "Unknown"
	if state == client.UnitStateHealthy {
		msg = fmt.Sprintf("Healthy: communicating with pid '%d'", c.proc.PID)
	} else if state == client.UnitStateDegraded {
		if c.missedCheckins == 1 {
			msg = fmt.Sprintf("Degraded: pid '%d' missed 1 check-in", c.proc.PID)
		} else {
			msg = fmt.Sprintf("Degraded: pid '%d' missed %d check-ins", c.proc.PID, c.missedCheckins)
		}
	}
	if c.observed.State != state || c.observed.Message != msg {
		c.observed.State = state
		c.observed.Message = msg
		c.sendObserved()
	}
}

func (c *CommandRuntime) sendObserved() {
	c.ch <- c.observed.Copy()
}

func (c *CommandRuntime) start(comm Communicator) error {
	if c.proc != nil {
		// already running
		return nil
	}
	cmdSpec := c.current.Spec.Spec.Command
	var env []string
	for _, e := range cmdSpec.Env {
		env = append(env, fmt.Sprintf("%s=%s", e.Name, e.Value))
	}
	proc, err := process.Start(c.current.Spec.BinaryPath, os.Geteuid(), os.Getgid(), cmdSpec.Args, env, attachOutErr)
	if err != nil {
		return err
	}
	c.lastCheckin = time.Time{}
	c.missedCheckins = 0
	c.proc = proc
	c.forceCompState(client.UnitStateStarting, fmt.Sprintf("Starting: spawned pid '%d'", c.proc.PID))
	c.startWatcher(proc, comm)
	return nil
}

func (c *CommandRuntime) stop(ctx context.Context) error {
	if c.proc == nil {
		// already stopped
		return nil
	}
	cmdSpec := c.current.Spec.Spec.Command
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

func (c *CommandRuntime) startWatcher(info *process.Info, comm Communicator) {
	go func() {
		err := comm.WriteConnInfo(info.Stdin)
		if err != nil {
			c.forceCompState(client.UnitStateFailed, fmt.Sprintf("Failed: failed to provide connection information to spawned pid '%d': %s", info.PID, err))
			// kill instantly
			info.Kill()
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

func (c *CommandRuntime) handleProc(state *os.ProcessState) bool {
	switch c.actionState {
	case actionStart:
		// should still be running
		stopMsg := fmt.Sprintf("Failed: pid '%d' exited with code '%d'", state.Pid(), state.ExitCode())
		c.forceCompState(client.UnitStateFailed, stopMsg)
		return true
	case actionStop:
		// stopping (should have exited)
		stopMsg := fmt.Sprintf("Stopped: pid '%d' exited with code '%d'", state.Pid(), state.ExitCode())
		c.forceCompState(client.UnitStateStopped, stopMsg)
	}
	return false
}

func (c *CommandRuntime) mustSendExpected() bool {
	if len(c.expected.Units) != len(c.observed.Units) {
		// mismatch on unit count
		return true
	}
	for ek, e := range c.expected.Units {
		o, ok := c.observed.Units[ek]
		if !ok {
			// unit missing
			return true
		}
		if o.configStateIdx != e.configStateIdx || e.State != o.State {
			// config or state mismatch
			return true
		}
	}
	return false
}

func (c *CommandRuntime) sendExpected(comm Communicator) error {
	units := make([]*proto.UnitExpected, 0, len(c.expected.Units))
	for k, u := range c.expected.Units {
		e := &proto.UnitExpected{
			Id:             k.UnitID,
			Type:           proto.UnitType(k.UnitType),
			State:          proto.State(u.State),
			ConfigStateIdx: u.configStateIdx,
			Config:         "",
		}
		o, ok := c.observed.Units[k]
		if !ok || o.configStateIdx != u.configStateIdx {
			cfg, err := yaml.Marshal(u.config)
			if err != nil {
				return fmt.Errorf("failed to marshal YAML for unit %s: %w", k.UnitID, err)
			}
			e.Config = string(cfg)
		}
		units = append(units, e)
	}
	comm.CheckinExpected(&proto.CheckinExpected{Units: units})
	return nil
}

func (c *CommandRuntime) cleanupStopped() bool {
	cleaned := false
	for ek, e := range c.expected.Units {
		if e.State == client.UnitStateStopped {
			// should be stopped; check if observed is also reporting stopped
			o, ok := c.observed.Units[ek]
			if ok && o.State == client.UnitStateStopped {
				// its also stopped; so it can now be removed from both
				delete(c.expected.Units, ek)
				delete(c.observed.Units, ek)
				cleaned = true
			}
		}
	}
	return cleaned
}

func attachOutErr(cmd *exec.Cmd) error {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return nil
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/control"
	"github.com/elastic/elastic-agent/internal/pkg/agent/control/cproto"
)

// UnitType is the type of the unit
type UnitType = cproto.UnitType

// State is the state codes
type State = cproto.State

const (
	// UnitTypeInput is an input unit.
	UnitTypeInput UnitType = cproto.UnitType_INPUT
	// UnitTypeOutput is an output unit.
	UnitTypeOutput UnitType = cproto.UnitType_OUTPUT
)

const (
	// Starting is when the it is still starting.
	Starting State = cproto.State_STARTING
	// Configuring is when it is configuring.
	Configuring State = cproto.State_CONFIGURING
	// Healthy is when it is healthy.
	Healthy State = cproto.State_HEALTHY
	// Degraded is when it is degraded.
	Degraded State = cproto.State_DEGRADED
	// Failed is when it is failed.
	Failed State = cproto.State_FAILED
	// Stopping is when it is stopping.
	Stopping State = cproto.State_STOPPING
	// Stopped is when it is stopped.
	Stopped State = cproto.State_STOPPED
	// Upgrading is when it is upgrading.
	Upgrading State = cproto.State_UPGRADING
	// Rollback is when it is upgrading is rolling back.
	Rollback State = cproto.State_ROLLBACK
)

// Version is the current running version of the daemon.
type Version struct {
	Version   string
	Commit    string
	BuildTime time.Time
	Snapshot  bool
}

// ComponentUnitState is a state of a unit running inside a component.
type ComponentUnitState struct {
	UnitID   string                 `json:"unit_id" yaml:"unit_id"`
	UnitType UnitType               `json:"unit_type" yaml:"unit_type"`
	State    State                  `json:"state" yaml:"state"`
	Message  string                 `json:"message" yaml:"message"`
	Payload  map[string]interface{} `json:"payload,omitempty" yaml:"payload,omitempty"`
}

// ComponentState is a state of a component managed by the Elastic Agent.
type ComponentState struct {
	ID      string               `json:"id" yaml:"id"`
	Name    string               `json:"name" yaml:"name"`
	State   State                `json:"state" yaml:"state"`
	Message string               `json:"message" yaml:"message"`
	Units   []ComponentUnitState `json:"units" yaml:"units"`
}

// AgentState is the current state of the Elastic Agent.
type AgentState struct {
	State      State            `json:"state" yaml:"state"`
	Message    string           `json:"message" yaml:"message"`
	Components []ComponentState `json:"components" yaml:"components"`
}

// ProcMeta is the running version and ID information for a running process.
type ProcMeta struct {
	Process            string
	Name               string
	Hostname           string
	ID                 string
	EphemeralID        string
	Version            string
	BuildCommit        string
	BuildTime          time.Time
	Username           string
	UserID             string
	UserGID            string
	BinaryArchitecture string
	RouteKey           string
	ElasticLicensed    bool
	Error              string
}

// ProcPProf returns pprof data for a process.
type ProcPProf struct {
	Name     string
	RouteKey string
	Result   []byte
	Error    string
}

// Client communicates to Elastic Agent through the control protocol.
type Client interface {
	// Connect connects to the running Elastic Agent.
	Connect(ctx context.Context) error
	// Disconnect disconnects from the running Elastic Agent.
	Disconnect()
	// Version returns the current version of the running agent.
	Version(ctx context.Context) (Version, error)
	// State returns the current state of the running agent.
	State(ctx context.Context) (*AgentState, error)
	// Restart triggers restarting the current running daemon.
	Restart(ctx context.Context) error
	// Upgrade triggers upgrade of the current running daemon.
	Upgrade(ctx context.Context, version string, sourceURI string) (string, error)
	// ProcMeta gathers running process meta-data.
	ProcMeta(ctx context.Context) ([]ProcMeta, error)
	// Pprof gathers data from the /debug/pprof/ endpoints specified.
	Pprof(ctx context.Context, d time.Duration, pprofTypes []cproto.PprofOption, appName, routeKey string) (map[string][]ProcPProf, error)
	// ProcMetrics gathers /buffer data and from the agent and each running process and returns the result.
	ProcMetrics(ctx context.Context) (*cproto.ProcMetricsResponse, error)
}

// client manages the state and communication to the Elastic Agent.
type client struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	client cproto.ElasticAgentControlClient
}

// New creates a client connection to Elastic Agent.
func New() Client {
	return &client{}
}

// Connect connects to the running Elastic Agent.
func (c *client) Connect(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)
	conn, err := dialContext(ctx)
	if err != nil {
		return err
	}
	c.client = cproto.NewElasticAgentControlClient(conn)
	return nil
}

// Disconnect disconnects from the running Elastic Agent.
func (c *client) Disconnect() {
	if c.cancel != nil {
		c.cancel()
		c.wg.Wait()
		c.ctx = nil
		c.cancel = nil
	}
}

// Version returns the current version of the running agent.
func (c *client) Version(ctx context.Context) (Version, error) {
	res, err := c.client.Version(ctx, &cproto.Empty{})
	if err != nil {
		return Version{}, err
	}
	bt, err := time.Parse(control.TimeFormat(), res.BuildTime)
	if err != nil {
		return Version{}, err
	}
	return Version{
		Version:   res.Version,
		Commit:    res.Commit,
		BuildTime: bt,
		Snapshot:  res.Snapshot,
	}, nil
}

// State returns the current state of the running agent.
func (c *client) State(ctx context.Context) (*AgentState, error) {
	res, err := c.client.State(ctx, &cproto.Empty{})
	if err != nil {
		return nil, err
	}
	s := &AgentState{
		State:      res.State,
		Message:    res.Message,
		Components: make([]ComponentState, 0, len(res.Components)),
	}
	for _, comp := range res.Components {
		units := make([]ComponentUnitState, 0, len(comp.Units))
		for _, unit := range comp.Units {
			var payload map[string]interface{}
			if unit.Payload != "" {
				err := json.Unmarshal([]byte(unit.Payload), &payload)
				if err != nil {
					return nil, err
				}
			}
			units = append(units, ComponentUnitState{
				UnitID:   unit.UnitId,
				UnitType: unit.UnitType,
				State:    unit.State,
				Message:  unit.Message,
				Payload:  payload,
			})
		}
		s.Components = append(s.Components, ComponentState{
			ID:      comp.Id,
			Name:    comp.Name,
			State:   comp.State,
			Message: comp.Message,
			Units:   units,
		})
	}
	return s, nil
}

// Restart triggers restarting the current running daemon.
func (c *client) Restart(ctx context.Context) error {
	res, err := c.client.Restart(ctx, &cproto.Empty{})
	if err != nil {
		return err
	}
	if res.Status == cproto.ActionStatus_FAILURE {
		return fmt.Errorf(res.Error)
	}
	return nil
}

// Upgrade triggers upgrade of the current running daemon.
func (c *client) Upgrade(ctx context.Context, version string, sourceURI string) (string, error) {
	res, err := c.client.Upgrade(ctx, &cproto.UpgradeRequest{
		Version:   version,
		SourceURI: sourceURI,
	})
	if err != nil {
		return "", err
	}
	if res.Status == cproto.ActionStatus_FAILURE {
		return "", fmt.Errorf(res.Error)
	}
	return res.Version, nil
}

// ProcMeta gathers running beat metadata.
func (c *client) ProcMeta(ctx context.Context) ([]ProcMeta, error) {
	resp, err := c.client.ProcMeta(ctx, &cproto.Empty{})
	if err != nil {
		return nil, err
	}
	procMeta := []ProcMeta{}

	for _, proc := range resp.Procs {
		meta := ProcMeta{
			Process:            proc.Process,
			Name:               proc.Name,
			Hostname:           proc.Hostname,
			ID:                 proc.Id,
			EphemeralID:        proc.EphemeralId,
			Version:            proc.Version,
			BuildCommit:        proc.BuildCommit,
			Username:           proc.Username,
			UserID:             proc.UserId,
			UserGID:            proc.UserGid,
			BinaryArchitecture: proc.Architecture,
			RouteKey:           proc.RouteKey,
			ElasticLicensed:    proc.ElasticLicensed,
			Error:              proc.Error,
		}
		if proc.BuildTime != "" {
			ts, err := time.Parse(time.RFC3339, proc.BuildTime)
			if err != nil {
				if meta.Error != "" {
					meta.Error += ", " + err.Error()
				} else {
					meta.Error = err.Error()
				}
			} else {
				meta.BuildTime = ts
			}
		}
		procMeta = append(procMeta, meta)
	}
	return procMeta, nil
}

// Pprof gathers /debug/pprof data and returns a map of pprof-type: ProcPProf data
func (c *client) Pprof(ctx context.Context, d time.Duration, pprofTypes []cproto.PprofOption, appName, routeKey string) (map[string][]ProcPProf, error) {
	resp, err := c.client.Pprof(ctx, &cproto.PprofRequest{
		PprofType:     pprofTypes,
		TraceDuration: d.String(),
		AppName:       appName,
		RouteKey:      routeKey,
	})
	if err != nil {
		return nil, err
	}
	res := map[string][]ProcPProf{}
	for _, pType := range pprofTypes {
		res[pType.String()] = make([]ProcPProf, 0)
	}
	for _, r := range resp.Results {
		res[r.PprofType.String()] = append(res[r.PprofType.String()], ProcPProf{
			Name:     r.AppName,
			RouteKey: r.RouteKey,
			Result:   r.Result,
			Error:    r.Error,
		})
	}
	return res, nil
}

// ProcMetrics gathers /buffer data and from the agent and each running process and returns the result.
func (c *client) ProcMetrics(ctx context.Context) (*cproto.ProcMetricsResponse, error) {
	return c.client.ProcMetrics(ctx, &cproto.Empty{})
}

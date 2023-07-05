// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/elastic/elastic-agent/pkg/control"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"

	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
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
	Version   string    `json:"version" yaml:"version"`
	Commit    string    `json:"commit" yaml:"commit"`
	BuildTime time.Time `json:"build_time" yaml:"build_time"`
	Snapshot  bool      `json:"snapshot" yaml:"snapshot"`
	FIPS      bool      `json:"fips" yaml:"fips"`
}

// ComponentVersionInfo is the version information for the component.
type ComponentVersionInfo struct {
	// Name of the component.
	Name string `json:"name" yaml:"name"`
	// Version of the component.
	Version string `json:"version" yaml:"version"`
	// Extra meta information about the version.
	Meta map[string]string `json:"meta,omitempty" yaml:"meta,omitempty"`
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
	ID          string               `json:"id" yaml:"id"`
	Name        string               `json:"name" yaml:"name"`
	State       State                `json:"state" yaml:"state"`
	Message     string               `json:"message" yaml:"message"`
	Units       []ComponentUnitState `json:"units" yaml:"units"`
	VersionInfo ComponentVersionInfo `json:"version_info" yaml:"version_info"`
}

// AgentStateInfo is the overall information about the Elastic Agent.
type AgentStateInfo struct {
	ID        string `json:"id" yaml:"id"`
	Version   string `json:"version" yaml:"version"`
	Commit    string `json:"commit" yaml:"commit"`
	BuildTime string `json:"build_time" yaml:"build_time"`
	Snapshot  bool   `json:"snapshot" yaml:"snapshot"`
}

// AgentState is the current state of the Elastic Agent.
type AgentState struct {
	Info         AgentStateInfo   `json:"info" yaml:"info"`
	State        State            `json:"state" yaml:"state"`
	Message      string           `json:"message" yaml:"message"`
	Components   []ComponentState `json:"components" yaml:"components"`
	FleetState   State            `yaml:"fleet_state"`
	FleetMessage string           `yaml:"fleet_message"`
}

// DiagnosticFileResult is a diagnostic file result.
type DiagnosticFileResult struct {
	Name        string
	Filename    string
	Description string
	ContentType string
	Content     []byte
	Generated   time.Time
}

// DiagnosticUnitRequest allows a specific unit to be targeted for diagnostics.
type DiagnosticUnitRequest struct {
	ComponentID string
	UnitID      string
	UnitType    UnitType
}

// DiagnosticUnitResult is a set of results for a unit.
type DiagnosticUnitResult struct {
	ComponentID string
	UnitID      string
	UnitType    UnitType
	Err         error
	Results     []DiagnosticFileResult
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
	// StateWatch watches the current state of the running agent.
	StateWatch(ctx context.Context) (ClientStateWatch, error)
	// Restart triggers restarting the current running daemon.
	Restart(ctx context.Context) error
	// Upgrade triggers upgrade of the current running daemon.
	Upgrade(ctx context.Context, version string, sourceURI string, skipVerify bool, pgpBytes ...string) (string, error)
	// DiagnosticAgent gathers diagnostics information for the running Elastic Agent.
	DiagnosticAgent(ctx context.Context) ([]DiagnosticFileResult, error)
	// DiagnosticUnits gathers diagnostics information from specific units (or all if non are provided).
	DiagnosticUnits(ctx context.Context, units ...DiagnosticUnitRequest) ([]DiagnosticUnitResult, error)
	// Configure sends a new configuration to the Elastic Agent.
	//
	// Only works in the case that Elastic Agent is started in testing mode.
	Configure(ctx context.Context, config string) error
}

// ClientStateWatch allows the state of the running Elastic Agent to be watched.
type ClientStateWatch interface {
	// Recv receives the next agent state.
	Recv() (*AgentState, error)
}

// Option is an option to adjust how the client operates.
type Option func(c *client)

// WithAddress adjust the connection address for the client.
func WithAddress(address string) Option {
	return func(c *client) {
		c.address = address
	}
}

// WithMaxMsgSize adjures the GRPC connection maximum message size.
func WithMaxMsgSize(maxMsgSize int) Option {
	return func(c *client) {
		c.maxMsgSize = maxMsgSize
	}
}

// client manages the state and communication to the Elastic Agent.
type client struct {
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	client     cproto.ElasticAgentControlClient
	address    string
	maxMsgSize int
}

// New creates a client connection to Elastic Agent.
func New(opts ...Option) Client {
	cfg := configuration.DefaultGRPCConfig()
	c := &client{
		address:    control.Address(),
		maxMsgSize: cfg.MaxMsgSize,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Connect connects to the running Elastic Agent.
func (c *client) Connect(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)
	conn, err := dialContext(ctx, c.address, c.maxMsgSize)
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
		FIPS:      res.Fips,
	}, nil
}

// State returns the current state of the running agent.
func (c *client) State(ctx context.Context) (*AgentState, error) {
	res, err := c.client.State(ctx, &cproto.Empty{})
	if err != nil {
		return nil, err
	}
	return toState(res)
}

// StateWatch watches the current state of the running agent.
func (c *client) StateWatch(ctx context.Context) (ClientStateWatch, error) {
	cli, err := c.client.StateWatch(ctx, &cproto.Empty{})
	if err != nil {
		return nil, err
	}
	return &stateWatcher{cli}, nil
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
func (c *client) Upgrade(ctx context.Context, version string, sourceURI string, skipVerify bool, pgpBytes ...string) (string, error) {
	res, err := c.client.Upgrade(ctx, &cproto.UpgradeRequest{
		Version:    version,
		SourceURI:  sourceURI,
		SkipVerify: skipVerify,
		PgpBytes:   pgpBytes,
	})
	if err != nil {
		return "", err
	}
	if res.Status == cproto.ActionStatus_FAILURE {
		return "", fmt.Errorf(res.Error)
	}
	return res.Version, nil
}

// DiagnosticAgent gathers diagnostics information for the running Elastic Agent.
func (c *client) DiagnosticAgent(ctx context.Context) ([]DiagnosticFileResult, error) {
	resp, err := c.client.DiagnosticAgent(ctx, &cproto.DiagnosticAgentRequest{})
	if err != nil {
		return nil, err
	}

	files := make([]DiagnosticFileResult, 0, len(resp.Results))
	for _, f := range resp.Results {
		files = append(files, DiagnosticFileResult{
			Name:        f.Name,
			Filename:    f.Filename,
			Description: f.Description,
			ContentType: f.ContentType,
			Content:     f.Content,
			Generated:   f.Generated.AsTime(),
		})
	}
	return files, nil
}

// DiagnosticUnits gathers diagnostics information from specific units (or all if non are provided).
func (c *client) DiagnosticUnits(ctx context.Context, units ...DiagnosticUnitRequest) ([]DiagnosticUnitResult, error) {
	reqs := make([]*cproto.DiagnosticUnitRequest, 0, len(units))
	for _, u := range units {
		reqs = append(reqs, &cproto.DiagnosticUnitRequest{
			ComponentId: u.ComponentID,
			UnitType:    u.UnitType,
			UnitId:      u.UnitID,
		})
	}

	respStream, err := c.client.DiagnosticUnits(ctx, &cproto.DiagnosticUnitsRequest{Units: reqs})
	if err != nil {
		return nil, err
	}

	results := make([]DiagnosticUnitResult, 0)
	for {
		var u *cproto.DiagnosticUnitResponse
		u, err = respStream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve unit diagnostics: %w", err)
		}

		files := make([]DiagnosticFileResult, 0, len(u.Results))
		for _, f := range u.Results {
			files = append(files, DiagnosticFileResult{
				Name:        f.Name,
				Filename:    f.Filename,
				Description: f.Description,
				ContentType: f.ContentType,
				Content:     f.Content,
				Generated:   f.Generated.AsTime(),
			})
		}
		var err error
		if u.Error != "" {
			err = errors.New(u.Error)
		}
		results = append(results, DiagnosticUnitResult{
			ComponentID: u.ComponentId,
			UnitID:      u.UnitId,
			UnitType:    u.UnitType,
			Err:         err,
			Results:     files,
		})
	}

	return results, nil
}

// Configure sends a new configuration to the Elastic Agent.
//
// Only works in the case that Elastic Agent is started in testing mode.
func (c *client) Configure(ctx context.Context, config string) error {
	_, err := c.client.Configure(ctx, &cproto.ConfigureRequest{Config: config})
	return err
}

type stateWatcher struct {
	client cproto.ElasticAgentControl_StateWatchClient
}

// Recv receives the next agent state.
func (sw *stateWatcher) Recv() (*AgentState, error) {
	resp, err := sw.client.Recv()
	if err != nil {
		return nil, err
	}
	return toState(resp)
}

func toState(res *cproto.StateResponse) (*AgentState, error) {
	s := &AgentState{
		Info: AgentStateInfo{
			ID:        res.Info.Id,
			Version:   res.Info.Version,
			Commit:    res.Info.Commit,
			BuildTime: res.Info.BuildTime,
			Snapshot:  res.Info.Snapshot,
		},
		State:        res.State,
		Message:      res.Message,
		FleetState:   res.FleetState,
		FleetMessage: res.FleetMessage,

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
		cs := ComponentState{
			ID:      comp.Id,
			Name:    comp.Name,
			State:   comp.State,
			Message: comp.Message,
			Units:   units,
		}
		if comp.VersionInfo != nil {
			cs.VersionInfo = ComponentVersionInfo{
				Name:    comp.VersionInfo.Name,
				Version: comp.VersionInfo.Version,
				Meta:    comp.VersionInfo.Meta,
			}
		}
		s.Components = append(s.Components, cs)
	}
	return s, nil
}

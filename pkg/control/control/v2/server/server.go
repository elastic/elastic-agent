// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/elastic/elastic-agent/pkg/control/control"
	"github.com/elastic/elastic-agent/pkg/control/control/v1/proto"
	v1server "github.com/elastic/elastic-agent/pkg/control/control/v1/server"
	cproto2 "github.com/elastic/elastic-agent/pkg/control/control/v2/cproto"

	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmgrpc"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// TestModeConfigSetter is used only for testing mode.
type TestModeConfigSetter interface {
	// SetConfig sets the configuration.
	SetConfig(ctx context.Context, cfg string) error
}

// Server is the daemon side of the control protocol.
type Server struct {
	cproto2.UnimplementedElasticAgentControlServer

	logger     *logger.Logger
	agentInfo  *info.AgentInfo
	coord      *coordinator.Coordinator
	listener   net.Listener
	server     *grpc.Server
	tracer     *apm.Tracer
	diagHooks  diagnostics.Hooks
	grpcConfig *configuration.GRPCConfig

	tmSetter TestModeConfigSetter
}

// New creates a new control protocol server.
func New(log *logger.Logger, agentInfo *info.AgentInfo, coord *coordinator.Coordinator, tracer *apm.Tracer, diagHooks diagnostics.Hooks, grpcConfig *configuration.GRPCConfig) *Server {
	return &Server{
		logger:     log,
		agentInfo:  agentInfo,
		coord:      coord,
		tracer:     tracer,
		diagHooks:  diagHooks,
		grpcConfig: grpcConfig,
	}
}

// SetTestModeConfigSetter sets the test mode configuration setter.
func (s *Server) SetTestModeConfigSetter(setter TestModeConfigSetter) {
	s.tmSetter = setter
}

// Start starts the GRPC endpoint and accepts new connections.
func (s *Server) Start() error {
	if s.server != nil {
		// already started
		return nil
	}

	lis, err := createListener(s.logger)
	if err != nil {
		s.logger.Errorf("unable to create listener: %s", err)
		return err
	}
	s.listener = lis
	if s.tracer != nil {
		apmInterceptor := apmgrpc.NewUnaryServerInterceptor(apmgrpc.WithRecovery(), apmgrpc.WithTracer(s.tracer))
		s.server = grpc.NewServer(grpc.UnaryInterceptor(apmInterceptor), grpc.MaxRecvMsgSize(s.grpcConfig.MaxMsgSize))
	} else {
		s.server = grpc.NewServer(grpc.MaxRecvMsgSize(s.grpcConfig.MaxMsgSize))
	}
	cproto2.RegisterElasticAgentControlServer(s.server, s)

	v1Wrapper := v1server.New(s.logger, s, s.tracer)
	proto.RegisterElasticAgentControlServer(s.server, v1Wrapper)

	// start serving GRPC connections
	go func() {
		err := s.server.Serve(lis)
		if err != nil {
			s.logger.Errorf("error listening for GRPC: %s", err)
		}
	}()

	return nil
}

// Stop stops the GRPC endpoint.
func (s *Server) Stop() {
	if s.server != nil {
		s.server.Stop()
		s.server = nil
		s.listener = nil
		cleanupListener(s.logger)
	}
}

// Version returns the currently running version.
func (s *Server) Version(_ context.Context, _ *cproto2.Empty) (*cproto2.VersionResponse, error) {
	return &cproto2.VersionResponse{
		Version:   release.Version(),
		Commit:    release.Commit(),
		BuildTime: release.BuildTime().Format(control.TimeFormat()),
		Snapshot:  release.Snapshot(),
	}, nil
}

// State returns the overall state of the agent.
func (s *Server) State(_ context.Context, _ *cproto2.Empty) (*cproto2.StateResponse, error) {
	state := s.coord.State()
	return stateToProto(&state, s.agentInfo)
}

// StateWatch streams the current state of the Elastic Agent to the client.
func (s *Server) StateWatch(_ *cproto2.Empty, srv cproto2.ElasticAgentControl_StateWatchServer) error {
	ctx := srv.Context()
	sub := s.coord.StateSubscribe(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case state := <-sub.Ch():
			resp, err := stateToProto(&state, s.agentInfo)
			if err != nil {
				return err
			}
			err = srv.Send(resp)
			if err != nil {
				return err
			}
		}
	}
}

// Restart performs re-exec.
func (s *Server) Restart(_ context.Context, _ *cproto2.Empty) (*cproto2.RestartResponse, error) {
	s.coord.ReExec(nil)
	return &cproto2.RestartResponse{
		Status: cproto2.ActionStatus_SUCCESS,
	}, nil
}

// Upgrade performs the upgrade operation.
func (s *Server) Upgrade(ctx context.Context, request *cproto2.UpgradeRequest) (*cproto2.UpgradeResponse, error) {
	err := s.coord.Upgrade(ctx, request.Version, request.SourceURI, nil)
	if err != nil {
		return &cproto2.UpgradeResponse{
			Status: cproto2.ActionStatus_FAILURE,
			Error:  err.Error(),
		}, nil
	}
	return &cproto2.UpgradeResponse{
		Status:  cproto2.ActionStatus_SUCCESS,
		Version: request.Version,
	}, nil
}

// DiagnosticAgent returns diagnostic information for this running Elastic Agent.
func (s *Server) DiagnosticAgent(ctx context.Context, _ *cproto2.DiagnosticAgentRequest) (*cproto2.DiagnosticAgentResponse, error) {
	res := make([]*cproto2.DiagnosticFileResult, 0, len(s.diagHooks))
	for _, h := range s.diagHooks {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		r := h.Hook(ctx)
		res = append(res, &cproto2.DiagnosticFileResult{
			Name:        h.Name,
			Filename:    h.Filename,
			Description: h.Description,
			ContentType: h.ContentType,
			Content:     r,
			Generated:   timestamppb.New(time.Now().UTC()),
		})
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &cproto2.DiagnosticAgentResponse{Results: res}, nil
}

// DiagnosticUnits returns diagnostic information for the specific units (or all units if non-provided).
func (s *Server) DiagnosticUnits(req *cproto2.DiagnosticUnitsRequest, srv cproto2.ElasticAgentControl_DiagnosticUnitsServer) error {
	reqs := make([]runtime.ComponentUnitDiagnosticRequest, 0, len(req.Units))
	for _, u := range req.Units {
		reqs = append(reqs, runtime.ComponentUnitDiagnosticRequest{
			Component: component.Component{
				ID: u.ComponentId,
			},
			Unit: component.Unit{
				ID:   u.UnitId,
				Type: client.UnitType(u.UnitType),
			},
		})
	}

	diag := s.coord.PerformDiagnostics(srv.Context(), reqs...)
	for _, d := range diag {
		r := &cproto2.DiagnosticUnitResponse{
			ComponentId: d.Component.ID,
			UnitType:    cproto2.UnitType(d.Unit.Type),
			UnitId:      d.Unit.ID,
			Error:       "",
			Results:     nil,
		}
		if d.Err != nil {
			r.Error = d.Err.Error()
		} else {
			results := make([]*cproto2.DiagnosticFileResult, 0, len(d.Results))
			for _, fr := range d.Results {
				results = append(results, &cproto2.DiagnosticFileResult{
					Name:        fr.Name,
					Filename:    fr.Filename,
					Description: fr.Description,
					ContentType: fr.ContentType,
					Content:     fr.Content,
					Generated:   fr.Generated,
				})
			}
			r.Results = results
		}

		if err := srv.Send(r); err != nil {
			return err
		}
	}

	return nil
}

// Configure configures the running Elastic Agent configuration.
//
// Only available in TESTING_MODE.
func (s *Server) Configure(ctx context.Context, req *cproto2.ConfigureRequest) (*cproto2.Empty, error) {
	if s.tmSetter == nil {
		return nil, errors.New("TESTING_MODE is not enabled")
	}
	err := s.tmSetter.SetConfig(ctx, req.Config)
	if err != nil {
		return nil, err
	}
	return &cproto2.Empty{}, nil
}

func stateToProto(state *coordinator.State, agentInfo *info.AgentInfo) (*cproto2.StateResponse, error) {
	var err error
	components := make([]*cproto2.ComponentState, 0, len(state.Components))
	for _, comp := range state.Components {
		units := make([]*cproto2.ComponentUnitState, 0, len(comp.State.Units))
		for key, unit := range comp.State.Units {
			payload := []byte("")
			if unit.Payload != nil {
				payload, err = json.Marshal(unit.Payload)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal componend %s unit %s payload: %w", comp.Component.ID, key.UnitID, err)
				}
			}
			units = append(units, &cproto2.ComponentUnitState{
				UnitType: cproto2.UnitType(key.UnitType),
				UnitId:   key.UnitID,
				State:    cproto2.State(unit.State),
				Message:  unit.Message,
				Payload:  string(payload),
			})
		}
		components = append(components, &cproto2.ComponentState{
			Id:      comp.Component.ID,
			Name:    comp.Component.Type(),
			State:   cproto2.State(comp.State.State),
			Message: comp.State.Message,
			Units:   units,
			VersionInfo: &cproto2.ComponentVersionInfo{
				Name:    comp.State.VersionInfo.Name,
				Version: comp.State.VersionInfo.Version,
				Meta:    comp.State.VersionInfo.Meta,
			},
		})
	}
	return &cproto2.StateResponse{
		Info: &cproto2.StateAgentInfo{
			Id:        agentInfo.AgentID(),
			Version:   release.Version(),
			Commit:    release.Commit(),
			BuildTime: release.BuildTime().Format(control.TimeFormat()),
			Snapshot:  release.Snapshot(),
		},
		State:      state.State,
		Message:    state.Message,
		Components: components,
	}, nil
}

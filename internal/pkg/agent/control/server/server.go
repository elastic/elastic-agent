// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/elastic/elastic-agent/pkg/component/runtime"

	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmgrpc"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/control"
	"github.com/elastic/elastic-agent/internal/pkg/agent/control/cproto"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Server is the daemon side of the control protocol.
type Server struct {
	cproto.UnimplementedElasticAgentControlServer
	logger      *logger.Logger
	agentInfo   *info.AgentInfo
	coord       *coordinator.Coordinator
	listener    net.Listener
	server      *grpc.Server
	tracer      *apm.Tracer
	grpcConfig  *configuration.GRPCConfig
	diagHooksFn []func() diagnostics.Hooks
}

// New creates a new control protocol server.
func New(log *logger.Logger, agentInfo *info.AgentInfo, coord *coordinator.Coordinator, tracer *apm.Tracer, grpcConfig *configuration.GRPCConfig, diagHooksFn ...func() diagnostics.Hooks) *Server {
	return &Server{
		logger:     log,
		agentInfo:  agentInfo,
		coord:      coord,
		tracer:     tracer,
		grpcConfig: grpcConfig,
		diagHooks:  diagHooksFn,
	}
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
	cproto.RegisterElasticAgentControlServer(s.server, s)

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
func (s *Server) Version(_ context.Context, _ *cproto.Empty) (*cproto.VersionResponse, error) {
	return &cproto.VersionResponse{
		Version:   release.Version(),
		Commit:    release.Commit(),
		BuildTime: release.BuildTime().Format(control.TimeFormat()),
		Snapshot:  release.Snapshot(),
	}, nil
}

// State returns the overall state of the agent.
func (s *Server) State(_ context.Context, _ *cproto.Empty) (*cproto.StateResponse, error) {
	var err error

	state := s.coord.State(true)
	components := make([]*cproto.ComponentState, 0, len(state.Components))
	for _, comp := range state.Components {
		units := make([]*cproto.ComponentUnitState, 0, len(comp.State.Units))
		for key, unit := range comp.State.Units {
			payload := []byte("")
			if unit.Payload != nil {
				payload, err = json.Marshal(unit.Payload)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal componend %s unit %s payload: %w", comp.Component.ID, key.UnitID, err)
				}
			}
			units = append(units, &cproto.ComponentUnitState{
				UnitType: cproto.UnitType(key.UnitType),
				UnitId:   key.UnitID,
				State:    cproto.State(unit.State),
				Message:  unit.Message,
				Payload:  string(payload),
			})
		}
		components = append(components, &cproto.ComponentState{
			Id:      comp.Component.ID,
			Name:    comp.Component.Type(),
			State:   cproto.State(comp.State.State),
			Message: comp.State.Message,
			Units:   units,
			VersionInfo: &cproto.ComponentVersionInfo{
				Name:    comp.State.VersionInfo.Name,
				Version: comp.State.VersionInfo.Version,
				Meta:    comp.State.VersionInfo.Meta,
			},
		})
	}
	return &cproto.StateResponse{
		Info: &cproto.StateAgentInfo{
			Id:        s.agentInfo.AgentID(),
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

// Restart performs re-exec.
func (s *Server) Restart(_ context.Context, _ *cproto.Empty) (*cproto.RestartResponse, error) {
	s.coord.ReExec(nil)
	return &cproto.RestartResponse{
		Status: cproto.ActionStatus_SUCCESS,
	}, nil
}

// Upgrade performs the upgrade operation.
func (s *Server) Upgrade(ctx context.Context, request *cproto.UpgradeRequest) (*cproto.UpgradeResponse, error) {
	err := s.coord.Upgrade(ctx, request.Version, request.SourceURI, nil)
	if err != nil {
		return &cproto.UpgradeResponse{
			Status: cproto.ActionStatus_FAILURE,
			Error:  err.Error(),
		}, nil
	}
	return &cproto.UpgradeResponse{
		Status:  cproto.ActionStatus_SUCCESS,
		Version: request.Version,
	}, nil
}

// DiagnosticAgent returns diagnostic information for this running Elastic Agent.
func (s *Server) DiagnosticAgent(ctx context.Context, _ *cproto.DiagnosticAgentRequest) (*cproto.DiagnosticAgentResponse, error) {
	diagHooks := make([]diagnostics.Hook, 0)
	for _, fn := range s.diagHooksFn {
		hooks := fn()
		diagHooks = append(diagHooks, hooks...)
	}
	res := make([]*cproto.DiagnosticFileResult, 0, len(diagHooks))
	for _, h := range diagHooks {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		r, ts := h.Hook(ctx)
		res = append(res, &cproto.DiagnosticFileResult{
			Name:        h.Name,
			Filename:    h.Filename,
			Description: h.Description,
			ContentType: h.ContentType,
			Content:     r,
			Generated:   timestamppb.New(ts),
		})
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &cproto.DiagnosticAgentResponse{Results: res}, nil
}

// DiagnosticUnits returns diagnostic information for the specific units (or all units if non-provided).
func (s *Server) DiagnosticUnits(req *cproto.DiagnosticUnitsRequest, srv cproto.ElasticAgentControl_DiagnosticUnitsServer) error {
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
		r := &cproto.DiagnosticUnitResponse{
			ComponentId: d.Component.ID,
			UnitType:    cproto.UnitType(d.Unit.Type),
			UnitId:      d.Unit.ID,
			Error:       "",
			Results:     nil,
		}
		if d.Err != nil {
			r.Error = d.Err.Error()
		} else {
			results := make([]*cproto.DiagnosticFileResult, 0, len(d.Results))
			for _, fr := range d.Results {
				results = append(results, &cproto.DiagnosticFileResult{
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

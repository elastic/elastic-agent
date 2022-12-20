// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

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
	v2proto "github.com/elastic/elastic-agent/internal/pkg/agent/control/cproto"
	v1proto "github.com/elastic/elastic-agent/internal/pkg/agent/control/proto"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Wrapper to allow embedded two types with the same UnimplementedElasticAgentControlServer name
// from different packages.
type v1ElasticControlServer struct {
	v1proto.UnimplementedElasticAgentControlServer
}

// Server is the daemon side of the control protocol.
type Server struct {
	v2proto.UnimplementedElasticAgentControlServer
	v1ElasticControlServer

	logger     *logger.Logger
	agentInfo  *info.AgentInfo
	coord      *coordinator.Coordinator
	listener   net.Listener
	server     *grpc.Server
	tracer     *apm.Tracer
	diagHooks  diagnostics.Hooks
	grpcConfig *configuration.GRPCConfig
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
	v2proto.RegisterElasticAgentControlServer(s.server, s)
	v1proto.RegisterElasticAgentControlServer(s.server, s)

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
func (s *Server) Version(_ context.Context, _ *v2proto.Empty) (*v2proto.VersionResponse, error) {
	return &v2proto.VersionResponse{
		Version:   release.Version(),
		Commit:    release.Commit(),
		BuildTime: release.BuildTime().Format(control.TimeFormat()),
		Snapshot:  release.Snapshot(),
	}, nil
}

func (s *Server) Status(_ context.Context, _ *v1proto.Empty) (*v1proto.StatusResponse, error) {
	return &v1proto.StatusResponse{
		Status:  v1proto.Status_V1_FAILED,
		Message: "this is a test",
	}, nil
}

// State returns the overall state of the agent.
func (s *Server) State(_ context.Context, _ *v2proto.Empty) (*v2proto.StateResponse, error) {
	var err error

	state := s.coord.State(true)
	components := make([]*v2proto.ComponentState, 0, len(state.Components))
	for _, comp := range state.Components {
		units := make([]*v2proto.ComponentUnitState, 0, len(comp.State.Units))
		for key, unit := range comp.State.Units {
			payload := []byte("")
			if unit.Payload != nil {
				payload, err = json.Marshal(unit.Payload)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal componend %s unit %s payload: %w", comp.Component.ID, key.UnitID, err)
				}
			}
			units = append(units, &v2proto.ComponentUnitState{
				UnitType: v2proto.UnitType(key.UnitType),
				UnitId:   key.UnitID,
				State:    v2proto.State(unit.State),
				Message:  unit.Message,
				Payload:  string(payload),
			})
		}
		components = append(components, &v2proto.ComponentState{
			Id:      comp.Component.ID,
			Name:    comp.Component.Type(),
			State:   v2proto.State(comp.State.State),
			Message: comp.State.Message,
			Units:   units,
			VersionInfo: &v2proto.ComponentVersionInfo{
				Name:    comp.State.VersionInfo.Name,
				Version: comp.State.VersionInfo.Version,
				Meta:    comp.State.VersionInfo.Meta,
			},
		})
	}
	return &v2proto.StateResponse{
		Info: &v2proto.StateAgentInfo{
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
func (s *Server) Restart(_ context.Context, _ *v2proto.Empty) (*v2proto.RestartResponse, error) {
	s.coord.ReExec(nil)
	return &v2proto.RestartResponse{
		Status: v2proto.ActionStatus_SUCCESS,
	}, nil
}

// Upgrade performs the upgrade operation.
func (s *Server) Upgrade(ctx context.Context, request *v2proto.UpgradeRequest) (*v2proto.UpgradeResponse, error) {
	err := s.coord.Upgrade(ctx, request.Version, request.SourceURI, nil)
	if err != nil {
		return &v2proto.UpgradeResponse{
			Status: v2proto.ActionStatus_FAILURE,
			Error:  err.Error(),
		}, nil
	}
	return &v2proto.UpgradeResponse{
		Status:  v2proto.ActionStatus_SUCCESS,
		Version: request.Version,
	}, nil
}

// DiagnosticAgent returns diagnostic information for this running Elastic Agent.
func (s *Server) DiagnosticAgent(ctx context.Context, _ *v2proto.DiagnosticAgentRequest) (*v2proto.DiagnosticAgentResponse, error) {
	res := make([]*v2proto.DiagnosticFileResult, 0, len(s.diagHooks))
	for _, h := range s.diagHooks {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		r := h.Hook(ctx)
		res = append(res, &v2proto.DiagnosticFileResult{
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
	return &v2proto.DiagnosticAgentResponse{Results: res}, nil
}

// DiagnosticUnits returns diagnostic information for the specific units (or all units if non-provided).
func (s *Server) DiagnosticUnits(req *v2proto.DiagnosticUnitsRequest, srv v2proto.ElasticAgentControl_DiagnosticUnitsServer) error {
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
		r := &v2proto.DiagnosticUnitResponse{
			ComponentId: d.Component.ID,
			UnitType:    v2proto.UnitType(d.Unit.Type),
			UnitId:      d.Unit.ID,
			Error:       "",
			Results:     nil,
		}
		if d.Err != nil {
			r.Error = d.Err.Error()
		} else {
			results := make([]*v2proto.DiagnosticFileResult, 0, len(d.Results))
			for _, fr := range d.Results {
				results = append(results, &v2proto.DiagnosticFileResult{
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

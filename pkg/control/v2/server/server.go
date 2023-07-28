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

	"github.com/elastic/elastic-agent/pkg/control"
	"github.com/elastic/elastic-agent/pkg/control/v1/proto"
	v1server "github.com/elastic/elastic-agent/pkg/control/v1/server"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"

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
	cproto.UnimplementedElasticAgentControlServer

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
	cproto.RegisterElasticAgentControlServer(s.server, s)

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
	state := s.coord.State()
	return stateToProto(&state, s.agentInfo)
}

// StateWatch streams the current state of the Elastic Agent to the client.
func (s *Server) StateWatch(_ *cproto.Empty, srv cproto.ElasticAgentControl_StateWatchServer) error {
	ctx := srv.Context()
	// TODO: Should we expose the subscription buffer size in the RPC? This
	// would e.g. let subscribers who only care about the latest state set a
	// buffer size of 0 so they will always receive the most recent value
	// instead of the full sequence.
	subChan := s.coord.StateSubscribe(ctx, 32)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case state := <-subChan:
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
func (s *Server) Restart(_ context.Context, _ *cproto.Empty) (*cproto.RestartResponse, error) {
	s.coord.ReExec(nil)
	return &cproto.RestartResponse{
		Status: cproto.ActionStatus_SUCCESS,
	}, nil
}

// Upgrade performs the upgrade operation.
func (s *Server) Upgrade(ctx context.Context, request *cproto.UpgradeRequest) (*cproto.UpgradeResponse, error) {
	err := s.coord.Upgrade(ctx, request.Version, request.SourceURI, nil, request.SkipVerify, request.PgpBytes...)
	if err != nil {
		//nolint:nilerr // ignore the error, return a failure upgrade response
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
func (s *Server) DiagnosticAgent(ctx context.Context, req *cproto.DiagnosticAgentRequest) (*cproto.DiagnosticAgentResponse, error) {
	res := make([]*cproto.DiagnosticFileResult, 0, len(s.diagHooks))
	for _, h := range s.diagHooks {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		r := h.Hook(ctx)
		res = append(res, &cproto.DiagnosticFileResult{
			Name:        h.Name,
			Filename:    h.Filename,
			Description: h.Description,
			ContentType: h.ContentType,
			Content:     r,
			Generated:   timestamppb.New(time.Now().UTC()),
		})
	}

	for _, metric := range req.AdditionalMetrics {
		switch metric {
		case cproto.AdditionalDiagnosticRequest_CPU:
			duration := time.Second * 30
			s.logger.Infof("Collecting CPU metrics, waiting for %s", duration)
			cpuResults, err := diagnostics.CreateCPUProfile(ctx, duration)
			if err != nil {
				return nil, fmt.Errorf("error gathering CPU profile: %w", err)
			}
			res = append(res, &cproto.DiagnosticFileResult{
				Name:        "cpuprofile",
				Filename:    "cpu.pprof",
				Description: "CPU profile",
				ContentType: "application/octet-stream",
				Content:     cpuResults,
				Generated:   timestamppb.New(time.Now().UTC()),
			})
		}
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &cproto.DiagnosticAgentResponse{Results: res}, nil
}

// DiagnosticComponents returns diagnostic information for the given components
func (s *Server) DiagnosticComponents(req *cproto.DiagnosticComponentsRequest, respServ cproto.ElasticAgentControl_DiagnosticComponentsServer) error {
	reqs := []component.Component{}
	for _, comp := range req.Components {
		reqs = append(reqs, component.Component{ID: comp.GetComponentId()})
	}

	diags, err := s.coord.PerformComponentDiagnostics(respServ.Context(), req.AdditionalMetrics, reqs...)
	if err != nil {
		return fmt.Errorf("error fetching component-level diagnostics: %w", err)
	}
	for _, diag := range diags {
		respFiles := []*cproto.DiagnosticFileResult{}
		for _, file := range diag.Results {
			respFiles = append(respFiles, &cproto.DiagnosticFileResult{
				Name:        file.Name,
				Filename:    file.Filename,
				Description: file.Description,
				ContentType: file.ContentType,
				Content:     file.Content,
				Generated:   file.Generated,
			})
		}
		respStruct := &cproto.DiagnosticComponentResponse{
			ComponentId: diag.Component.ID,
			Results:     respFiles,
		}
		if diag.Err != nil {
			respStruct.Error = diag.Err.Error()
		}
		err := respServ.Send(respStruct)
		if err != nil {
			return fmt.Errorf("error sending response: %w", err)
		}
	}
	return nil
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

// Configure configures the running Elastic Agent configuration.
//
// Only available in testing mode.
func (s *Server) Configure(ctx context.Context, req *cproto.ConfigureRequest) (*cproto.Empty, error) {
	if s.tmSetter == nil {
		return nil, errors.New("testing mode is not enabled")
	}
	err := s.tmSetter.SetConfig(ctx, req.Config)
	if err != nil {
		return nil, err
	}
	return &cproto.Empty{}, nil
}

func stateToProto(state *coordinator.State, agentInfo *info.AgentInfo) (*cproto.StateResponse, error) {
	var err error
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
			Id:        agentInfo.AgentID(),
			Version:   release.Version(),
			Commit:    release.Commit(),
			BuildTime: release.BuildTime().Format(control.TimeFormat()),
			Snapshot:  release.Snapshot(),
		},
		State:        state.State,
		Message:      state.Message,
		FleetState:   state.FleetState,
		FleetMessage: state.FleetMessage,
		Components:   components,
	}, nil
}

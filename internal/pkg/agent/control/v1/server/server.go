// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package server

import (
	"context"

	"go.elastic.co/apm"

	"github.com/elastic/elastic-agent/internal/pkg/agent/control"
	"github.com/elastic/elastic-agent/internal/pkg/agent/control/v1/proto"
	cproto "github.com/elastic/elastic-agent/internal/pkg/agent/control/v2/cproto"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type serverV2 interface {
	State(_ context.Context, _ *cproto.Empty) (*cproto.StateResponse, error)
	Restart(_ context.Context, _ *cproto.Empty) (*cproto.RestartResponse, error)
	Upgrade(_ context.Context, _ *cproto.UpgradeRequest) (*cproto.UpgradeResponse, error)
}

// Server is the daemon side of the control protocol.
type Server struct {
	proto.UnimplementedElasticAgentControlServer

	logger   *logger.Logger
	v2Server serverV2
	tracer   *apm.Tracer
}

// New creates a new control protocol server.
func New(log *logger.Logger, v2Server serverV2, tracer *apm.Tracer) *Server {
	return &Server{
		logger:   log,
		v2Server: v2Server,
		tracer:   tracer,
	}
}

// Version returns the currently running version.
func (s *Server) Version(ctx context.Context, _ *proto.Empty) (*proto.VersionResponse, error) {
	return &proto.VersionResponse{
		Version:   release.Version(),
		Commit:    release.Commit(),
		BuildTime: release.BuildTime().Format(control.TimeFormat()),
		Snapshot:  release.Snapshot(),
	}, nil
}

// Status returns the overall status of the agent.
func (s *Server) Status(ctx context.Context, _ *proto.Empty) (*proto.StatusResponse, error) {
	resp, err := s.v2Server.State(ctx, &cproto.Empty{})
	if err != nil {
		return nil, err
	}

	return &proto.StatusResponse{
		Status:       agentStateToProto(resp.State),
		Message:      resp.Message,
		Applications: componentStateToProto(resp.Components),
	}, nil
}

// Restart performs re-exec.
func (s *Server) Restart(ctx context.Context, _ *proto.Empty) (*proto.RestartResponse, error) {
	_, err := s.v2Server.Restart(ctx, &cproto.Empty{})
	return &proto.RestartResponse{Status: proto.ActionStatus_V1_SUCCESS}, err

}

// Upgrade performs the upgrade operation.
func (s *Server) Upgrade(ctx context.Context, request *proto.UpgradeRequest) (*proto.UpgradeResponse, error) {
	resp, _ := s.v2Server.Upgrade(ctx, &cproto.UpgradeRequest{
		Version:   request.Version,
		SourceURI: request.SourceURI,
	})

	if resp.Status == cproto.ActionStatus_FAILURE {
		return &proto.UpgradeResponse{
			Status:  proto.ActionStatus_V1_FAILURE,
			Version: resp.Error,
		}, nil
	}

	return &proto.UpgradeResponse{
		Status:  proto.ActionStatus_V1_SUCCESS,
		Version: request.Version,
	}, nil
}

func agentStateToProto(state cproto.State) proto.Status {
	if state == cproto.State_DEGRADED {
		return proto.Status_V1_DEGRADED
	}
	if state == cproto.State_FAILED {
		return proto.Status_V1_FAILED
	}
	return proto.Status_V1_HEALTHY
}

func componentStateToProto(components []*cproto.ComponentState) []*proto.ApplicationStatus {
	s := make([]*proto.ApplicationStatus, len(components))
	for i, c := range components {
		s[i] = &proto.ApplicationStatus{
			Id:      c.Id,
			Name:    c.Name,
			Status:  agentStateToProto(c.State),
			Message: c.Message,
			Payload: "",
		}
	}
	return s
}

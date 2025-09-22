// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"google.golang.org/grpc"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/otel/elasticdiagnosticsextension"
	"github.com/elastic/elastic-agent/pkg/control"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/ipc"
)

type server struct {
	cproto.UnimplementedElasticAgentControlServer
	listener net.Listener
	server   *grpc.Server
	logger   *logp.Logger
}

func NewServer() *server {
	return &server{logger: logp.L()}
}

func (s *server) Start() error {
	lis, err := ipc.CreateListener(s.logger, control.AdressEDOT())
	if err != nil {
		return err
	}
	s.listener = lis
	s.server = grpc.NewServer(grpc.MaxRecvMsgSize(configuration.DefaultGRPCConfig().MaxMsgSize))
	cproto.RegisterElasticAgentControlServer(s.server, s)
	go func() {
		fmt.Println("started server")
		err := s.server.Serve(lis)
		if err != nil {
			fmt.Println("error listening for GRPC: %s", err)
		}
	}()
	return nil
}

func (s *server) Stop() error {
	if s.server != nil {
		s.server.Stop()
		s.server = nil
		s.listener = nil
		ipc.CleanupListener(s.logger, control.AdressEDOT())
	}
	return nil
}

func (s *server) DiagnosticAgent(ctx context.Context, _ *cproto.DiagnosticAgentRequest) (*cproto.DiagnosticAgentResponse, error) {
	resp, err := PerformDiagnosticsExt()
	if err != nil {
		return nil, err
	}
	res := &cproto.DiagnosticAgentResponse{
		Results: make([]*cproto.DiagnosticFileResult, 0),
	}
	for _, r := range resp.GlobalDiagnostics {
		res.Results = append(res.Results, &cproto.DiagnosticFileResult{
			Name:        r.Name,
			Filename:    r.Filename,
			ContentType: r.ContentType,
			Content:     r.Content,
			Description: r.Description,
		})
	}
	return res, nil
}

func (s *server) DiagnosticComponents(req *cproto.DiagnosticComponentsRequest, respServ cproto.ElasticAgentControl_DiagnosticComponentsServer) error {
	resp, err := PerformDiagnosticsExt()
	if err != nil {
		return err
	}
	for _, r := range resp.ComponentDiagnostics {
		res := &cproto.DiagnosticComponentResponse{
			Results: make([]*cproto.DiagnosticFileResult, 0),
		}
		res.Results = append(res.Results, &cproto.DiagnosticFileResult{
			Name:        r.Name,
			Filename:    r.Filename,
			ContentType: r.ContentType,
			Content:     r.Content,
			Description: r.Description,
		})
		res.ComponentId = r.Name
		err := respServ.Send(res)
		if err != nil {
			return fmt.Errorf("error sending response: %w", err)
		}
	}
	return nil
}

func PerformDiagnosticsExt() (*elasticdiagnosticsextension.Response, error) {
	tr := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", strings.TrimPrefix(paths.DiagnosticsExtensionSocket(), "unix://"))
		},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://localhost/diagnostics")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var respSerialized elasticdiagnosticsextension.Response

	if err := json.Unmarshal(respBytes, &respSerialized); err != nil {
		return nil, err
	}

	return &respSerialized, nil
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package unitserver delivers the units of OTel components to their beat receivers
// over the Elastic Agent control protocol, so that changing a unit doesn't change
// the collector configuration.
//
// Connections use mutual TLS like the runtime manager's control protocol: each
// component gets a token and a client certificate, which its receiver reads from
// the connection info in its config.
//
// The server only delivers configuration. Receivers report their status through
// the collector like any other receiver, so the server ignores the observed state
// they send back.
package unitserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/gofrs/uuid/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	gproto "google.golang.org/protobuf/proto"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/client/chunk"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/core/authority"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/ipc"
)

type unitKey struct {
	unitType client.UnitType
	id       string
}

// serverName is the name in the server certificate, which clients verify.
const serverName = "elastic-agent-otel-units"

// componentUnits holds the expected units of one component, and the
// credentials its receiver connects with.
type componentUnits struct {
	units map[unitKey]*proto.UnitExpected
	// changed is closed and replaced whenever the units change.
	changed chan struct{}

	token      string
	clientCert *authority.Pair
}

// Server is a control protocol server that only implements check-ins, and only
// to send expected units. A receiver's token identifies its component.
type Server struct {
	proto.UnimplementedElasticAgentServer

	logger         *logger.Logger
	address        string
	agentInfo      info.Agent
	maxMessageSize int
	ca             *authority.CertificateAuthority
	serverCert     *authority.Pair

	mx         sync.Mutex
	components map[string]*componentUnits
	// tokens maps receiver tokens to component IDs.
	tokens map[string]string
	// updated is closed and replaced on every Update, for receivers whose
	// component has no units yet.
	updated chan struct{}
}

// New returns a server that listens on address, a unix:// or npipe:// URL.
func New(logger *logger.Logger, address string, agentInfo info.Agent, maxMessageSize int) (*Server, error) {
	ca, err := authority.NewCA()
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate authority: %w", err)
	}
	serverCert, err := ca.GeneratePairWithName(serverName)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}
	return &Server{
		logger:         logger,
		address:        address,
		agentInfo:      agentInfo,
		maxMessageSize: maxMessageSize,
		ca:             ca,
		serverCert:     serverCert,
		components:     make(map[string]*componentUnits),
		tokens:         make(map[string]string),
		updated:        make(chan struct{}),
	}, nil
}

// Run serves the control protocol until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	listener, err := ipc.CreateListener(s.logger, s.address)
	if err != nil {
		return fmt.Errorf("failed to create listener for %s: %w", s.address, err)
	}
	defer ipc.CleanupListener(s.logger, s.address)

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(s.ca.Crt()) {
		return errors.New("failed to add the certificate authority to the pool")
	}
	creds := credentials.NewTLS(&tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
		Certificates: []tls.Certificate{*s.serverCert.Certificate},
		MinVersion:   tls.VersionTLS12,
	})
	server := grpc.NewServer(grpc.Creds(creds), grpc.MaxRecvMsgSize(s.maxMessageSize))
	proto.RegisterElasticAgentServer(server, s)

	go func() {
		<-ctx.Done()
		server.Stop()
	}()
	s.logger.Infof("Serving units to OTel receivers at %s", s.address)
	if err := server.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) && ctx.Err() == nil {
		return err
	}
	return ctx.Err()
}

// Update sets the expected units for the components whose units are delivered
// over the control protocol. Units of other components are ignored, and
// components missing from the list lose all their units.
func (s *Server) Update(components []component.Component) {
	s.mx.Lock()
	defer s.mx.Unlock()

	seen := make(map[string]bool)
	for _, comp := range components {
		if !comp.UsesControlProtocolUnits() {
			continue
		}
		seen[comp.ID] = true
		cu, ok := s.components[comp.ID]
		if !ok {
			var err error
			cu, err = s.newComponentUnits()
			if err != nil {
				s.logger.Errorf("failed to create control protocol credentials for %s: %v", comp.ID, err)
				continue
			}
			s.components[comp.ID] = cu
			s.tokens[cu.token] = comp.ID
		}
		if cu.update(comp.Units) {
			close(cu.changed)
			cu.changed = make(chan struct{})
		}
	}
	for id, cu := range s.components {
		if !seen[id] {
			delete(s.components, id)
			delete(s.tokens, cu.token)
			close(cu.changed)
		}
	}
	close(s.updated)
	s.updated = make(chan struct{})
}

// newComponentUnits creates the state for a new component, with credentials
// that stay the same for as long as the component exists, so its receiver
// config doesn't change.
func (s *Server) newComponentUnits() (*componentUnits, error) {
	token, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	clientCert, err := s.ca.GeneratePair()
	if err != nil {
		return nil, err
	}
	return &componentUnits{
		units:      make(map[unitKey]*proto.UnitExpected),
		changed:    make(chan struct{}),
		token:      token.String(),
		clientCert: clientCert,
	}, nil
}

// ConnectionInfo returns the connection info for a component's receiver, in the
// same format the runtime manager gives beat processes on stdin. It contains the
// receiver's private key and token, so it must be treated as a secret.
func (s *Server) ConnectionInfo(componentID string) ([]byte, error) {
	s.mx.Lock()
	defer s.mx.Unlock()
	cu, ok := s.components[componentID]
	if !ok {
		return nil, fmt.Errorf("unknown component %s", componentID)
	}
	return gproto.Marshal(&proto.StartUpInfo{
		Addr:           s.address,
		ServerName:     serverName,
		Token:          cu.token,
		CaCert:         s.ca.Crt(),
		PeerCert:       cu.clientCert.Crt,
		PeerKey:        cu.clientCert.Key,
		Services:       []proto.ConnInfoServices{proto.ConnInfoServices_CheckinV2},
		Supports:       []proto.ConnectionSupports{proto.ConnectionSupports_CheckinChunking},
		MaxMessageSize: uint32(s.maxMessageSize), //nolint:gosec // set by the caller, well below the limit
		AgentInfo: &proto.AgentInfo{
			Id:           s.agentInfo.AgentID(),
			Version:      s.agentInfo.Version(),
			Snapshot:     s.agentInfo.Snapshot(),
			Unprivileged: s.agentInfo.Unprivileged(),
		},
	})
}

// update applies the component units and reports whether anything changed.
func (cu *componentUnits) update(units []component.Unit) bool {
	changed := false
	seen := make(map[unitKey]bool)
	for _, unit := range units {
		if unit.Err != nil || unit.Config == nil {
			continue
		}
		key := unitKey{unitType: unit.Type, id: unit.ID}
		seen[key] = true
		existing, ok := cu.units[key]
		switch {
		case !ok:
			cu.units[key] = &proto.UnitExpected{
				Id:             unit.ID,
				Type:           proto.UnitType(unit.Type),
				State:          proto.State_HEALTHY,
				ConfigStateIdx: 1,
				Config:         unit.Config,
				LogLevel:       proto.UnitLogLevel(unit.LogLevel),
			}
			changed = true
		case !gproto.Equal(existing.Config, unit.Config):
			existing.Config = unit.Config
			existing.ConfigStateIdx++
			existing.LogLevel = proto.UnitLogLevel(unit.LogLevel)
			changed = true
		case existing.LogLevel != proto.UnitLogLevel(unit.LogLevel):
			existing.LogLevel = proto.UnitLogLevel(unit.LogLevel)
			changed = true
		}
	}
	for key := range cu.units {
		if !seen[key] {
			delete(cu.units, key)
			changed = true
		}
	}
	return changed
}

// expected returns the expected state for a component and a channel that is
// closed when it changes.
func (s *Server) expected(componentID string) (*proto.CheckinExpected, <-chan struct{}) {
	s.mx.Lock()
	defer s.mx.Unlock()

	msg := &proto.CheckinExpected{
		AgentInfo: &proto.AgentInfo{
			Id:           s.agentInfo.AgentID(),
			Version:      s.agentInfo.Version(),
			Snapshot:     s.agentInfo.Snapshot(),
			Unprivileged: s.agentInfo.Unprivileged(),
		},
	}
	cu, ok := s.components[componentID]
	if !ok {
		// Unknown or removed component: send no units, and check again on the
		// next update.
		return msg, s.updated
	}
	msg.Units = make([]*proto.UnitExpected, 0, len(cu.units))
	for _, unit := range cu.units {
		// copy, as Update modifies the units in place
		msg.Units = append(msg.Units, gproto.Clone(unit).(*proto.UnitExpected))
	}
	return msg, cu.changed
}

// CheckinV2 sends the receiver its expected units whenever they change.
func (s *Server) CheckinV2(server proto.ElasticAgent_CheckinV2Server) error {
	first, err := chunk.RecvObserved(server)
	if err != nil {
		return err
	}
	s.mx.Lock()
	componentID, ok := s.tokens[first.Token]
	s.mx.Unlock()
	if !ok {
		return status.Error(codes.PermissionDenied, "invalid token")
	}
	chunking := slices.Contains(first.Supports, proto.ConnectionSupports_CheckinChunking)
	s.logger.Debugf("OTel receiver for component %s connected", componentID)

	// The receiver reports its status through the collector, so observed
	// check-ins are only read to notice when the stream ends.
	recvDone := make(chan error, 1)
	go func() {
		for {
			if _, err := chunk.RecvObserved(server); err != nil {
				recvDone <- err
				return
			}
		}
	}()

	var lastSent *proto.CheckinExpected
	for {
		expected, changed := s.expected(componentID)
		if lastSent == nil || !gproto.Equal(lastSent, expected) {
			if err := s.send(server, expected, chunking); err != nil {
				return err
			}
			lastSent = expected
		}
		select {
		case <-changed:
		case err := <-recvDone:
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		case <-server.Context().Done():
			return nil
		}
	}
}

func (s *Server) send(server proto.ElasticAgent_CheckinV2Server, msg *proto.CheckinExpected, chunking bool) error {
	if !chunking {
		return server.Send(msg)
	}
	msgs, err := chunk.Expected(msg, s.maxMessageSize)
	if err != nil {
		return fmt.Errorf("failed to chunk expected units: %w", err)
	}
	for _, m := range msgs {
		if err := server.Send(m); err != nil {
			return err
		}
	}
	return nil
}

// Actions accepts the actions stream, as the client always opens it, but never
// sends any actions.
func (s *Server) Actions(server proto.ElasticAgent_ActionsServer) error {
	for {
		if _, err := server.Recv(); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

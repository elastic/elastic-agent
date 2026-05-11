// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runtime

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	protobuf "google.golang.org/protobuf/proto"

	"github.com/gofrs/uuid/v5"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/client/chunk"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/core/authority"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Communicator provides an interface for a runtime to communicate with its running component.
type Communicator interface {
	// WriteStartUpInfo writes the connection information to the writer, informing the component it has access
	// to the provided services.
	WriteStartUpInfo(w io.Writer, services ...client.Service) error
	// CheckinExpected sends the expected state to the component.
	//
	// observed is the observed message received from the component and what was used to compute the provided
	// expected message. In the case that `CheckinExpected` is being called from a configuration change resulting
	// in a previously observed message not being present then `nil` should be passed in for observed.
	CheckinExpected(expected *proto.CheckinExpected, observed *proto.CheckinObserved)
	// CheckinObserved receives the observed state from the component.
	CheckinObserved() <-chan *proto.CheckinObserved
}

type runtimeComm struct {
	logger     *logger.Logger
	listenAddr string
	ca         *authority.CertificateAuthority
	agentInfo  info.Agent

	name  string
	token string
	cert  *authority.Pair

	maxMessageSize  int
	chunkingAllowed bool

	checkinConn bool
	checkinDone chan bool
	checkinLock sync.RWMutex

	checkinExpected chan *proto.CheckinExpected
	checkinObserved chan *proto.CheckinObserved

	initCheckinObserved   *proto.CheckinObserved
	initCheckinExpectedCh chan *proto.CheckinExpected
	initCheckinObservedMx sync.Mutex
	runtimeCheckinDone    chan struct{}

	actionsConn     bool
	actionsDone     chan bool
	actionsLock     sync.RWMutex
	actionsRequest  chan *proto.ActionRequest
	actionsResponse chan *proto.ActionResponse
}

func newRuntimeComm(logger *logger.Logger, listenAddr string, ca *authority.CertificateAuthority, agentInfo info.Agent, maxMessageSize int) (*runtimeComm, error) {
	token, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	name, err := genServerName()
	if err != nil {
		return nil, err
	}
	pair, err := ca.GeneratePairWithName(name)
	if err != nil {
		return nil, err
	}
	return &runtimeComm{
		logger:                logger,
		listenAddr:            listenAddr,
		ca:                    ca,
		agentInfo:             agentInfo,
		name:                  name,
		token:                 token.String(),
		cert:                  pair,
		maxMessageSize:        maxMessageSize,
		chunkingAllowed:       false, // not allow until the client says they support it
		checkinConn:           true,
		initCheckinExpectedCh: make(chan *proto.CheckinExpected),
		checkinExpected:       make(chan *proto.CheckinExpected, 1),
		checkinObserved:       make(chan *proto.CheckinObserved),
		actionsConn:           true,
		actionsRequest:        make(chan *proto.ActionRequest),
		actionsResponse:       make(chan *proto.ActionResponse),
	}, nil
}

func (c *runtimeComm) WriteStartUpInfo(w io.Writer, services ...client.Service) error {
	hasV2 := false
	srvs := make([]proto.ConnInfoServices, 0, len(services))
	for _, srv := range services {
		if srv == client.ServiceCheckin {
			return fmt.Errorf("cannot provide access to v1 checkin service")
		}
		if srv == client.ServiceCheckinV2 {
			hasV2 = true
		}
		srvs = append(srvs, proto.ConnInfoServices(srv))
	}
	if !hasV2 {
		srvs = append(srvs, proto.ConnInfoServices_CheckinV2)
	}
	startupInfo := &proto.StartUpInfo{
		Addr:       c.listenAddr,
		ServerName: c.name,
		Token:      c.token,
		CaCert:     c.ca.Crt(),
		PeerCert:   c.cert.Crt,
		PeerKey:    c.cert.Key,
		Services:   srvs,
		// chunking is always allowed if the client supports it
		Supports:       []proto.ConnectionSupports{proto.ConnectionSupports_CheckinChunking},
		MaxMessageSize: uint32(c.maxMessageSize), //nolint:gosec // guaranteed to be valid
		AgentInfo: &proto.AgentInfo{
			Id:           c.agentInfo.AgentID(),
			Version:      c.agentInfo.Version(),
			Snapshot:     c.agentInfo.Snapshot(),
			Mode:         ProtoAgentMode(c.agentInfo),
			Unprivileged: c.agentInfo.Unprivileged(),
		},
	}
	infoBytes, err := protobuf.Marshal(startupInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal startup information: %w", err)
	}
	_, err = w.Write(infoBytes)
	if err != nil {
		return fmt.Errorf("failed to write startup information: %w", err)
	}
	return nil
}

func (c *runtimeComm) CheckinExpected(
	expected *proto.CheckinExpected,
	observed *proto.CheckinObserved,
) {
	if c.agentInfo != nil && c.agentInfo.AgentID() != "" {
		expected.AgentInfo = &proto.AgentInfo{
			Id:           c.agentInfo.AgentID(),
			Version:      c.agentInfo.Version(),
			Snapshot:     c.agentInfo.Snapshot(),
			Mode:         ProtoAgentMode(c.agentInfo),
			Unprivileged: c.agentInfo.Unprivileged(),
		}
	} else {
		expected.AgentInfo = nil
	}

	// we need to determine if the communicator is currently waiting to complete the initial checkin process
	// and if the given observed message is the same as the one the communicator is waiting for
	c.initCheckinObservedMx.Lock()
	// waitingForInitCheckin captures if communicator is waiting to complete the initial checkin process
	waitingForInitCheckin := c.initCheckinObserved != nil
	// shouldIgnore captures if we should ignore this checkin expected taking into account waitingForInitCheckin
	shouldIgnore := waitingForInitCheckin && c.initCheckinObserved != observed
	if waitingForInitCheckin && !shouldIgnore {
		// here the given observed message is the same as the one the communicator is waiting for to complete
		// the initial checkin process, thus clear the state
		c.initCheckinObserved = nil
	}
	// when doneCh is closed the communicator is done and sending to any of the checkin expected channels,
	// namely init (c.initCheckinExpectedCh) and regular (c.checkinExpected), should unblock
	doneCh := c.runtimeCheckinDone
	c.initCheckinObservedMx.Unlock()

	if shouldIgnore {
		// ignore this checkin expected
		return
	}

	if waitingForInitCheckin {
		// send to the init checkin expected channel
		// no draining here as we don't want to lose any message
		select {
		case <-doneCh:
		case c.initCheckinExpectedCh <- expected:
		}
	} else {
		// send to the regular checkin expected channel and drain it
		// as we care only about the last message being sent
		select {
		case <-c.checkinExpected:
		default:
		}

		select {
		case <-doneCh:
			// this isn't exactly required but better safe than SDH
		case c.checkinExpected <- expected:
		}
	}
}

func (c *runtimeComm) CheckinObserved() <-chan *proto.CheckinObserved {
	return c.checkinObserved
}

func (c *runtimeComm) checkin(server proto.ElasticAgent_CheckinV2Server, init *proto.CheckinObserved) error {
	c.checkinLock.Lock()
	if c.checkinDone != nil {
		// already connected (cannot have multiple); close connection
		c.checkinLock.Unlock()
		c.logger.Debug("check-in stream already connected for component; closing connection")
		return status.Error(codes.AlreadyExists, "component already connected")
	}
	if !c.checkinConn {
		// being destroyed cannot reconnect; close connection
		c.checkinLock.Unlock()
		c.logger.Debug("check-in stream being destroyed connection not allowed; closing connection")
		return status.Error(codes.Unavailable, "component cannot connect being destroyed")
	}

	checkinDone := make(chan bool)
	c.checkinDone = checkinDone
	c.checkinLock.Unlock()

	defer func() {
		c.checkinLock.Lock()
		c.checkinDone = nil
		c.checkinLock.Unlock()
	}()

	c.initCheckinObservedMx.Lock()
	// clears the latest queued expected message
	select {
	case <-c.checkinExpected:
	default:
	}
	c.initCheckinObserved = init
	runtimeCheckinDone := make(chan struct{})
	c.runtimeCheckinDone = runtimeCheckinDone
	c.initCheckinObservedMx.Unlock()
	defer func(ch chan struct{}) {
		close(ch)
	}(runtimeCheckinDone)

	// send the initial observed message, so the respective runtime (e.g. commandRuntime, serviceRuntime, etc. )
	// then calls CheckinExpected method with the result
	select {
	case <-checkinDone:
		// runtimeComm is destroyed return
		return status.Error(codes.Unavailable, "component is being destroyed")
	case c.checkinObserved <- init:
	}

	recvDone := make(chan bool)
	go func() {
		// this goroutine will not be leaked, because when the server CheckinV2 function
		// returns (lives inside the manager) it will close the connection.
		// That will cause the chunk.RecvObserved function to return with an error and thus
		// this goroutine will exit. Another reason that this goroutine could exit for
		// is if the checkinDone channel is closed which happens when the runtimeComm is
		// destroyed (when the runtime.Run() exits).
		defer func() {
			close(recvDone)
		}()

		for {
			// always allow a chunked observed message to be received
			checkin, err := chunk.RecvObserved(server)
			if err != nil {
				if reportableErr(err) {
					c.logger.Debugf("check-in stream failed to receive data: %s", err)
				}
				return
			}
			select {
			case <-checkinDone:
				// runtimeComm is destroyed return
				return
			case c.checkinObserved <- checkin:
			}
		}
	}()

	initCheckinCompleted := false
	var afterInitCheckinExpectedCh chan *proto.CheckinExpected
	for {
		var expected *proto.CheckinExpected
		select {
		case <-checkinDone:
			// runtimeComm is destroyed return
			return status.Error(codes.Unavailable, "component is being destroyed")
		case <-recvDone:
			// the goroutine that receives observed messages has exited we can't continue
			// This acts also as a proxy to the server.Context().Done() method which
			// will be closed when the server is closed.
			return status.Error(codes.Unavailable, "component is being destroyed")
		case expected = <-c.initCheckinExpectedCh:
			// unbuffered channel to receive the first expected state
			if !initCheckinCompleted {
				initCheckinCompleted = true
				afterInitCheckinExpectedCh = c.checkinExpected
			} else {
				// this shouldn't occur, but better safe than SDH
				c.logger.Warn("check-in stream received unexpected init expected state, ignoring...")
				continue
			}
		case expected = <-afterInitCheckinExpectedCh:
		}

		err := sendExpectedChunked(server, expected, c.chunkingAllowed, c.maxMessageSize)
		if err != nil {
			c.logger.Debugf("check-in stream failed to send expected state: %s", err)
			if reportableErr(err) {
				return err
			}
			return nil
		}
	}
}

func (c *runtimeComm) actions(server proto.ElasticAgent_ActionsServer) error {
	c.actionsLock.Lock()
	if c.actionsDone != nil {
		// already connected (cannot have multiple); close connection
		c.actionsLock.Unlock()
		c.logger.Debug("check-in stream already connected for component; closing connection")
		return status.Error(codes.AlreadyExists, "application already connected")
	}
	if !c.actionsConn {
		// being destroyed cannot reconnect; close connection
		c.actionsLock.Unlock()
		c.logger.Debug("check-in stream being destroyed connection not allowed; closing connection")
		return status.Error(codes.Unavailable, "application cannot connect being destroyed")
	}

	actionsDone := make(chan bool)
	c.actionsDone = actionsDone
	c.actionsLock.Unlock()

	defer func() {
		c.actionsLock.Lock()
		c.actionsDone = nil
		c.actionsLock.Unlock()
	}()

	recvDone := make(chan bool)
	sendDone := make(chan bool)
	go func() {
		defer func() {
			close(sendDone)
		}()
		for {
			var req *proto.ActionRequest
			select {
			case <-actionsDone:
				return
			case <-recvDone:
				return
			case req = <-c.actionsRequest:
			}

			err := server.Send(req)
			if err != nil {
				if reportableErr(err) {
					c.logger.Debugf("actions stream failed to send action request: %s", err)
				}
				return
			}
		}
	}()

	go func() {
		for {
			resp, err := server.Recv()
			if err != nil {
				if reportableErr(err) {
					c.logger.Debugf("check-in stream failed to receive data: %s", err)
				}
				close(recvDone)
				return
			}
			c.actionsResponse <- resp
		}
	}()

	<-sendDone
	return nil
}

func (c *runtimeComm) destroy() {
	c.destroyCheckin()
	c.destroyActions()
}

func (c *runtimeComm) destroyCheckin() {
	c.checkinLock.Lock()
	c.checkinConn = false
	if c.checkinDone != nil {
		close(c.checkinDone)
		c.checkinDone = nil
	}
	c.checkinLock.Unlock()
}

func (c *runtimeComm) destroyActions() {
	c.actionsLock.Lock()
	c.actionsConn = false
	if c.actionsDone != nil {
		close(c.actionsDone)
		c.actionsDone = nil
	}
	c.actionsLock.Unlock()
}

func reportableErr(err error) bool {
	if errors.Is(err, io.EOF) {
		return false
	}
	s, ok := status.FromError(err)
	if !ok {
		return true
	}
	if s.Code() == codes.Canceled {
		return false
	}
	return true
}

func genServerName() (string, error) {
	u, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(u.String(), "-", ""), nil
}

func sendExpectedChunked(server proto.ElasticAgent_CheckinV2Server, msg *proto.CheckinExpected, chunkingAllowed bool, maxSize int) error {
	if !chunkingAllowed {
		// chunking is disabled
		return server.Send(msg)
	}
	msgs, err := chunk.Expected(msg, maxSize)
	if err != nil {
		return err
	}
	for _, msg := range msgs {
		if err := server.Send(msg); err != nil {
			return err
		}
	}
	return nil
}

// ProtoAgentMode converts the agent info mode bool to the AgentManagedMode enum
func ProtoAgentMode(agent info.Agent) proto.AgentManagedMode {
	if agent.IsStandalone() {
		return proto.AgentManagedMode_STANDALONE
	}
	return proto.AgentManagedMode_MANAGED
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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

	"github.com/gofrs/uuid"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/core/authority"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Communicator provides an interface for a runtime to communicate with its running component.
type Communicator interface {
	// WriteConnInfo writes the connection information to the writer, informing the component it has access
	// to the provided services.
	WriteConnInfo(w io.Writer, services ...client.Service) error
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
	agentInfo  *info.AgentInfo

	name  string
	token string
	cert  *authority.Pair

	checkinConn bool
	checkinDone chan bool
	checkinLock sync.RWMutex

	checkinExpected chan *proto.CheckinExpected
	checkinObserved chan *proto.CheckinObserved

	initCheckinObserved   *proto.CheckinObserved
	initCheckinExpectedCh chan *proto.CheckinExpected
	initCheckinObservedMx sync.Mutex

	actionsConn     bool
	actionsDone     chan bool
	actionsLock     sync.RWMutex
	actionsRequest  chan *proto.ActionRequest
	actionsResponse chan *proto.ActionResponse
}

func newRuntimeComm(logger *logger.Logger, listenAddr string, ca *authority.CertificateAuthority, agentInfo *info.AgentInfo) (*runtimeComm, error) {
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
		logger:          logger,
		listenAddr:      listenAddr,
		ca:              ca,
		agentInfo:       agentInfo,
		name:            name,
		token:           token.String(),
		cert:            pair,
		checkinConn:     true,
		checkinExpected: make(chan *proto.CheckinExpected, 10), // size of 10 gives a buffer for expected, only last is used
		checkinObserved: make(chan *proto.CheckinObserved),
		actionsConn:     true,
		actionsRequest:  make(chan *proto.ActionRequest),
		actionsResponse: make(chan *proto.ActionResponse),
	}, nil
}

func (c *runtimeComm) WriteConnInfo(w io.Writer, services ...client.Service) error {
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
	connInfo := &proto.ConnInfo{
		Addr:       c.listenAddr,
		ServerName: c.name,
		Token:      c.token,
		CaCert:     c.ca.Crt(),
		PeerCert:   c.cert.Crt,
		PeerKey:    c.cert.Key,
		Services:   srvs,
	}
	infoBytes, err := protobuf.Marshal(connInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal connection information: %w", err)
	}
	_, err = w.Write(infoBytes)
	if err != nil {
		return fmt.Errorf("failed to write connection information: %w", err)
	}
	return nil
}

func (c *runtimeComm) CheckinExpected(
	expected *proto.CheckinExpected,
	observed *proto.CheckinObserved,
) {
	if c.agentInfo != nil && c.agentInfo.AgentID() != "" {
		expected.AgentInfo = &proto.CheckinAgentInfo{
			Id:       c.agentInfo.AgentID(),
			Version:  c.agentInfo.Version(),
			Snapshot: c.agentInfo.Snapshot(),
		}
	} else {
		expected.AgentInfo = nil
	}

	// we need to determine if the communicator is currently in the initial observed message path
	// in the case that it is we send the expected state over a different channel
	c.initCheckinObservedMx.Lock()
	initObserved := c.initCheckinObserved
	expectedCh := c.initCheckinExpectedCh
	if initObserved != nil {
		// the next call to `CheckinExpected` must be from the initial `CheckinObserved` message
		if observed != initObserved {
			// not the initial observed message; we don't send it
			c.initCheckinObservedMx.Unlock()
			return
		}
		// it is the expected from the initial observed message
		// clear the initial state
		c.initCheckinObserved = nil
		c.initCheckinExpectedCh = nil
		c.initCheckinObservedMx.Unlock()
		expectedCh <- expected
		return
	}
	c.initCheckinObservedMx.Unlock()

	// not in the initial observed message path; send it over the standard channel
	c.logger.Infof("CheckinExpected about to send event to checkinExpected, len: %d", len(c.checkinExpected))
	c.checkinExpected <- expected
	c.logger.Infof("CheckinExpected sent event to checkinExpected, len: %d", len(c.checkinExpected))
}

func (c *runtimeComm) CheckinObserved() <-chan *proto.CheckinObserved {
	return c.checkinObserved
}

// latestCheckinExpected ensures that the latest expected checkin is used
func (c *runtimeComm) latestCheckinExpected(exp *proto.CheckinExpected) *proto.CheckinExpected {
	latest := exp
	for {
		select {
		case latest = <-c.checkinExpected:
		default:
			return latest
		}
	}
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

	initExp := make(chan *proto.CheckinExpected)
	recvDone := make(chan bool)
	sendDone := make(chan bool)
	go func() {
		defer func() {
			close(sendDone)
		}()

		// initial startup waits for the first expected message from the dedicated initExp channel
		select {
		case <-checkinDone:
			return
		case <-recvDone:
			return
		case expected := <-initExp:
			err := server.Send(expected)
			if err != nil {
				if reportableErr(err) {
					c.logger.Debugf("check-in stream failed to send initial expected state: %s", err)
				}
				return
			}
		}

		for {
			var expected *proto.CheckinExpected
			select {
			case <-checkinDone:
				return
			case <-recvDone:
				return
			case expected = <-c.checkinExpected:
				c.logger.Infof("got event from checkinExpected in c.checkin(), len: %d", len(c.checkinExpected))
				expected = c.latestCheckinExpected(expected)
			}

			err := server.Send(expected)
			if err != nil {
				if reportableErr(err) {
					c.logger.Debugf("check-in stream failed to send expected state: %s", err)
				}
				return
			}
		}
	}()

	// at this point the client is connected, and it has sent it's first initial checkin
	// the initial expected message must come before the sender goroutine will send any other
	// expected messages. `CheckinExpected` method will also drop any expected messages that do not
	// match the observed message to ensure that the expected that we receive is from the initial
	// observed state.
	c.initCheckinObservedMx.Lock()
	c.initCheckinObserved = init
	c.initCheckinExpectedCh = initExp
	c.latestCheckinExpected(nil) // clears all queued expected messages
	c.initCheckinObservedMx.Unlock()

	// send the initial message (manager then calls `CheckinExpected` method with the result)
	c.checkinObserved <- init

	go func() {
		for {
			checkin, err := server.Recv()
			if err != nil {
				if reportableErr(err) {
					c.logger.Debugf("check-in stream failed to receive data: %s", err)
				}
				close(recvDone)
				return
			}
			c.checkinObserved <- checkin
		}
	}()

	<-sendDone
	return nil
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
	return strings.Replace(u.String(), "-", "", -1), nil
}

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

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"

	protobuf "google.golang.org/protobuf/proto"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"

	"github.com/gofrs/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/internal/pkg/core/authority"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Communicator provides an interface for a runtime to communicate with its running component.
type Communicator interface {
	// WriteConnInfo writes the connection information to the writer, informing the component it has access
	// to the provided services.
	WriteConnInfo(w io.Writer, services ...client.Service) error
	// CheckinExpected sends the expected state to the component.
	CheckinExpected(expected *proto.CheckinExpected)
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

func (c *runtimeComm) CheckinExpected(expected *proto.CheckinExpected) {
	if c.agentInfo != nil && c.agentInfo.AgentID() != "" {
		expected.AgentInfo = &proto.CheckinAgentInfo{
			Id:       c.agentInfo.AgentID(),
			Version:  c.agentInfo.Version(),
			Snapshot: c.agentInfo.Snapshot(),
		}
	} else {
		expected.AgentInfo = nil
	}
	c.checkinExpected <- expected
}

func (c *runtimeComm) CheckinObserved() <-chan *proto.CheckinObserved {
	return c.checkinObserved
}

// latestCheckinExpected ensures that the latest expected checkin is used
func (c *runtimeComm) latestCheckinExpected(exp *proto.CheckinExpected) *proto.CheckinExpected {
	latest := exp
	latestByKey := make(map[ComponentUnitKey]*proto.UnitExpected)
	if latest != nil {
		for _, unit := range latest.Units {
			latestByKey[ComponentUnitKey{client.UnitType(unit.Type), unit.Id}] = unit
		}
	}
	for {
		select {
		case next := <-c.checkinExpected:
			// ensure that this message includes data from a previous message
			//
			// it is possible that this next message did not include the `Config` for the unit because the
			// previous message include it already thinking that the component got that unit config
			//
			// ensure that if that is the case that we copy the config from the previous onto the latest
			//
			// this really should not happen and this is very defensive in design, but I believe it is better
			// to be very defensive to ensure that the component always receive its needed configuration for
			// a unit then have a very rare chance that we don't send it
			for _, unit := range next.Units {
				if unit.Config != nil {
					// has a config and its latest, nothing to do
					continue
				}
				prevUnit, ok := latestByKey[ComponentUnitKey{client.UnitType(unit.Type), unit.Id}]
				if !ok {
					// previous didn't have the unit at all; so nothing to do
					continue
				}
				if prevUnit.Config != nil && prevUnit.ConfigStateIdx == unit.ConfigStateIdx {
					// copy the unit from the previous onto the new latest
					unit.Config = prevUnit.Config
				}
			}
			if latest != nil && latest.AgentInfo != nil && next.AgentInfo == nil {
				// copy the agent info to the new latest
				next.AgentInfo = latest.AgentInfo
			}
			latest = next
			latestByKey = make(map[ComponentUnitKey]*proto.UnitExpected, len(latest.Units))
			for _, unit := range latest.Units {
				latestByKey[ComponentUnitKey{client.UnitType(unit.Type), unit.Id}] = unit
			}
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

	waitExp := make(chan bool)
	recvDone := make(chan bool)
	sendDone := make(chan bool)
	go func() {
		defer func() {
			close(sendDone)
		}()
	WAIT:
		// wait until the goroutine should start listening on the `checkinExpected channel
		// see comment below about why this waits until the `waitExp` is closed
		for {
			select {
			case <-checkinDone:
				return
			case <-recvDone:
				return
			case <-waitExp:
				break WAIT
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
	// all other previous messages on `c.checkinExpected` are void. The push onto `c.checkinObserved`
	// should result in a new message on `c.checkinExpected` so before that push we want to clear
	// the channel as well as prevent the sender channel from reading from `c.checkinExpected` until
	// we have sent the message on `c.checkinObserved`.
	c.latestCheckinExpected(nil)
	c.checkinObserved <- init
	close(waitExp)

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

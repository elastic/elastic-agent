// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleetservertest

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"time"
)

type Server struct {
	*httptest.Server
}

var timeNow = time.Now

type Option func(o *options)

type options struct {
	address string
	logFn   func(format string, a ...any)
	agentID string
}

// NewServer returns a new started *httptest.Server mocking the Fleet Server API.
// If a route is called and its handler (the *Fn field) is nil a
// http.StatusNotImplemented error will be returned.
func NewServer(h *Handlers, opts ...Option) *Server {
	os := options{}
	for _, o := range opts {
		o(&os)
	}

	if os.logFn != nil {
		h.logFn = os.logFn
	}
	if os.agentID != "" {
		h.AgentID = os.agentID
	}

	mux := NewRouter(h)

	address := ":0"
	if os.address != "" {
		address = os.address
	}

	l, err := net.Listen("tcp", address) //nolint:gosec // it's a test
	if err != nil {
		panic(fmt.Sprintf("NewServer failed to create a net.Listener: %v", err))
	}

	s := Server{
		Server: &httptest.Server{
			Listener: l,
			Config:   &http.Server{Handler: mux}}, //nolint:gosec // it's a test
	}
	s.Start()

	return &s
}

// WithRequestLog sets the server to log every request using logFn.
func WithRequestLog(logFn func(format string, a ...any)) Option {
	return func(o *options) {
		o.logFn = logFn
	}
}

// WithAddress will set the address the server will listen on. The format is as
// defined by net.Listen for a tcp connection.
func WithAddress(addr string) Option {
	return func(o *options) {
		o.address = addr
	}
}

// WithAgentID sets the agentID considered enrolled with the server. If enroll
// isn't called or the agentID 'manually' set, the server will reject the requests.
func WithAgentID(id string) Option {
	return func(o *options) {
		o.agentID = id
	}
}

// NewServerWithFakeComponent returns mock Fleet Server ready to use for Agent's
// e2e tests. The server has the Status, Checkin, Enroll and Ack handlers
// configured. You need to implement:
//   - nextAction, called on every checkin to get the actions to return
//   - acker, responsible for ack-ing the actions.
//
// See TestRunFleetServer and ExampleNewServer_checkin_and_ackWithAcker for more
// details on how to use it and define `nextAction` and `acker`.
func NewServerWithFakeComponent(
	apiKey APIKey,
	enrolmentToken string,
	agentID string,
	policyID string,
	nextAction func() (CheckinAction, *HTTPError),
	acker func(id string) (AckResponseItem, bool),
	opts ...Option) *Server {

	handlers := &Handlers{
		APIKey:          apiKey.Key,
		EnrollmentToken: enrolmentToken,
		AgentID:         agentID, // as there is no enrol, the agentID needs to be manually set
		CheckinFn:       NewHandlerCheckinFakeComponent(nextAction),
		EnrollFn:        NewHandlerEnroll(agentID, policyID, apiKey),
		AckFn:           NewHandlerAckWithAcker(acker),
		StatusFn:        NewHandlerStatusHealth(),
	}

	return NewServer(handlers, opts...)
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleetservertest

import (
	"net/http/httptest"
)

type Data struct {
	AgentID string

	APIKey APIKey

	// EnrollmentToken is the enrollment the agent should use to enroll with
	// Fleet Server.
	EnrollmentToken string
}

type Server struct {
	*httptest.Server
	Data Data
}

// NewServer returns a new started *httptest.Server mocking the Fleet Server API.
// If a route is called and its handler (the *Fn field) is nil a.
// http.StatusNotImplemented error will be returned.
// If insecure is set, no authorization check will be performed.
func NewServer(h Handlers, _ Data) *Server {
	mux := NewRouter(h)

	return &Server{
		Server: httptest.NewServer(mux),
	}
}

// NewServerWithFakeComponent returns mock Fleet Server ready to use for Agent's
// e2e tests. The server has the Status, Checkin, Enroll and Ack handlers
// configured. If any of those handlers are defined on api, it'll overwrite the
// default implementation. The returned policy contains one integration using
// the fake input.
//
// TODO: it needs to receive output configuration throug a WithEs/WithShipper
// function //
func NewServerWithFakeComponent(h Handlers, policyID, ackToken string, data Data) *Server {
	// {
	//    "api_key": "REDACTED:REDACTED",
	//    "hosts": [
	//      "https://REDACTED.some.elstc.co:443"
	//    ],
	//    "type": "elasticsearch"
	//  }

	if h.StatusFn == nil {
		h.StatusFn = NewHandlerStatusHealth()
	}
	if h.CheckinFn == nil {
		h.CheckinFn = NewHandlerCheckin(ackToken)
	}
	if h.EnrollFn == nil {
		h.EnrollFn = NewHandlerEnroll(policyID, data.APIKey)
	}
	if h.AckFn == nil {
		h.AckFn = NewHandlerAck()
	}

	mux := NewRouter(h)
	return &Server{
		Server: httptest.NewServer(mux),
		Data:   data,
	}
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleetservertest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
)

// API holds the handlers for the fleet-api, see https://petstore.swagger.io/?url=https://raw.githubusercontent.com/elastic/fleet-server/main/model/openapi.yml
// for rendered OpenAPI definition. If any of the handlers are nil, a
// http.StatusNotImplemented is returned for the route.
//
// Authentication is made extracting he API key or enrollment token,
// from the HeaderAuthorization header and compared against API.APIKey or
// API.EnrollmentToken. API.EnrollmentToken is used for Enroll requests and
// API.APIKey for all others.
type API struct {
	// APIKey is the API key to authenticate with Fleet Server.
	APIKey string
	// APIKeyID is the API ID key to authenticate with Fleet Server.
	APIKeyID string

	// EnrollmentToken is the enrollment the agent should use to enroll with
	// Fleet Server.
	EnrollmentToken string

	AckFn func(
		ctx context.Context,
		agentID string,
		ackRequest AckRequest) (*AckResponse, *HTTPError)

	CheckinFn func(
		ctx context.Context,
		id string,
		userAgent string,
		acceptEncoding string,
		checkinRequest CheckinRequest) (*CheckinResponse, *HTTPError)

	EnrollFn func(
		ctx context.Context,
		agentID string,
		userAgent string,
		enrollRequest EnrollRequest) (*EnrollResponse, *HTTPError)

	ArtifactFn func(
		ctx context.Context,
		artifactID string,
		sha2 string) *HTTPError

	StatusFn func(
		ctx context.Context) (*StatusResponse, *HTTPError)

	UploadBeginFn func(
		ctx context.Context,
		requestBody UploadBeginRequest) (*UploadBeginResponse, *HTTPError)

	UploadChunkFn func(
		ctx context.Context,
		uploadID string,
		chunkNum int32,
		xChunkSHA2 string,
		body io.ReadCloser) *HTTPError

	UploadCompleteFn func(
		ctx context.Context,
		uploadID string,
		uploadCompleteRequest UploadCompleteRequest) *HTTPError
}

type Server struct {
	*httptest.Server

	// APIKey is the API key to authenticate with Fleet Server.
	APIKey string
	// APIKeyID is the API ID key to authenticate with Fleet Server.
	APIKeyID string

	// EnrollmentToken is the enrollment the agent should use to enroll with
	// Fleet Server.
	EnrollmentToken string
}

// NewServer returns a new started *httptest.Server mocking the Fleet Server API.
// If a route is called and its handler (the *Fn field) is nil a.
// http.StatusNotImplemented error will be returned.
// If insecure is set, no authorization check will be performed.
func NewServer(api API) *Server {
	mux := NewRouter(Handlers{api: api})

	return &Server{
		Server:          httptest.NewServer(mux),
		APIKey:          api.APIKey,
		APIKeyID:        api.APIKeyID,
		EnrollmentToken: api.EnrollmentToken,
	}
}

// NewServerWithFakeComponent returns mock Fleet Server ready to use for Agent's
// e2e tests.The server has the Status, Checkin, Enroll and Ack handlers
// configured. If any of those handlers are defined on api, it'll overwrite the
// default implementation. The returned policy contains one integration using
// the fake input and if useShipper is true, it'll use the shipper.
// TODO: it needs to receive output configuration throug a WithEs/WithShipper
// function //
func NewServerWithFakeComponent(api API, agentID, policyID, ackToken string) *Server {
	if api.StatusFn == nil {
		api.StatusFn = NewStatusHandlerHealth()
	}
	if api.CheckinFn == nil {
		api.CheckinFn = NewCheckinHandler(agentID, ackToken, false)
	}
	if api.EnrollFn == nil {
		api.EnrollFn = NewEnrollHandler(agentID, policyID, APIKey{
			ID:  api.APIKey,
			Key: api.APIKeyID,
		})
	}
	if api.AckFn == nil {
		api.AckFn = NewAckHander(agentID)
	}

	mux := NewRouter(Handlers{api: api})
	return &Server{
		Server:          httptest.NewServer(mux),
		APIKey:          api.APIKey,
		APIKeyID:        api.APIKeyID,
		EnrollmentToken: api.EnrollmentToken,
	}
}

// TODO: Make a NewFullyFunctional fleet-server:
// - status
// - checkin - use fake input
// - enroll
// - ack

// AgentAcks -
func (a API) AgentAcks(
	ctx context.Context,
	id string,
	ackRequest AckRequest) (*AckResponse, *HTTPError) {
	if a.AckFn == nil {
		return nil,
			&HTTPError{StatusCode: http.StatusNotImplemented,
				Message: "agent acs Handlers not implemented"}
	}

	resp, err := a.AckFn(ctx, id, ackRequest)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// AgentCheckin -
func (a API) AgentCheckin(
	ctx context.Context,
	id string,
	userAgent string,
	acceptEncoding string,
	checkinRequest CheckinRequest) (*CheckinResponse, *HTTPError) {
	if a.CheckinFn == nil {
		return nil,
			&HTTPError{StatusCode: http.StatusNotImplemented,
				Message: "agent checkin Handlers not implemented"}
	}

	resp, err := a.CheckinFn(
		ctx, id, userAgent, acceptEncoding, checkinRequest)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// AgentEnroll -
func (a API) AgentEnroll(
	ctx context.Context,
	id string,
	userAgent string,
	enrollRequest EnrollRequest) (*EnrollResponse, *HTTPError) {
	if a.EnrollFn == nil {
		return nil,
			&HTTPError{StatusCode: http.StatusNotImplemented,
				Message: "agent checkin Handlers not implemented"}
	}

	resp, err := a.EnrollFn(ctx, id, userAgent, enrollRequest)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Artifact -
func (a API) Artifact(
	ctx context.Context,
	id string,
	sha2 string) *HTTPError {
	if a.ArtifactFn == nil {
		return &HTTPError{StatusCode: http.StatusNotImplemented,
			Message: "artifact Handlers not implemented"}
	}

	return a.ArtifactFn(ctx, id, sha2)
}

// Status -
func (a API) Status(
	ctx context.Context) (*StatusResponse, *HTTPError) {
	if a.StatusFn == nil {
		return nil, &HTTPError{StatusCode: http.StatusNotImplemented,
			Message: "status Handlers not implemented"}
	}

	resp, err := a.StatusFn(ctx)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// UploadBegin - Initiate a file upload process
func (a API) UploadBegin(
	ctx context.Context,
	requestBody UploadBeginRequest) (*UploadBeginResponse, *HTTPError) {
	if a.UploadBeginFn == nil {
		return nil, &HTTPError{StatusCode: http.StatusNotImplemented,
			Message: "upload begin Handlers not implemented"}

	}

	resp, err := a.UploadBeginFn(ctx, requestBody)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// UploadChunk - Upload a section of file data
func (a API) UploadChunk(
	ctx context.Context,
	id string,
	chunkNum int32,
	chunkSHA2 string,
	body io.ReadCloser) *HTTPError {
	if a.UploadChunkFn == nil {
		return &HTTPError{StatusCode: http.StatusNotImplemented,
			Message: "upload chunk Handlers not implemented"}
	}

	return a.UploadChunkFn(ctx, id, chunkNum, chunkSHA2, body)
}

// UploadComplete - Complete a file upload process
func (a API) UploadComplete(
	ctx context.Context,
	id string,
	uploadCompleteRequest UploadCompleteRequest) (*UploadComplete200Response, *HTTPError) {
	if a.UploadCompleteFn == nil {
		return nil, &HTTPError{StatusCode: http.StatusNotImplemented,
			Message: "upload complete Handlers not implemented"}
	}

	err := a.UploadCompleteFn(ctx, id, uploadCompleteRequest)
	if err != nil {
		return nil, err
	}

	return &UploadComplete200Response{Status: "ok"}, nil
}

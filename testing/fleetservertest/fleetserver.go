package fleetservertest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
)

// It was generated using https://openapi-generator.tech/
// Once it's installed, call it using the fleet-server open api spec: fleet-server/model/openapi.yml
// openapi-generator-cli generate  -i ../../../fleet-server/model/openapi.yml -g go-server -o ./

// API holds the handlers for the fleet-api, see https://petstore.swagger.io/?url=https://raw.githubusercontent.com/elastic/fleet-server/main/model/openapi.yml
// for rendered OpenAPI definition.
// If any of the handlers are nil, a http.StatusNotImplemented is returned for
// the route.
type API struct {
	AckFn func(
		ctx context.Context,
		id string,
		ackRequest AckRequest) (*AckResponse, *HTTPError)

	CheckinFn func(
		ctx context.Context,
		id string,
		userAgent string,
		acceptEncoding string,
		checkinRequest CheckinRequest) (*CheckinResponse, *HTTPError)

	EnrollFn func(
		ctx context.Context,
		id string,
		userAgent string,
		enrollRequest EnrollRequest) (*EnrollResponse, *HTTPError)

	ArtifactFn func(
		ctx context.Context,
		id string,
		sha2 string) *HTTPError

	StatusFn func(
		ctx context.Context) (*StatusResponse, *HTTPError)

	UploadBeginFn func(
		ctx context.Context,
		requestBody UploadBeginRequest) (*UploadBeginResponse, *HTTPError)

	UploadChunkFn func(
		ctx context.Context,
		id string,
		chunkNum int32,
		xChunkSHA2 string,
		body io.ReadCloser) *HTTPError

	UploadCompleteFn func(
		ctx context.Context,
		id string,
		uploadCompleteRequest UploadCompleteRequest) *HTTPError
}

// NewServer returns a new started *httptest.Server mocking the Fleet Server API.
// If a route is called and its handler (the *Fn field) is nil a.
// http.StatusNotImplemented error will be returned.
func NewServer(api API) *httptest.Server {
	mux := NewRouter(Handlers{api: api})

	return httptest.NewServer(mux)
}

// AgentAcks -
func (a API) AgentAcks(
	ctx context.Context,
	id string,
	ackRequest AckRequest) (*AckResponse, *HTTPError) {
	if a.AckFn == nil {
		return nil,
			&HTTPError{StatusCode: http.StatusNotImplemented,
				Message: "agent acs API not implemented"}
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
				Message: "agent checkin API not implemented"}
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
				Message: "agent checkin API not implemented"}
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
			Message: "artifact API not implemented"}
	}

	return a.ArtifactFn(ctx, id, sha2)
}

// Status -
func (a API) Status(
	ctx context.Context) (*StatusResponse, *HTTPError) {
	if a.StatusFn == nil {
		return nil, &HTTPError{StatusCode: http.StatusNotImplemented,
			Message: "status API not implemented"}
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
			Message: "upload begin API not implemented"}

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
			Message: "upload chunk API not implemented"}
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
			Message: "upload complete API not implemented"}
	}

	err := a.UploadCompleteFn(ctx, id, uploadCompleteRequest)
	if err != nil {
		return nil, err
	}

	return &UploadComplete200Response{Status: "ok"}, nil
}

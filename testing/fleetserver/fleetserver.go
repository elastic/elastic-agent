package fleetserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/elastic/elastic-agent/testing/fleetserver/openapi"
)

// It was generated using https://openapi-generator.tech/
// Once it's installed, call it using the fleet-server open api spec: fleet-server/model/openapi.yml
// openapi-generator-cli generate  -i ../../../fleet-server/model/openapi.yml -g go-server -o ./

// API holds the handlers for the fleet-api, see https://petstore.swagger.io/?url=https://raw.githubusercontent.com/elastic/fleet-server/main/model/openapi.yml#/default/uploadComplete
// for rendered OpenAPI definition.
// If any of the handlers are nil, a http.StatusNotImplemented is returned for
// the route.
type API struct {
	AckFn func(
		ctx context.Context,
		id string,
		xRequestID string,
		ackRequest openapi.AckRequest) (openapi.AckResponse, *openapi.ModelError)

	CheckinFn func(
		ctx context.Context,
		id string,
		userAgent string,
		acceptEncoding string,
		xRequestID string,
		checkinRequest openapi.CheckinRequest) (openapi.CheckinResponse, *openapi.ModelError)

	EnrollFn func(
		ctx context.Context,
		id string,
		userAgent string,
		xRequestID string,
		enrollRequest openapi.EnrollRequest) (openapi.EnrollResponse, *openapi.ModelError)

	ArtifactFn func(
		ctx context.Context,
		id string,
		sha2 string,
		xRequestID string) (openapi.ImplResponse, *openapi.ModelError)

	StatusFn func(
		ctx context.Context,
		xRequestID string) (openapi.StatusResponse, *openapi.ModelError)

	UploadBeginFn func(
		ctx context.Context,
		requestBody map[string]interface{},
		xRequestID string) (openapi.UploadBeginResponse, *openapi.ModelError)

	UploadChunkFn func(
		ctx context.Context,
		id string,
		chunkNum int32,
		xChunkSHA2 string,
		body *os.File,
		xRequestID string) (openapi.ImplResponse, *openapi.ModelError)

	UploadCompleteFn func(
		ctx context.Context,
		id string,
		uploadCompleteRequest openapi.UploadCompleteRequest,
		xRequestID string) (openapi.UploadComplete200Response, *openapi.ModelError)
}

// NewTest returns a new started *httptest.Server mocking the Fleet Server API.
// If a route is called and its handler (the *Fn field) is nil a.
// http.StatusNotImplemented error will be returned.
// If api is nil, NewTest panics
func NewTest(api *API) *httptest.Server {
	if api == nil {
		panic("api cannot be nil")
	}

	r := openapi.NewDefaultApiController(api)
	mux := openapi.NewRouter(r)

	return httptest.NewServer(mux)
}

// AgentAcks -
func (s *API) AgentAcks(
	ctx context.Context,
	id string,
	xRequestID string,
	ackRequest openapi.AckRequest) (openapi.ImplResponse, error) {
	if s.AckFn == nil {
		return openapi.Response(http.StatusNotImplemented, nil),
			errors.New("agent acs API not implemented")
	}

	resp, err := s.AckFn(ctx, id, xRequestID, ackRequest)
	if err != nil {
		return openapi.Response(err.StatusCode, err), nil
	}

	return openapi.Response(http.StatusOK, resp), nil
}

// AgentCheckin -
func (s *API) AgentCheckin(
	ctx context.Context,
	id string,
	userAgent string,
	acceptEncoding string,
	xRequestID string,
	checkinRequest openapi.CheckinRequest) (openapi.ImplResponse, error) {
	if s.CheckinFn == nil {
		return openapi.Response(http.StatusNotImplemented, nil),
			errors.New("agent checkin API not implemented")
	}

	resp, err := s.CheckinFn(
		ctx, id, userAgent, acceptEncoding, xRequestID, checkinRequest)
	if err != nil {
		return openapi.Response(err.StatusCode, err), nil
	}

	return openapi.Response(http.StatusOK, resp), nil
}

// AgentEnroll -
func (s *API) AgentEnroll(
	ctx context.Context,
	id string,
	userAgent string,
	xRequestID string,
	enrollRequest openapi.EnrollRequest) (openapi.ImplResponse, error) {
	if s.EnrollFn == nil {
		return openapi.Response(http.StatusNotImplemented, nil),
			errors.New("agent enroll API not implemented")
	}

	resp, err := s.EnrollFn(ctx, id, userAgent, xRequestID, enrollRequest)
	if err != nil {
		return openapi.Response(err.StatusCode, err), nil
	}

	return openapi.Response(http.StatusOK, resp), nil
}

// Artifact -
func (s *API) Artifact(
	ctx context.Context,
	id string,
	sha2 string,
	xRequestID string) (openapi.ImplResponse, error) {
	if s.ArtifactFn == nil {
		return openapi.Response(http.StatusNotImplemented, nil),
			errors.New("artifact API not implemented")
	}

	resp, err := s.ArtifactFn(ctx, id, sha2, xRequestID)
	if err != nil {
		return openapi.Response(err.StatusCode, err), nil
	}

	return openapi.Response(http.StatusOK, resp), nil
}

// Status -
func (s *API) Status(
	ctx context.Context,
	xRequestID string) (openapi.ImplResponse, error) {
	if s.StatusFn == nil {
		return openapi.Response(http.StatusNotImplemented, nil),
			errors.New("status API not implemented")
	}

	resp, err := s.StatusFn(ctx, xRequestID)
	if err != nil {
		return openapi.Response(err.StatusCode, err), nil
	}

	return openapi.Response(http.StatusOK, resp), nil
}

// UploadBegin - Initiate a file upload process
func (s *API) UploadBegin(
	ctx context.Context,
	requestBody map[string]interface{},
	xRequestID string) (openapi.ImplResponse, error) {
	if s.UploadBeginFn == nil {
		return openapi.Response(http.StatusNotImplemented, nil),
			errors.New("upload begin API not implemented")
	}

	resp, err := s.UploadBeginFn(ctx, requestBody, xRequestID)
	if err != nil {
		return openapi.Response(err.StatusCode, err), nil
	}

	return openapi.Response(http.StatusOK, resp), nil
}

// UploadChunk - Upload a section of file data
func (s *API) UploadChunk(
	ctx context.Context,
	id string,
	chunkNum int32,
	xChunkSHA2 string,
	body *os.File,
	xRequestID string) (openapi.ImplResponse, error) {
	if s.UploadChunkFn == nil {
		return openapi.Response(http.StatusNotImplemented, nil),
			errors.New("upload chunk API not implemented")
	}

	resp, err := s.UploadChunkFn(ctx, id, chunkNum, xChunkSHA2, body, xRequestID)
	if err != nil {
		return openapi.Response(err.StatusCode, err), nil
	}

	return openapi.Response(http.StatusOK, resp), nil
}

// UploadComplete - Complete a file upload process
func (s *API) UploadComplete(
	ctx context.Context,
	id string,
	uploadCompleteRequest openapi.UploadCompleteRequest,
	xRequestID string) (openapi.ImplResponse, error) {
	if s.UploadCompleteFn == nil {
		return openapi.Response(http.StatusNotImplemented, nil),
			errors.New("upload complete API not implemented")
	}

	resp, err := s.UploadCompleteFn(ctx, id, uploadCompleteRequest, xRequestID)
	if err != nil {
		return openapi.Response(err.StatusCode, err), nil
	}

	return openapi.Response(http.StatusOK, resp), nil
}

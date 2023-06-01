package fleetservertest

import (
	"context"
	"io"
	"net/http/httptest"
)

// API holds the handlers for the fleet-api, see https://petstore.swagger.io/?url=https://raw.githubusercontent.com/elastic/fleet-server/main/model/openapi.yml
// for rendered OpenAPI definition. If any of the handlers are nil, a
// http.StatusNotImplemented is returned for the route.
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

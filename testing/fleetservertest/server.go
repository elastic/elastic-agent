// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleetservertest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

// Handlers holds the handlers for the fleet-api, see https://petstore.swagger.io/?url=https://raw.githubusercontent.com/elastic/fleet-server/main/model/openapi.yml
// for rendered OpenAPI definition. If any of the handlers are nil, a
// http.StatusNotImplemented is returned for the route.
//
// Authentication is made extracting he API key or enrollment token,
// from the HeaderAuthorization header and compared against API.APIKey or
// API.EnrollmentToken. API.EnrollmentToken is used for Enroll requests and
// API.APIKey for all others.
// TODO(Anderson): fix me!
type Handlers struct {
	// AgentID is the ID of the last enrolled agent.
	AgentID string

	APIKey          string
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

type Route struct {
	Name    string
	Method  string
	Pattern string
	AuthKey string
	Handler http.Handler
}

// NewRouter creates a new router for any number of api routers
func NewRouter(hs Handlers) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range hs.Routes() {
		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(AuthenticationMiddleware(route.AuthKey, route.Handler))
	}

	return router
}

// Routes returns all the api routes for the Handlers
func (h *Handlers) Routes() []Route {
	return []Route{
		{
			Name:    "AgentAcks",
			Method:  http.MethodPost,
			Pattern: PathAgentAcks,
			AuthKey: h.APIKey,
			Handler: http.HandlerFunc(h.AgentAcks),
		},
		{
			Name:    "AgentCheckin",
			Method:  http.MethodPost,
			Pattern: PathAgentCheckin,
			AuthKey: h.APIKey,
			Handler: http.HandlerFunc(h.AgentCheckin),
		},
		{
			Name:    "AgentEnroll",
			Method:  http.MethodPost,
			Pattern: PathAgentEnroll,
			AuthKey: h.EnrollmentToken,
			Handler: http.HandlerFunc(h.AgentEnroll),
		},
		{
			Name:    "Artifact",
			Method:  http.MethodGet,
			Pattern: PathArtifact,
			AuthKey: h.APIKey,
			Handler: http.HandlerFunc(h.Artifact),
		},
		{
			Name:    "Status",
			Method:  http.MethodGet,
			Pattern: PathStatus,
			AuthKey: h.APIKey,
			Handler: http.HandlerFunc(h.Status),
		},
		{
			Name:    "UploadBegin",
			Method:  http.MethodPost,
			Pattern: PathUploadBegin,
			AuthKey: h.APIKey,
			Handler: http.HandlerFunc(h.UploadBegin),
		},
		{
			Name:    "UploadChunk",
			Method:  http.MethodPut,
			Pattern: PathUploadChunk,
			AuthKey: h.APIKey,
			Handler: http.HandlerFunc(h.UploadChunk),
		},
		{
			Name:    "UploadComplete",
			Method:  http.MethodPost,
			Pattern: PathUploadComplete,
			AuthKey: h.APIKey,
			Handler: http.HandlerFunc(h.UploadComplete),
		},
	}
}

// AgentAcks -
func (h *Handlers) AgentAcks(w http.ResponseWriter, r *http.Request) {
	if h.AckFn == nil {
		err := &HTTPError{StatusCode: http.StatusNotImplemented,
			Message: "agent acs Handlers not implemented"}
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	params := mux.Vars(r)
	idParam := params["id"]
	ackRequestParam := AckRequest{}
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&ackRequestParam); err != nil {
		respondAsJSON(http.StatusBadRequest, HTTPError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("%v", err),
		}, w)
		return
	}

	result, err := h.AckFn(r.Context(), idParam, ackRequestParam)
	if err != nil {
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	respondAsJSON(http.StatusOK, result, w)
}

// AgentCheckin -
func (h *Handlers) AgentCheckin(w http.ResponseWriter, r *http.Request) {
	if h.CheckinFn == nil {
		err := &HTTPError{StatusCode: http.StatusNotImplemented,
			Message: "checkin Handlers not implemented"}
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	params := mux.Vars(r)
	idParam := params["id"]
	userAgentParam := r.Header.Get("User-Agent")
	acceptEncodingParam := r.Header.Get("Accept-Encoding")
	checkinRequestParam := CheckinRequest{}

	d := json.NewDecoder(r.Body)
	if err := d.Decode(&checkinRequestParam); err != nil {
		respondAsJSON(http.StatusBadRequest, HTTPError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("%v", err),
		}, w)
		return
	}

	result, err := h.CheckinFn(
		r.Context(),
		idParam,
		userAgentParam,
		acceptEncodingParam,
		checkinRequestParam)
	if err != nil {
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	respondAsJSON(http.StatusOK, result, w)
}

// AgentEnroll -
func (h *Handlers) AgentEnroll(w http.ResponseWriter, r *http.Request) {
	if h.EnrollFn == nil {
		err := &HTTPError{StatusCode: http.StatusNotImplemented,
			Message: "agent checkin Handlers not implemented"}
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	userAgentParam := r.Header.Get("User-Agent")
	enrollRequestParam := EnrollRequest{}
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&enrollRequestParam); err != nil {
		respondAsJSON(http.StatusBadRequest, HTTPError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("%v", err),
		}, w)
		return
	}

	result, err := h.EnrollFn(
		r.Context(),
		userAgentParam,
		enrollRequestParam)
	if err != nil {
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	respondAsJSON(http.StatusOK, result, w)
}

// Artifact -
func (h *Handlers) Artifact(w http.ResponseWriter, r *http.Request) {
	if h.ArtifactFn == nil {
		err := &HTTPError{StatusCode: http.StatusNotImplemented,
			Message: "artifact Handlers not implemented"}
		respondAsJSON(err.StatusCode, err, w)
		return

	}
	params := mux.Vars(r)
	idParam := params["id"]
	sha2Param := params["sha2"]

	err := h.ArtifactFn(r.Context(), idParam, sha2Param)
	if err != nil {
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	respondAsJSON(http.StatusOK, nil, w)
}

// Status -
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	if h.StatusFn == nil {
		err := &HTTPError{StatusCode: http.StatusNotImplemented,
			Message: "status Handlers not implemented"}
		respondAsJSON(err.StatusCode, err, w)
		return

	}

	result, err := h.StatusFn(r.Context())
	if err != nil {
		if result != nil {
			respondAsJSON(err.StatusCode, result, w)
		}
		respondAsJSON(err.StatusCode, err, w)
		return
	}
	respondAsJSON(http.StatusOK, result, w)
}

// UploadBegin - Initiate a file upload process
func (h *Handlers) UploadBegin(w http.ResponseWriter, r *http.Request) {
	if h.UploadBeginFn == nil {
		err := &HTTPError{StatusCode: http.StatusNotImplemented,
			Message: "upload begin Handlers not implemented"}
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	requestBodyParam := UploadBeginRequest{}
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&requestBodyParam); err != nil {
		respondAsJSON(http.StatusBadRequest, HTTPError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("%v", err),
		}, w)
		return
	}

	result, err := h.UploadBeginFn(r.Context(), requestBodyParam)
	if err != nil {
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	respondAsJSON(http.StatusOK, result, w)
}

// UploadChunk - Upload a section of file data
func (h *Handlers) UploadChunk(w http.ResponseWriter, r *http.Request) {
	if h.UploadChunkFn == nil {
		err := &HTTPError{StatusCode: http.StatusNotImplemented,
			Message: "upload chunk Handlers not implemented"}
		respondAsJSON(err.StatusCode, err, w)
		return

	}

	params := mux.Vars(r)
	idParam := params["id"]

	chunkNumParam := params["chunkNum"]
	if chunkNumParam == "" {
		respondAsJSON(http.StatusBadRequest, HTTPError{
			StatusCode: http.StatusBadRequest,
			Message:    "chunkNum is empty",
		}, w)
	}

	chunkNum, err := strconv.ParseInt(chunkNumParam, 10, 32)
	if err != nil {
		respondAsJSON(http.StatusBadRequest, HTTPError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("%v", err),
		}, w)
	}

	chunkSHA2 := r.Header.Get("X-Chunk-SHA2")
	// Currently fleet-server limits the size of each chunk to 4 MiB.
	body := http.MaxBytesReader(w, r.Body, 4194304 /*4 MiB*/)

	uerr := h.UploadChunkFn(
		r.Context(),
		idParam,
		int32(chunkNum),
		chunkSHA2,
		body)
	if uerr != nil {
		respondAsJSON(uerr.StatusCode, uerr, w)
		return
	}
	respondAsJSON(http.StatusOK, nil, w)
}

// UploadComplete - Complete a file upload process
func (h *Handlers) UploadComplete(w http.ResponseWriter, r *http.Request) {
	if h.UploadCompleteFn == nil {
		err := &HTTPError{StatusCode: http.StatusNotImplemented,
			Message: "upload complete Handlers not implemented"}
		respondAsJSON(err.StatusCode, err, w)
		return
	}
	params := mux.Vars(r)
	idParam := params["id"]
	uploadCompleteRequestParam := UploadCompleteRequest{}
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&uploadCompleteRequestParam); err != nil {
		respondAsJSON(http.StatusBadRequest, HTTPError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("%v", err),
		}, w)
		return
	}

	err := h.UploadCompleteFn(r.Context(), idParam, uploadCompleteRequestParam)
	if err != nil {
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	respondAsJSON(http.StatusOK, `{"status": "ok"}`, w)
}

// respondAsJSON uses the json encoder to write an interface to the http response with an optional status code
func respondAsJSON(status int, body interface{}, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(status)

	if body == nil {
		return
	}

	if err := json.NewEncoder(w).Encode(body); err != nil {
		//nolint:forbidigo // it's to be used in tests
		fmt.Printf("could not write response body: %v\n", err)
	}
}

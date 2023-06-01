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

// Handlers binds http requests to an api service and writes the service results to the http response
type Handlers struct {
	api API
}

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

// NewRouter creates a new router for any number of api routers
func NewRouter(hs Handlers) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range hs.Routes() {
		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(route.HandlerFunc)
	}

	return router
}

// Routes returns all the api routes for the Handlers
func (h *Handlers) Routes() []Route {
	return []Route{
		{
			Name:        "AgentAcks",
			Method:      http.MethodPost,
			Pattern:     PathAgentAcks,
			HandlerFunc: h.AgentAcks,
		},
		{
			Name:        "AgentCheckin",
			Method:      http.MethodPost,
			Pattern:     PathAgentCheckin,
			HandlerFunc: h.AgentCheckin,
		},
		{
			Name:        "AgentEnroll",
			Method:      http.MethodPost,
			Pattern:     PathAgentEnroll,
			HandlerFunc: h.AgentEnroll,
		},
		{
			Name:        "Artifact",
			Method:      http.MethodGet,
			Pattern:     PathArtifact,
			HandlerFunc: h.Artifact,
		},
		{
			Name:        "Status",
			Method:      http.MethodGet,
			Pattern:     PathStatus,
			HandlerFunc: h.Status,
		},
		{
			Name:        "UploadBegin",
			Method:      http.MethodPost,
			Pattern:     PathUploadBegin,
			HandlerFunc: h.UploadBegin,
		},
		{
			Name:        "UploadChunk",
			Method:      http.MethodPut,
			Pattern:     PathUploadChunk,
			HandlerFunc: h.UploadChunk,
		},
		{
			Name:        "UploadComplete",
			Method:      http.MethodPost,
			Pattern:     PathUploadComplete,
			HandlerFunc: h.UploadComplete,
		},
	}
}

// AgentAcks -
func (h *Handlers) AgentAcks(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	idParam := params["id"]

	ackRequestParam := AckRequest{}
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&ackRequestParam); err != nil {
		respondAsJSON(http.StatusBadRequest, HTTPError{
			StatusCode: http.StatusBadRequest,
			Error:      http.StatusText(http.StatusBadRequest),
			Message:    fmt.Sprintf("%v", err),
		}, w)
		return
	}

	result, err := h.api.AgentAcks(r.Context(), idParam, ackRequestParam)
	if err != nil {
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	respondAsJSON(http.StatusOK, result, w)
}

// AgentCheckin -
func (h *Handlers) AgentCheckin(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	idParam := params["id"]
	userAgentParam := r.Header.Get("User-Agent")
	acceptEncodingParam := r.Header.Get("Accept-Encoding")
	checkinRequestParam := CheckinRequest{}

	d := json.NewDecoder(r.Body)
	if err := d.Decode(&checkinRequestParam); err != nil {
		respondAsJSON(http.StatusBadRequest, HTTPError{
			StatusCode: http.StatusBadRequest,
			Error:      http.StatusText(http.StatusBadRequest),
			Message:    fmt.Sprintf("%v", err),
		}, w)
		respondAsJSON(http.StatusBadRequest, HTTPError{
			StatusCode: http.StatusBadRequest,
			Error:      http.StatusText(http.StatusBadRequest),
			Message:    fmt.Sprintf("%v", err),
		}, w)
		return
	}

	result, err := h.api.AgentCheckin(
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
	params := mux.Vars(r)
	idParam := params["id"]
	userAgentParam := r.Header.Get("User-Agent")
	enrollRequestParam := EnrollRequest{}
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&enrollRequestParam); err != nil {
		respondAsJSON(http.StatusBadRequest, HTTPError{
			StatusCode: http.StatusBadRequest,
			Error:      http.StatusText(http.StatusBadRequest),
			Message:    fmt.Sprintf("%v", err),
		}, w)
		return
	}

	result, err := h.api.AgentEnroll(
		r.Context(),
		idParam,
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
	params := mux.Vars(r)
	idParam := params["id"]
	sha2Param := params["sha2"]

	err := h.api.Artifact(r.Context(), idParam, sha2Param)
	if err != nil {
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	respondAsJSON(http.StatusOK, nil, w)
}

// Status -
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	result, err := h.api.Status(r.Context())
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
	requestBodyParam := UploadBeginRequest{}
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&requestBodyParam); err != nil {
		respondAsJSON(http.StatusBadRequest, HTTPError{
			StatusCode: http.StatusBadRequest,
			Error:      http.StatusText(http.StatusBadRequest),
			Message:    fmt.Sprintf("%v", err),
		}, w)
		return
	}

	result, err := h.api.UploadBegin(r.Context(), requestBodyParam)
	if err != nil {
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	respondAsJSON(http.StatusOK, result, w)
}

// UploadChunk - Upload a section of file data
func (h *Handlers) UploadChunk(w http.ResponseWriter, r *http.Request) {
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

	uerr := h.api.UploadChunk(
		r.Context(),
		idParam,
		int32(chunkNum),
		chunkSHA2,
		body)
	if err != nil {
		respondAsJSON(uerr.StatusCode, err, w)
		return
	}
	respondAsJSON(http.StatusOK, nil, w)
}

// UploadComplete - Complete a file upload process
func (h *Handlers) UploadComplete(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	idParam := params["id"]
	uploadCompleteRequestParam := UploadCompleteRequest{}
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&uploadCompleteRequestParam); err != nil {
		respondAsJSON(http.StatusBadRequest, HTTPError{
			StatusCode: http.StatusBadRequest,
			Error:      http.StatusText(http.StatusBadRequest),
			Message:    fmt.Sprintf("%v", err),
		}, w)
		return
	}

	result, err := h.api.UploadComplete(r.Context(), idParam, uploadCompleteRequestParam)
	if err != nil {
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	respondAsJSON(http.StatusOK, result, w)
}

// respondAsJSON uses the json encoder to write an interface to the http response with an optional status code
func respondAsJSON(status int, body interface{}, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(status)

	if body == nil {
		return
	}

	if err := json.NewEncoder(w).Encode(body); err != nil {
		fmt.Printf("could not write response body: %v\n", err)
	}
}

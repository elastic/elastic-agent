package fleetserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

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
func (c *Handlers) Routes() []Route {
	return []Route{
		{
			Name:        "AgentAcks",
			Method:      http.MethodPost,
			Pattern:     "/api/fleet/agents/{id}/acks",
			HandlerFunc: c.AgentAcks,
		},
		{
			Name:        "AgentCheckin",
			Method:      http.MethodPost,
			Pattern:     "/api/fleet/agents/{id}/checkin",
			HandlerFunc: c.AgentCheckin,
		},
		{
			Name:        "AgentEnroll",
			Method:      http.MethodPost,
			Pattern:     "/api/fleet/agents/{id}",
			HandlerFunc: c.AgentEnroll,
		},
		{
			Name:        "Artifact",
			Method:      http.MethodGet,
			Pattern:     "/api/fleet/artifacts/{id}/{sha2}",
			HandlerFunc: c.Artifact,
		},
		{
			Name:        "Status",
			Method:      http.MethodGet,
			Pattern:     "/api/status",
			HandlerFunc: c.Status,
		},
		{
			Name:        "UploadBegin",
			Method:      http.MethodPost,
			Pattern:     "/api/fleet/uploads",
			HandlerFunc: c.UploadBegin,
		},
		{
			Name:        "UploadChunk",
			Method:      http.MethodPut,
			Pattern:     "/api/fleet/uploads/{id}/{chunkNum}",
			HandlerFunc: c.UploadChunk,
		},
		{
			Name:        "UploadComplete",
			Method:      http.MethodPost,
			Pattern:     "/api/fleet/uploads/{id}",
			HandlerFunc: c.UploadComplete,
		},
	}
}

// AgentAcks -
func (c *Handlers) AgentAcks(w http.ResponseWriter, r *http.Request) {
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

	result, err := c.api.AgentAcks(r.Context(), idParam, ackRequestParam)
	if err != nil {
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	respondAsJSON(http.StatusOK, result, w)
}

// AgentCheckin -
func (c *Handlers) AgentCheckin(w http.ResponseWriter, r *http.Request) {
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

	result, err := c.api.AgentCheckin(
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
func (c *Handlers) AgentEnroll(w http.ResponseWriter, r *http.Request) {
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

	result, err := c.api.AgentEnroll(
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
func (c *Handlers) Artifact(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	idParam := params["id"]
	sha2Param := params["sha2"]

	err := c.api.Artifact(r.Context(), idParam, sha2Param)
	if err != nil {
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	respondAsJSON(http.StatusOK, nil, w)
}

// Status -
func (c *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	result, err := c.api.Status(r.Context())
	if err != nil {
		respondAsJSON(err.StatusCode, err, w)
		return
	}
	respondAsJSON(http.StatusOK, result, w)
}

// UploadBegin - Initiate a file upload process
func (c *Handlers) UploadBegin(w http.ResponseWriter, r *http.Request) {
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

	result, err := c.api.UploadBegin(r.Context(), requestBodyParam)
	if err != nil {
		respondAsJSON(err.StatusCode, err, w)
		return
	}

	respondAsJSON(http.StatusOK, result, w)
}

// UploadChunk - Upload a section of file data
func (c *Handlers) UploadChunk(w http.ResponseWriter, r *http.Request) {
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

	uerr := c.api.UploadChunk(
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
func (c *Handlers) UploadComplete(w http.ResponseWriter, r *http.Request) {
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

	result, err := c.api.UploadComplete(r.Context(), idParam, uploadCompleteRequestParam)
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

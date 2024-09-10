// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package monitoring

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
)

const errTypeUnexpected = "UNEXPECTED"

type apiError interface {
	Status() int
}

// CoordinatorState is used by the HTTP handlers that take a coordinator object.
// This interface exists to help make testing easier.
type CoordinatorState interface {
	State() coordinator.State
	IsActive(timeout time.Duration) bool
}

func createHandler(fn func(w http.ResponseWriter, r *http.Request) error) *apiHandler {
	return &apiHandler{
		innerFn: fn,
	}
}

type apiHandler struct {
	innerFn func(w http.ResponseWriter, r *http.Request) error
}

// ServeHTTP sets status code based on err returned
func (h *apiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.innerFn(w, r)
	if err != nil {
		switch e := err.(type) { //nolint:errorlint // Will need refactor.
		case apiError:
			w.WriteHeader(e.Status())
		default:
			w.WriteHeader(http.StatusInternalServerError)

		}

		writeResponse(w, unexpectedErrorWithReason(err.Error()))
	}
}

func writeResponse(w http.ResponseWriter, c interface{}) {
	bytes, err := json.Marshal(c)
	if err != nil {
		// json marshal failed
		fmt.Fprintf(w, "Not valid json: %v", err)
		return
	}

	fmt.Fprint(w, string(bytes))

}

type errResponse struct {
	// Type is a type of error
	Type string `json:"type"`

	// Reason is a detailed error message
	Reason string `json:"reason"`
}

func unexpectedErrorWithReason(reason string, args ...interface{}) errResponse {
	return errResponse{
		Type:   errTypeUnexpected,
		Reason: fmt.Sprintf(reason, args...),
	}
}

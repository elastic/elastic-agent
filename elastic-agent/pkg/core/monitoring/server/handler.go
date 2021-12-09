// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package server

import (
	"fmt"
	"net/http"
)

type apiError interface {
	Status() int
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
		switch e := err.(type) {
		case apiError:
			w.WriteHeader(e.Status())
		default:
			w.WriteHeader(http.StatusInternalServerError)

		}

		writeResponse(w, unexpectedErrorWithReason(err.Error()))
	}
}

func unexpectedErrorWithReason(reason string, args ...interface{}) errResponse {
	return errResponse{
		Type:   errTypeUnexpected,
		Reason: fmt.Sprintf(reason, args...),
	}
}

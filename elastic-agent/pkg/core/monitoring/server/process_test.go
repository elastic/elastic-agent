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
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseID(t *testing.T) {
	cases := []struct {
		Name               string
		ID                 string
		ExpectedError      bool
		ExpectedStatusCode int
		ExpectedProgram    programDetail
	}{
		{"path injected id", ".././../etc/passwd", true, http.StatusBadRequest, programDetail{}},
		{"pipe injected id", "first | second", true, http.StatusBadRequest, programDetail{}},
		{"filebeat with suffix", "filebeat;cat demo-default-monitoring", true, http.StatusBadRequest, programDetail{}},

		{"filebeat correct", "filebeat-default", false, http.StatusBadRequest, programDetail{output: "default", binaryName: "filebeat"}},
		{"filebeat monitor correct", "filebeat-default-monitoring", false, http.StatusBadRequest, programDetail{output: "default", binaryName: "filebeat", isMonitoring: true}},

		{"mb correct", "metricbeat-default", false, http.StatusBadRequest, programDetail{output: "default", binaryName: "metricbeat"}},
		{"mb monitor correct", "metricbeat-default-monitoring", false, http.StatusBadRequest, programDetail{output: "default", binaryName: "metricbeat", isMonitoring: true}},

		{"endpoint correct", "endpoint-security-default", false, http.StatusBadRequest, programDetail{output: "default", binaryName: "endpoint-security"}},
		{"endpoint monitor correct", "endpoint-security-default-monitoring", false, http.StatusBadRequest, programDetail{output: "default", binaryName: "endpoint-security", isMonitoring: true}},

		{"unknown", "unknown-default", true, http.StatusNotFound, programDetail{}},
		{"unknown monitor", "unknown-default-monitoring", true, http.StatusNotFound, programDetail{}},
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			pd, err := parseID(tc.ID)
			if !tc.ExpectedError {
				require.NoError(t, err)
			}

			if tc.ExpectedStatusCode > 0 && tc.ExpectedError {
				statErr, ok := err.(apiError)
				require.True(t, ok)
				require.Equal(t, tc.ExpectedStatusCode, statErr.Status())
			}

			require.Equal(t, tc.ExpectedProgram.binaryName, pd.binaryName)
			require.Equal(t, tc.ExpectedProgram.output, pd.output)
			require.Equal(t, tc.ExpectedProgram.isMonitoring, pd.isMonitoring)
		})
	}
}

func TestStatusErr(t *testing.T) {
	cases := map[string]struct {
		Error              error
		ExpectedStatusCode int
	}{
		"no error":                       {nil, 0},
		"normal error":                   {errors.New("something bad happened"), http.StatusInternalServerError},
		"status bound err - not found":   {errorWithStatus(http.StatusNotFound, errors.New("something was not found")), http.StatusNotFound},
		"status bound err - internal":    {errorWithStatus(http.StatusInternalServerError, errors.New("something was not found")), http.StatusInternalServerError},
		"status bound err - bad request": {errorWithStatus(http.StatusBadRequest, errors.New("something really bad happened")), http.StatusBadRequest},
	}

	dummyHandler := func(err error) func(w http.ResponseWriter, r *http.Request) error {
		return func(w http.ResponseWriter, r *http.Request) error {
			return err
		}
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := createHandler(dummyHandler(tc.Error))
			tw := &testWriter{}
			r, err := http.NewRequest("GET", "", nil)
			require.NoError(t, err)

			h.ServeHTTP(tw, r)

			require.Equal(t, tc.ExpectedStatusCode, tw.statusCode)
		})
	}
}

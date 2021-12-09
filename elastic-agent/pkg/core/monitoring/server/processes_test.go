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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/process"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/state"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/sorted"
)

func TestProcesses(t *testing.T) {
	testRoutes := func(routes map[string]stater) func() *sorted.Set {
		set := sorted.NewSet()
		for k, s := range routes {
			set.Add(k, s)
		}

		return func() *sorted.Set { return set }
	}

	t.Run("nothing running", func(t *testing.T) {
		r := testRoutes(nil)
		w := &testWriter{}
		fn := processesHandler(r)
		fn(w, nil)

		pr := processesResponse{
			Processes: nil,
		}

		assert.Equal(t, 1, len(w.responses))
		if !assert.True(t, jsonComparer(w.responses[0], pr)) {
			diff := cmp.Diff(pr, w.responses[0])
			t.Logf("Mismatch (-want, +got)\n%s", diff)
		}
	})

	t.Run("process running", func(t *testing.T) {
		r := testRoutes(map[string]stater{
			"default": &testStater{
				states: map[string]state.State{
					"filebeat--8.0.0": {
						ProcessInfo: &process.Info{
							PID: 123,
							Process: &os.Process{
								Pid: 123,
							},
						},
						Status: state.Configuring,
					},
				},
			},
		})
		w := &testWriter{}
		fn := processesHandler(r)
		fn(w, nil)

		pr := processesResponse{
			Processes: []processInfo{
				{
					ID:     "filebeat-default",
					PID:    "123",
					Binary: "filebeat",
					Source: sourceInfo{Kind: "configured", Outputs: []string{"default"}},
				},
			},
		}

		assert.Equal(t, 1, len(w.responses))
		if !assert.True(t, jsonComparer(w.responses[0], pr)) {
			diff := cmp.Diff(w.responses[0], pr)
			t.Logf("Mismatch (-want, +got)\n%s", diff)
		}
	})

	t.Run("monitoring running", func(t *testing.T) {
		r := testRoutes(map[string]stater{
			"default": &testStater{
				states: map[string]state.State{
					"filebeat--8.0.0--tag": {
						ProcessInfo: &process.Info{
							PID: 123,
							Process: &os.Process{
								Pid: 123,
							},
						},
						Status: state.Configuring,
					},
				},
			},
		})
		w := &testWriter{}
		fn := processesHandler(r)
		fn(w, nil)

		pr := processesResponse{
			Processes: []processInfo{
				{
					ID:     "filebeat-default-monitoring",
					PID:    "123",
					Binary: "filebeat",
					Source: sourceInfo{Kind: "internal", Outputs: []string{"default"}},
				},
			},
		}

		assert.Equal(t, 1, len(w.responses))
		if !assert.True(t, jsonComparer(w.responses[0], pr)) {
			diff := cmp.Diff(w.responses[0], pr)
			t.Logf("Mismatch (-want, +got)\n%s", diff)
		}
	})
}

type testStater struct {
	states map[string]state.State
}

func (s *testStater) State() map[string]state.State {
	return s.states
}

type testWriter struct {
	responses  []string
	statusCode int
}

func (w *testWriter) Header() http.Header {
	return http.Header{}
}

func (w *testWriter) Write(r []byte) (int, error) {
	if w.responses == nil {
		w.responses = make([]string, 0)
	}
	w.responses = append(w.responses, string(r))

	return len(r), nil
}

func (w *testWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

func jsonComparer(expected string, candidate interface{}) bool {
	candidateJSON, err := json.Marshal(&candidate)
	if err != nil {
		fmt.Println(err)
		return false
	}

	cbytes := make([]byte, 0, len(candidateJSON))
	bbuf := bytes.NewBuffer(cbytes)
	if err := json.Compact(bbuf, candidateJSON); err != nil {
		fmt.Println(err)
		return false
	}

	return bytes.Equal([]byte(expected), bbuf.Bytes())
}

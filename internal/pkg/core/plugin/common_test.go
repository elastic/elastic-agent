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

package plugin

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/program"
	"github.com/elastic/elastic-agent-poc/internal/pkg/core/logger"
)

func TestRestartNeeded(t *testing.T) {
	tt := []struct {
		Name          string
		OldOutput     map[string]interface{}
		NewOutput     map[string]interface{}
		ShouldRestart bool

		ExpectedRestart bool
	}{
		{
			"same empty output",
			map[string]interface{}{},
			map[string]interface{}{},
			true,
			false,
		},
		{
			"same not empty output",
			map[string]interface{}{"output": map[string]interface{}{"username": "user", "password": "123456"}},
			map[string]interface{}{"output": map[string]interface{}{"username": "user", "password": "123456"}},
			true,
			false,
		},
		{
			"different empty output",
			map[string]interface{}{},
			map[string]interface{}{"output": map[string]interface{}{"username": "user", "password": "123456"}},
			true,
			false,
		},
		{
			"different not empty output",
			map[string]interface{}{"output": map[string]interface{}{"username": "user", "password": "123456"}},
			map[string]interface{}{"output": map[string]interface{}{"username": "user", "password": "s3cur3_Pa55;"}},
			true,
			true,
		},
		{
			"different not empty output no restart required",
			map[string]interface{}{"output": map[string]interface{}{"username": "user", "password": "123456"}},
			map[string]interface{}{"output": map[string]interface{}{"username": "user", "password": "s3cur3_Pa55;"}},
			false,
			false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			cf, err := newTestConfigFetcher(tc.OldOutput)
			require.NoError(t, err)
			s := testProgramSpec(tc.ShouldRestart)
			l, _ := logger.New("tst", false)

			IsRestartNeeded(l, s, cf, tc.NewOutput)
		})
	}
}

func newTestConfigFetcher(cfg map[string]interface{}) (*testConfigFetcher, error) {
	cfgStr, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, errors.New(err, errors.TypeApplication)
	}

	return &testConfigFetcher{cfg: string(cfgStr)}, nil
}

type testConfigFetcher struct {
	cfg string
}

func (f testConfigFetcher) Config() string { return f.cfg }

func testProgramSpec(restartOnOutput bool) program.Spec {
	return program.Spec{
		RestartOnOutputChange: restartOnOutput,
	}
}

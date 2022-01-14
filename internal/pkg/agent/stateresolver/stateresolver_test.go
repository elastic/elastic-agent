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

package stateresolver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/program"
	"github.com/elastic/elastic-agent-poc/internal/pkg/core/logger"
)

func TestStateResolverAcking(t *testing.T) {
	submit := &cfg{
		id:        "config-1",
		createdAt: time.Now(),
		programs: []program.Program{
			fb("1"), mb("1"),
		},
	}

	t.Run("when we ACK the should state", func(t *testing.T) {
		log, _ := logger.New("", false)
		r, err := NewStateResolver(log)
		require.NoError(t, err)

		// Current state is empty.
		_, _, steps, ack, err := r.Resolve(submit)
		require.NoError(t, err)
		require.Equal(t, 2, len(steps))

		// Ack the should state.
		ack()

		// Current sate is not empty lets try to resolve the same configuration.
		_, _, steps, _, err = r.Resolve(submit)
		require.NoError(t, err)
		require.Equal(t, 0, len(steps))
	})

	t.Run("when we don't ACK the should state", func(t *testing.T) {
		log, _ := logger.New("", false)
		r, err := NewStateResolver(log)
		require.NoError(t, err)

		// Current state is empty.
		_, _, steps1, _, err := r.Resolve(submit)
		require.NoError(t, err)
		require.Equal(t, 2, len(steps1))

		// We didn't ACK the should state, verify that resolve produce the same output.
		_, _, steps2, _, err := r.Resolve(submit)
		require.NoError(t, err)
		require.Equal(t, 2, len(steps2))

		assert.Equal(t, steps1, steps2)
	})
}

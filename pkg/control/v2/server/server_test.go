// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package server

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gotest.tools/assert"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator/state"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
)

func TestFleetStateMapping(t *testing.T) {

	testcases := []struct {
		name    string
		state   cproto.State
		message string
	}{
		{
			name:    "waiting first checkin response",
			state:   cproto.State_STARTING,
			message: "",
		},
		{
			name:    "last checkin successful",
			state:   cproto.State_HEALTHY,
			message: "Connected",
		},
		{
			name:    "last checkin failed",
			state:   cproto.State_FAILED,
			message: "<error value coming from fleet gateway>",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			inputState := new(state.State)
			inputState.FleetState = tc.state
			inputState.FleetMessage = tc.message

			agentInfo := new(info.AgentInfo)

			stateResponse, err := stateToProto(inputState, agentInfo)
			require.NoError(t, err)

			assert.Equal(t, stateResponse.FleetState, tc.state)
			assert.Equal(t, stateResponse.FleetMessage, tc.message)
		})
	}

}

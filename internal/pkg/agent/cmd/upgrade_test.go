// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"

	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
)

type mockClient struct {
	stateErr string
	state    cproto.State
}

func (mc *mockClient) Connect(ctx context.Context) error { return nil }
func (mc *mockClient) Disconnect()                       {}
func (mc *mockClient) Version(ctx context.Context) (client.Version, error) {
	return client.Version{}, nil
}
func (mc *mockClient) State(ctx context.Context) (*client.AgentState, error) {
	if mc.stateErr != "" {
		return nil, errors.New(mc.stateErr)
	}

	return &client.AgentState{State: mc.state}, nil
}
func (mc *mockClient) StateWatch(ctx context.Context) (client.ClientStateWatch, error) {
	return nil, nil
}
func (mc *mockClient) Restart(ctx context.Context) error { return nil }
func (mc *mockClient) Upgrade(ctx context.Context, version string, sourceURI string, skipVerify bool, skipDefaultPgp bool, pgpBytes ...string) (string, error) {
	return "", nil
}
func (mc *mockClient) DiagnosticAgent(ctx context.Context, additionalDiags []client.AdditionalMetrics) ([]client.DiagnosticFileResult, error) {
	return nil, nil
}
func (mc *mockClient) DiagnosticUnits(ctx context.Context, units ...client.DiagnosticUnitRequest) ([]client.DiagnosticUnitResult, error) {
	return nil, nil
}
func (mc *mockClient) DiagnosticComponents(ctx context.Context, additionalDiags []client.AdditionalMetrics, components ...client.DiagnosticComponentRequest) ([]client.DiagnosticComponentResult, error) {
	return nil, nil
}
func (mc *mockClient) Configure(ctx context.Context, config string) error { return nil }

func TestIsUpgradeInProgress(t *testing.T) {
	tests := map[string]struct {
		state    cproto.State
		stateErr string

		expected    bool
		expectedErr string
	}{
		"state_error": {
			state:    cproto.State_STARTING,
			stateErr: "some error",

			expected:    false,
			expectedErr: "failed to get agent state: some error",
		},
		"state_upgrading": {
			state:    cproto.State_UPGRADING,
			stateErr: "",

			expected:    true,
			expectedErr: "",
		},
		"state_healthy": {
			state:    cproto.State_HEALTHY,
			stateErr: "",

			expected:    false,
			expectedErr: "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mc := mockClient{state: test.state, stateErr: test.stateErr}
			inProgress, err := isUpgradeInProgress(&mc)
			if test.expectedErr != "" {
				require.Equal(t, test.expectedErr, err.Error())
			} else {
				require.Equal(t, test.expected, inProgress)
			}
		})
	}
}

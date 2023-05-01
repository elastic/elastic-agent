// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator/state"
	"github.com/elastic/elastic-agent/internal/pkg/agent/protection"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type MockActionProtectionCoordinator struct {
	signatureValidationKey []byte
}

var signatureValidationKey []byte

func init() {
	var err error
	signatureValidationKey, err = base64.StdEncoding.DecodeString(`MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuaakkgkOQlVh78UOZuT8fOcocIMXAp01azX5ZK4LkLiMe8BjENTF/tT8rf3nlu5mqBvlePc/IJMXMYiN5YJo4A==`)
	if err != nil {
		panic(err)
	}
}

func (c *MockActionProtectionCoordinator) Protection() protection.Config {
	return protection.Config{
		SignatureValidationKey: signatureValidationKey,
	}
}

func (c *MockActionProtectionCoordinator) State() state.State {
	return state.State{
		Components: []runtime.ComponentComponentState{
			{
				Component: component.Component{
					Units: []component.Unit{
						{
							Type:   client.UnitTypeInput,
							Config: &proto.UnitExpectedConfig{Type: "endpoint"},
						},
					},
				},
			},
		},
	}
}

func (c *MockActionProtectionCoordinator) PerformAction(ctx context.Context, comp component.Component, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error) {
	return nil, nil
}

type MockAcker struct {
	Acked []fleetapi.Action
}

func (m *MockAcker) Ack(_ context.Context, action fleetapi.Action) error {
	m.Acked = append(m.Acked, action)
	return nil
}

func (m *MockAcker) Commit(_ context.Context) error {
	return nil
}

func (m *MockAcker) Clear() {
	m.Acked = nil
}

func TestActionHandler(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	log, _ := logger.New("", false)
	coord := &MockActionProtectionCoordinator{signatureValidationKey: signatureValidationKey}
	agentID := "bafdd485-104b-41e8-acd7-65a21d4105d0"

	acker := &MockAcker{}

	action := &fleetapi.ActionApp{
		ActionID:   "c80e9219-70bf-43d3-b8cd-b5131a771751",
		ActionType: "INPUT_ACTION",
		InputType:  "endpoint",
		Data:       json.RawMessage(`{"command": "isolate"}`),
	}
	goodSigned := &fleetapi.Signed{
		Data:      "eyJhY3Rpb25faWQiOiJjODBlOTIxOS03MGJmLTQzZDMtYjhjZC1iNTEzMWE3NzE3NTEiLCJleHBpcmF0aW9uIjoiMjAyMy0wNS0xNVQxNjo0NTozMi43NzZaIiwidHlwZSI6IklOUFVUX0FDVElPTiIsImlucHV0X3R5cGUiOiJlbmRwb2ludCIsImRhdGEiOnsiY29tbWFuZCI6Imlzb2xhdGUifSwiQHRpbWVzdGFtcCI6IjIwMjMtMDUtMDFUMTY6NDU6MzIuNzc2WiIsImFnZW50cyI6WyJiYWZkZDQ4NS0xMDRiLTQxZTgtYWNkNy02NWEyMWQ0MTA1ZDAiXSwidGltZW91dCI6MzAwLCJ1c2VyX2lkIjoiMzg0NDExMDU0MSJ9",
		Signature: "MEUCIQDlOSEm5YtJgg70nMQUhNIUIxi4fL1xo+gHzzypefk7bgIgLyn1wVi1urM2VZM2rxOMIN+hao/LWft7in5ZXnZmwy0=",
	}

	handler := NewAppAction(log, coord, agentID)

	tests := []struct {
		name          string
		action        *fleetapi.ActionApp
		wantErr       error  // Handler error
		wantActionErr string // Action result error
	}{
		{
			name:   "not signed", // Should succeed. Not signed actions are acceptable. Agent doesn't enforce actions signing
			action: action,
		},
		{
			name: "empty data or signature", // Should fail if "signed" property is present
			action: func() *fleetapi.ActionApp {
				a := *action // Copy
				a.Signed = &fleetapi.Signed{}
				return &a
			}(),
			wantActionErr: "action failed validation: " + action.InputType,
		},
		{
			name: "valid signature", // Valid signature should succeed
			action: func() *fleetapi.ActionApp {
				a := *action // Copy
				a.Signed = goodSigned
				return &a
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer acker.Clear()
			err := handler.Handle(ctx, tc.action, acker)
			require.ErrorIs(t, err, tc.wantErr)
			if tc.wantErr == nil {
				require.Len(t, acker.Acked, 1)
				actionAck := acker.Acked[0].(*fleetapi.ActionApp)
				if tc.wantActionErr != "" {
					require.EqualValues(t, tc.wantActionErr, actionAck.Error)
				}
			}
		})
	}
}

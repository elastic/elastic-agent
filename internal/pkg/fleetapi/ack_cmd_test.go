// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	api "github.com/elastic/fleet-server/pkg/api"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	pkgfleetapi "github.com/elastic/elastic-agent/pkg/fleetapi"
)

func TestAck(t *testing.T) {
	const withAPIKey = "secret"
	agentInfo := &agentinfo{}

	t.Run("Test ack roundtrip", withServerWithAuthClient(
		func(t *testing.T) *http.ServeMux {
			raw := `{"action": "acks"}` // The expected action from fleet server is "acks"
			mux := http.NewServeMux()
			path := fmt.Sprintf("/api/fleet/agents/%s/acks", agentInfo.AgentID())
			mux.HandleFunc(path, authHandler(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)

				var responses AckRequest

				decoder := json.NewDecoder(r.Body)
				defer r.Body.Close()

				err := decoder.Decode(&responses)
				require.NoError(t, err)

				require.Equal(t, 1, len(responses.Events))

				event, err := responses.Events[0].AsGenericEvent()
				require.NoError(t, err)
				require.Equal(t, "my-id", event.ActionId)

				fmt.Fprint(w, raw)
			}, withAPIKey))
			return mux
		}, withAPIKey,
		func(t *testing.T, client client.Sender) {
			action := &pkgfleetapi.ActionPolicyChange{
				ActionID:   "my-id",
				ActionType: "POLICY_CHANGE",
				Data: pkgfleetapi.ActionPolicyChangeData{Policy: map[string]interface{}{
					"id": "config_id",
				}},
			}

			cmd := NewAckCmd(&agentinfo{}, client)

			request := AckRequest{
				Events: []api.AckRequest_Events_Item{
					action.AckEvent(agentInfo.AgentID(), time.Now()),
				},
			}

			r, err := cmd.Execute(context.Background(), &request)
			require.NoError(t, err)
			require.Equal(t, "acks", r.Action)
		},
	))
}

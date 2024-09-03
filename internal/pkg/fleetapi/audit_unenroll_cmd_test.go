// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleetapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"

	"github.com/stretchr/testify/require"
)

func Test_AuditUnenrollCmd_Execute(t *testing.T) {
	const withAPIKey = "secret"
	agentInfo := &agentinfo{}

	t.Run("test audit/unenroll roundtrip", withServerWithAuthClient(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			path := fmt.Sprintf(auditUnenrollPath, agentInfo.AgentID())
			mux.HandleFunc(path, authHandler(func(w http.ResponseWriter, r *http.Request) {
				decoder := json.NewDecoder(r.Body)
				defer r.Body.Close()
				request := &AuditUnenrollRequest{}
				err := decoder.Decode(&request)
				require.NoError(t, err)
				require.Equal(t, ReasonUninstall, request.Reason)
				w.WriteHeader(http.StatusOK)
			}, withAPIKey))
			return mux
		}, withAPIKey,
		func(t *testing.T, client client.Sender) {
			cmd := NewAuditUnenrollCmd(agentInfo, client)
			request := &AuditUnenrollRequest{
				Reason:    ReasonUninstall,
				Timestamp: time.Now(),
			}
			resp, err := cmd.Execute(context.Background(), request)
			require.NoError(t, err)
			resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
		},
	))
}

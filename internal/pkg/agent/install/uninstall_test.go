// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	pkgfleetapi "github.com/elastic/elastic-agent/pkg/fleetapi"
)

// noopProgressDescriber is a no-op ProgressDescriber for use in tests.
type noopProgressDescriber struct{}

func (n *noopProgressDescriber) Describe(string) {}

func TestNotifyFleetAuditUnenroll(t *testing.T) {
	fleetAuditWaitInit = time.Millisecond * 10
	fleetAuditWaitMax = time.Millisecond * 100
	t.Cleanup(func() {
		fleetAuditWaitInit = time.Second
		fleetAuditWaitMax = time.Second * 10
	})

	tests := []struct {
		name      string
		getServer func() *httptest.Server
		err       error
	}{{
		name: "succeeds after a retry",
		getServer: func() *httptest.Server {
			callCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if callCount == 0 {
					callCount++
					w.WriteHeader(http.StatusNotFound)
					return
				}
				callCount++
				w.WriteHeader(http.StatusOK)
			}))
			return server
		},
		err: nil,
	}, {
		name: "returns 401",
		getServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			}))
		},
		err: nil,
	}, {
		name: "returns 409",
		getServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusConflict)
			}))
		},
		err: fmt.Errorf("unretryable return status: 409"),
	}}

	log, _ := logp.NewInMemoryLocal("test", zap.NewDevelopmentEncoderConfig())
	pt := &noopProgressDescriber{}
	var agentID agentInfo = "testID"

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := tc.getServer()
			defer server.Close()

			cfg := &configuration.Configuration{
				Fleet: &configuration.FleetAgentConfig{
					AccessAPIKey: "example-key",
					Client: remote.Config{
						Protocol: remote.ProtocolHTTP,
						Host:     server.URL,
					},
				},
			}
			err := notifyFleetAuditUninstall(context.Background(), log, pt, cfg, &agentID)
			if tc.err == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.err.Error())
			}
		})
	}

	t.Run("fails with no retries", func(t *testing.T) {
		fleetAuditAttempts = 1
		t.Cleanup(func() {
			fleetAuditAttempts = 10
		})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		cfg := &configuration.Configuration{
			Fleet: &configuration.FleetAgentConfig{
				AccessAPIKey: "example-key",
				Client: remote.Config{
					Protocol: remote.ProtocolHTTP,
					Host:     server.URL,
				},
			},
		}
		err := notifyFleetAuditUninstall(context.Background(), log, pt, cfg, &agentID)
		assert.EqualError(t, err, "notify Fleet: failed")

	})
}

type MockNotifyFleetAuditUninstall struct {
	Called bool
}

func (m *MockNotifyFleetAuditUninstall) Call(ctx context.Context, log *logp.Logger, pt ProgressDescriber, cfg *configuration.Configuration, ai pkgfleetapi.AgentInfo) {
	m.Called = true
}

func TestSkipFleetAuditUnenroll(t *testing.T) {
	log := &logp.Logger{}
	pt := &noopProgressDescriber{}
	cfg := &configuration.Configuration{}
	var agentID agentInfo = "testID"

	testCases := []struct {
		notifyFleet    bool
		localFleet     bool
		skipFleetAudit bool
	}{
		{true, true, true},
		{true, true, false},
		{true, false, true},
		{false, true, true},
		{false, true, false},
		{false, false, true},
		{false, false, false},
	}

	for i, tc := range testCases {
		t.Run(
			fmt.Sprintf("test case #%d: %t:%t:%t", i, tc.notifyFleet, tc.localFleet, tc.skipFleetAudit),
			func(t *testing.T) {
				mockNotify := &MockNotifyFleetAuditUninstall{}
				notifyFleetIfNeeded(context.Background(), log, pt, cfg, agentID, tc.notifyFleet, tc.localFleet, tc.skipFleetAudit, notifyFleetAuditUninstall)
				assert.False(t, mockNotify.Called, "NotifyFleetAuditUninstall should not be invoked when notifyFleet: %t - localFleet: %t - skipFleetAudit: %t", tc.notifyFleet, tc.localFleet, tc.skipFleetAudit)
			},
		)
	}

}

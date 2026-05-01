// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/testing/certutil"
	"github.com/elastic/elastic-agent-libs/testing/proxytest"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

// TestPolicyChangePersistsWithoutAck verifies that an agent enrolled in a
// policy with disable_policy_change_acks=true reports the applied policy id
// and revision in subsequent checkin requests.
//
// Without persisting the POLICY_CHANGE action in the state store when acks
// are disabled, the fleet gateway has no action to read on the next checkin
// and the agent reports an empty agent_policy_id with policy_revision_idx=0,
// which leaves Fleet's view of the agent stuck at the pre-policy state. See
// https://github.com/elastic/kibana/issues/264983
func TestPolicyChangePersistsWithoutAck(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
	})

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(15*time.Minute))
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	proxyCAKey, proxyCACert, _, err := certutil.NewRootCA()
	require.NoError(t, err, "creating proxy CA")

	var (
		mu                sync.Mutex
		latestPolicyID    string
		latestRevisionIdx int64
		checkinCount      int
	)
	proxy := proxytest.New(
		t,
		proxytest.WithRequestLog("policy-change-no-ack", t.Logf),
		proxytest.WithMITMCA(proxyCAKey, proxyCACert),
		proxytest.WithServerTLSConfig(&tls.Config{}),
		proxytest.WithVerifyRequest(func(r *http.Request) error {
			if !isAgentCheckinRequest(r) {
				return nil
			}
			body, err := readCheckinBody(r)
			if err != nil {
				t.Logf("failed to read checkin body: %v", err)
				return nil
			}
			var req struct {
				AgentPolicyID     string `json:"agent_policy_id"`
				PolicyRevisionIDX int64  `json:"policy_revision_idx"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				t.Logf("failed to decode checkin body: %v", err)
				return nil
			}
			mu.Lock()
			checkinCount++
			if req.AgentPolicyID != "" {
				latestPolicyID = req.AgentPolicyID
			}
			if req.PolicyRevisionIDX > latestRevisionIdx {
				latestRevisionIdx = req.PolicyRevisionIDX
			}
			mu.Unlock()
			return nil
		}),
	)
	require.NoError(t, proxy.Start(), "starting proxy")
	t.Cleanup(proxy.Close)

	createPolicyReq := kibana.AgentPolicy{
		Name:        fmt.Sprintf("test-policy-no-ack-%s", uuid.Must(uuid.NewV4()).String()),
		Namespace:   info.Namespace,
		Description: "test policy for policy_change persistence without ack",
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
		AgentFeatures: []map[string]interface{}{
			{
				"name":    "disable_policy_change_acks",
				"enabled": true,
			},
		},
	}

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Insecure:       true,
		ProxyURL:       proxy.LocalhostURL,
	}

	policy, agentID, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, agentFixture, info.KibanaClient, createPolicyReq)
	require.NoError(t, err)
	t.Logf("created policy %s, enrolled agent %s", policy.ID, agentID)

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		assert.NoError(t, fleettools.UnEnrollAgent(cleanupCtx, info.KibanaClient, agentID))
	})

	check.ConnectedToFleet(ctx, t, agentFixture, 5*time.Minute)

	// After the first POLICY_CHANGE has been applied, every subsequent checkin
	// should carry the agent's policy_id and policy_revision_idx because the
	// handler persists the action in the state store regardless of the ack
	// flag. Without the fix, the gateway sees no persisted action and the
	// fields remain at their zero values.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		mu.Lock()
		gotPolicyID := latestPolicyID
		gotRevision := latestRevisionIdx
		seen := checkinCount
		mu.Unlock()

		assert.Greater(c, seen, 0, "no checkin requests observed through proxy yet")
		assert.Equal(c, policy.ID, gotPolicyID,
			"agent did not report agent_policy_id in any checkin; "+
				"the POLICY_CHANGE action was likely not persisted in the state store when acks are disabled")
		assert.Greater(c, gotRevision, int64(0),
			"agent did not report a non-zero policy_revision_idx in any checkin; "+
				"the POLICY_CHANGE action was likely not persisted in the state store when acks are disabled")
	}, 5*time.Minute, 5*time.Second)
}

// readCheckinBody reads the body from a checkin request, decompressing it if
// necessary, and restores r.Body so the proxy can forward the request.
func readCheckinBody(r *http.Request) ([]byte, error) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if cerr := r.Body.Close(); cerr != nil {
		return nil, fmt.Errorf("close body: %w", cerr)
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))

	if !strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		return raw, nil
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()
	decompressed, err := io.ReadAll(gz)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	return decompressed, nil
}

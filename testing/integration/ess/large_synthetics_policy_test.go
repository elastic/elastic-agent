// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

const (
	// syntheticsBatchSize is intentionally larger than the @elastic/synthetics CLI
	// default of 250 (src/push/kibana_api.ts) to reduce the number of round-trips
	// when seeding 10 000 monitors. The Kibana project API accepts up to 1 500
	// lightweight monitors per request.
	syntheticsBatchSize = 1000

	numHTTPMonitors = 8000
	numICMPMonitors = 1000
	numTCPMonitors  = 1000
)

// TestLargeSyntheticsPolicy verifies that an elastic-agent can enroll into and
// stay healthy under a Fleet policy that contains 10 000 synthetic monitors
// (8 000 HTTP + 1 000 TCP + 1 000 ICMP) on a single private location.
func TestLargeSyntheticsPolicy(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{
			KibanaMemoryMB: 4096,
		},
		Local: false,
		Sudo:  true,
	})

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(30*time.Minute))
	defer cancel()

	// 1. Start a local HTTP server. All three monitor types target it so it must
	//    remain alive for the duration of the test.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Hello, World!")
	}))
	t.Cleanup(ts.Close)

	tsURL, err := url.Parse(ts.URL)
	require.NoError(t, err)
	tsHost := tsURL.Hostname()
	tsPort := tsURL.Port()

	// 2. Create a Fleet agent policy.
	uid := uuid.Must(uuid.NewV4()).String()
	policyResp, err := info.KibanaClient.CreatePolicy(ctx, kibana.AgentPolicy{
		Name:        fmt.Sprintf("test-large-synthetics-%s", uid),
		Namespace:   info.Namespace,
		Description: "large synthetics policy test",
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	})
	require.NoError(t, err)
	t.Logf("created Fleet policy %s", policyResp.ID)

	// 3. Create a Synthetics private location backed by the Fleet policy.
	locationLabel := fmt.Sprintf("test-location-%s", uid)
	privLocID, err := createSyntheticsPrivateLocation(ctx, info.KibanaClient, locationLabel, policyResp.ID)
	require.NoError(t, err)
	t.Logf("created private location %s (label: %s)", privLocID, locationLabel)

	// 4. Push 10 000 monitors to the private location in batches.
	projectName := fmt.Sprintf("large-policy-test-%s", uid)
	monitors := buildSyntheticsMonitors(tsHost, tsPort, locationLabel)
	t.Logf("pushing %d monitors in batches of %d", len(monitors), syntheticsBatchSize)
	require.NoError(t, bulkPushSyntheticsMonitors(ctx, t, info.KibanaClient, projectName, monitors))
	t.Logf("pushed %d monitors", len(monitors))

	// 5. Install the agent enrolled into the policy.
	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	agentID, err := tools.InstallAgentForPolicy(ctx, t, atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     true,
	}, agentFixture, info.KibanaClient, policyResp.ID)
	require.NoError(t, err)
	t.Logf("enrolled agent %s", agentID)

	// 6. Wait for the agent to connect to Fleet and for every component to
	//    reach the HEALTHY state.
	check.ConnectedToFleet(ctx, t, agentFixture, 10*time.Minute)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := agentFixture.ExecStatus(ctx)
		require.NoError(c, err)
		require.NotEmpty(c, status.Components, "expected at least one component")
		for _, comp := range status.Components {
			assert.Equalf(c, int(cproto.State_HEALTHY), comp.State, "component %s not healthy", comp.Name)
		}
		t.Logf("agent healthy with %d components", len(status.Components))
	}, 10*time.Minute, 10*time.Second, "agent did not reach fully healthy state")
}

// --- Kibana Synthetics API helpers ---

type syntheticsPrivateLocationResp struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	AgentPolicyID string `json:"agentPolicyId"`
}

func createSyntheticsPrivateLocation(ctx context.Context, client *kibana.Client, label, policyID string) (string, error) {
	body, err := json.Marshal(map[string]string{
		"label":         label,
		"agentPolicyId": policyID,
	})
	if err != nil {
		return "", fmt.Errorf("marshaling private location request: %w", err)
	}

	headers := http.Header{"Content-Type": []string{"application/json"}}
	resp, err := client.SendWithContext(ctx, http.MethodPost, "/api/synthetics/private_locations", nil, headers, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("sending private location request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading private location response: %w", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("private location API returned %d: %s", resp.StatusCode, respBody)
	}

	var loc syntheticsPrivateLocationResp
	if err := json.Unmarshal(respBody, &loc); err != nil {
		return "", fmt.Errorf("decoding private location response: %w", err)
	}
	return loc.ID, nil
}

type syntheticsMonitorSchema struct {
	ID               string   `json:"id"`
	Type             string   `json:"type"`
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	Schedule         int      `json:"schedule"` // minutes; project API accepts a plain integer
	PrivateLocations []string `json:"privateLocations"`
	URLs             string   `json:"urls,omitempty"`
	Hosts            string   `json:"hosts,omitempty"`
}

type syntheticsBulkPutRequest struct {
	Monitors []syntheticsMonitorSchema `json:"monitors"`
}

type syntheticsBulkPutResponse struct {
	CreatedMonitors []any `json:"createdMonitors"`
	UpdatedMonitors []any `json:"updatedMonitors"`
	FailedMonitors  []struct {
		ID      string          `json:"id"`
		Reason  string          `json:"reason"`
		Details string          `json:"details"`
		Payload json.RawMessage `json:"payload,omitempty"`
	} `json:"failedMonitors"`
}

func buildSyntheticsMonitors(host, port, locationLabel string) []syntheticsMonitorSchema {
	total := numHTTPMonitors + numICMPMonitors + numTCPMonitors
	monitors := make([]syntheticsMonitorSchema, 0, total)

	for i := range numHTTPMonitors {
		path := uuid.Must(uuid.NewV4()).String()
		monitors = append(monitors, syntheticsMonitorSchema{
			ID:               fmt.Sprintf("http-monitor-%d", i),
			Type:             "http",
			Name:             fmt.Sprintf("HTTP Monitor %d", i),
			Enabled:          true,
			Schedule:         1,
			PrivateLocations: []string{locationLabel},
			URLs:             fmt.Sprintf("http://%s:%s/%s", host, port, path),
		})
	}

	for i := range numTCPMonitors {
		monitors = append(monitors, syntheticsMonitorSchema{
			ID:               fmt.Sprintf("tcp-monitor-%d", i),
			Type:             "tcp",
			Name:             fmt.Sprintf("TCP Monitor %d", i),
			Enabled:          true,
			Schedule:         1,
			PrivateLocations: []string{locationLabel},
			Hosts:            fmt.Sprintf("%s:%s", host, port),
		})
	}

	for i := range numICMPMonitors {
		monitors = append(monitors, syntheticsMonitorSchema{
			ID:               fmt.Sprintf("icmp-monitor-%d", i),
			Type:             "icmp",
			Name:             fmt.Sprintf("ICMP Monitor %d", i),
			Enabled:          true,
			Schedule:         1,
			PrivateLocations: []string{locationLabel},
			Hosts:            host,
		})
	}

	return monitors
}

// bulkPushSyntheticsMonitors uploads monitors to the Synthetics project API in
// batches of syntheticsBatchSize with a short inter-batch pause to avoid
// overwhelming the server.
func bulkPushSyntheticsMonitors(ctx context.Context, t *testing.T, client *kibana.Client, projectName string, monitors []syntheticsMonitorSchema) error {
	apiURL := fmt.Sprintf("/api/synthetics/project/%s/monitors/_bulk_update", projectName)
	headers := http.Header{"Content-Type": []string{"application/json"}}

	for start := 0; start < len(monitors); start += syntheticsBatchSize {
		end := min(start+syntheticsBatchSize, len(monitors))
		batchNum := start / syntheticsBatchSize

		reqBody, err := json.Marshal(syntheticsBulkPutRequest{Monitors: monitors[start:end]})
		if err != nil {
			return fmt.Errorf("marshaling batch %d: %w", batchNum, err)
		}

		t.Logf("pushing batch %d (%d-%d of %d)", batchNum, start, end, len(monitors))
		if err := sendBatchWithRetry(ctx, t, client, apiURL, headers, reqBody, batchNum); err != nil {
			return err
		}
	}
	return nil
}

// sendBatchWithRetry sends a single batch to the Kibana Synthetics API. On
// transient failures (network error, 429, 5xx) it retries with exponential
// backoff (15s base, 2× multiplier, 5 min cap, 10 attempts).
func sendBatchWithRetry(ctx context.Context, t *testing.T, client *kibana.Client, apiURL string, headers http.Header, reqBody []byte, batchNum int) error {
	const (
		maxAttempts = 10
		baseDelay   = 15 * time.Second
		maxDelay    = 5 * time.Minute
	)
	var lastErr error
	delay := baseDelay
	for attempt := range maxAttempts {
		if attempt > 0 {
			t.Logf("batch %d: attempt %d failed (%v); backing off %s", batchNum, attempt, lastErr, delay)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			delay = min(delay*2, maxDelay)
		}

		resp, err := client.SendWithContext(ctx, http.MethodPut, apiURL, nil, headers, bytes.NewReader(reqBody))
		if err != nil {
			lastErr = fmt.Errorf("network error: %w", err)
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("reading response: %w", err)
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("status %d: %s", resp.StatusCode, respBody)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("batch %d returned %d: %s", batchNum, resp.StatusCode, respBody)
		}

		var putResp syntheticsBulkPutResponse
		if err := json.Unmarshal(respBody, &putResp); err != nil {
			return fmt.Errorf("decoding batch %d response: %w", batchNum, err)
		}
		if len(putResp.FailedMonitors) > 0 {
			first := putResp.FailedMonitors[0]
			return fmt.Errorf("batch %d: %d monitors failed; first: id=%s reason=%q details=%q",
				batchNum, len(putResp.FailedMonitors), first.ID, first.Reason, first.Details)
		}
		return nil
	}
	return fmt.Errorf("batch %d: max retries exceeded; last error: %w", batchNum, lastErr)
}

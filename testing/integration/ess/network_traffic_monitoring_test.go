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
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/testing/integration"
)

type NetworkTrafficRunner struct {
	suite.Suite
	info         *define.Info
	agentFixture *atesting.Fixture

	ESHost     string
	policyID   string
	policyName string
}

func TestNetworkTraffic(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Windows},
		},
		// The network_traffic Fleet integration relies on packetbeat, which
		// has no windows/arm64 build, so the agent component never reaches
		// HEALTHY on this combination.
		SkipOS: []define.OS{{Type: define.Windows, Arch: define.ARM64}},
	})

	suite.Run(t, &NetworkTrafficRunner{info: info})
}

func (runner *NetworkTrafficRunner) SetupSuite() {
	fixture, err := define.NewFixtureFromLocalBuild(runner.T(), define.Version())
	require.NoError(runner.T(), err)
	runner.agentFixture = fixture

	policyUUID := uuid.Must(uuid.NewV4()).String()
	basePolicy := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   runner.info.Namespace,
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	policyResp, _, err := tools.InstallAgentWithPolicy(ctx, runner.T(), installOpts, runner.agentFixture, runner.info.KibanaClient, basePolicy)
	require.NoError(runner.T(), err)

	runner.policyID = policyResp.ID
	runner.policyName = policyResp.Name
	runner.ESHost = os.Getenv("ELASTICSEARCH_HOST")

	packageFile := filepath.Join("testdata", "network_traffic_package.json")
	_, err = tools.InstallPackageFromDefaultFile(ctx, runner.info.KibanaClient, "network_traffic",
		integration.PreinstalledPackages["network_traffic"], packageFile, uuid.Must(uuid.NewV4()).String(), policyResp.ID)
	require.NoError(runner.T(), err)

}

func (runner *NetworkTrafficRunner) switchToOtelRuntime() {
	body := fmt.Sprintf(`
{
  "name": "%s",
  "namespace": "%s",
  "overrides": {
    "agent": {
      "internal": {
        "runtime": {
          "default": "otel"
        }
      }
    }
  }
}
`, runner.policyName, runner.info.Namespace)
	resp, err := runner.info.KibanaClient.Send(
		http.MethodPut,
		fmt.Sprintf("/api/fleet/agent_policies/%s", runner.policyID),
		nil,
		nil,
		bytes.NewBufferString(body),
	)
	if err != nil {
		runner.T().Fatalf("could not execute request to Kibana/Fleet: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		runner.T().Errorf("received a non 200-OK when adding overwrite to policy. "+
			"Status code: %d", resp.StatusCode)
		respDump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			runner.T().Fatalf("could not dump error response from Kibana: %s", err)
		}
		runner.T().Log("================================================================================")
		runner.T().Log("Kibana error response:")
		runner.T().Log(string(respDump))
		runner.T().FailNow()
	}
}

// extractESHostname returns just the hostname portion of an ES URL like
// "https://xxxx.es.elastic-cloud.com:9243".
func extractESHostname(esURL string) string {
	u, err := url.Parse(esURL)
	if err != nil || u.Hostname() == "" {
		return esURL
	}
	return u.Hostname()
}

// triggerFreshTLSConnection opens a single short-lived HTTPS connection to the
// ES endpoint. Using DisableKeepAlives forces a new TCP connection (and
// therefore a new TLS handshake) each call, which packetbeat can capture in
// full once the receiver is running.
func triggerFreshTLSConnection(ctx context.Context, t *testing.T, esHost string) {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
		Timeout:   15 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, esHost, nil)
	if err != nil {
		t.Logf("triggerFreshTLSConnection: could not build request: %v", err)
		return
	}
	if u := os.Getenv("ELASTICSEARCH_USERNAME"); u != "" {
		req.SetBasicAuth(u, os.Getenv("ELASTICSEARCH_PASSWORD"))
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Logf("triggerFreshTLSConnection: request failed (non-fatal): %v", err)
		return
	}
	resp.Body.Close()
}

// validateNetworkTrafficEvents polls ES until a fully-captured TLS handshake
// event appears (tls.established:true) for the given agent, destination, and
// time window. retrigger is called before each ES poll so that fresh TCP+TLS
// connections are made throughout the wait period — this handles the race where
// pbreceiver's libpcap is not yet capturing when the first trigger fires.
func (runner *NetworkTrafficRunner) validateNetworkTrafficEvents(ctx context.Context, t *testing.T, agentID string, afterTime time.Time, destDomain string, retrigger func()) mapstr.M {
	t.Helper()

	now := time.Now()
	var query map[string]any
	var doc mapstr.M
	defer func() {
		if t.Failed() {
			bs, err := json.Marshal(query)
			if err != nil {
				t.Errorf("executed at %s: %v",
					now.Format(time.RFC3339Nano), query)
				return
			}
			t.Errorf("executed at %s: query: %s",
				now.Format(time.RFC3339Nano), string(bs))
		}
	}()

	t.Logf("starting to query ES for network traffic events at %s (after=%s dest=%s)",
		now.Format(time.RFC3339Nano), afterTime.UTC().Format(time.RFC3339Nano), destDomain)
	require.Eventually(t, func() bool {
		now = time.Now()
		if retrigger != nil {
			retrigger()
		}
		// Require a fully captured handshake (both ClientHello and ServerHello
		// seen by packetbeat), scoped to the ES endpoint and only connections
		// opened after afterTime. This avoids matching partial captures caused
		// by the receiver starting after the exporter's TLS handshake completes,
		// and avoids cross-contamination between process-mode and OTel-mode runs.
		query = map[string]any{
			"query": map[string]any{
				"bool": map[string]any{
					"must": []map[string]any{
						{"match": map[string]any{"agent.id": agentID}},
						{"exists": map[string]any{"field": "tls.client.server_name"}},
						{"term": map[string]any{"tls.established": true}},
						{"term": map[string]any{"destination.domain": destDomain}},
						{"range": map[string]any{"event.start": map[string]any{
							"gte": afterTime.UTC().Format(time.RFC3339Nano),
						}}},
					},
				},
			},
		}
		res, err := estools.PerformQueryForRawQuery(ctx, query, "logs-network_traffic.tls*", runner.info.ESClient)
		require.NoError(t, err)
		if res.Hits.Total.Value < 1 {
			return false
		}
		doc = res.Hits.Hits[0].Source
		return true
	}, time.Minute*10, time.Second*10, "could not fetch events for network_traffic")
	return doc
}

func (runner *NetworkTrafficRunner) TestBeatsMetrics() {
	t := runner.T()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*20)
	defer cancel()

	agentStatus, err := runner.agentFixture.ExecStatus(ctx)
	require.NoError(t, err, "could not get agent status")

	esHostname := extractESHostname(runner.ESHost)
	require.NotEmpty(t, esHostname, "could not determine ES hostname from ELASTICSEARCH_HOST")

	// Validate process mode
	var processDoc mapstr.M
	t.Run("process", func(t *testing.T) {
		captureStart := time.Now()
		processDoc = runner.validateNetworkTrafficEvents(ctx, t, agentStatus.Info.ID, captureStart, esHostname,
			func() { triggerFreshTLSConnection(ctx, t, runner.ESHost) })
	})

	// Switch to OTel runtime and validate the same data
	var otelDoc mapstr.M
	t.Run("otel", func(t *testing.T) {
		// captureStart is set before the policy switch so that the OTel exporter's
		// initial TLS connections to ES — captured by pbreceiver as the pipeline
		// starts — fall within the query window. pbreceiver in-process cannot
		// capture connections from the test binary (privilege boundary), so we
		// rely on the exporter's natural traffic rather than a synthetic trigger.
		captureStart := time.Now()

		runner.switchToOtelRuntime()

		// Wait for the agent to pick up the new policy and become healthy.
		require.Eventually(t, func() bool {
			err := runner.agentFixture.IsHealthy(ctx)
			if err != nil {
				t.Logf("waiting for agent healthy after otel switch: %s", err.Error())
				return false
			}
			return true
		}, 2*time.Minute, 5*time.Second)

		otelDoc = runner.validateNetworkTrafficEvents(ctx, t, agentStatus.Info.ID, captureStart, esHostname, nil)
	})

	// Compare documents from process and otel modes have the same keys
	t.Run("compare", func(t *testing.T) {
		if processDoc == nil || otelDoc == nil {
			t.Skip("skipping comparison because a previous subtest failed")
		}
		// tls.detailed.resumption_method is present only for resumed TLS sessions;
		// whether a session is resumed depends on the TLS session cache state at
		// the time of the triggered connection and is non-deterministic across runs.
		// event.duration / event.end depend on connection close timing and are a
		// known structural difference between process and OTel beat-receiver modes
		// (see beat_receivers_test.go).
		ignoredFields := append(RuntimeComparisonIgnoredFields,
			"event.duration",
			"event.end",
			"tls.detailed.resumption_method",
		)
		AssertMapstrKeysEqual(t, processDoc, otelDoc, ignoredFields, "expected network_traffic document keys to be equal between process and otel modes")
	})
}

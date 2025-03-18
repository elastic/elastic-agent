// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

// TestAgentMonitoring is a test to provide a baseline for what
// elastic-agent monitoring looks like with classic monitoring.  It
// will be expanded in the future to compare with beats receivers for
// elastic-agent monitoring.
func TestAgentMonitoring(t *testing.T) {
	// Flow
	// 1. Create and install policy with just monitoring
	// 2. Download the policy, add the API key
	// 3. Install without enrolling in fleet
	// 4. Make sure logs and metrics for agent monitoring are being received
	info := define.Require(t, define.Requirements{
		Group: Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
		Sudo:  true,
	})

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
	defer cancel()

	// 1. Create and install policy with just monitoring
	createPolicyReq := kibana.AgentPolicy{
		Name:        fmt.Sprintf("%s-%s", t.Name(), uuid.Must(uuid.NewV4()).String()),
		Namespace:   info.Namespace,
		Description: fmt.Sprintf("%s policy", t.Name()),
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}
	policyResponse, err := info.KibanaClient.CreatePolicy(ctx, createPolicyReq)
	require.NoError(t, err, "error creating policy")

	// 2. Download the policy, add the API key
	downloadURL := fmt.Sprintf("/api/fleet/agent_policies/%s/download", policyResponse.ID)
	resp, err := info.KibanaClient.Connection.SendWithContext(ctx, http.MethodGet, downloadURL, nil, nil, nil)
	require.NoError(t, err, "error downloading policy")
	policy, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "error reading policy response")
	defer resp.Body.Close()

	apiKeyResponse, err := createESApiKey(info.ESClient)
	require.NoError(t, err, "failed to get api key")
	require.True(t, len(apiKeyResponse.Encoded) > 1, "api key is invalid %q", apiKeyResponse)
	apiKey, err := base64.StdEncoding.DecodeString(apiKeyResponse.Encoded)
	require.NoError(t, err, "error decoding api key")

	type PolicyOutputs struct {
		Type   string   `yaml:"type"`
		Hosts  []string `yaml:"hosts"`
		Preset string   `yaml:"preset"`
		ApiKey string   `yaml:"api_key"`
	}
	type PolicyStruct struct {
		ID                string                   `yaml:"id"`
		Revision          int                      `yaml:"revision"`
		Outputs           map[string]PolicyOutputs `yaml:"outputs"`
		Fleet             map[string]any           `yaml:"fleet"`
		OutputPermissions map[string]any           `yaml:"output_permissions"`
		Agent             map[string]any           `yaml:"agent"`
		Inputs            []map[string]any         `yaml:"inputs"`
		Signed            map[string]any           `yaml:"signed"`
		SecretReferences  []map[string]any         `yaml:"secret_references"`
		Namespaces        []map[string]any         `yaml:"namespaces"`
	}

	y := PolicyStruct{}
	err = yaml.Unmarshal(policy, &y)
	require.NoError(t, err, "error unmarshalling policy")
	d, prs := y.Outputs["default"]
	require.True(t, prs, "default must be in outputs")
	d.ApiKey = string(apiKey)
	y.Outputs["default"] = d
	policyBytes, err := yaml.Marshal(y)
	require.NoErrorf(t, err, "error marshalling policy, struct was %v", y)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("policy was %s", string(policyBytes))
		}
	})

	// 3. Install without enrolling in fleet
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Privileged:     true,
		Force:          true,
	}

	err = fixture.Prepare(ctx)
	require.NoError(t, err, "error preparing fixture")

	err = fixture.Configure(ctx, policyBytes)
	require.NoError(t, err, "error configuring fixture")

	output, err := fixture.InstallWithoutEnroll(ctx, &installOpts)
	require.NoErrorf(t, err, "error install withouth enroll: %s\ncombinedoutput:\n%s", err, string(output))

	require.Eventually(t, func() bool {
		err = fixture.IsHealthy(ctx)
		if err != nil {
			t.Logf("waiting for agent healthy: %s", err.Error())
			return false
		}
		return true
	}, 1*time.Minute, 1*time.Second)

	// 4. Make sure logs and metrics for agent monitoring are being received
	type test struct {
		dsType      string
		dsDataset   string
		dsNamespace string
	}

	tests := []test{
		{dsType: "logs", dsDataset: "elastic_agent", dsNamespace: info.Namespace},
		{dsType: "metrics", dsDataset: "elastic_agent.elastic_agent", dsNamespace: info.Namespace},
		{dsType: "metrics", dsDataset: "elastic_agent.filebeat", dsNamespace: info.Namespace},
		{dsType: "metrics", dsDataset: "elastic_agent.metricbeat", dsNamespace: info.Namespace},
	}

	for _, tc := range tests {
		require.Eventuallyf(t,
			func() bool {
				findCtx, findCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer findCancel()
				rawQuery := map[string]any{
					"query": map[string]any{
						"bool": map[string]any{
							"must": []map[string]any{
								{
									"match": map[string]any{"data_stream.type": tc.dsType},
								},
								{
									"match": map[string]any{"data_stream.dataset": tc.dsDataset},
								},
								{
									"match": map[string]any{"data_stream.namespace": tc.dsNamespace},
								},
							},
						},
					},
				}
				docs, err := estools.PerformQueryForRawQuery(findCtx, rawQuery, tc.dsType+"-*", info.ESClient)
				require.NoError(t, err)
				return docs.Hits.Total.Value > 0
			},
			2*time.Minute, 5*time.Second,
			"No documents found for type: %s, dataset: %s, namespace: %s", tc.dsType, tc.dsDataset, tc.dsNamespace)
	}
}

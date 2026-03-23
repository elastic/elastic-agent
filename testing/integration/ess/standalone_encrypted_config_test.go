// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/testing/estools"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/installtest"
	"github.com/elastic/elastic-agent/testing/integration"
)

func TestStandaloneEncyptedConfigInstall(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()

	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	err = fixture.Configure(ctx, []byte(`agent:
  features:
    encrypted_config:
      enabled: true
  logging:
    level: debug
`))
	require.NoError(t, err)

	opts := atesting.InstallOpts{Force: true, Privileged: true}
	out, err := fixture.Install(ctx, &opts)
	require.NoErrorf(t, err, "install failed, output: %s", string(out))

	topPath := installtest.DefaultTopPath()
	_, err = os.Stat(filepath.Join(topPath, "fleet.enc"))
	require.NoError(t, err, "expected fleet.enc to be created")
	p, err := os.ReadFile(filepath.Join(topPath, "elastic-agent.yml"))
	require.NoError(t, err, "unable to read elastic-agent.yml file")
	require.EqualValues(t, storage.DefaultAgentEncryptedStandaloneConfig, p, "unexpected contents in elastic-agent.yml")
	require.NoError(t, checkNoBakFile(topPath))
	t.Log("Install test success")

	t.Log("Create standalone policy with API key")
	polResp, err := info.KibanaClient.CreatePolicy(ctx, defaultPolicy())
	require.NoError(t, err, "unable to create policy")
	standaloneParams := url.Values{}
	standaloneParams.Set("standalone", "true")
	downloadPolResp, err := info.KibanaClient.SendWithContext(ctx, http.MethodGet, fmt.Sprintf("/api/fleet/agent_policies/%s/download", polResp.ID), standaloneParams, nil, nil)
	require.NoError(t, err, "Unable to download policy")
	defer downloadPolResp.Body.Close()

	apiKeyResponse, err := estools.CreateAPIKey(t.Context(), info.ESClient, estools.APIKeyRequest{Name: "test-api-key", Expiration: "1d"})
	require.NoError(t, err, "failed to get api key")
	require.True(t, len(apiKeyResponse.Encoded) > 1, "api key is invalid %q", apiKeyResponse)
	apiKey, err := getDecodedApiKey(apiKeyResponse)
	require.NoError(t, err, "error decoding api key")

	type PolicyOutput struct {
		Type   string   `yaml:"type"`
		Hosts  []string `yaml:"hosts"`
		Preset string   `yaml:"preset"`
		ApiKey string   `yaml:"api_key"`
	}
	type Policy struct {
		ID                string                   `yaml:"id"`
		Revision          int                      `yaml:"revision"`
		Outputs           map[string]*PolicyOutput `yaml:"outputs"`
		OutputPermissions map[string]any           `yaml:"output_permissions"`
		Agent             struct {
			Download   map[string]any `yaml:"download"`
			Monitoring map[string]any `yaml:"monitoring"`
			Features   struct {
				EncryptedConfig struct {
					Enabled bool `yaml:"enabled"`
				} `yaml:"encrypted_config"`
			} `yaml:"features"`
		} `yaml:"agent"`
		Inputs           []map[string]any `yaml:"inputs"`
		SecretReferences []map[string]any `yaml:"secret_references"`
		Namespaces       []string         `yaml:"namespaces"`
	}
	policy := Policy{}
	polBytes, err := io.ReadAll(downloadPolResp.Body)
	require.NoError(t, err)
	err = yaml.Unmarshal(polBytes, &policy)
	require.NoError(t, err)
	require.Contains(t, policy.Outputs, "default")
	policy.Outputs["default"].ApiKey = apiKey

	t.Run("config reload at start", func(t *testing.T) {
		t.Log("Replace elastic-agent.yml")
		policy.Agent.Features.EncryptedConfig.Enabled = true
		polBytes, err := yaml.Marshal(&policy)
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(topPath, "elastic-agent.yml"), polBytes, 0640)
		require.NoError(t, err)

		t.Log("Restart agent")
		err = fixture.ExecRestart(ctx)
		require.NoError(t, err)

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			status, err := fixture.ExecStatus(ctx)
			assert.NoError(c, err)
			assert.Equal(c, int(cproto.State_HEALTHY), status.State, "Expected healthy status")
			assert.Len(c, status.Components, 3, "unexpected number of components") // Current components are all monitoring related:  beat/metrics-monitoring, filestream-monitoring, http/metrics-monitoring
		}, time.Minute, time.Second)

		_, err = os.Stat(filepath.Join(topPath, "fleet.enc"))
		assert.NoError(t, err, "expected fleet.enc to be created")
		p, err := os.ReadFile(filepath.Join(topPath, "elastic-agent.yml"))
		assert.NoError(t, err, "unable to read elastic-agent.yml file")
		assert.EqualValues(t, storage.DefaultAgentEncryptedStandaloneConfig, p, "unexpected contents in elastic-agent.yml")
		assert.NoError(t, checkNoBakFile(topPath))
	})

	t.Run("disable encryption", func(t *testing.T) {
		t.Log("Replace elastic-agent.yml")
		policy.Agent.Features.EncryptedConfig.Enabled = false
		polBytes, err := yaml.Marshal(&policy)
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(topPath, "elastic-agent.yml"), polBytes, 0640)
		require.NoError(t, err)

		t.Log("Restart agent")
		err = fixture.ExecRestart(ctx)
		require.NoError(t, err)

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			status, err := fixture.ExecStatus(ctx)
			assert.NoError(c, err)
			assert.Equal(c, int(cproto.State_HEALTHY), status.State, "Expected healthy status")
			assert.Len(c, status.Components, 3, "unexpected number of components") // Current components are all monitoring related:  beat/metrics-monitoring, filestream-monitoring, http/metrics-monitoring
		}, time.Minute, time.Second)

		p, err := os.ReadFile(filepath.Join(topPath, "elastic-agent.yml"))
		assert.NoError(t, err, "unable to read elastic-agent.yml file")
		assert.EqualValues(t, polBytes, p, "unexpected contents in elastic-agent.yml")
		assert.NoError(t, checkNoBakFile(topPath))
	})
}

func checkNoBakFile(path string) error {
	return filepath.WalkDir(path, func(dir string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(d.Name(), ".bak") {
			return fmt.Errorf("backup file detected: %s", d.Name())
		}
		return nil
	})
}

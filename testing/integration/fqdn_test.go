// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.
//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/kibana"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestFQDN(t *testing.T) {
	info := define.Require(t, define.Requirements{
		OS: []define.OS{
			{Type: define.Linux},
		},
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
	})

	suite.Run(t, &FQDN{requirementsInfo: info})
}

type FQDN struct {
	suite.Suite
	requirementsInfo *define.Info
	agentFixture     *atesting.Fixture

	externalIP       string
	originalHostname string
	originalEtcHosts []byte
}

// Before suite
func (s *FQDN) SetupSuite() {
	agentFixture, err := define.NewFixture(s.T(), define.Version())
	require.NoError(s.T(), err)
	s.agentFixture = agentFixture

	s.saveExternalIP()

	// Save original /etc/hosts so we can restore it at the end of each test
	s.saveOriginalEtcHosts(context.Background())

	// Save original hostname so we can restore it at the end of each test
	s.saveOriginalHostname(context.Background())
}

// After each test
func (s *FQDN) TearDownTest() {
	s.T().Log("Un-enrolling Elastic Agent...")
	assert.NoError(s.T(), tools.UnEnrollAgent(s.requirementsInfo.KibanaClient))

	s.T().Log("Restoring hostname...")
	s.restoreOriginalHostname(context.Background())

	s.T().Log("Restoring original /etc/hosts...")
	s.restoreOriginalEtcHosts()
}

func (s *FQDN) TestFQDN() {
	ctx := context.Background()
	kibClient := s.requirementsInfo.KibanaClient

	shortName := strings.ToLower(randStr(6))
	fqdn := shortName + ".baz.io"
	s.T().Logf("Set FQDN on host to %s", fqdn)
	s.setHostFQDN(ctx, s.externalIP, fqdn)

	// Fleet API requires the namespace to be lowercased and not contain
	// special characters.
	policyNamespace := strings.ToLower(s.requirementsInfo.Namespace)
	policyNamespace = regexp.MustCompile("[^a-zA-Z0-9]+").ReplaceAllString(policyNamespace, "")

	s.T().Log("Enroll agent in Fleet with a test policy")
	createPolicyReq := kibana.AgentPolicy{
		Name:        "test-policy-fqdn-" + strings.ReplaceAll(fqdn, ".", "-"),
		Namespace:   policyNamespace,
		Description: fmt.Sprintf("Test policy for FQDN E2E test (%s)", fqdn),
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
		AgentFeatures: []map[string]interface{}{
			{
				"name":    "fqdn",
				"enabled": false,
			},
		},
	}
	policy, err := tools.InstallAgentWithPolicy(s.T(), s.agentFixture, kibClient, s.requirementsInfo.ESClient, createPolicyReq)
	require.NoError(s.T(), err)

	s.T().Log("Verify that agent name is short hostname")
	agent := s.verifyAgentName(shortName)

	s.T().Log("Verify that hostname in `logs-*` and `metrics-*` is short hostname")
	s.verifyHostNameInIndices("logs-*", shortName)
	s.verifyHostNameInIndices("metrics-*", shortName)

	s.T().Log("Update Agent policy to enable FQDN")
	policy.AgentFeatures = []map[string]interface{}{
		{
			"name":    "fqdn",
			"enabled": true,
		},
	}
	updatePolicyReq := kibana.AgentPolicyUpdateRequest{
		Name:          policy.Name,
		Namespace:     policyNamespace,
		AgentFeatures: policy.AgentFeatures,
	}
	_, err = kibClient.UpdatePolicy(policy.ID, updatePolicyReq)
	require.NoError(s.T(), err)

	s.T().Log("Wait until policy has been applied by Agent")
	expectedAgentPolicyRevision := agent.PolicyRevision + 1
	require.Eventually(
		s.T(),
		tools.WaitForPolicyRevision(s.T(), kibClient, agent.ID, expectedAgentPolicyRevision),
		2*time.Minute,
		1*time.Second,
	)

	s.T().Log("Verify that agent name is FQDN")
	s.verifyAgentName(fqdn)

	s.T().Log("Verify that hostname in `logs-*` and `metrics-*` is FQDN")
	s.verifyHostNameInIndices("logs-*", fqdn)
	s.verifyHostNameInIndices("metrics-*", fqdn)

	s.T().Log("Update Agent policy to disable FQDN")
	policy.AgentFeatures = []map[string]interface{}{
		{
			"name":    "fqdn",
			"enabled": false,
		},
	}
	updatePolicyReq = kibana.AgentPolicyUpdateRequest{
		Name:          policy.Name,
		Namespace:     policyNamespace,
		AgentFeatures: policy.AgentFeatures,
	}
	_, err = kibClient.UpdatePolicy(policy.ID, updatePolicyReq)
	require.NoError(s.T(), err)

	s.T().Log("Wait until policy has been applied by Agent")
	expectedAgentPolicyRevision++
	require.Eventually(
		s.T(),
		tools.WaitForPolicyRevision(s.T(), kibClient, agent.ID, expectedAgentPolicyRevision),
		2*time.Minute,
		1*time.Second,
	)

	s.T().Log("Verify that agent name is short hostname again")
	s.verifyAgentName(shortName)

	s.T().Log("Verify that hostname in `logs-*` and `metrics-*` is short hostname again")
	s.verifyHostNameInIndices("logs-*", shortName)
	s.verifyHostNameInIndices("metrics-*", shortName)
}

func (s *FQDN) verifyAgentName(hostname string) *kibana.AgentExisting {
	var agent *kibana.AgentExisting
	var err error

	s.Require().Eventually(
		func() bool {
			agent, err = tools.GetAgentByHostnameFromList(s.requirementsInfo.KibanaClient, hostname)
			return err == nil && agent != nil
		},
		1*time.Minute,
		5*time.Second,
	)

	return agent
}

func (s *FQDN) verifyHostNameInIndices(indices, hostname string) {
	search := s.requirementsInfo.ESClient.Search

	s.Require().Eventually(
		func() bool {
			resp, err := search(
				search.WithIndex(indices),
				search.WithSort("@timestamp:desc"),
				search.WithFilterPath("hits.hits"),
				search.WithSize(1),
			)
			require.NoError(s.T(), err)
			require.False(s.T(), resp.IsError())
			defer resp.Body.Close()

			var body struct {
				Hits struct {
					Hits []struct {
						Source struct {
							Host struct {
								Name string `json:"name"`
							} `json:"host"`
						} `json:"_source"`
					} `json:"hits"`
				} `json:"hits"`
			}
			decoder := json.NewDecoder(resp.Body)
			err = decoder.Decode(&body)
			require.NoError(s.T(), err)

			require.Len(s.T(), body.Hits.Hits, 1)
			hit := body.Hits.Hits[0]
			return hostname == hit.Source.Host.Name
		},
		2*time.Minute,
		5*time.Second,
	)
}

func (s *FQDN) saveOriginalHostname(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "hostname")
	out, err := cmd.Output()
	s.Require().NoError(err)
	s.originalHostname = strings.TrimSpace(string(out))
}

func (s *FQDN) saveOriginalEtcHosts(ctx context.Context) {
	filename := string(filepath.Separator) + filepath.Join("etc", "hosts")
	etcHosts, err := os.ReadFile(filename)
	s.Require().NoError(err)

	s.originalEtcHosts = etcHosts
}

func (s *FQDN) setHostFQDN(ctx context.Context, externalIP, fqdn string) {
	filename := string(filepath.Separator) + filepath.Join("etc", "hosts")

	// Add entry for FQDN in /etc/hosts
	parts := strings.Split(fqdn, ".")
	shortName := parts[0]
	line := fmt.Sprintf("%s\t%s %s\n", externalIP, fqdn, shortName)

	etcHosts := append(s.originalEtcHosts, []byte(line)...)
	err := os.WriteFile(filename, etcHosts, 0644)
	s.Require().NoError(err)

	// Set hostname to FQDN
	cmd := exec.CommandContext(ctx, "hostname", shortName)
	output, err := cmd.Output()
	if err != nil {
		s.T().Log(string(output))
	}
	s.Require().NoError(err)
}

func (s *FQDN) restoreOriginalEtcHosts() {
	filename := string(filepath.Separator) + filepath.Join("etc", "hosts")
	err := os.WriteFile(filename, s.originalEtcHosts, 0644)
	s.Require().NoError(err)
}

func (s *FQDN) restoreOriginalHostname(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "hostname", s.originalHostname)
	output, err := cmd.Output()
	if err != nil {
		s.T().Log(string(output))
	}
	s.Require().NoError(err)
}

func (s *FQDN) saveExternalIP() {
	resp, err := http.Get("https://api.ipify.org")
	s.Require().NoError(err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)

	s.externalIP = strings.TrimSpace(string(body))
}

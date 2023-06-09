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

	externalIP string
	origFQDN   string
}

// Before suite
func (s *FQDN) SetupSuite() {
	agentFixture, err := define.NewFixture(s.T())
	require.NoError(s.T(), err)
	s.agentFixture = agentFixture

	externalIP, err := getExternalIP()
	require.NoError(s.T(), err)
	s.externalIP = externalIP
}

// Before each test
func (s *FQDN) SetupTest() {
	ctx := context.Background()

	// Save original hostname so we can restore it at the end of each test
	origFQDN, err := getHostFQDN(ctx)
	require.NoError(s.T(), err)
	s.origFQDN = origFQDN
}

func (s *FQDN) TearDownTest() {
	ctx := context.Background()

	// Restore original FQDN
	err := setHostFQDN(ctx, s.externalIP, s.origFQDN)
	require.NoError(s.T(), err)
}

func (s *FQDN) TestFQDN() {
	ctx := context.Background()
	kibClient := s.requirementsInfo.KibanaClient

	// Set FQDN on host
	shortName := randStr(6)
	fqdn := shortName + ".baz.io"
	err := setHostFQDN(ctx, s.externalIP, fqdn)
	require.NoError(s.T(), err)

	// Fleet API requires the namespace to be lowercased and not contain
	// special characters.
	policyNamespace := strings.ToLower(s.requirementsInfo.Namespace)
	policyNamespace = regexp.MustCompile("[^a-zA-Z0-9]+").ReplaceAllString(policyNamespace, "")
	s.T().Logf("Using policy namespace: %s", policyNamespace)

	// Enroll agent in Fleet with a test policy
	createPolicyReq := kibana.AgentPolicy{
		Name:        "test-policy-fqdn-" + strings.ReplaceAll(fqdn, ".", "-"),
		Namespace:   policyNamespace,
		Description: fmt.Sprintf("Test policy for FQDN E2E test (%s)", fqdn),
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}
	policy, err := tools.InstallAgentWithPolicy(s.T(), s.agentFixture, kibClient, createPolicyReq)
	require.NoError(s.T(), err)

	// Verify that agent name is short hostname
	agent, err := tools.GetAgentByHostnameFromList(kibClient, shortName)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), agent)

	// Verify that hostname in `logs-*` and `metrics-*` is short hostname
	s.verifyHostNameInIndices("logs-*", shortName)
	s.verifyHostNameInIndices("metrics-*", shortName)

	// Update Agent policy to enable FQDN
	policy.AgentFeatures = []map[string]interface{}{
		{
			"name":    "fqdn",
			"enabled": true,
		},
	}
	updatePolicyReq := kibana.AgentPolicyUpdateRequest{AgentFeatures: policy.AgentFeatures}
	_, err = kibClient.UpdatePolicy(policy.ID, updatePolicyReq)
	require.NoError(s.T(), err)

	// Wait until policy has been applied by Agent
	expectedAgentPolicyRevision := agent.PolicyRevision + 1
	require.Eventually(
		s.T(),
		tools.WaitForPolicyRevision(s.T(), kibClient, agent.ID, expectedAgentPolicyRevision),
		2*time.Minute,
		1*time.Second,
	)

	// Verify that agent name is FQDN
	agent, err = tools.GetAgentByHostnameFromList(kibClient, fqdn)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), agent)

	// Verify that hostname in `logs-*` and `metrics-*` is FQDN
	s.verifyHostNameInIndices("logs-*", fqdn)
	s.verifyHostNameInIndices("metrics-*", fqdn)

	// Update Agent policy to disable FQDN
	policy.AgentFeatures = []map[string]interface{}{
		{
			"name":    "fqdn",
			"enabled": false,
		},
	}
	updatePolicyReq = kibana.AgentPolicyUpdateRequest{AgentFeatures: policy.AgentFeatures}
	_, err = kibClient.UpdatePolicy(policy.ID, updatePolicyReq)
	require.NoError(s.T(), err)

	// Wait until policy has been applied by Agent
	expectedAgentPolicyRevision++
	require.Eventually(
		s.T(),
		tools.WaitForPolicyRevision(s.T(), kibClient, agent.ID, expectedAgentPolicyRevision),
		2*time.Minute,
		1*time.Second,
	)

	// Verify that agent name is short hostname again
	agent, err = tools.GetAgentByHostnameFromList(kibClient, shortName)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), agent)

	// Verify that hostname in `logs-*` and `metrics-*` is short hostname again
	s.verifyHostNameInIndices("logs-*", shortName)
	s.verifyHostNameInIndices("metrics-*", shortName)
}

func (s *FQDN) verifyHostNameInIndices(indices, hostname string) {
	search := s.requirementsInfo.ESClient.Search
	resp, err := search(
		search.WithIndex(indices),
		search.WithSort("@timestamp:desc"),
		search.WithFilterPath("hits.hits"),
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

	for _, hit := range body.Hits.Hits {
		assert.Equal(s.T(), hostname, hit.Source.Host.Name)
	}
}

func getHostFQDN(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "hostname", "--fqdn")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("unable to get FQDN: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}

func setHostFQDN(ctx context.Context, externalIP, fqdn string) error {
	// Check if FQDN is already set in /etc/hosts
	filename := string(filepath.Separator) + filepath.Join("etc", "hosts")
	etcHosts, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("unable to read /etc/hosts: %w", err)
	}

	lines := string(etcHosts)
	lines = strings.TrimSuffix(lines, "\n")
	for _, line := range strings.Split(lines, "\n") {
		if strings.Contains(line, fqdn) {
			// Desired fqdn is already set in /etc/hosts; nothing
			// more to do!
			return nil
		}
	}

	// Add entry for FQDN in /etc/hosts
	parts := strings.Split(fqdn, ".")
	shortName := parts[0]
	line := fmt.Sprintf("%s\t%s %s\n", externalIP, fqdn, shortName)

	etcHosts = append(etcHosts, []byte(line)...)
	if err := os.WriteFile(filename, etcHosts, 0644); err != nil {
		return fmt.Errorf("unable to write FQDN to /etc/hosts: %w", err)
	}

	// Set hostname to FQDN
	cmd := exec.CommandContext(ctx, "hostname", shortName)
	if _, err := cmd.Output(); err != nil {
		return fmt.Errorf("unable to set hostname to FQDN: %w", err)
	}

	return nil
}

func getExternalIP() (string, error) {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return "", fmt.Errorf("unable to determine IP: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to parse IP address: %w", err)
	}

	ip := string(body)
	ip = strings.TrimSpace(ip)

	return ip, nil
}

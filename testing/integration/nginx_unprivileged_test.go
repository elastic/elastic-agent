// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/estools"
)

var nginxStatusModule string = `

server {
  listen 81;
  server_name localhost;

  access_log off;
  allow 127.0.0.1;
  # deny all;

  location /nginx_status {
    # Choose your status module

    # freely available with open source NGINX
    stub_status;

    # for open source NGINX < version 1.7.5
    # stub_status on;

    # available only with NGINX Plus
    # status;

    # ensures the version information can be retrieved
    server_tokens on;
  }
}

`

// ExtendedRunner is the main test runner
type NginxUnprivilegedRunner struct {
	suite.Suite
	info                   *define.Info
	agentFixture           *atesting.Fixture
	policyID               string
	policyName             string
	healthCheckTime        time.Duration
	healthCheckRefreshTime time.Duration
}

func TestNginxUnprivileged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: "fleet",
		Stack: &define.Stack{},
		OS: []define.OS{
			{Type: define.Linux, Distro: "ubuntu"},
		},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	runner := &NginxUnprivilegedRunner{
		info:                   info,
		healthCheckTime:        time.Minute * 5,
		healthCheckRefreshTime: time.Second * 5,
	}

	suite.Run(t, runner)
}

func (runner *NginxUnprivilegedRunner) SetupSuite() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "apt-get", "install", "-v", "nginx-full")
	out, err := cmd.CombinedOutput()
	require.NoError(runner.T(), err, "error while installing nginx: %s", string(out))

	err = os.WriteFile("/etc/nginx/conf.d/status.conf", []byte(nginxStatusModule), 0750)
	require.NoError(runner.T(), err)

	cmd = exec.CommandContext(ctx, "nginx", "-s", "reload")
	out, err = cmd.CombinedOutput()
	require.NoError(runner.T(), err, "error while reloading nginx: %s", string(out))

	fixture, err := define.NewFixtureFromLocalBuild(runner.T(), define.Version())
	require.NoError(runner.T(), err)
	runner.agentFixture = fixture

	policyUUID := uuid.Must(uuid.NewV4()).String()
	basePolicy := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   "default",
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     false,
	}

	policyResp, err := tools.InstallAgentWithPolicy(ctx, runner.T(), installOpts, runner.agentFixture, runner.info.KibanaClient, basePolicy)
	require.NoError(runner.T(), err)

	runner.policyID = policyResp.ID
	runner.policyName = basePolicy.Name

	_, err = tools.InstallPackageFromDefaultFile(ctx, runner.info.KibanaClient, "nginx", "1.23.0", "nginx_integration_setup.json", uuid.Must(uuid.NewV4()).String(), policyResp.ID)
	require.NoError(runner.T(), err)
}

func (runner *NginxUnprivilegedRunner) TestComponentHealth() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*10)
	defer cancel()
	timer := time.NewTimer(time.Second * 60)
	defer timer.Stop()

	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()
	done := false
	for !done {
		select {
		case <-timer.C:
			done = true
		case <-ticker.C:
			err := runner.agentFixture.IsHealthy(ctx)
			require.NoError(runner.T(), err)
		}
	}

	query := map[string]interface{}{
		"exists": map[string]interface{}{
			"field": "nginx.stubstatus",
		},
	}
	docs, err := estools.GetLatestDocumentMatchingQuery(ctx, runner.info.ESClient, query, "metrics-nginx.stubstatus-default")
	require.NoError(runner.T(), err)
	require.Truef(runner.T(), docs.Hits.Total.Value > 0, "Expected at least one document, but none were found.")

	query = map[string]interface{}{
		"exists": map[string]interface{}{
			"field": "error.message",
		},
	}
	docs, err = estools.GetLatestDocumentMatchingQuery(ctx, runner.info.ESClient, query, "metrics-nginx.stubstatus-default")
	require.NoError(runner.T(), err)
	require.Truef(runner.T(), docs.Hits.Total.Value == 0, "Expected zero error messages, found %v", docs.Hits.Hits)
}

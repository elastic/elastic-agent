// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// // go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/estools"
	"github.com/elastic/go-sysinfo"
	"github.com/elastic/go-sysinfo/types"
)

type ExtendedRunner struct {
	suite.Suite
	info                   *define.Info
	agentFixture           *atesting.Fixture
	ESHost                 string
	healthCheckTime        time.Duration
	healthCheckRefreshTime time.Duration
}

// TestComponent is used as a key in our map of component metrics
type TestComponent struct {
	Binary   string `mapstructure:"binary"`
	Dataset  string `mapstructure:"dataset"`
	ID       string `mapstructure:"id"`
	CompType string `mapstructure:"type"`
}

type MemoryMetrics struct {
	GcNext      uint64 `mapstructure:"gc_next"`
	MemoryAlloc uint64 `mapstructure:"memory_alloc"`
	MemorySys   uint64 `mapstructure:"memory_sys"`
	MemoryTotal uint64 `mapstructure:"memory_total"`
	RSS         uint64 `mapstructure:"rss"`
}

type HandlesMetrics struct {
	Open  int           `mapstructure:"open"`
	Limit HandlesLimits `mapstructure:"limit"`
}

type HandlesLimits struct {
	Hard uint   `mapstructure:"hard"`
	Soft uint64 `mapstructure:"soft"`
}

// MetricsSystem is used for windows handles metrics
type MetricsSystem struct {
	Handles HandlesMetrics `mapstructure:"handles"`
}

type processWatcher struct {
	handle     types.Process
	pid        int
	name       string
	regHandles tools.Slope
}

func TestLongRunningAgentForLeaks(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: "fleet",
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Windows},
		},
	})

	if os.Getenv("TEST_LONG_RUNNING") == "" {
		t.Skip("not running extended test unless TEST_LONG_RUNNING is set")
	}

	suite.Run(t, &ExtendedRunner{info: info, healthCheckTime: time.Minute * 3, healthCheckRefreshTime: time.Second * 20})
}

func (runner *ExtendedRunner) SetupSuite() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "install", "-v", "github.com/mingrammer/flog@latest")
	out, err := cmd.CombinedOutput()
	require.NoError(runner.T(), err, "got out: %s", string(out))

	cmd = exec.CommandContext(ctx, "flog", "-t", "log", "-f", "apache_error", "-o", "/var/log/httpd/error_log", "-b", "50485760", "-p", "1048576")
	out, err = cmd.CombinedOutput()
	require.NoError(runner.T(), err, "got out: %s", string(out))

	policyUUID := uuid.New().String()
	unpr := false
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Unprivileged:   &unpr,
	}

	fixture, err := define.NewFixture(runner.T(), define.Version())
	require.NoError(runner.T(), err)
	runner.agentFixture = fixture

	basePolicy := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   "default",
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	policyResp, err := tools.InstallAgentWithPolicy(ctx, runner.T(), installOpts, runner.agentFixture, runner.info.KibanaClient, basePolicy)
	require.NoError(runner.T(), err)

	// install system package
	runner.InstallPackage(ctx, "system", "1.53.1", "agent_long_test_base_system_integ.json", uuid.New().String(), policyResp.ID)

	// install cef
	runner.InstallPackage(ctx, "apache", "1.17.0", "agent_long_test_apache.json", uuid.New().String(), policyResp.ID)

}

func (runner *ExtendedRunner) InstallPackage(ctx context.Context, name string, version string, cfgFile string, policyUUID string, policyID string) {
	installPackage := kibana.PackagePolicyRequest{}

	jsonRaw, err := os.ReadFile(cfgFile)
	require.NoError(runner.T(), err)

	err = json.Unmarshal(jsonRaw, &installPackage)
	require.NoError(runner.T(), err)

	installPackage.Package.Version = version
	installPackage.ID = policyUUID
	installPackage.PolicyID = policyID
	installPackage.Namespace = "default"
	installPackage.Name = fmt.Sprintf("%s-long-test-%s", name, policyUUID)
	installPackage.Vars = map[string]interface{}{}

	runner.T().Logf("Installing %s package....", name)
	_, err = runner.info.KibanaClient.InstallFleetPackage(ctx, installPackage)
	require.NoError(runner.T(), err, "error creating fleet package")
}

func (runner *ExtendedRunner) TestHandleLeak() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	testRuntime := os.Getenv("LONG_TEST_RUNTIME")
	if testRuntime == "" {
		testRuntime = "15m"
	}

	status, err := runner.agentFixture.ExecStatus(ctx)
	require.NoError(runner.T(), err)

	// because we need to separately fetch the PIDs, wait until everything is healthy before we look for running beats
	require.Eventually(runner.T(), func() bool {
		allHealthy := true
		status, err := runner.agentFixture.ExecStatus(ctx)

		apacheMatch := "logfile-apache"
		foundApache := false
		systemMatch := "metrics-default"
		foundSystem := false

		require.NoError(runner.T(), err)
		for _, comp := range status.Components {
			// make sure the components include the expected integrations
			for _, v := range comp.Units {
				runner.T().Logf("unit ID: %s", v.UnitID)
				// the full unit ID will be something like "log-default-logfile-cef-3f0764f0-4ade-4f46-9ead-f2f0f7865676"
				if !foundApache && strings.Contains(v.UnitID, apacheMatch) {
					foundApache = true
				}
				if !foundSystem && strings.Contains(v.UnitID, systemMatch) {
					foundSystem = true
				}
			}
			runner.T().Logf("component state: %s", comp.Message)
			if comp.State != int(cproto.State_HEALTHY) {
				allHealthy = false
			}
		}
		return allHealthy && foundApache && foundSystem
	}, runner.healthCheckTime, runner.healthCheckRefreshTime, "install never became healthy")

	handles := []processWatcher{}

	// track running beats
	// the `last 30s` metrics tend to report gauges, which we can't use for calculating a derivative.
	// so separately fetch the PIDs
	pidInStatusMessageRegex := regexp.MustCompile(`[\d]+`)
	status, err = runner.agentFixture.ExecStatus(ctx)
	require.NoError(runner.T(), err)
	for _, comp := range status.Components {
		pidStr := pidInStatusMessageRegex.FindString(comp.Message)
		pid, err := strconv.ParseInt(pidStr, 10, 64)
		require.NoError(runner.T(), err)

		handle, err := sysinfo.Process(int(pid))
		require.NoError(runner.T(), err)
		handlesReg := tools.NewSlope(fmt.Sprintf("%s handle usage", comp.Name))

		runner.T().Logf("created handle watcher for %s (%d)", comp.Name, pid)
		handles = append(handles, processWatcher{handle: handle, pid: int(pid), name: comp.Name, regHandles: handlesReg})
	}

	testDuration, err := time.ParseDuration(testRuntime)
	require.NoError(runner.T(), err)

	timer := time.NewTimer(testDuration)
	defer timer.Stop()

	// time to perform a health check
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

	done := false
	start := time.Now()
	for !done {
		select {
		case <-timer.C:
			done = true
		case <-ticker.C:
			err := runner.agentFixture.IsHealthy(ctx)
			require.NoError(runner.T(), err)
			// for each running process, collect memory and handles
			for _, handle := range handles {

				ohc, ok := handle.handle.(types.OpenHandleCounter)
				if ok {
					handleCount, err := ohc.OpenHandleCount()
					require.NoError(runner.T(), err)
					handle.regHandles.AddDatapoint(float64(handleCount), time.Since(start))
				}

			}
		}
	}

	// we're measuring the handle usage as y=mx+b
	// if the slope is increasing above a certain rate, fail the test
	// A number of factors can change the slope during a test; shortened runtime (lots of handles allocated in the first few seconds, producing an upward slope),
	// filebeat trying to open a large number of log files, etc
	handleSlopeFailure := 0.1

	for _, handle := range handles {
		err = handle.regHandles.Run()
		require.NoError(runner.T(), err)

		runner.T().Logf("=============================== %s (%d)", handle.name, handle.pid)
		runner.T().Logf("handle formula: %s", handle.regHandles.Formula())
		handleSlope := handle.regHandles.GetSlope()
		require.LessOrEqual(runner.T(), handleSlope, handleSlopeFailure, "increase in open handles exceeded threshold: %s", handle.regHandles.Debug())
		runner.T().Logf("===============================")
	}

	// post-test: make sure that we actually ingested logs.
	docs, err := estools.GetResultsForAgentAndDatastream(ctx, runner.info.ESClient, "apache.error", status.Info.ID)
	assert.NoError(runner.T(), err, "error fetching apache logs")
	assert.Greater(runner.T(), docs.Hits.Total.Value, 0, "could not find any matching apache logs for agent ID %s", status.Info.ID)
	runner.T().Logf("Generated %d apache logs", docs.Hits.Total.Value)

	docs, err = estools.GetResultsForAgentAndDatastream(ctx, runner.info.ESClient, "system.cpu", status.Info.ID)
	assert.NoError(runner.T(), err, "error fetching system metrics")
	assert.Greater(runner.T(), docs.Hits.Total.Value, 0, "could not find any matching system metrics for agent ID %s", status.Info.ID)
	runner.T().Logf("Generated %d system events", docs.Hits.Total.Value)
}

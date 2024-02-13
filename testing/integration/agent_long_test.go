// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	logrunner "github.com/leehinman/spigot/pkg/runner"
	"github.com/sajari/regression"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/go-sysinfo"
	"github.com/elastic/go-sysinfo/types"
	"github.com/elastic/go-ucfg"
)

type ExtendedRunner struct {
	suite.Suite
	info         *define.Info
	agentFixture *atesting.Fixture

	ESHost string
}

type ComponentMetrics struct {
	Memory        MemoryMetrics  `mapstructure:"memstats"`
	Handles       HandlesMetrics `mapstructure:"handles"`
	UnixTimestamp int64
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
	regHandles *regression.Regression
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
		t.Skipf("not running extended test unless TEST_LONG_RUNNING is set")
	}

	suite.Run(t, &ExtendedRunner{info: info})
}

func (runner *ExtendedRunner) SetupSuite() {
	err := os.MkdirAll("/var/log/cef", 0o755)
	require.NoError(runner.T(), err)
	spigotConfig := map[string]interface{}{
		"generator": map[string]interface{}{
			"type": "citrix:cef",
		},
		"output": map[string]interface{}{
			"type":      "file",
			"directory": "/var/log/cef/",
			"pattern":   "cef*.log",
			"delimiter": "\n",
		},
		"interval": "20s",
		"records":  "1000",
	}
	cfg, err := ucfg.NewFrom(spigotConfig)
	require.NoError(runner.T(), err)

	logger, err := logrunner.New(cfg)
	require.NoError(runner.T(), err)

	go func() {
		err := logger.Execute()
		require.NoError(runner.T(), err)
	}()

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

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

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
	runner.InstallPackage(ctx, "system", "agent_long_test_base_system_integ.json", uuid.New().String(), policyResp.ID)

	// install cef
	runner.InstallPackage(ctx, "cef", "agent_long_test_cef.json", uuid.New().String(), policyResp.ID)

}

func (runner *ExtendedRunner) InstallPackage(ctx context.Context, name string, cfgFile string, policyUUID string, policyID string) {
	systemLatest, err := tools.GetLatestPackageRelease(ctx, name)
	require.NoError(runner.T(), err)
	runner.T().Logf("using %s version %s", name, systemLatest)

	installPackage := kibana.PackagePolicyRequest{}

	jsonRaw, err := os.ReadFile(cfgFile)
	require.NoError(runner.T(), err)

	err = json.Unmarshal(jsonRaw, &installPackage)
	require.NoError(runner.T(), err)

	installPackage.Package.Version = systemLatest
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
		testRuntime = "20m"
	}

	// because we need to separately fetch the PIDs, wait until everything is healthy before we look for running beats
	require.Eventually(runner.T(), func() bool {
		allHealthy := true
		status, err := runner.agentFixture.ExecStatus(context.Background())

		require.NoError(runner.T(), err)
		for _, comp := range status.Components {
			runner.T().Logf("component state: %s", comp.Message)
			if comp.State != int(cproto.State_HEALTHY) {
				allHealthy = false
			}
		}
		return allHealthy
	}, time.Minute*3, time.Second*20)

	handles := []processWatcher{}

	regex := regexp.MustCompile(`[\d]+`)
	status, err := runner.agentFixture.ExecStatus(context.Background())
	require.NoError(runner.T(), err)
	// track running beats
	// the `last 30s` metrics tend to report gauges, which we can't use for calculating a derivative.
	// so separately fetch the PIDs
	for _, comp := range status.Components {
		pidStr := regex.FindString(comp.Message)
		pid, err := strconv.ParseInt(pidStr, 10, 64)
		require.NoError(runner.T(), err)

		handle, err := sysinfo.Process(int(pid))
		require.NoError(runner.T(), err)
		handlesReg := new(regression.Regression)
		handlesReg.SetObserved(fmt.Sprintf("%s handle usage", comp.Name))
		handlesReg.SetVar(0, "time")

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
					handle.regHandles.Train(regression.DataPoint(float64(handleCount), []float64{time.Since(start).Seconds()}))
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
		runner.T().Logf("handle formula: %v", handle.regHandles.Formula)
		coeffs := handle.regHandles.GetCoeffs()
		handleSlope := coeffs[1]
		// This is a hack to deal with the fact that we'll pick up zombie processes that seem to happen when agent restarts
		if math.IsNaN(handleSlope) {
			continue
		}
		require.LessOrEqual(runner.T(), handleSlope, handleSlopeFailure, "increase in open handles exceeded threshold: %s", handle.regHandles)

		runner.T().Logf("===============================")
	}

}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// //go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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
	handle types.Process
	pid    int
	name   string
	reg    *regression.Regression
}

func TestAgentLong(t *testing.T) {
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

	if os.Getenv("TEST_EXTENDED") == "" {
		t.Skipf("not running extended test unless TEST_EXTENDED is set")
	}

	suite.Run(t, &ExtendedRunner{info: info})
}

func (runner *ExtendedRunner) SetupSuite() {
	// create ~40 1MB files that will be picked up by the `/var/log/httpd/error_log*` pattern
	cmd := exec.Command("go", "install", "-v", "github.com/mingrammer/flog@latest")
	out, err := cmd.CombinedOutput()
	require.NoError(runner.T(), err, "got out: %s", string(out))

	cmd = exec.Command("flog", "-t", "log", "-f", "apache_error", "-o", "/var/log/httpd/error_log", "-b", "50485760", "-p", "1048576")
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

	systemPackage := kibana.PackagePolicyRequest{}

	jsonRaw, err := os.ReadFile("agent_long_test_base_system_integ.json")
	require.NoError(runner.T(), err)

	err = json.Unmarshal(jsonRaw, &systemPackage)
	require.NoError(runner.T(), err)

	systemPackage.ID = policyUUID
	systemPackage.PolicyID = policyResp.ID
	systemPackage.Namespace = "default"
	systemPackage.Name = fmt.Sprintf("system-long-test-%s", policyUUID)
	systemPackage.Vars = map[string]interface{}{}

	runner.T().Logf("Installing fleet package....")
	_, err = runner.info.KibanaClient.InstallFleetPackage(ctx, systemPackage)
	require.NoError(runner.T(), err, "error creating fleet package")

	// install apache

	policyUUIDApache := uuid.New().String()
	apachePackage := kibana.PackagePolicyRequest{}

	jsonRaw, err = os.ReadFile("agent_long_test_apache_integ.json")
	require.NoError(runner.T(), err)

	err = json.Unmarshal(jsonRaw, &apachePackage)
	require.NoError(runner.T(), err)

	apachePackage.ID = policyUUIDApache
	apachePackage.PolicyID = policyResp.ID
	apachePackage.Namespace = "default"
	apachePackage.Name = fmt.Sprintf("system-long-test-%s", policyUUIDApache)
	apachePackage.Vars = map[string]interface{}{}

	runner.T().Logf("Installing fleet package....")
	_, err = runner.info.KibanaClient.InstallFleetPackage(ctx, apachePackage)
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
			if comp.State != int(cproto.State_HEALTHY) {
				allHealthy = false
			}
		}
		return allHealthy
	}, time.Minute*3, time.Second*20)

	procs, err := sysinfo.Processes()
	require.NoError(runner.T(), err)

	handles := []processWatcher{}

	// track running beats
	// the `last 30s` metrics tend to report gauges, which we can't use for calculating a derivative.
	// so separately fetch the PIDs
	for _, proc := range procs {
		info, err := proc.Info()
		require.NoError(runner.T(), err)
		if strings.Contains(info.Name, "beat") || strings.Contains(info.Name, "elastic-agent") {
			handle, err := sysinfo.Process(proc.PID())
			require.NoError(runner.T(), err)
			reg := new(regression.Regression)
			reg.SetObserved(fmt.Sprintf("%s handle usage", info.Name))
			reg.SetVar(0, "handles")
			reg.SetVar(1, "memory")
			runner.T().Logf("created handle watcher for %s (%d)", info.Name, proc.PID())
			handles = append(handles, processWatcher{handle: handle, pid: proc.PID(), name: info.Name, reg: reg})
		}
	}

	testDuration, err := time.ParseDuration(testRuntime)
	require.NoError(runner.T(), err)

	timer := time.NewTimer(testDuration)

	// time to perform a health check
	ticker := time.Tick(time.Second * 10)

	done := false
	for {
		if done {
			break
		}
		select {
		case <-timer.C:
			done = true
		case <-ticker:
			err := runner.agentFixture.IsHealthy(ctx)
			require.NoError(runner.T(), err)
			for _, handle := range handles {

				procMem, err := handle.handle.Memory()
				require.NoError(runner.T(), err)
				ohc, ok := handle.handle.(types.OpenHandleCounter)
				if ok {
					handleCount, err := ohc.OpenHandleCount()
					require.NoError(runner.T(), err)
					handle.reg.Train(regression.DataPoint(float64(handleCount), []float64{float64(time.Now().Unix()), float64(procMem.Virtual)}))
				}

			}
		}
	}

	// we're measuring the handle/memory usage as y=mx+b
	// if the slope is increasing above a certain rate, fail the test
	handleSlopeFailure := float64(2)
	memorySlopeFailure := 2e-3

	for _, handle := range handles {
		err = handle.reg.Run()
		require.NoError(runner.T(), err)

		runner.T().Logf("=============================== %s", handle.name)
		runner.T().Logf("formula: %v", handle.reg.Formula)
		runner.T().Logf("data: %#v", handle.reg)
		// coefficient 0: offset (b), 1: handle slope, 2: memory slope
		coeffs := handle.reg.GetCoeffs()
		runner.T().Logf("Coeff: %#v", coeffs)
		handleSlope := coeffs[1]
		if math.IsNaN(handleSlope) {
			continue
		}
		require.LessOrEqual(runner.T(), handleSlope, handleSlopeFailure, "increase in open handles exceeded threshold")
		memorySlope := coeffs[2]
		require.LessOrEqual(runner.T(), memorySlope, memorySlopeFailure, "increasin in memory usage exceeded threshold")

		runner.T().Logf("===============================")
	}

}

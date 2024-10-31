// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"archive/zip"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/testing/certutil"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/proxytest"
)

const (
	endpointHealthPollingTimeout = 5 * time.Minute
)

var protectionTests = []struct {
	name      string
	protected bool
}{
	{
		name: "unprotected",
	},
	{
		name:      "protected",
		protected: true,
	},
}

// TestInstallAndCLIUninstallWithEndpointSecurity tests that the agent can
// install and uninstall the endpoint-security service while remaining healthy.
//
// Installing endpoint-security requires a Fleet managed agent with the Elastic Defend integration
// installed. The endpoint-security service is uninstalled when the agent is uninstalled.
//
// The agent is automatically uninstalled as part of test cleanup when installed with
// fixture.Install via tools.InstallAgentWithPolicy. Failure to uninstall the agent will fail the
// test automatically.
func TestInstallAndCLIUninstallWithEndpointSecurity(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	for _, tc := range protectionTests {
		t.Run(tc.name, func(t *testing.T) {
			testInstallAndCLIUninstallWithEndpointSecurity(t, info, tc.protected)
		})
	}
}

// TestInstallAndUnenrollWithEndpointSecurity tests that the agent can install
// and uninstall the endpoint-security service while remaining healthy. In
// this case endpoint-security is uninstalled because the agent was unenrolled, which
// triggers the creation of an empty agent policy removing all inputs (only when not force
// unenrolling). The empty agent policy triggers the uninstall of endpoint because endpoint was
// removed from the policy.
//
// Like the CLI uninstall test, the agent is uninstalled from the command line at the end of the test
// but at this point endpoint is already uninstalled.
func TestInstallAndUnenrollWithEndpointSecurity(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	for _, tc := range protectionTests {
		t.Run(tc.name, func(t *testing.T) {
			testInstallAndUnenrollWithEndpointSecurity(t, info, tc.protected)
		})
	}
}

// TestInstallWithEndpointSecurityAndRemoveEndpointIntegration tests that the
// agent can install and uninstall the endpoint-security service after the
// Elastic Defend integration was removed from the policy while remaining
// healthy.
//
// Installing endpoint-security requires a Fleet managed agent with the Elastic Defend integration
// installed. The endpoint-security service is uninstalled the Elastic Defend integration was removed from the policy.
//
// Like the CLI uninstall test, the agent is uninstalled from the command line at the end of the test
// but at this point endpoint should be already uninstalled.
func TestInstallWithEndpointSecurityAndRemoveEndpointIntegration(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	for _, tc := range protectionTests {
		t.Run(tc.name, func(t *testing.T) {
			testInstallWithEndpointSecurityAndRemoveEndpointIntegration(t, info, tc.protected)
		})
	}
}

// installSecurityAgent is a helper function to install an elastic-agent in priviliged mode with the force+non-interactve flags.
// the policy the agent is enrolled with can have protection enabled if passed
func installSecurityAgent(ctx context.Context, t *testing.T, info *define.Info, protected bool) (*atesting.Fixture, kibana.PolicyResponse) {
	t.Helper()

	// Get path to agent executable.
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err, "could not create agent fixture")

	t.Log("Enrolling the agent in Fleet")
	policyUUID := uuid.Must(uuid.NewV4()).String()

	createPolicyReq := buildPolicyWithTamperProtection(
		kibana.AgentPolicy{
			Name:        "test-policy-" + policyUUID,
			Namespace:   "default",
			Description: "Test policy " + policyUUID,
			MonitoringEnabled: []kibana.MonitoringEnabledOption{
				kibana.MonitoringEnabledLogs,
				kibana.MonitoringEnabledMetrics,
			},
		},
		protected,
	)

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     true,
	}

	policy, err := tools.InstallAgentWithPolicy(ctx, t,
		installOpts, fixture, info.KibanaClient, createPolicyReq)
	require.NoError(t, err, "failed to install agent with policy")
	return fixture, policy
}

// buildPolicyWithTamperProtection helper function to build the policy request with or without tamper protection
func buildPolicyWithTamperProtection(policy kibana.AgentPolicy, protected bool) kibana.AgentPolicy {
	if protected {
		policy.AgentFeatures = append(policy.AgentFeatures, map[string]interface{}{
			"name":    "tamper_protection",
			"enabled": true,
		})
	}
	policy.IsProtected = protected
	return policy
}

func testInstallAndCLIUninstallWithEndpointSecurity(t *testing.T, info *define.Info, protected bool) {
	deadline := time.Now().Add(10 * time.Minute)
	ctx, cancel := testcontext.WithDeadline(t, context.Background(), deadline)
	defer cancel()

	fixture, policy := installSecurityAgent(ctx, t, info, protected)

	t.Cleanup(func() {
		t.Log("Un-enrolling Elastic Agent...")
		// Use a separate context as the one in the test body will have been cancelled at this point.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		assert.NoError(t, fleettools.UnEnrollAgent(cleanupCtx, info.KibanaClient, policy.ID))
	})

	t.Log("Installing Elastic Defend")
	pkgPolicyResp, err := installElasticDefendPackage(t, info, policy.ID)
	require.NoErrorf(t, err, "Policy Response was: %v", pkgPolicyResp)

	t.Log("Polling for endpoint-security to become Healthy")
	ctx, cancel = context.WithTimeout(ctx, endpointHealthPollingTimeout)
	defer cancel()

	agentClient := fixture.Client()
	err = agentClient.Connect(ctx)
	require.NoError(t, err, "could not connect to local agent")

	require.Eventually(t,
		func() bool { return agentAndEndpointAreHealthy(t, ctx, agentClient) },
		endpointHealthPollingTimeout,
		time.Second,
		"Endpoint component or units are not healthy.",
	)
	t.Log("Verified endpoint component and units are healthy")
}

func testInstallAndUnenrollWithEndpointSecurity(t *testing.T, info *define.Info, protected bool) {
	ctx, cn := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cn()

	fixture, policy := installSecurityAgent(ctx, t, info, protected)

	t.Log("Installing Elastic Defend")
	_, err := installElasticDefendPackage(t, info, policy.ID)
	require.NoError(t, err)

	t.Log("Polling for endpoint-security to become Healthy")
	ctx, cancel := context.WithTimeout(context.Background(), endpointHealthPollingTimeout)
	defer cancel()

	agentClient := fixture.Client()
	err = agentClient.Connect(ctx)
	require.NoError(t, err)

	require.Eventually(t,
		func() bool { return agentAndEndpointAreHealthy(t, ctx, agentClient) },
		endpointHealthPollingTimeout,
		time.Second,
		"Endpoint component or units are not healthy.",
	)
	t.Log("Verified endpoint component and units are healthy")

	// Unenroll the agent
	t.Log("Unenrolling the agent")

	hostname, err := os.Hostname()
	require.NoError(t, err)

	agentID, err := fleettools.GetAgentIDByHostname(ctx, info.KibanaClient, policy.ID, hostname)
	require.NoError(t, err)

	_, err = info.KibanaClient.UnEnrollAgent(ctx, kibana.UnEnrollAgentRequest{ID: agentID})
	require.NoError(t, err)

	t.Log("Waiting for inputs to stop")
	require.Eventually(t,
		func() bool {
			state, err := agentClient.State(ctx)
			if err != nil {
				t.Logf("Error getting agent state: %s", err)
				return false
			}

			if state.State != client.Healthy {
				t.Logf("Agent is not Healthy\n%+v", state)
				return false
			}

			if len(state.Components) != 0 {
				t.Logf("Components have not been stopped and uninstalled!\n%+v", state)
				return false
			}

			return true
		},
		endpointHealthPollingTimeout,
		time.Second,
		"All components not removed.",
	)
	t.Log("Verified endpoint component and units are removed")

	// Verify that the Endpoint directory was correctly removed.
	// Regression test for https://github.com/elastic/elastic-agent/issues/3077
	agentInstallPath := fixture.WorkDir()
	files, err := os.ReadDir(filepath.Clean(filepath.Join(agentInstallPath, "..")))
	require.NoError(t, err)

	t.Logf("Checking directories at install path %s", agentInstallPath)
	for _, f := range files {
		if !f.IsDir() {
			continue
		}

		t.Log("Found directory", f.Name())
		require.False(t, strings.Contains(f.Name(), "Endpoint"), "Endpoint directory was not removed")
	}
}

func testInstallWithEndpointSecurityAndRemoveEndpointIntegration(t *testing.T, info *define.Info, protected bool) {
	ctx, cn := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cn()

	fixture, policy := installSecurityAgent(ctx, t, info, protected)

	t.Log("Installing Elastic Defend")
	pkgPolicyResp, err := installElasticDefendPackage(t, info, policy.ID)
	require.NoErrorf(t, err, "Policy Response was: %#v", pkgPolicyResp)

	t.Log("Polling for endpoint-security to become Healthy")
	ctx, cancel := context.WithTimeout(context.Background(), endpointHealthPollingTimeout)
	defer cancel()

	agentClient := fixture.Client()
	err = agentClient.Connect(ctx)
	require.NoError(t, err)

	require.Eventually(t,
		func() bool { return agentAndEndpointAreHealthy(t, ctx, agentClient) },
		endpointHealthPollingTimeout,
		time.Second,
		"Endpoint component or units are not healthy.",
	)
	t.Log("Verified endpoint component and units are healthy")

	t.Logf("Removing Elastic Defend: %v", fmt.Sprintf("/api/fleet/package_policies/%v", pkgPolicyResp.Item.ID))
	_, err = info.KibanaClient.DeleteFleetPackage(ctx, pkgPolicyResp.Item.ID)
	require.NoError(t, err)

	t.Log("Waiting for endpoint to stop")
	require.Eventually(t,
		func() bool { return agentIsHealthyNoEndpoint(t, ctx, agentClient) },
		endpointHealthPollingTimeout,
		time.Second,
		"Endpoint component or units are still present.",
	)
	t.Log("Verified endpoint component and units are removed")

	// Verify that the Endpoint directory was correctly removed.
	// Regression test for https://github.com/elastic/elastic-agent/issues/3077
	agentInstallPath := fixture.WorkDir()
	files, err := os.ReadDir(filepath.Clean(filepath.Join(agentInstallPath, "..")))
	require.NoError(t, err)

	t.Logf("Checking directories at install path %s", agentInstallPath)
	for _, f := range files {
		if !f.IsDir() {
			continue
		}

		t.Log("Found directory", f.Name())
		// If Endpoint was not currently removed, let's see what was left
		if strings.Contains(f.Name(), "Endpoint") {
			info, err := f.Info()
			if err != nil {
				t.Logf("could not get file info for %q to check what was left"+
					"behind: %v", f.Name(), err)
			}
			ls, err := os.ReadDir(info.Name())
			if err != nil {
				t.Logf("could not list fileson for %q to check what was left"+
					"behind: %v", f.Name(), err)
			}
			var dirEntries []string
			for _, de := range ls {
				dirEntries = append(dirEntries, de.Name())
			}

			if len(dirEntries) == 0 {
				t.Fatalf("Endpoint directory was not removed, but it's empty")
			}
			t.Fatalf("Endpoint directory was not removed, the directory content is: %s",
				strings.Join(dirEntries, ", "))
		}
	}
}

// This is a subset of kibana.AgentPolicyUpdateRequest, using until elastic-agent-libs PR https://github.com/elastic/elastic-agent-libs/pull/141 is merged
// TODO: replace with the elastic-agent-libs when available
type agentPolicyUpdateRequest struct {
	// Name of the policy. Required in an update request.
	Name string `json:"name"`
	// Namespace of the policy. Required in an update request.
	Namespace   string `json:"namespace"`
	IsProtected bool   `json:"is_protected"`
}

// Tests that install of Elastic Defend fails if Agent is installed in a base
// path other than default
func TestEndpointSecurityNonDefaultBasePath(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	ctx, cn := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cn()

	// Get path to agent executable.
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	t.Log("Enrolling the agent in Fleet")
	policyUUID := uuid.Must(uuid.NewV4()).String()
	createPolicyReq := kibana.AgentPolicy{
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
		Privileged:     true,
		BasePath:       filepath.Join(paths.DefaultBasePath, "not_default"),
	}
	policyResp, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, fixture, info.KibanaClient, createPolicyReq)
	require.NoErrorf(t, err, "Policy Response was: %v", policyResp)

	t.Log("Installing Elastic Defend")
	pkgPolicyResp, err := installElasticDefendPackage(t, info, policyResp.ID)
	require.NoErrorf(t, err, "Policy Response was: %v", pkgPolicyResp)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	c := fixture.Client()

	require.Eventually(t, func() bool {
		err := c.Connect(ctx)
		if err != nil {
			t.Logf("connecting client to agent: %v", err)
			return false
		}
		defer c.Disconnect()
		state, err := c.State(ctx)
		if err != nil {
			t.Logf("error getting the agent state: %v", err)
			return false
		}
		t.Logf("agent state: %+v", state)
		if state.State != cproto.State_DEGRADED {
			return false
		}
		for _, c := range state.Components {
			if strings.Contains(c.Message,
				"Elastic Defend requires Elastic Agent be installed at the default installation path") {
				return true
			}
		}
		return false
	}, 2*time.Minute, 10*time.Second, "Agent never became DEGRADED with default install message")
}

// Tests that install of Elastic Defend fails if Agent is installed unprivileged.
func TestEndpointSecurityUnprivileged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation

		// Only supports Linux at the moment.
		OS: []define.OS{
			{
				Type: define.Linux,
			},
		},
	})

	ctx, cn := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cn()

	// Get path to agent executable.
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	t.Log("Enrolling the agent in Fleet")
	policyUUID := uuid.Must(uuid.NewV4()).String()
	createPolicyReq := kibana.AgentPolicy{
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
		Privileged:     false, // ensure always unprivileged
	}
	policyResp, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, fixture, info.KibanaClient, createPolicyReq)
	require.NoErrorf(t, err, "Policy Response was: %v", policyResp)

	t.Log("Installing Elastic Defend")
	pkgPolicyResp, err := installElasticDefendPackage(t, info, policyResp.ID)
	require.NoErrorf(t, err, "Policy Response was: %v", pkgPolicyResp)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	c := fixture.Client()

	errMsg := "Elastic Defend requires Elastic Agent be running as root"
	if runtime.GOOS == define.Windows {
		errMsg = "Elastic Defend requires Elastic Agent be running as Administrator or SYSTEM"
	}
	require.Eventually(t, func() bool {
		err := c.Connect(ctx)
		if err != nil {
			t.Logf("connecting client to agent: %v", err)
			return false
		}
		defer c.Disconnect()
		state, err := c.State(ctx)
		if err != nil {
			t.Logf("error getting the agent state: %v", err)
			return false
		}
		t.Logf("agent state: %+v", state)
		if state.State != cproto.State_DEGRADED {
			return false
		}
		for _, c := range state.Components {
			if strings.Contains(c.Message, errMsg) {
				return true
			}
		}
		return false
	}, 2*time.Minute, 10*time.Second, "Agent never became DEGRADED with root/Administrator install message")
}

// Tests that trying to switch from privileged to unprivileged with Elastic Defend fails.
func TestEndpointSecurityCannotSwitchToUnprivileged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation

		// Only supports Linux at the moment.
		OS: []define.OS{
			{
				Type: define.Linux,
			},
		},
	})

	ctx, cn := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cn()

	// Get path to agent executable.
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	t.Log("Enrolling the agent in Fleet")
	policyUUID := uuid.Must(uuid.NewV4()).String()
	createPolicyReq := kibana.AgentPolicy{
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
		Privileged:     true, // ensure always privileged
	}
	policyResp, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, fixture, info.KibanaClient, createPolicyReq)
	require.NoErrorf(t, err, "Policy Response was: %v", policyResp)

	t.Log("Installing Elastic Defend")
	pkgPolicyResp, err := installElasticDefendPackage(t, info, policyResp.ID)
	require.NoErrorf(t, err, "Policy Response was: %v", pkgPolicyResp)

	t.Log("Polling for endpoint-security to become Healthy")
	healthyCtx, cancel := context.WithTimeout(ctx, endpointHealthPollingTimeout)
	defer cancel()

	agentClient := fixture.Client()
	err = agentClient.Connect(healthyCtx)
	require.NoError(t, err)

	require.Eventually(t,
		func() bool { return agentAndEndpointAreHealthy(t, healthyCtx, agentClient) },
		endpointHealthPollingTimeout,
		time.Second,
		"Endpoint component or units are not healthy.",
	)
	t.Log("Verified endpoint component and units are healthy")

	performSwitchCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	output, err := fixture.Exec(performSwitchCtx, []string{"unprivileged", "-f"})
	require.Errorf(t, err, "unprivileged command should have failed")
	assert.Contains(t, string(output), "unable to switch to unprivileged mode due to the following service based components having issues")
	assert.Contains(t, string(output), "endpoint")
}

// TestEndpointLogsAreCollectedInDiagnostics tests that diagnostics archive contain endpoint logs
func TestEndpointLogsAreCollectedInDiagnostics(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	ctx, cn := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cn()

	// Get path to agent executable.
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	t.Log("Enrolling the agent in Fleet")
	policyUUID := uuid.Must(uuid.NewV4()).String()
	createPolicyReq := kibana.AgentPolicy{
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
		Privileged:     true,
	}

	policyResp, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, fixture, info.KibanaClient, createPolicyReq)
	require.NoErrorf(t, err, "Policy Response was: %v", policyResp)

	t.Cleanup(func() {
		t.Log("Un-enrolling Elastic Agent...")
		// Use a separate context as the one in the test body will have been cancelled at this point.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		assert.NoError(t, fleettools.UnEnrollAgent(cleanupCtx, info.KibanaClient, policyResp.ID))
	})

	t.Log("Installing Elastic Defend")
	pkgPolicyResp, err := installElasticDefendPackage(t, info, policyResp.ID)
	require.NoErrorf(t, err, "Policy Response was: %v", pkgPolicyResp)

	// wait for endpoint to be healthy
	t.Log("Polling for endpoint-security to become Healthy")
	pollingCtx, pollingCancel := context.WithTimeout(ctx, endpointHealthPollingTimeout)
	defer pollingCancel()

	require.Eventually(t,
		func() bool {
			agentClient := fixture.Client()
			err = agentClient.Connect(ctx)
			if err != nil {
				t.Logf("error connecting to agent: %v", err)
				return false
			}
			defer agentClient.Disconnect()
			return agentAndEndpointAreHealthy(t, pollingCtx, agentClient)
		},
		endpointHealthPollingTimeout,
		time.Second,
		"Endpoint component or units are not healthy.",
	)

	// get endpoint component name
	endpointComponents := getEndpointComponents(ctx, t, fixture.Client())
	require.NotEmpty(t, endpointComponents, "there should be at least one endpoint component")

	t.Logf("endpoint components: %v", endpointComponents)

	outDir := t.TempDir()
	diagFile := t.Name() + ".zip"
	diagAbsPath := filepath.Join(outDir, diagFile)
	_, err = fixture.Exec(ctx, []string{"diagnostics", "-f", diagAbsPath})
	require.NoError(t, err, "diagnostics command failed")
	require.FileExists(t, diagAbsPath, "diagnostic archive should have been created")
	checkDiagnosticsForEndpointFiles(t, diagAbsPath, endpointComponents)
}

func getEndpointComponents(ctx context.Context, t *testing.T, c client.Client) []string {

	err := c.Connect(ctx)
	require.NoError(t, err, "connecting to agent to retrieve endpoint components")
	defer c.Disconnect()

	agentState, err := c.State(ctx)
	require.NoError(t, err, "retrieving agent state")

	var endpointComponents []string
	for _, componentState := range agentState.Components {
		if strings.Contains(componentState.Name, "endpoint") {
			endpointComponents = append(endpointComponents, componentState.ID)
		}
	}
	return endpointComponents
}

func checkDiagnosticsForEndpointFiles(t *testing.T, diagsPath string, endpointComponents []string) {
	zipReader, err := zip.OpenReader(diagsPath)
	require.NoError(t, err, "error opening diagnostics archive")

	defer func(zipReader *zip.ReadCloser) {
		err := zipReader.Close()
		assert.NoError(t, err, "error closing diagnostic archive")
	}(zipReader)

	t.Logf("---- Contents of diagnostics archive")
	for _, file := range zipReader.File {
		t.Logf("%q - %+v", file.Name, file.FileHeader.FileInfo())
	}
	t.Logf("---- End contents of diagnostics archive")
	// check there are files under the components/ directory
	for _, componentName := range endpointComponents {
		endpointComponentDirName := fmt.Sprintf("components/%s", componentName)
		endpointComponentDir, err := zipReader.Open(endpointComponentDirName)
		if assert.NoErrorf(t, err, "error looking up directory %q for endpoint component %q in diagnostic archive: %v", endpointComponentDirName, componentName, err) {
			defer func(endpointComponentDir fs.File) {
				err := endpointComponentDir.Close()
				if err != nil {
					assert.NoError(t, err, "error closing endpoint component directory")
				}
			}(endpointComponentDir)
			if assert.Implementsf(t, (*fs.ReadDirFile)(nil), endpointComponentDir, "endpoint component %q should have a directory in the diagnostic archive under %s", componentName, endpointComponentDirName) {
				dirFile := endpointComponentDir.(fs.ReadDirFile)
				endpointFiles, err := dirFile.ReadDir(-1)
				assert.NoErrorf(t, err, "error reading endpoint component %q directory %q in diagnostic archive", componentName, endpointComponentDirName)
				assert.NotEmptyf(t, endpointFiles, "endpoint component %q directory should not be empty", componentName)
			}
		}
	}

	// check endpoint logs
	servicesLogDirName := "logs/services"
	servicesLogDir, err := zipReader.Open(servicesLogDirName)
	if assert.NoErrorf(t, err, "error looking up directory %q in diagnostic archive: %v", servicesLogDirName, err) {
		defer func(servicesLogDir fs.File) {
			err := servicesLogDir.Close()
			if err != nil {
				assert.NoError(t, err, "error closing services logs directory")
			}
		}(servicesLogDir)
		if assert.Implementsf(t, (*fs.ReadDirFile)(nil), servicesLogDir, "service logs should be in a directory in the diagnostic archive under %s", servicesLogDir) {
			dirFile := servicesLogDir.(fs.ReadDirFile)
			servicesLogFiles, err := dirFile.ReadDir(-1)
			assert.NoError(t, err, "error reading services logs directory %q in diagnostic archive", servicesLogDirName)
			assert.True(t,
				slices.ContainsFunc(servicesLogFiles,
					func(entry fs.DirEntry) bool {
						return strings.HasPrefix(entry.Name(), "endpoint-") && strings.HasSuffix(entry.Name(), ".log")
					}),
				"service logs should contain endpoint-*.log files",
			)
		}
	}
}

func agentIsHealthyNoEndpoint(t *testing.T, ctx context.Context, agentClient client.Client) bool {
	t.Helper()

	state, err := agentClient.State(ctx)
	if err != nil {
		t.Logf("Error getting agent state: %s", err)
		return false
	}

	if state.State != client.Healthy {
		t.Logf("Agent is not Healthy\n%+v", state)
		return false
	}

	foundEndpointComponent := false
	foundEndpointInputUnit := false
	foundEndpointOutputUnit := false
	for _, comp := range state.Components {
		isEndpointComponent := strings.Contains(comp.Name, "endpoint")
		if isEndpointComponent {
			foundEndpointComponent = true
		}
		if comp.State != client.Healthy {
			t.Logf("Component is not Healthy\n%+v", comp)
			return false
		}

		for _, unit := range comp.Units {
			if isEndpointComponent {
				if unit.UnitType == client.UnitTypeInput {
					foundEndpointInputUnit = true
				}
				if unit.UnitType == client.UnitTypeOutput {
					foundEndpointOutputUnit = true
				}
			}

			if unit.State != client.Healthy {
				t.Logf("Unit is not Healthy\n%+v", unit)
				return false
			}
		}
	}

	// Ensure both the endpoint input and output units were found and healthy.
	if foundEndpointComponent || foundEndpointInputUnit || foundEndpointOutputUnit {
		t.Logf("State did contain endpoint or endpoint units!\n%+v", state)
		return false
	}

	return true
}

// TestForceInstallOverProtectedPolicy tests that running `elastic-agent install -f`
// when an installed agent is running a policy with tamper protection enabled fails.
func TestForceInstallOverProtectedPolicy(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	deadline := time.Now().Add(10 * time.Minute)
	ctx, cancel := testcontext.WithDeadline(t, context.Background(), deadline)
	defer cancel()

	fixture, policy := installSecurityAgent(ctx, t, info, true)

	t.Cleanup(func() {
		t.Log("Un-enrolling Elastic Agent...")
		// Use a separate context as the one in the test body will have been cancelled at this point.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		assert.NoError(t, fleettools.UnEnrollAgent(cleanupCtx, info.KibanaClient, policy.ID))
	})

	t.Log("Installing Elastic Defend")
	pkgPolicyResp, err := installElasticDefendPackage(t, info, policy.ID)
	require.NoErrorf(t, err, "Policy Response was: %v", pkgPolicyResp)

	t.Log("Polling for endpoint-security to become Healthy")
	ctx, cancel = context.WithTimeout(ctx, endpointHealthPollingTimeout)
	defer cancel()

	agentClient := fixture.Client()
	err = agentClient.Connect(ctx)
	require.NoError(t, err, "could not connect to local agent")

	require.Eventually(t,
		func() bool { return agentAndEndpointAreHealthy(t, ctx, agentClient) },
		endpointHealthPollingTimeout,
		time.Second,
		"Endpoint component or units are not healthy.",
	)
	t.Log("Verified endpoint component and units are healthy")

	t.Log("Run elastic-agent install -f...")
	// We use the same policy with tamper protection enabled for this test and expect it to fail.
	token, err := info.KibanaClient.CreateEnrollmentAPIKey(ctx, kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policy.ID,
	})
	require.NoError(t, err)
	url, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	require.NoError(t, err)

	args := []string{
		"install",
		"--force",
		"--url",
		url,
		"--enrollment-token",
		token.APIKey,
	}
	out, err := fixture.Exec(ctx, args)
	require.Errorf(t, err, "No error detected, command output: %s", out)
}

func TestInstallDefendWithMTLSandEncCertKey(t *testing.T) {
	stack := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})
	ctx := context.Background()
	testUUID := uuid.Must(uuid.NewV4()).String()
	policyID := "mTLS-defend-" + testUUID

	fleetServerURL, err := fleettools.DefaultURL(ctx, stack.KibanaClient)
	require.NoError(t, err, "failed getting Fleet Server URL")

	defaultFleetHost := fleetServerURL[8:]
	fleethostWrong, err := url.Parse("https://fixme.elastic.co:443")
	require.NoError(t, err, "failed parsing fleethostWrong")

	// ================================= proxy =================================
	mtlsCLI, mtlsPolicy, oneWayTLSPolicy, proxyCLI, proxyPolicymTLS, proxyPolicyOneWayTLS := prepareProxies(t, fleethostWrong, defaultFleetHost)

	// =================== Prepare fleet hosts and proxies ===================

	// create mTLS proxy
	fleetProxymTLS, err := stack.KibanaClient.CreateFleetProxy(ctx, kibana.ProxiesRequest{
		CertificateAuthorities: mtlsPolicy.proxyCAPath,
		Certificate:            mtlsPolicy.clientCertPath,
		CertificateKey:         mtlsPolicy.clientCertKeyPath,
		ID:                     "mTLS" + testUUID,
		Name:                   "mTLS" + testUUID,
		URL:                    proxyPolicymTLS.URL,
	})
	require.NoError(t, err, "error creating proxy on fleet")

	// create TLS proxy
	fleetProxyOneWay, err := stack.KibanaClient.CreateFleetProxy(ctx, kibana.ProxiesRequest{
		CertificateAuthorities: oneWayTLSPolicy.proxyCAPath,
		ID:                     "oneWayTLS" + testUUID,
		Name:                   "oneWayTLS" + testUUID,
		URL:                    proxyPolicyOneWayTLS.URL,
	})
	require.NoError(t, err, "error creating proxy on fleet")

	// add new fleet-server host with mTLS proxy
	fleetKibanaHostmTLS, err := stack.KibanaClient.NewFleetServerHosts(ctx, kibana.ListFleetServerHostsRequest{
		ID:        "proxyPolicymTLS" + testUUID,
		Name:      "proxyPolicymTLS" + testUUID,
		HostURLs:  []string{fleethostWrong.String()},
		IsDefault: false,
		ProxyID:   fleetProxymTLS.Item.ID,
	})
	require.NoError(t, err, "error creating fleet host with mTLS proxy")

	// add new fleet-server host with oen way TLS proxy
	fleetKibanaHostOneWayTLS, err := stack.KibanaClient.NewFleetServerHosts(ctx, kibana.ListFleetServerHostsRequest{
		ID:        "proxyPolicyOneWayTLS" + testUUID,
		Name:      "proxyPolicyOneWayTLS" + testUUID,
		HostURLs:  []string{fleethostWrong.String()},
		IsDefault: false,
		ProxyID:   fleetProxyOneWay.Item.ID,
	})
	require.NoError(t, err, "error creating fleet host with one way TLS proxy")

	// create policy without proxy and respective enrollment token
	policyNoProxyTmpl := kibana.AgentPolicy{
		ID:          policyID,
		Name:        policyID,
		Namespace:   "default",
		Description: policyID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	// ============================ Create policies ============================

	policyNoProxy, err := stack.KibanaClient.CreatePolicy(ctx, policyNoProxyTmpl)
	require.NoErrorf(t, err, "failed creating policy %s", policyID)
	pkgPolicyNoProxyResp, err := installElasticDefendPackage(t, stack, policyNoProxyTmpl.ID)
	require.NoErrorf(t, err, "failed adding Elastic Defend to policy: response was: %v", pkgPolicyNoProxyResp)
	enrollmentTokenNoProxyResp, err := stack.KibanaClient.CreateEnrollmentAPIKey(
		ctx, kibana.CreateEnrollmentAPIKeyRequest{
			PolicyID: policyNoProxy.ID,
		})
	require.NoError(t, err, "failed creating enrollment API key for policy with no proxy")

	// create policy with mTLS proxy and respective enrollment token
	policymTLSProxyTmpl := kibana.AgentPolicy{
		ID:                "with-mTLS-Proxy-" + policyID,
		Name:              "with-mTLS-Proxy-" + policyID,
		Namespace:         "default",
		Description:       "with-mTLS-Proxy-" + policyID,
		FleetServerHostID: fleetKibanaHostmTLS.Item.ID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}
	policymTLSProxy, err := stack.KibanaClient.CreatePolicy(ctx, policymTLSProxyTmpl)
	require.NoErrorf(t, err, "failed creating policy %s", policyID)
	pkgPolicymTLSProxyResp, err := installElasticDefendPackage(t, stack, policymTLSProxy.ID)
	require.NoErrorf(t, err, "failed adding Elastic Defend to policy: response was: %v", pkgPolicymTLSProxyResp)
	enrollmentTokenmTLSProxyResp, err := stack.KibanaClient.CreateEnrollmentAPIKey(
		ctx, kibana.CreateEnrollmentAPIKeyRequest{
			PolicyID: policymTLSProxy.ID,
		})
	require.NoError(t, err, "failed creating enrollment API key for policy with mTLS proxy")

	// create policy with one way TLS proxy and respective enrollment token
	policyOneWayTLSProxyTmpl := kibana.AgentPolicy{
		ID:                "with-oneWay-Proxy-" + policyID,
		Name:              "with-oneWay-Proxy-" + policyID,
		Namespace:         "default",
		Description:       "with-oneWay-Proxy-" + policyID,
		FleetServerHostID: fleetKibanaHostOneWayTLS.Item.ID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}
	policyOneWayProxy, err := stack.KibanaClient.CreatePolicy(ctx, policyOneWayTLSProxyTmpl)
	require.NoErrorf(t, err, "failed creating policy %s", policyID)
	pkgPolicyOneWayProxy, err := installElasticDefendPackage(t, stack, policyOneWayProxy.ID)
	require.NoErrorf(t, err, "failed adding Elastic Defend to policy: response was: %v", pkgPolicyOneWayProxy)
	enrollmentTokenOneWayProxyResp, err := stack.KibanaClient.CreateEnrollmentAPIKey(
		ctx, kibana.CreateEnrollmentAPIKeyRequest{
			PolicyID: policyOneWayProxy.ID,
		})
	require.NoError(t, err, "failed creating enrollment API key for policy with one way TLS proxy")

	// =============================== test cases ==============================
	tcs := []struct {
		Name                   string
		URL                    string
		EnrollmentToken        string
		ProxyURL               string
		CertificateAuthorities []string
		Certificate            string
		Key                    string

		KeyPassphrase string
		assertInspect func(*testing.T, *atesting.Fixture)
	}{
		{
			Name:            "proxy-from-cli-and-plain-cert-key",
			URL:             fleethostWrong.String(),
			EnrollmentToken: enrollmentTokenNoProxyResp.APIKey,
			ProxyURL:        proxyCLI.URL,

			CertificateAuthorities: []string{mtlsCLI.proxyCAPath},
			Certificate:            mtlsCLI.clientCertPath,
			Key:                    mtlsCLI.clientCertKeyPath,
			assertInspect: func(t *testing.T, f *atesting.Fixture) {
				got, err := f.ExecInspect(ctx)
				require.NoErrorf(t, err, "error running inspect cmd")

				assert.Equal(t, proxyCLI.URL, got.Fleet.ProxyURL)
				assert.Equal(t, mtlsCLI.clientCertPath, got.Fleet.Ssl.Certificate)
				assert.Equal(t, mtlsCLI.clientCertKeyPath, got.Fleet.Ssl.Key)
				assert.Empty(t, got.Fleet.Ssl.KeyPassphrasePath, "policy should have removed key_passphrase_path as key isn't passphrase protected anymore")
			},
		},
		{
			Name:            "proxy-from-cli-and-passphrase-protected-cert-key",
			URL:             fleethostWrong.String(),
			EnrollmentToken: enrollmentTokenNoProxyResp.APIKey,
			ProxyURL:        proxyCLI.URL,

			CertificateAuthorities: []string{mtlsCLI.proxyCAPath},
			Certificate:            mtlsCLI.clientCertPath,
			Key:                    mtlsCLI.clientCertKeyEncPath,
			KeyPassphrase:          mtlsCLI.clientCertKeyPassPath,
			assertInspect: func(t *testing.T, f *atesting.Fixture) {
				got, err := f.ExecInspect(ctx)
				require.NoErrorf(t, err, "error running inspect cmd")

				assert.Equal(t, proxyCLI.URL, got.Fleet.ProxyURL)
				assert.Equal(t, mtlsCLI.clientCertPath, got.Fleet.Ssl.Certificate)
				assert.Equal(t, mtlsCLI.clientCertKeyEncPath, got.Fleet.Ssl.Key)
				assert.Equal(t, mtlsCLI.clientCertKeyPassPath, got.Fleet.Ssl.KeyPassphrasePath)
			},
		},
		{
			Name:            "proxy-from-cli-and-passphrase-protected-cert-key-proxy-from-policy-one-way-TLS",
			URL:             fleethostWrong.String(),
			EnrollmentToken: enrollmentTokenOneWayProxyResp.APIKey,
			ProxyURL:        proxyCLI.URL,

			CertificateAuthorities: []string{mtlsCLI.proxyCAPath},
			Certificate:            mtlsCLI.clientCertPath,
			Key:                    mtlsCLI.clientCertKeyEncPath,
			KeyPassphrase:          mtlsCLI.clientCertKeyPassPath,
			assertInspect: func(t *testing.T, f *atesting.Fixture) {
				// wait for the agent to apply the policy coming from fleet-server
				buff := &strings.Builder{}
				assert.Eventuallyf(t, func() bool {
					buff.Reset()

					got, err := f.ExecInspect(ctx)
					if err != nil {
						buff.WriteString(fmt.Sprintf("error running inspect cmd: %v", err))
						return false
					}

					return proxyPolicyOneWayTLS.URL == got.Fleet.ProxyURL
				}, time.Minute, time.Second, "inspect never showed proxy from policy: %s", buff)

				t.Skip("remove skip once https://github.com/elastic/elastic-agent/issues/5888 is fixed")
				got, err := f.ExecInspect(ctx)
				require.NoErrorf(t, err, "error running inspect cmd")

				assert.Equal(t, proxyPolicyOneWayTLS.URL, got.Fleet.ProxyURL)
				assert.Equal(t, []string{oneWayTLSPolicy.proxyCAPath}, got.Fleet.Ssl.CertificateAuthorities)
				assert.Empty(t, got.Fleet.Ssl.Certificate, "client certificate isn't present in the proxy from the policy")
				assert.Empty(t, got.Fleet.Ssl.Key, "client certificate key isn't present in the proxy from the policy")
				assert.Empty(t, got.Fleet.Ssl.KeyPassphrasePath, "client certificate key passphrase isn't present in the proxy from the policy")
			},
		},
		{
			Name:            "proxy-from-cli-and-policy-both-with-plain-cert-key",
			URL:             fleethostWrong.String(),
			EnrollmentToken: enrollmentTokenmTLSProxyResp.APIKey,
			ProxyURL:        proxyCLI.URL,

			CertificateAuthorities: []string{mtlsCLI.proxyCAPath},
			Certificate:            mtlsCLI.clientCertPath,
			Key:                    mtlsCLI.clientCertKeyPath,

			assertInspect: func(t *testing.T, f *atesting.Fixture) {
				// wait for the agent to apply the policy coming from fleet-server
				buff := &strings.Builder{}
				assert.Eventuallyf(t, func() bool {
					buff.Reset()

					got, err := f.ExecInspect(ctx)
					if err != nil {
						buff.WriteString(fmt.Sprintf("error running inspect cmd: %v", err))
						return false
					}

					return proxyPolicymTLS.URL == got.Fleet.ProxyURL
				}, time.Minute, time.Second, "inspect never showed proxy from policy: %s", buff)

				got, err := f.ExecInspect(ctx)
				if err != nil {
					require.NoError(t, err, "error running inspect cmd")
					return
				}
				assert.Equal(t, proxyPolicymTLS.URL, got.Fleet.ProxyURL)
				assert.Equal(t, mtlsPolicy.clientCertPath, got.Fleet.Ssl.Certificate)
				assert.Equal(t, mtlsPolicy.clientCertKeyPath, got.Fleet.Ssl.Key)
				assert.Empty(t, got.Fleet.Ssl.KeyPassphrasePath, "policy should have removed key_passphrase_path as key isn't passphrase protected anymore")
			},
		},
		{
			Name:            "proxy-from-cli-with-passphrase-protected-cert-key-and-policy-with-plain-cert-key",
			URL:             fleethostWrong.String(),
			EnrollmentToken: enrollmentTokenmTLSProxyResp.APIKey,
			ProxyURL:        proxyCLI.URL,

			CertificateAuthorities: []string{mtlsCLI.proxyCAPath},
			Certificate:            mtlsCLI.clientCertPath,
			Key:                    mtlsCLI.clientCertKeyEncPath,
			KeyPassphrase:          mtlsCLI.clientCertKeyPassPath,

			assertInspect: func(t *testing.T, f *atesting.Fixture) {
				// wait for the agent to apply the policy coming from fleet-server
				buff := &strings.Builder{}
				assert.Eventuallyf(t, func() bool {
					buff.Reset()

					got, err := f.ExecInspect(ctx)
					if err != nil {
						buff.WriteString(fmt.Sprintf("error running inspect cmd: %v", err))
						return false
					}

					return proxyPolicymTLS.URL == got.Fleet.ProxyURL
				}, time.Minute, time.Second, "inspect never showed proxy from policy: %s", buff)

				got, err := f.ExecInspect(ctx)
				if err != nil {
					require.NoError(t, err, "error running inspect cmd")
					return
				}

				assert.Equal(t, proxyPolicymTLS.URL, got.Fleet.ProxyURL)
				assert.Equal(t, mtlsPolicy.clientCertPath, got.Fleet.Ssl.Certificate)
				assert.Equal(t, mtlsPolicy.clientCertKeyPath, got.Fleet.Ssl.Key)
				assert.Empty(t, got.Fleet.Ssl.KeyPassphrasePath, "policy should have removed key_passphrase_path as key isn't passphrase protected anymore")
			},
		},
		{
			Name:            "no-proxy-from-cli-and-proxy-from-policy-with-plain-cert-key",
			URL:             "https://" + defaultFleetHost,
			EnrollmentToken: enrollmentTokenmTLSProxyResp.APIKey,

			assertInspect: func(t *testing.T, f *atesting.Fixture) {
				// wait for the agent to apply the policy coming from fleet-server
				buff := &strings.Builder{}
				assert.Eventuallyf(t, func() bool {
					buff.Reset()

					got, err := f.ExecInspect(ctx)
					if err != nil {
						buff.WriteString(fmt.Sprintf("error running inspect cmd: %v", err))
						return false
					}

					return proxyPolicymTLS.URL == got.Fleet.ProxyURL
				}, time.Minute, time.Second, "inspect never showed proxy from policy: %s", buff)

				got, err := f.ExecInspect(ctx)
				if err != nil {
					require.NoError(t, err, "error running inspect cmd")
					return
				}

				assert.Equal(t, proxyPolicymTLS.URL, got.Fleet.ProxyURL)
				assert.Equal(t, mtlsPolicy.clientCertPath, got.Fleet.Ssl.Certificate)
				assert.Equal(t, mtlsPolicy.clientCertKeyPath, got.Fleet.Ssl.Key)
				assert.Empty(t, got.Fleet.Ssl.KeyPassphrasePath, "key_passphrase_path was never set")
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			installOpts := atesting.InstallOpts{
				NonInteractive: true,
				Force:          true,
				Privileged:     true,
				ProxyURL:       tc.ProxyURL,
				EnrollOpts: atesting.EnrollOpts{
					URL:             tc.URL,
					EnrollmentToken: tc.EnrollmentToken,

					CertificateAuthorities: tc.CertificateAuthorities,
					Certificate:            tc.Certificate,
					Key:                    tc.Key,
					KeyPassphrasePath:      tc.KeyPassphrase,
				},
			}

			fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
			require.NoError(t, err, "could not create agent fixture")

			out, err := fixture.Install(ctx, &installOpts)
			require.NoError(t, err, "could not install agent. Output: %s", string(out))

			err = fixture.Client().Connect(ctx)
			require.NoError(t, err, "could not connect to agent daemon")

			require.Eventually(t,
				func() bool { return agentAndEndpointAreHealthy(t, ctx, fixture.Client()) },
				endpointHealthPollingTimeout,
				time.Minute,
				"Defend or the agent are not healthy.",
			)

			tc.assertInspect(t, fixture)
		})
	}
}

func prepareProxies(t *testing.T, fleethostWrong *url.URL, defaultFleetHost string) (
	certificatePaths, certificatePaths, certificatePaths, *proxytest.Proxy, *proxytest.Proxy, *proxytest.Proxy) {

	mtlsCLI := generateMTLSCerts(t, "mtlsCLI")
	mtlsPolicy := generateMTLSCerts(t, "mtlsPolicy")
	oneWayTLSPolicy := generateMTLSCerts(t, "oneWayTLSPolicy")

	proxyCLI := proxytest.New(t,
		proxytest.WithVerboseLog(),
		proxytest.WithRequestLog("proxyCLI", t.Logf),
		proxytest.WithRewrite(fleethostWrong.Host, defaultFleetHost),
		proxytest.WithMITMCA(mtlsCLI.proxyCAKey, mtlsCLI.proxyCACert),
		proxytest.WithServerTLSConfig(&tls.Config{
			Certificates: []tls.Certificate{*mtlsCLI.proxyCert},
			ClientCAs:    mtlsCLI.clientCACertPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
		}))
	err := proxyCLI.StartTLS()
	require.NoError(t, err, "error starting proxyCLI")
	t.Logf("proxyCLI running on %s", proxyCLI.URL)
	t.Cleanup(proxyCLI.Close)

	proxyPolicymTLS := proxytest.New(t,
		proxytest.WithVerboseLog(),
		proxytest.WithRequestLog("proxyPolicymTLS", t.Logf),
		proxytest.WithRewrite(fleethostWrong.Host, defaultFleetHost),
		proxytest.WithMITMCA(mtlsPolicy.proxyCAKey, mtlsPolicy.proxyCACert),
		proxytest.WithServerTLSConfig(&tls.Config{
			Certificates: []tls.Certificate{*mtlsPolicy.proxyCert},
			ClientCAs:    mtlsPolicy.clientCACertPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
		}))
	err = proxyPolicymTLS.StartTLS()
	require.NoError(t, err, "error starting proxyPolicymTLS")
	t.Logf("proxyPolicymTLS running on %s", proxyPolicymTLS.URL)
	t.Cleanup(proxyPolicymTLS.Close)

	proxyPolicyOneWayTLS := proxytest.New(t,
		proxytest.WithVerboseLog(),
		proxytest.WithRequestLog("proxyOneWayTLSPolicy", t.Logf),
		proxytest.WithRewrite(fleethostWrong.Host, defaultFleetHost),
		proxytest.WithMITMCA(oneWayTLSPolicy.proxyCAKey, oneWayTLSPolicy.proxyCACert),
		proxytest.WithServerTLSConfig(&tls.Config{
			Certificates: []tls.Certificate{*oneWayTLSPolicy.proxyCert},
			MinVersion:   tls.VersionTLS13,
		}))
	err = proxyPolicyOneWayTLS.StartTLS()
	require.NoError(t, err, "error starting proxyPolicyOneWayTLS")
	t.Logf("proxyPolicymTLS running on %s", proxyPolicyOneWayTLS.URL)
	t.Cleanup(proxyPolicyOneWayTLS.Close)

	return mtlsCLI, mtlsPolicy, oneWayTLSPolicy, proxyCLI, proxyPolicymTLS, proxyPolicyOneWayTLS
}

func generateMTLSCerts(t *testing.T, name string) certificatePaths {
	// Create a temporary directory to store certificates that will not be
	// deleted at the end of the test. If the certificates are deleted before
	// agent uninstall runs, it'll cause the agent uninstall to fail as it loads
	// all the configs, including the certificates, which would be gone if the
	// directory is deleted.
	tmpDir, err := os.MkdirTemp(os.TempDir(), t.Name()+"-"+name)
	t.Logf("[%s] certificates saved on: %s", name, tmpDir)

	proxyCAKey, proxyCACert, proxyCAPair, err := certutil.NewRSARootCA(
		certutil.WithCNPrefix("proxy-" + name))
	require.NoError(t, err, "error creating root CA")

	proxyCert, proxyCertPair, err := certutil.GenerateRSAChildCert(
		"localhost",
		[]net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback, net.IPv6zero},
		proxyCAKey,
		proxyCACert,
		certutil.WithCNPrefix("proxy-"+name))
	require.NoError(t, err, "error creating server certificate")

	clientCAKey, clientCACert, clientCAPair, err := certutil.NewRSARootCA(
		certutil.WithCNPrefix("client-" + name))
	require.NoError(t, err, "error creating root CA")
	clientCACertPool := x509.NewCertPool()
	clientCACertPool.AddCert(clientCACert)

	clientCert, clientCertPair, err := certutil.GenerateRSAChildCert(
		"localhost",
		[]net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback, net.IPv6zero},
		clientCAKey,
		clientCACert,
		certutil.WithCNPrefix("client-"+name))
	require.NoError(t, err, "error creating server certificate")
	passphrase := "aReallySecurePassphrase"

	encKey, err := certutil.EncryptKey(clientCert.PrivateKey, passphrase)
	require.NoError(t, err, "error encrypting certificate key")

	// =========================== save certificates ===========================
	proxyCACertFile := filepath.Join(tmpDir, "proxyCA.crt")
	err = os.WriteFile(proxyCACertFile, proxyCAPair.Cert, 0644)
	require.NoErrorf(t, err, "could not save %q", proxyCACertFile)

	proxyCAKeyFile := filepath.Join(tmpDir, "proxyCA.key")
	err = os.WriteFile(proxyCAKeyFile, proxyCAPair.Key, 0644)
	require.NoErrorf(t, err, "could not save %q", proxyCAKeyFile)

	proxyCertFile := filepath.Join(tmpDir, "proxyCert.crt")
	err = os.WriteFile(proxyCertFile, proxyCertPair.Cert, 0644)
	require.NoErrorf(t, err, "could not save %q", proxyCertFile)

	proxyKeyFile := filepath.Join(tmpDir, "proxyCert.key")
	err = os.WriteFile(proxyKeyFile, proxyCertPair.Key, 0644)
	require.NoErrorf(t, err, "could not save %q", proxyKeyFile)

	clientCACertFile := filepath.Join(tmpDir, "clientCA.crt")
	err = os.WriteFile(clientCACertFile, clientCAPair.Cert, 0644)
	require.NoErrorf(t, err, "could not save %q", clientCACertFile)

	clientCAKeyFile := filepath.Join(tmpDir, "clientCA.key")
	err = os.WriteFile(clientCAKeyFile, clientCAPair.Key, 0644)
	require.NoErrorf(t, err, "could not save %q", clientCAKeyFile)

	clientCertCertFile := filepath.Join(tmpDir, "clientCert.crt")
	err = os.WriteFile(clientCertCertFile, clientCertPair.Cert, 0644)
	require.NoErrorf(t, err, "could not save %q", clientCertCertFile)

	clientCertKeyFile := filepath.Join(tmpDir, "clientCert.key")
	err = os.WriteFile(clientCertKeyFile, clientCertPair.Key, 0644)
	require.NoErrorf(t, err, "could not save %q", clientCertKeyFile)

	clientCertKeyEncFile := filepath.Join(tmpDir, "clientCertEnc.key")
	err = os.WriteFile(clientCertKeyEncFile, encKey, 0644)
	require.NoErrorf(t, err, "could not save %q", clientCertKeyEncFile)

	clientCertKeyPassFile := filepath.Join(tmpDir, "clientCertKey.pass")
	err = os.WriteFile(clientCertKeyPassFile, []byte(passphrase), 0644)
	require.NoErrorf(t, err, "could not save %q", clientCertKeyPassFile)

	return certificatePaths{
		proxyCAKey:  proxyCAKey,
		proxyCACert: proxyCACert,
		proxyCAPath: proxyCACertFile,
		proxyCert:   proxyCert,

		clientCACertPool:      clientCACertPool,
		clientCAPath:          clientCACertFile,
		clientCertPath:        clientCertCertFile,
		clientCertKeyPath:     clientCertKeyFile,
		clientCertKeyEncPath:  clientCertKeyEncFile,
		clientCertKeyPassPath: clientCertKeyPassFile,
	}
}

type certificatePaths struct {
	proxyCAKey  crypto.PrivateKey
	proxyCACert *x509.Certificate
	proxyCert   *tls.Certificate
	proxyCAPath string

	clientCAPath          string
	clientCACertPool      *x509.CertPool
	clientCertPath        string
	clientCertKeyPath     string
	clientCertKeyEncPath  string
	clientCertKeyPassPath string
}

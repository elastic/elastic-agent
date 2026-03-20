// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"archive/zip"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
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
	"github.com/elastic/elastic-agent-libs/testing/proxytest"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/integration"
	"github.com/elastic/elastic-agent/testing/upgradetest"
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

func TestUpgradeAgentWithTamperProtectedEndpoint_DEB(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Deb,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{
				Type: define.Linux,
			},
		},
	})

	t.Run("Upgrade from older version to newer version", func(t *testing.T) {
		upgradeFromVersion, err := upgradetest.PreviousMinor()
		require.NoError(t, err)
		testTamperProtectedInstallUpgrade(t, info, "deb", upgradeFromVersion.String(), true, false)
	})

	t.Run("Install same version over the installed agent", func(t *testing.T) {
		testTamperProtectedInstallUpgrade(t, info, "deb", define.Version(), false, false)
	})

	t.Run("Upgrade with endpoint stopped before upgrade", func(t *testing.T) {
		upgradeFromVersion, err := upgradetest.PreviousMinor()
		require.NoError(t, err)
		testTamperProtectedInstallUpgrade(t, info, "deb", upgradeFromVersion.String(), true, true)
	})

	t.Run("Make sure unprotected upgrades are not broken", func(t *testing.T) {
		testUnprotectedInstallUpgrade(t, info, "deb")
	})
}

func TestUpgradeAgentWithTamperProtectedEndpoint_RPM(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.RPM,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{
				Type:   define.Linux,
				Distro: "rhel",
			},
		},
	})

	t.Run("Upgrade from older version to newer version", func(t *testing.T) {
		upgradeFromVersion, err := upgradetest.PreviousMinor()
		require.NoError(t, err)
		testTamperProtectedInstallUpgrade(t, info, "rpm", upgradeFromVersion.String(), true, false)
	})

	t.Run("Install same version over the installed agent", func(t *testing.T) {
		testTamperProtectedInstallUpgrade(t, info, "rpm", define.Version(), false, false)
	})

	t.Run("Upgrade with endpoint stopped before upgrade", func(t *testing.T) {
		upgradeFromVersion, err := upgradetest.PreviousMinor()
		require.NoError(t, err)
		testTamperProtectedInstallUpgrade(t, info, "rpm", upgradeFromVersion.String(), true, true)
	})
	t.Run("Make sure unprotected upgrades are not broken", func(t *testing.T) {
		testUnprotectedInstallUpgrade(t, info, "rpm")
	})
}

func getEndpointVersion(t *testing.T) string {
	cmd := exec.Command("sudo", "/opt/Elastic/Endpoint/elastic-endpoint", "version")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err)
	// version: 8.18.0-SNAPSHOT, compiled: Wed Feb 19 01:00:00 2025, branch: HEAD, commit: c450b50f91507c3166b072df8557f5efd871103a
	endpointVersionFragment, _, found := strings.Cut(string(output), ",")
	require.True(t, found)

	endpointVersion, found := strings.CutPrefix(endpointVersionFragment, "version: ")
	require.True(t, found)

	return endpointVersion
}

func getInstallCommand(ctx context.Context, packageFormat string, srcPkg string, envVars []string) (*exec.Cmd, error) {
	args := []string{}

	if len(envVars) != 0 {
		args = append(args, envVars...)
	}

	switch packageFormat {
	case "deb":
		// since the previous agent is enrolled it means that the /etc/elastic-agent/elastic-agent.yml has changed
		// and dpkg will ask if we want to overwrite it. Since this is a non-interactive install we need to
		// force to keep the existing config
		args = append(args, "dpkg", "--force-confold", "-i")
	case "rpm":
		args = append(args, "rpm", "-Uvh", "--force")
	default:
		return nil, fmt.Errorf("unknown package format for install command: %s", packageFormat)
	}
	args = append(args, srcPkg)
	return exec.CommandContext(ctx, "sudo", args...), nil
}

func addEndpointCleanup(t *testing.T, uninstallToken string) {
	t.Cleanup(func() {
		_, err := os.Stat("/opt/Elastic/Endpoint/elastic-endpoint")
		if os.IsNotExist(err) {
			t.Log("Endpoint binary does not exist, aborting endpoint cleanup")
			return
		}

		out, err := exec.Command("sudo", "systemctl", "stop", "ElasticEndpoint").CombinedOutput()
		if err != nil {
			t.Log(string(out))
			t.Logf("error while stopping Elastic Endpoint: %s", err.Error())
		}

		if atesting.KeepInstalledFlag() {
			t.Logf("\"Keep installed\" flag is set, won't be removing endpoint. If you want to remove endpoint later on, use the following uninstall token: %s", uninstallToken)
			return
		}

		uninstallContext, uninstallCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer uninstallCancel()

		t.Logf("Uninstalling endpoint with the following uninstall token: %s", uninstallToken)
		_, err = exec.CommandContext(uninstallContext, "/opt/Elastic/Endpoint/elastic-endpoint", "uninstall", "--uninstall-token", uninstallToken).CombinedOutput()
		if err != nil {
			t.Fatalf("error when cleaning up elastic-endpoint: uninstall token %s", uninstallToken)
		}

		t.Log("Endpoint is successfully uninstalled by the cleanup function")
	})
}

func installFirstAgent(ctx context.Context, t *testing.T, info *define.Info, isProtected bool, packageFormat string, upgradeFromVersion string) (*atesting.Fixture, string) {
	var fixture *atesting.Fixture
	var err error

	if upgradeFromVersion == define.Version() {
		fixture, err = define.NewFixtureFromLocalBuild(t, define.Version(), atesting.WithPackageFormat(packageFormat))
	} else {
		fixture, err = atesting.NewFixture(
			t,
			upgradeFromVersion,
			atesting.WithFetcher(atesting.ArtifactFetcher()),
			atesting.WithPackageFormat(packageFormat),
		)
	}
	require.NoError(t, err, "failed to create fixture")
	err = fixture.Prepare(ctx)
	require.NoError(t, err, "failed to prepare fixture")

	t.Log("Creating a generic policy and enrollment token")
	policy := createBasicPolicy()
	policyResp, enrollKeyResp := createPolicyAndEnrollmentToken(ctx, t, info.KibanaClient, policy)

	t.Log("Install elastic defend")
	pkgPolicyResp, err := installElasticDefendPackage(t, info, policyResp.ID)
	require.NoErrorf(t, err, "Policy Response was: %v", pkgPolicyResp)

	updateReq := kibana.AgentPolicyUpdateRequest{
		Name:        policy.Name,
		Namespace:   policy.Namespace,
		IsProtected: &isProtected,
	}

	t.Log("Updating the policy to set \"is_protected\" to true")
	_, err = info.KibanaClient.UpdatePolicy(ctx, policyResp.ID, updateReq)

	t.Log("Get the policy uninstall token")
	uninstallToken, err := tools.GetUninstallToken(ctx, info.KibanaClient, policyResp.ID)
	require.NoError(t, err, "failed to get uninstall token")

	opts := atesting.InstallOpts{}
	t.Log("Install and enroll the first agent")
	_, err = tools.InstallAgentForPolicyWithToken(ctx, t, opts, fixture, info.KibanaClient, enrollKeyResp)
	require.NoError(t, err, "failed to install agent for policy with token")

	addEndpointCleanup(t, uninstallToken)

	agentClient := fixture.Client()
	err = agentClient.Connect(ctx)
	require.NoError(t, err, "could not connect to the initial agent")

	require.Eventually(t,
		func() bool { return agentAndEndpointAreHealthy(t, ctx, agentClient) },
		endpointHealthPollingTimeout,
		time.Second,
		"Endpoint component or units are not healthy prior to upgrade.",
	)

	t.Log("The initial installation of both the agent and endpoint are healthy")

	return fixture, uninstallToken
}

func testUnprotectedInstallUpgrade(
	t *testing.T,
	info *define.Info,
	packageFormat string,
) {
	ctx := t.Context()

	upgradeFromVersion, err := upgradetest.PreviousMinor()
	require.NoError(t, err)

	installFirstAgent(ctx, t, info, false, packageFormat, upgradeFromVersion.String())

	initEndpointVersion := getEndpointVersion(t)
	t.Logf("The initial endpoint version is %s", initEndpointVersion)

	t.Log("Setup agent fixture with the test build")
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), atesting.WithPackageFormat(packageFormat))
	require.NoError(t, err)
	err = fixture.Prepare(ctx)
	require.NoError(t, err, "failed to prepare fixture")

	t.Log("Getting source package")
	srcPkg, err := fixture.SrcPackage(ctx)
	require.NoError(t, err)

	t.Log("Installing the second agent, upgrading from the older version")
	installCmd, err := getInstallCommand(ctx, fixture.PackageFormat(), srcPkg, nil)
	require.NoError(t, err)

	out, err := installCmd.CombinedOutput()
	t.Log(string(out))
	require.NoError(t, err, "agent installation with package manager should not fail")

	err = fixture.SetDebRpmClient()
	require.NoError(t, err, "could not set DEB/RPM client")

	upgradedAgentClient := fixture.Client()
	err = upgradedAgentClient.Connect(ctx)
	require.NoError(t, err, "could not connect to the upgraded agent")

	require.Eventually(t,
		func() bool { return agentAndEndpointAreHealthy(t, ctx, upgradedAgentClient) },
		endpointHealthPollingTimeout,
		time.Second,
		"Endpoint component or units are not healthy after the upgrade.",
	)

	t.Log("Validate that the initial endpoint version is smaller than the upgraded version")
	upgradedEndpointVersion := getEndpointVersion(t)
	t.Logf("The upgraded endpoint version is %s", upgradedEndpointVersion)

	startEndpointVersion, err := version.ParseVersion(initEndpointVersion)
	require.NoError(t, err)

	parsedUpgradedVersion, err := version.ParseVersion(upgradedEndpointVersion)
	require.NoError(t, err)

	t.Logf("Comparing start version %s to upgraded version %s", startEndpointVersion.String(), parsedUpgradedVersion.String())
	require.True(t, startEndpointVersion.Less(*parsedUpgradedVersion))

	t.Log("trying to uninstall without token, not expecting error")
	out, err = exec.Command("sudo", "elastic-agent", "uninstall", "-f").CombinedOutput()
	t.Log(string(out))
	require.NoError(t, err)

	_, err = exec.LookPath("elastic-agent")
	require.Error(t, err)

	t.Log("successfully uninstalled agent and endpoint")
}

func testTamperProtectedInstallUpgrade(
	t *testing.T,
	info *define.Info,
	packageFormat string,
	initialVersion string,
	checkVersionUpgrade bool,
	stopEndpointBeforeUpgrade bool,
) {
	ctx := t.Context()

	fixture, uninstallToken := installFirstAgent(ctx, t, info, true, packageFormat, initialVersion)

	initEndpointVersion := getEndpointVersion(t)
	t.Logf("The initial endpoint version is %s", initEndpointVersion)

	// Optionally stop the endpoint service before upgrade
	if stopEndpointBeforeUpgrade {
		t.Log("Stopping endpoint service before upgrade as requested")
		out, err := exec.Command("sudo", "systemctl", "stop", "ElasticEndpoint").CombinedOutput()
		t.Log(string(out))
		require.NoError(t, err, "failed to stop ElasticEndpoint before upgrade")
	}

	// try to uninstall the agent without a token and assert failure
	out, err := exec.Command("sudo", "elastic-agent", "uninstall", "-f").CombinedOutput()
	t.Log(string(out))
	require.Error(t, err, "uninstalling agent without a token should fail because of tamper protection")
	t.Log("Tamper protection for the initial installation of the agent is enabled")

	if checkVersionUpgrade {
		t.Log("Setup agent fixture with the test build")
		fixture, err = define.NewFixtureFromLocalBuild(t, define.Version(), atesting.WithPackageFormat(packageFormat))
		require.NoError(t, err, "failed to create agent fixture")
		err = fixture.Prepare(ctx)
		require.NoError(t, err, "failed to prepare agent fixture")
	}

	t.Log("Getting source package")
	srcPkg, err := fixture.SrcPackage(ctx)
	require.NoError(t, err, "failed to get source package")

	t.Log("Installing the second agent, upgrading from the older version")
	installCmd, err := getInstallCommand(ctx, fixture.PackageFormat(), srcPkg, nil)
	require.NoError(t, err, "failed to get install command")

	out, err = installCmd.CombinedOutput()
	t.Log(string(out))
	require.NoError(t, err, "agent installation with package manager should not fail")

	err = fixture.SetDebRpmClient()
	require.NoError(t, err, "failed to set deb/rpm client")

	upgradedAgentClient := fixture.Client()
	err = upgradedAgentClient.Connect(ctx)
	require.NoError(t, err, "could not connect to the upgraded agent")

	require.Eventually(t,
		func() bool { return agentAndEndpointAreHealthy(t, ctx, upgradedAgentClient) },
		endpointHealthPollingTimeout,
		time.Second,
		"Endpoint component or units are not healthy after the upgrade.",
	)

	if checkVersionUpgrade {
		t.Log("Validate that the initial endpoint version is smaller than the upgraded version")
		upgradedEndpointVersion := getEndpointVersion(t)
		t.Logf("The upgraded endpoint version is %s", upgradedEndpointVersion)

		startEndpointVersion, err := version.ParseVersion(initEndpointVersion)
		require.NoError(t, err, "failed to parse initial endpoint version")

		parsedUpgradedVersion, err := version.ParseVersion(upgradedEndpointVersion)
		require.NoError(t, err, "failed to parse upgraded endpoint version")

		t.Logf("Comparing start version %s to upgraded version %s", startEndpointVersion.String(), parsedUpgradedVersion.String())
		require.True(t, startEndpointVersion.Less(*parsedUpgradedVersion))
	}

	// try to uninstall the agent without token and assert that endpoint is not removed
	t.Log("trying to uninstall without token, expecting error")
	out, err = exec.Command("sudo", "elastic-agent", "uninstall", "-f").CombinedOutput()
	t.Log(string(out))
	require.Error(t, err, "uninstalling agent without a token should fail because of tamper protection")
	t.Log("tamper protection for the upgraded agent is enabled")

	// uninstall with the token and assert that endpoint is indeed removed.
	t.Log("trying to uninstall with token, not expecting any error")
	out, err = exec.Command("sudo", "elastic-agent", "uninstall", "-f", "--uninstall-token", uninstallToken).CombinedOutput()
	t.Log(string(out))
	require.NoError(t, err, string(out))

	_, err = exec.LookPath("elastic-agent")
	require.Error(t, err, "expected elastic-agent binary to not exist in PATH after uninstall")

	t.Log("successfully uninstalled endpoint using the uninstall token")
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
		Group: integration.FleetEndpointSecurity,
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
		Group: integration.FleetEndpointSecurity,
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
		Group: integration.FleetEndpointSecurity,
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

// installSecurityAgent is a helper function to install an elastic-agent in privileged mode with the force+non-interactve flags.
// the policy the agent is enrolled with can have protection enabled if passed
func installSecurityAgent(ctx context.Context, t *testing.T, info *define.Info, protected bool) (*atesting.Fixture, kibana.PolicyResponse, string) {
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

	policy, agentID, err := tools.InstallAgentWithPolicy(ctx, t,
		installOpts, fixture, info.KibanaClient, createPolicyReq)
	require.NoError(t, err, "failed to install agent with policy")

	return fixture, policy, agentID
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

	fixture, policy, agentID := installSecurityAgent(ctx, t, info, protected)

	t.Cleanup(func() {
		t.Log("Un-enrolling Elastic Agent...")
		// Use a separate context as the one in the test body will have been cancelled at this point.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		assert.NoError(t, fleettools.UnEnrollAgent(cleanupCtx, info.KibanaClient, agentID))
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

	fixture, policy, agentID := installSecurityAgent(ctx, t, info, protected)

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

	fixture, policy, _ := installSecurityAgent(ctx, t, info, protected)

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
	elasticInstallPath := filepath.Clean(filepath.Join(agentInstallPath, ".."))
	files, err := os.ReadDir(elasticInstallPath)
	require.NoError(t, err)

	t.Logf("Checking directories at install path %s", elasticInstallPath)
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
		Group: integration.FleetEndpointSecurity,
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
	policyResp, _, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, fixture, info.KibanaClient, createPolicyReq)
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
		Group: integration.FleetEndpointSecurity,
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
	policyResp, _, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, fixture, info.KibanaClient, createPolicyReq)
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
		Group: integration.FleetEndpointSecurity,
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
	policyResp, _, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, fixture, info.KibanaClient, createPolicyReq)
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
		Group: integration.FleetEndpointSecurity,
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

	policyResp, agentID, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, fixture, info.KibanaClient, createPolicyReq)
	require.NoErrorf(t, err, "Policy Response was: %v", policyResp)

	t.Cleanup(func() {
		t.Log("Un-enrolling Elastic Agent...")
		// Use a separate context as the one in the test body will have been cancelled at this point.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		assert.NoError(t, fleettools.UnEnrollAgent(cleanupCtx, info.KibanaClient, agentID))
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
		Group: integration.FleetEndpointSecurity,
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

	fixture, policy, agentID := installSecurityAgent(ctx, t, info, true)

	t.Cleanup(func() {
		t.Log("Un-enrolling Elastic Agent...")
		// Use a separate context as the one in the test body will have been cancelled at this point.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		assert.NoError(t, fleettools.UnEnrollAgent(cleanupCtx, info.KibanaClient, agentID))
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
	fleetURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	require.NoError(t, err)

	args := []string{
		"install",
		"--force",
		"--url",
		fleetURL,
		"--enrollment-token",
		token.APIKey,
	}
	out, err := fixture.Exec(ctx, args)
	require.Errorf(t, err, "No error detected, command output: %s", out)
}

func TestInstallDefendWithMTLSandEncCertKey(t *testing.T) {
	stack := define.Require(t, define.Requirements{
		Group: integration.FleetEndpointSecurity,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		// Only supported on Linux
		OS: []define.OS{{Type: define.Linux}},
	})

	ctx := context.Background()
	testUUID := uuid.Must(uuid.NewV4()).String()
	policyID := "mTLS-defend-" + testUUID

	fleetServerURL, err := fleettools.DefaultURL(ctx, stack.KibanaClient)
	require.NoError(t, err, "failed getting Fleet Server URL")

	defaultFleetHost := strings.TrimPrefix(fleetServerURL, "https://")
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
	fleetKibanaHostmTLS, err := stack.KibanaClient.CreateFleetServerHosts(ctx, kibana.ListFleetServerHostsRequest{
		ID:        "proxyPolicymTLS" + testUUID,
		Name:      "proxyPolicymTLS" + testUUID,
		HostURLs:  []string{fleethostWrong.String()},
		IsDefault: false,
		ProxyID:   fleetProxymTLS.Item.ID,
	})
	require.NoError(t, err, "error creating fleet host with mTLS proxy")

	// add new fleet-server host with one way TLS proxy
	fleetKibanaHostOneWayTLS, err := stack.KibanaClient.CreateFleetServerHosts(ctx, kibana.ListFleetServerHostsRequest{
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
				assert.Equal(t, "<REDACTED>", got.Fleet.Ssl.Certificate)
				assert.Equal(t, "<REDACTED>", got.Fleet.Ssl.Key)
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
				assert.Equal(t, "<REDACTED>", got.Fleet.Ssl.Certificate)
				assert.Equal(t, "<REDACTED>", got.Fleet.Ssl.Key)
				assert.Equal(t, "<REDACTED>", got.Fleet.Ssl.KeyPassphrasePath)
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
				assert.Equal(t, "<REDACTED>", got.Fleet.Ssl.Certificate)
				assert.Equal(t, "<REDACTED>", got.Fleet.Ssl.Key)
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
				assert.Equal(t, "<REDACTED>", got.Fleet.Ssl.Certificate)
				assert.Equal(t, "<REDACTED>", got.Fleet.Ssl.Key)
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
				assert.Equal(t, "<REDACTED>", got.Fleet.Ssl.Certificate)
				assert.Equal(t, "<REDACTED>", got.Fleet.Ssl.Key)
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
	certificatePaths, certificatePaths, certificatePaths, *proxytest.Proxy, *proxytest.Proxy, *proxytest.Proxy,
) {
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

// TestPolicyReassignWithTamperProtectedEndpoint creates a policy with Elastic Defend (i.e. Endpoint)
// in it, making sure it has tamper protection enabled, and enrolls an Agent to this policy.  A second
// policy, also with Elastic Defend and tamper protection enabled is created, and the Agent is reassigned
// to this policy. Endpoint should not be uninstalled and reinstalled as a result of this policy reassignment
// but should be running the new policy.
func TestPolicyReassignWithTamperProtectedEndpoint(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.FleetEndpointSecurity,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	t.Log("Creating the first policy and enrollment token")
	firstPolicy := createBasicPolicy()
	policyResp, enrollKeyResp := createPolicyAndEnrollmentToken(ctx, t, info.KibanaClient, firstPolicy)

	t.Log("Install Elastic Defend")
	pkgPolicyResp, err := installElasticDefendPackage(t, info, policyResp.ID)
	require.NoErrorf(t, err, "Policy Response was: %v", pkgPolicyResp)

	t.Log("Updating the first policy to add tamper protection")
	isProtected := true
	updateReq := kibana.AgentPolicyUpdateRequest{
		Name:        firstPolicy.Name,
		Namespace:   firstPolicy.Namespace,
		IsProtected: &isProtected,
	}
	_, err = info.KibanaClient.UpdatePolicy(ctx, policyResp.ID, updateReq)
	require.NoError(t, err)

	t.Log("Install and enroll Elastic Agent with the first policy")
	opts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     true,
	}
	agentID, err := tools.InstallAgentForPolicyWithToken(ctx, t, opts, fixture, info.KibanaClient, enrollKeyResp)
	require.NoError(t, err, "failed to install Elastic Agent with the first policy")

	t.Log("Get the first policy's uninstall token")
	uninstallToken, err := tools.GetUninstallToken(ctx, info.KibanaClient, policyResp.ID)
	require.NoError(t, err, "failed to get uninstall token for the first policy")

	// Only cleanup using first policy's uninstall token if the test fails
	// before Agent is reassigned to the second policy.
	isReassigned := false
	defer func() {
		if !isReassigned {
			addEndpointCleanup(t, uninstallToken)
		}
	}()

	t.Log("Ensuring Elastic Agent and Endpoint are healthy before policy reassignment")
	agentClient := fixture.Client()
	err = agentClient.Connect(ctx)
	require.NoError(t, err, "could not connect to the initial agent")

	require.Eventually(t,
		func() bool { return agentAndEndpointAreHealthy(t, ctx, agentClient) },
		endpointHealthPollingTimeout,
		time.Second,
		"Endpoint component or units are not healthy prior to policy reassignment",
	)

	// Get Endpoint's policy ID
	firstEndpointPolicyID := getEndpointPolicyID(t, ctx)

	t.Log("Creating the second policy")
	secondPolicy := createBasicPolicy()
	policyResp, _ = createPolicyAndEnrollmentToken(ctx, t, info.KibanaClient, secondPolicy)

	t.Log("Install Elastic Defend")
	pkgPolicyResp, err = installElasticDefendPackage(t, info, policyResp.ID)
	require.NoErrorf(t, err, "Policy Response was: %v", pkgPolicyResp)

	t.Log("Updating the second policy to add tamper protection")
	updateReq = kibana.AgentPolicyUpdateRequest{
		Name:        secondPolicy.Name,
		Namespace:   secondPolicy.Namespace,
		IsProtected: &isProtected,
	}
	_, err = info.KibanaClient.UpdatePolicy(ctx, policyResp.ID, updateReq)
	require.NoError(t, err)

	t.Log("Get the second policy's uninstall token")
	uninstallToken, err = tools.GetUninstallToken(ctx, info.KibanaClient, policyResp.ID)
	require.NoError(t, err, "failed to get uninstall token for the second policy")

	// Reassign the agent to the second policy
	t.Log("Reassigning the agent to the second policy")
	policyReassignReq := kibana.AgentPolicyReassignRequest{
		PolicyID: policyResp.ID,
	}

	err = info.KibanaClient.ReassignAgentToPolicy(ctx, agentID, policyReassignReq)
	require.NoError(t, err, "failed to reassign the agent to the second policy")

	isReassigned = true // Prevents cleaning up Endpoint using first policy's uninstall token
	addEndpointCleanup(t, uninstallToken)

	t.Log("Ensuring Elastic Agent and Endpoint are healthy after policy reassignment")
	require.Eventually(t,
		func() bool { return agentAndEndpointAreHealthy(t, ctx, agentClient) },
		endpointHealthPollingTimeout,
		time.Second,
		"Endpoint component or units are not healthy after policy reassignment",
	)

	// Assert that Endpoint is running a different policy.  We use a require.Eventually here because
	// the policy reassignment can take a few seconds to propagate to Endpoint.
	t.Log("Ensuring that Endpoint is running a different policy")
	require.Eventually(t,
		func() bool {
			secondEndpointPolicyID := getEndpointPolicyID(t, ctx)
			return firstEndpointPolicyID != secondEndpointPolicyID
		},
		1*time.Minute,
		time.Second,
		"Endpoint is not running a different policy after policy reassignment",
	)
}

func getEndpointPolicyID(t *testing.T, ctx context.Context) string {
	// /opt/Elastic/Endpoint/elastic-endpoint status --output json
	cmd := exec.CommandContext(ctx, "/opt/Elastic/Endpoint/elastic-endpoint", "status", "--output", "json")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err)

	var status struct {
		ElasticEndpoint struct {
			Policy struct {
				ID string `json:"id"`
			}
		} `json:"elastic-endpoint"`
	}
	err = json.Unmarshal(output, &status)
	require.NoError(t, err)

	return status.ElasticEndpoint.Policy.ID
}

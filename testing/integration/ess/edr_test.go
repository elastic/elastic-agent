// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	"github.com/elastic/elastic-agent-libs/testing/estools"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/integration"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

const edrFlavor = "edr"

// TestEDRInstallRejectsServersFlavor verifies that an installation of the EDR flavor cannot be
// switched to another flavor at install time.
func TestEDRInstallRejectsServersFlavor(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.FleetEDR,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(5*time.Minute))
	defer cancel()

	fixture, err := define.NewFixtureFromLocalEDRBuild(t, define.Version())
	require.NoError(t, err)
	require.NoError(t, fixture.EnsurePrepared(ctx))

	versionInfo, err := fixture.ExecVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, edrFlavor, versionInfo.Binary.Flavor, "the build under test is not an EDR build")

	output, err := fixture.Install(ctx, &atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     true,
		InstallServers: true,
	})
	require.Error(t, err, "installing the servers flavor of an EDR build must fail, output: %s", output)
	assert.Contains(t, string(output), "not supported by the edr flavor")
}

// TestEDRFlavorInstallAndUpgrade installs the EDR flavor of the Elastic Agent enrolled in Fleet,
// with the System and Elastic Defend integrations, verifies that all the inputs of both integrations
// work and then upgrades the agent to a new EDR build. The upgrade must only ever use the EDR
// artifact, and everything verified before the upgrade must still hold after it.
//
// It needs the EDR packages of the build under test, built with FLAVOR=edr (or FLAVOR=basic,edr),
// to be available next to the standard ones.
func TestEDRFlavorInstallAndUpgrade(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.FleetEDR,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Windows},
		},
	})

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(45*time.Minute))
	defer cancel()

	currentVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	startFixture, err := define.NewFixtureFromLocalEDRBuild(t, define.Version())
	require.NoError(t, err, "error creating the EDR start agent fixture")
	require.NoError(t, startFixture.EnsurePrepared(ctx))

	startVersionInfo, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, edrFlavor, startVersionInfo.Binary.Flavor, "the build under test is not an EDR build")

	// Install the EDR agent enrolled in Fleet.
	policyResp, agentID, err := tools.InstallAgentWithPolicy(ctx, t,
		atesting.InstallOpts{NonInteractive: true, Force: true, Privileged: true},
		startFixture, info.KibanaClient, defaultPolicy())
	require.NoError(t, err, "failed to install the agent with a policy")
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Minute)
		defer cleanupCancel()
		assert.NoError(t, fleettools.UnEnrollAgent(cleanupCtx, info.KibanaClient, agentID))
	})

	t.Log("Installing the System integration with the policy Fleet generates from the package")
	systemInputs, err := installGeneratedPackagePolicy(ctx, info.KibanaClient, "system", integration.PreinstalledPackages["system"], policyResp.ID)
	require.NoError(t, err, "failed to install the System integration")
	t.Logf("Inputs of the generated System policy: %v", systemInputs)

	t.Log("Installing the Elastic Defend integration")
	pkgPolicyResp, err := installElasticDefendPackage(t, info, policyResp.ID)
	require.NoErrorf(t, err, "failed to install Elastic Defend, response was: %v", pkgPolicyResp)

	// Everything must work before the upgrade.
	verifyEDRAgent(ctx, t, info, startFixture, agentID, systemInputs, time.Time{})

	// Upgrade to a new build of the EDR flavor.
	newVersionBuildMetadata := "build" + time.Now().Format("20060102150405")
	parsedNewVersion := version.NewParsedSemVer(currentVersion.Major(), currentVersion.Minor(), currentVersion.Patch(), "", newVersionBuildMetadata)

	srcPackage, err := startFixture.SrcPackage(ctx)
	require.NoError(t, err, "error retrieving the start fixture source package")
	require.Contains(t, filepath.Base(srcPackage), "elastic-agent-edr-", "the start package is not an EDR package")

	versionForFixture, repackagedArchive, err := repackageArchive(t, srcPackage, newVersionBuildMetadata, currentVersion, parsedNewVersion)
	require.NoError(t, err)
	edrPackageDir := filepath.Dir(repackagedArchive)

	endFixture, err := atesting.NewFixture(t, versionForFixture.String(),
		atesting.WithFetcher(atesting.LocalFetcher(edrPackageDir, atesting.WithLocalFlavor(edrFlavor))))
	require.NoError(t, err, "error creating the EDR end agent fixture")
	require.NoError(t, endFixture.EnsurePrepared(ctx))

	endVersionInfo, err := endFixture.ExecVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, edrFlavor, endVersionInfo.Binary.Flavor, "the upgrade target is not an EDR build")

	// The watcher is configured after enrollment, keeping the agent managed by Fleet.
	require.NoError(t, startFixture.Configure(ctx, []byte("fleet.enabled: true\n"+upgradetest.FastWatcherCfg)))

	t.Run("an EDR agent does not upgrade to a package of another flavor", func(t *testing.T) {
		// The same package, but named as a package of the standard flavor, is the only one available.
		otherFlavorDir := t.TempDir()
		otherFlavorName := strings.Replace(filepath.Base(repackagedArchive), "elastic-agent-edr-", "elastic-agent-", 1)
		require.NotEqual(t, filepath.Base(repackagedArchive), otherFlavorName)
		for _, suffix := range []string{"", ".sha512"} {
			content, err := os.ReadFile(repackagedArchive + suffix)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(otherFlavorDir, otherFlavorName+suffix), content, 0o644)) //nolint:gosec // G703: path in test temp dir
		}

		output, err := startFixture.Exec(ctx, []string{"upgrade", endVersionInfo.Binary.String(),
			"--source-uri", "file://" + otherFlavorDir, "--skip-verify"})
		t.Logf("upgrade output (err: %v):\n%s", err, output)
		require.Error(t, err, "the upgrade must not use a package of another flavor")

		require.Never(t, func() bool {
			return upgradetest.CheckHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary) == nil
		}, time.Minute, 5*time.Second, "the agent must not have moved to the end version")
		require.NoError(t, upgradetest.CheckHealthyAndVersion(ctx, startFixture, startVersionInfo.Binary),
			"the agent must still be healthy at the start version")
	})

	t.Log("Upgrading to the new EDR build")
	upgradeStarted := time.Now()
	output, err := startFixture.Exec(ctx, []string{"upgrade", endVersionInfo.Binary.String(),
		"--source-uri", "file://" + edrPackageDir, "--skip-verify"})
	if err != nil {
		// The gRPC server can shut down before replying, which is expected, see PerformUpgrade.
		outputString := string(output)
		require.True(t, strings.Contains(outputString, "Unavailable") && strings.Contains(outputString, "EOF"),
			"failed to start the upgrade: %v\n%s", err, outputString)
	}

	require.NoError(t, upgradetest.WaitForWatcher(ctx, 5*time.Minute, 10*time.Second), "upgrade watcher did not start")
	require.NoError(t, upgradetest.WaitHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary, 2*time.Minute, 10*time.Second, t))
	require.NoError(t, upgradetest.WaitForNoWatcher(ctx, 12*time.Minute, 10*time.Second, 10*time.Minute+15*time.Second),
		"upgrade watcher did not finish")
	require.NoError(t, upgradetest.CheckHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary),
		"the agent was rolled back after the upgrade")

	require.Eventually(t, check.FleetAgentStatus(ctx, t, info.KibanaClient, agentID, "online"),
		5*time.Minute, 10*time.Second, "the upgraded agent is not online in Fleet")

	// Everything must still work after the upgrade, with new data collected after it started.
	verifyEDRAgent(ctx, t, info, startFixture, agentID, systemInputs, upgradeStarted)
}

// verifyEDRAgent verifies an installed EDR agent that has the System and Elastic Defend integrations:
// the flavor it is installed with and reports, the components it ships, and that all the inputs of
// both integrations are healthy and producing data. systemInputs are the enabled inputs of the
// generated System policy. When since is set, the metrics must have new data from after that time.
func verifyEDRAgent(ctx context.Context, t *testing.T, info *define.Info, fixture *atesting.Fixture, agentID string, systemInputs []string, since time.Time) {
	t.Helper()

	t.Run("flavor", func(t *testing.T) {
		versionInfo, err := fixture.ExecVersion(ctx)
		require.NoError(t, err)
		assert.Equal(t, edrFlavor, versionInfo.Binary.Flavor, "binary flavor")

		flavorFile := filepath.Join(filepath.Dir(fixture.AgentDataDir()), ".flavor")
		content, err := os.ReadFile(flavorFile)
		require.NoError(t, err, "the install must record its flavor")
		assert.Equal(t, edrFlavor, strings.TrimSpace(string(content)), "recorded flavor")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			reported, err := fleetReportedFlavor(ctx, info.KibanaClient, agentID)
			require.NoError(c, err)
			assert.Equal(c, edrFlavor, reported)
		}, 3*time.Minute, 5*time.Second, "the agent does not report the edr flavor to Fleet")
	})

	t.Run("components", testComponentsPresence(ctx, fixture,
		[]componentPresenceDefinition{
			{"elastic-otel-collector", []string{"windows", "linux", "darwin"}},
			{"endpoint-security", []string{"windows", "linux", "darwin"}},
		},
		[]componentPresenceDefinition{
			{"pf-host-agent", []string{"linux"}},
			{"cloudbeat", []string{"linux"}},
			{"apm-server", []string{"windows", "linux", "darwin"}},
			{"fleet-server", []string{"windows", "linux", "darwin"}},
			{"pf-elastic-symbolizer", []string{"linux"}},
			{"pf-elastic-collector", []string{"linux"}},
		}))

	t.Run("integrations are healthy", func(t *testing.T) {
		agentClient := fixture.Client()
		require.NoError(t, agentClient.Connect(ctx), "could not connect to the local agent")
		defer agentClient.Disconnect()

		// Every component and unit must be healthy, including every input of the System integration
		// and the Elastic Defend input and output.
		require.Eventually(t,
			func() bool { return agentAndEndpointAreHealthy(t, ctx, agentClient) },
			endpointHealthPollingTimeout, time.Second,
			"the agent, its inputs or endpoint are not healthy")
	})

	t.Run("system integration data", func(t *testing.T) {
		verifySystemIntegrationData(ctx, t, info, fixture, agentID, systemInputs, since)
	})
}

// verifySystemIntegrationData verifies that every input of the generated System policy produces
// data: the logs inputs that apply to the platform (logfile and journald on Linux, winlog on
// Windows) and the system/metrics metricsets.
func verifySystemIntegrationData(ctx context.Context, t *testing.T, info *define.Info, fixture *atesting.Fixture, agentID string, systemInputs []string, since time.Time) {
	t.Helper()

	// The generated policy must have the inputs this platform can use. The System package decides
	// by the host which of its logs inputs apply, so on Linux it needs at least one of logfile and
	// journald.
	require.Contains(t, systemInputs, "system/metrics")
	if runtime.GOOS == "windows" {
		require.Contains(t, systemInputs, "winlog")
	} else {
		require.True(t, slices.Contains(systemInputs, "logfile") || slices.Contains(systemInputs, "journald"),
			"the generated System policy has neither the logfile nor the journald input: %v", systemInputs)
	}

	// system/metrics, available on every platform. These are metricsets the System package enables
	// by default.
	metricDatasets := []string{
		"system.cpu",
		"system.memory",
		"system.network",
		"system.process",
		"system.uptime",
		"system.socket_summary",
		"system.diskio",
		"system.filesystem",
		"system.fsstat",
	}
	if runtime.GOOS != "windows" {
		// load is not available on Windows.
		metricDatasets = append(metricDatasets, "system.load")
	}
	for _, dataset := range metricDatasets {
		t.Run("system/metrics "+dataset, func(t *testing.T) {
			requireDocuments(ctx, t, info, agentID, []string{dataset}, "", since)
		})
	}

	if runtime.GOOS == "windows" {
		// winlog
		for _, dataset := range []string{"system.application", "system.system"} {
			t.Run("winlog "+dataset, func(t *testing.T) {
				requireDocuments(ctx, t, info, agentID, []string{dataset}, "", time.Time{})
			})
		}
		return
	}

	// The package applies journald or logfile depending on the host, based on conditions in the
	// generated policy. The agent only runs the ones that apply, so verify the ones it runs.
	runsJournald, runsLogfile := agentRunsLogsInputs(ctx, t, fixture)
	t.Logf("The agent runs the journald input: %t, the logfile input: %t", runsJournald, runsLogfile)
	require.True(t, runsJournald || runsLogfile, "the agent runs neither the journald nor the logfile input of the System integration")
	if runsJournald {
		t.Run("journald", func(t *testing.T) {
			requireDocuments(ctx, t, info, agentID, []string{"system.syslog", "system.auth"}, "journald", time.Time{})
		})
	}
	if runsLogfile {
		t.Run("logfile", func(t *testing.T) {
			requireDocuments(ctx, t, info, agentID, []string{"system.syslog", "system.auth"}, "", time.Time{})
		})
	}
}

// agentRunsLogsInputs returns whether the agent has components running the journald and the logfile
// inputs.
func agentRunsLogsInputs(ctx context.Context, t *testing.T, fixture *atesting.Fixture) (journald bool, logfile bool) {
	t.Helper()

	agentClient := fixture.Client()
	require.NoError(t, agentClient.Connect(ctx), "could not connect to the local agent")
	defer agentClient.Disconnect()

	state, err := agentClient.State(ctx)
	require.NoError(t, err)
	for _, comp := range state.Components {
		switch {
		case strings.HasPrefix(comp.ID, "journald-"):
			journald = true
		case strings.HasPrefix(comp.ID, "log-"):
			// logfile policies run as the log input, not as filestream, which the agent monitoring uses.
			logfile = true
		}
	}
	return journald, logfile
}

// installGeneratedPackagePolicy adds a package to a policy using only the package name and version,
// which makes Fleet generate the package policy from the defaults of the package. It returns the
// types of the inputs that are enabled in the generated package policy.
func installGeneratedPackagePolicy(ctx context.Context, kibClient *kibana.Client, packageName string, packageVersion string, policyID string) ([]string, error) {
	request := map[string]interface{}{
		"name":      fmt.Sprintf("%s-%s", packageName, uuid.Must(uuid.NewV4()).String()),
		"namespace": "default",
		"policy_id": policyID,
		"package": map[string]interface{}{
			"name":    packageName,
			"version": packageVersion,
		},
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("error marshalling the package policy request: %w", err)
	}

	resp, err := kibClient.SendWithContext(ctx, http.MethodPost, "/api/fleet/package_policies", nil, nil, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("error creating the package policy: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading the package policy response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("creating the package policy returned %d: %s", resp.StatusCode, responseBody)
	}

	var created struct {
		Item struct {
			Inputs []struct {
				Type    string `json:"type"`
				Enabled bool   `json:"enabled"`
			} `json:"inputs"`
		} `json:"item"`
	}
	if err := json.Unmarshal(responseBody, &created); err != nil {
		return nil, fmt.Errorf("error decoding the package policy response: %w", err)
	}
	var enabled []string
	for _, input := range created.Item.Inputs {
		if input.Enabled {
			enabled = append(enabled, input.Type)
		}
	}
	return enabled, nil
}

// requireDocuments waits until there is at least a document of one of the datasets for the agent,
// optionally only of the given input type and only newer than since.
func requireDocuments(ctx context.Context, t *testing.T, info *define.Info, agentID string, datasets []string, inputType string, since time.Time) {
	t.Helper()

	must := []map[string]interface{}{
		{"match": map[string]interface{}{"agent.id": agentID}},
	}
	if inputType != "" {
		must = append(must, map[string]interface{}{"match": map[string]interface{}{"input.type": inputType}})
	}
	filter := []map[string]interface{}{
		{"terms": map[string]interface{}{"data_stream.dataset": datasets}},
	}
	if !since.IsZero() {
		filter = append(filter, map[string]interface{}{
			"range": map[string]interface{}{"@timestamp": map[string]interface{}{"gte": since.UTC().Format(time.RFC3339)}},
		})
	}
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{"must": must, "filter": filter},
		},
	}

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		docs, err := estools.PerformQueryForRawQuery(ctx, query, "*-*", info.ESClient)
		require.NoError(c, err, "error querying Elasticsearch")
		assert.Greater(c, docs.Hits.Total.Value, 0, "no documents for datasets %v (input %q, since %s)", datasets, inputType, since)
	}, 4*time.Minute, 5*time.Second, "no data in Elasticsearch for datasets %v (input %q)", datasets, inputType)
}

// fleetReportedFlavor returns the flavor the agent reports to Fleet in its local metadata.
func fleetReportedFlavor(ctx context.Context, kibClient *kibana.Client, agentID string) (string, error) {
	resp, err := kibClient.SendWithContext(ctx, http.MethodGet, fmt.Sprintf("/api/fleet/agents/%s", agentID), nil, nil, nil)
	if err != nil {
		return "", fmt.Errorf("error getting the agent from Fleet: %w", err)
	}
	defer resp.Body.Close()

	var body struct {
		Item struct {
			LocalMetadata struct {
				Elastic struct {
					Agent struct {
						Flavor string `json:"flavor"`
					} `json:"agent"`
				} `json:"elastic"`
			} `json:"local_metadata"`
		} `json:"item"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("error decoding the agent from Fleet: %w", err)
	}
	if body.Item.LocalMetadata.Elastic.Agent.Flavor == "" {
		return "", fmt.Errorf("the agent has not reported a flavor to Fleet yet")
	}
	return body.Item.LocalMetadata.Elastic.Agent.Flavor, nil
}

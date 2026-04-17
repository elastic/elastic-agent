// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/snapshots"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/integration"
)

func TestRpmLogIngestFleetManaged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.RPM,
		Stack: &define.Stack{},
		OS: []define.OS{
			{
				Type:   define.Linux,
				Distro: "rhel",
			},
		},
		Local: false,
		Sudo:  true,
	})

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), atesting.WithPackageFormat("rpm"))
	require.NoError(t, err)

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		InstallServers: false,
	}

	testRpmLogIngestFleetManagedWithCheck(ctx, t, agentFixture, info, installOpts,
		testComponentsPresence(ctx, agentFixture,
			[]componentPresenceDefinition{
				{"elastic-otel-collector", []string{"windows", "linux", "darwin"}},
				{"endpoint-security", []string{"windows", "linux", "darwin"}},
				{"pf-host-agent", []string{"linux"}},
			},
			[]componentPresenceDefinition{
				{"cloudbeat", []string{"linux"}},
				{"apm-server", []string{"windows", "linux", "darwin"}},
				{"fleet-server", []string{"windows", "linux", "darwin"}},
				{"pf-elastic-symbolizer", []string{"linux"}},
				{"pf-elastic-collector", []string{"linux"}},
			},
		),
	)
}

func TestRpmInstallsServers(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Deb,
		Stack: &define.Stack{},
		OS: []define.OS{
			{
				Type:   define.Linux,
				Distro: "rhel",
			},
		},
		Local: false,
		Sudo:  true,
	})

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), atesting.WithPackageFormat("rpm"))
	require.NoError(t, err)

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		InstallServers: true,
	}

	testRpmLogIngestFleetManagedWithCheck(ctx, t, agentFixture, info, installOpts,
		testComponentsPresence(ctx, agentFixture,
			[]componentPresenceDefinition{
				{"elastic-otel-collector", []string{"windows", "linux", "darwin"}},
				{"endpoint-security", []string{"windows", "linux", "darwin"}},
				{"pf-host-agent", []string{"linux"}},
				{"cloudbeat", []string{"linux"}},
				{"apm-server", []string{"windows", "linux", "darwin"}},
				{"fleet-server", []string{"windows", "linux", "darwin"}},
				{"pf-elastic-symbolizer", []string{"linux"}},
				{"pf-elastic-collector", []string{"linux"}},
			},
			[]componentPresenceDefinition{},
		),
	)
}

func testRpmLogIngestFleetManagedWithCheck(ctx context.Context, t *testing.T, agentFixture *atesting.Fixture, info *define.Info, installOpts atesting.InstallOpts, componentCheck func(t *testing.T)) {
	// 1. Create a policy in Fleet with monitoring enabled.
	// To ensure there are no conflicts with previous test runs against
	// the same ESS stack, we add the current time at the end of the policy
	// name. This policy does not contain any integration.
	t.Log("Enrolling agent in Fleet with a test policy")
	createPolicyReq := kibana.AgentPolicy{
		Name:        fmt.Sprintf("test-policy-enroll-%s", uuid.Must(uuid.NewV4()).String()),
		Namespace:   info.Namespace,
		Description: "test policy for agent enrollment",
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
		AgentFeatures: []map[string]interface{}{
			{
				"name":    "test_enroll",
				"enabled": true,
			},
		},
	}

	// 2. Install the Elastic-Agent with the policy that
	// was just created.
	policy, _, err := tools.InstallAgentWithPolicy(
		ctx,
		t,
		installOpts,
		agentFixture,
		info.KibanaClient,
		createPolicyReq)
	require.NoError(t, err)
	t.Logf("created policy: %s", policy.ID)
	check.ConnectedToFleet(ctx, t, agentFixture, 5*time.Minute)

	if componentCheck != nil {
		t.Run("check components set", componentCheck)
	}

	t.Run("Monitoring logs are shipped", func(t *testing.T) {
		integration.TestMonitoringLogsAreShipped(t, ctx, info, agentFixture, policy)
	})

	t.Run("Normal logs with flattened data_stream are shipped", func(t *testing.T) {
		integration.TestFlattenedDatastreamFleetPolicy(t, ctx, info, policy)
	})
}

func TestRpmFleetUpgrade(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.RPM,
		Stack: &define.Stack{},
		OS: []define.OS{
			{
				Type:   define.Linux,
				Distro: "rhel",
			},
		},
		Local: false,
		Sudo:  true,
	})

	testCases := []struct {
		name               string
		upgradeFromVersion *version.ParsedSemVer
		installingServers  bool
		expectingServers   bool
	}{
		{"legacy installation", version.NewParsedSemVer(8, 17, 3, "", ""), false, true},   // in case of legacy we don't apply flavor, expecting all to be preserved
		{"9.0 with basic flavor", version.NewParsedSemVer(9, 0, 0, "", ""), false, false}, // TODO: 9.0.0 is the first version to support installing servers. when 9.1.0 is released, this can be replaced by upgradetest.PreviousMinor()
		{"9.0 with servers flavor", version.NewParsedSemVer(9, 0, 0, "", ""), true, true}, // TODO: 9.0.0 is the first version to support installing servers. when 9.1.0 is released, this can be replaced by upgradetest.PreviousMinor()
	}

	currentVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	for _, tc := range testCases {
		if !tc.upgradeFromVersion.Less(*currentVersion) {
			// allow only upgrades to higher versions
			continue
		}

		t.Run(fmt.Sprintf("Upgrade RPM from %s - %q", tc.upgradeFromVersion.String(), tc.name), func(t *testing.T) {
			testRpmUpgrade(t, tc.upgradeFromVersion, info, tc.installingServers, tc.expectingServers, "")
		})
	}
}

func testRpmUpgrade(t *testing.T, upgradeFromVersion *version.ParsedSemVer, info *define.Info, installingServers bool, expectingServers bool, prefix string) {
	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// start from snapshot of the rpm
	startFixture, err := atesting.NewFixture(
		t,
		upgradeFromVersion.String(),
		atesting.WithFetcher(atesting.ArtifactFetcher()),
		atesting.WithPackageFormat("rpm"),
	)
	require.NoError(t, err)

	// end on the current build with rpm
	endFixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), atesting.WithPackageFormat("rpm"))
	require.NoError(t, err)

	// 1. Create a policy in Fleet with monitoring enabled.
	// To ensure there are no conflicts with previous test runs against
	// the same ESS stack, we add the current time at the end of the policy
	// name. This policy does not contain any integration.
	t.Log("Enrolling agent in Fleet with a test policy")
	createPolicyReq := kibana.AgentPolicy{
		Name:        fmt.Sprintf("test-policy-enroll-%s", uuid.Must(uuid.NewV4()).String()),
		Namespace:   info.Namespace,
		Description: "test policy for agent enrollment",
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
		AgentFeatures: []map[string]interface{}{
			{
				"name":    "test_enroll",
				"enabled": true,
			},
		},
	}

	installOpts := atesting.InstallOpts{
		BasePath:       prefix,
		NonInteractive: true,
		Force:          true,
		InstallServers: installingServers,
	}

	// 2. Install the Elastic-Agent with the policy that
	// was just created.
	policy, agentID, err := tools.InstallAgentWithPolicy(
		ctx,
		t,
		installOpts,
		startFixture,
		info.KibanaClient,
		createPolicyReq)
	require.NoError(t, err)
	t.Logf("created policy: %s", policy.ID)

	check.ConnectedToFleet(ctx, t, startFixture, 5*time.Minute)

	const migrationMarkerFile = "migration_marker.file"
	runDir, err := atesting.FindRunDir(startFixture)
	require.NoError(t, err, "failed at getting run dir")

	runMigrationMarker := filepath.Join(runDir, migrationMarkerFile)
	f, err := os.Create(runMigrationMarker)
	require.NoErrorf(t, err, "failed to create %q file", runMigrationMarker)
	_ = f.Close()

	// 3. Upgrade rpm to the build version
	srcPackage, err := endFixture.SrcPackage(ctx)
	require.NoError(t, err)
	cmdArgs := []string{"rpm", "-U", "-v"}
	if prefix != "" {
		cmdArgs = append(cmdArgs, "--prefix", prefix)
	}
	cmdArgs = append(cmdArgs, srcPackage)
	out, err := exec.CommandContext(ctx, "sudo", cmdArgs...).CombinedOutput() // #nosec G204 -- Need to pass in name of package
	require.NoError(t, err, string(out))

	// Inform endFixture of the install prefix so FindRunDir resolves the
	// correct data directory (e.g. /opt/elastic-agent/var/lib/elastic-agent).
	if prefix != "" {
		endFixture.SetInstallBasePath(prefix)
		// RPM scriptlets do not restart the service for prefix installs; do it explicitly.
		out, err = exec.CommandContext(ctx, "sudo", "systemctl", "restart", "elastic-agent").CombinedOutput()
		require.NoError(t, err, string(out))

		t.Run("service file is not a symlink into prefix after upgrade", func(t *testing.T) {
			checkServiceFileNotSymlinkInPrefix(t, prefix)
		})
	}

	newRunDir, err := atesting.FindRunDir(endFixture)
	require.NoError(t, err, "failed at getting run dir")
	require.NotEqual(t, runDir, newRunDir, "the run dirs from upgrade should not match")
	newRunMigrationMarker := filepath.Join(newRunDir, migrationMarkerFile)
	require.FileExistsf(t, newRunMigrationMarker, "%q is missing", newRunMigrationMarker)

	// 4. Wait for version in Fleet to match
	// Fleet will not include the `-SNAPSHOT` in the `GetAgentVersion` result
	noSnapshotVersion := strings.TrimSuffix(define.Version(), "-SNAPSHOT")
	require.Eventually(t, func() bool {
		t.Log("Getting Agent version...")
		newVersion, err := fleettools.GetAgentVersion(ctx, info.KibanaClient, agentID)
		if err != nil {
			t.Logf("error getting agent version: %v", err)
			return false
		}
		if noSnapshotVersion == newVersion {
			return true
		}
		t.Logf("Got Agent version %s != %s", newVersion, noSnapshotVersion)
		return false
	}, 5*time.Minute, time.Second)

	// 5. verify basic flavor is preserved
	if expectingServers {
		// for previous versions full install should be preserved
		t.Run("check components set", testComponentsPresence(ctx, endFixture,
			[]componentPresenceDefinition{
				{"elastic-otel-collector", []string{"windows", "linux", "darwin"}},
				{"endpoint-security", []string{"windows", "linux", "darwin"}},
				{"pf-host-agent", []string{"linux"}},
				{"cloudbeat", []string{"linux"}},
				{"apm-server", []string{"windows", "linux", "darwin"}},
				{"fleet-server", []string{"windows", "linux", "darwin"}},
				{"pf-elastic-symbolizer", []string{"linux"}},
				{"pf-elastic-collector", []string{"linux"}},
			},
			[]componentPresenceDefinition{},
		))
	} else {
		// for 9.0+ versions basic install should be preserved
		t.Run("check components set", testComponentsPresence(ctx, endFixture,
			[]componentPresenceDefinition{
				{"elastic-otel-collector", []string{"windows", "linux", "darwin"}},
				{"endpoint-security", []string{"windows", "linux", "darwin"}},
				{"pf-host-agent", []string{"linux"}},
			},
			[]componentPresenceDefinition{
				{"cloudbeat", []string{"linux"}},
				{"apm-server", []string{"windows", "linux", "darwin"}},
				{"fleet-server", []string{"windows", "linux", "darwin"}},
				{"pf-elastic-symbolizer", []string{"linux"}},
				{"pf-elastic-collector", []string{"linux"}},
			},
		))
	}
}

// checkServiceFileNotSymlinkInPrefix asserts that the systemd service file at
// /lib/systemd/system/elastic-agent.service is a regular file (not a symlink into
// the prefix mount), and that /etc/systemd/system/elastic-agent.service (if present)
// does not point into the prefix. A symlink into the prefix breaks service startup
// at boot when the prefix mount is not yet available.
func checkServiceFileNotSymlinkInPrefix(t *testing.T, prefix string) {
	t.Helper()

	libService := "/lib/systemd/system/elastic-agent.service"
	fi, err := os.Lstat(libService)
	require.NoError(t, err, "%s should exist after prefix installation", libService)
	require.Zero(t, fi.Mode()&os.ModeSymlink, "%s must be a regular file, not a symlink into the prefix mount", libService)

	etcService := "/etc/systemd/system/elastic-agent.service"
	fi, err = os.Lstat(etcService)
	if err == nil && fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(etcService)
		require.NoError(t, err)
		require.False(t, strings.HasPrefix(target, prefix),
			"%s symlink target %q must not point into prefix %s", etcService, target, prefix)
	}
}

func TestRpmWithPrefix(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.RPM,
		Stack: &define.Stack{},
		OS: []define.OS{
			{
				Type:   define.Linux,
				Distro: "rhel",
			},
		},
		Local: false,
		Sudo:  true,
	})

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), atesting.WithPackageFormat("rpm"))
	require.NoError(t, err)

	installOpts := atesting.InstallOpts{
		BasePath:       "/opt/elastic-agent",
		NonInteractive: true,
		Force:          true,
		InstallServers: false,
	}
	testRpmLogIngestFleetManagedWithCheck(ctx, t, agentFixture, info, installOpts, nil)

	t.Run("service file is not a symlink into prefix after install", func(t *testing.T) {
		checkServiceFileNotSymlinkInPrefix(t, installOpts.BasePath)
	})

	t.Run("upgrade to latest snapshot", func(t *testing.T) {
		ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(10*time.Minute))
		defer cancel()

		currentVersion, err := version.ParseVersion(define.Version())
		require.NoError(t, err)
		branch := fmt.Sprintf("%d.%d", currentVersion.Major(), currentVersion.Minor())

		snapshotClient := snapshots.NewSnapshotsClient()
		latestSnapshots, err := snapshotClient.FindLatestSnapshots(ctx, []string{branch})
		require.NoError(t, err)
		if len(latestSnapshots) == 0 {
			t.Skipf("no snapshot found for branch %s, skipping upgrade test", branch)
		}

		snapshotFixture, err := atesting.NewFixture(
			t,
			latestSnapshots[0].String(),
			atesting.WithFetcher(atesting.ArtifactFetcher()),
			atesting.WithPackageFormat("rpm"),
		)
		require.NoError(t, err)

		snapshotPackage, err := snapshotFixture.SrcPackage(ctx)
		require.NoError(t, err)
		snapshotFixture.SetInstallBasePath("/opt/elastic-agent")

		// When the snapshot version differs from the local build, set up a
		// migration marker so we can verify the data directory migration after
		// upgrade. When versions match (same patch), the agent reuses the
		// existing data directory so there is no migration to verify.
		sameVersion := define.Version() == snapshotFixture.Version()
		var runDir string
		const migrationMarkerFile = "migration_marker.file"
		if !sameVersion {
			runDir, err = atesting.FindRunDir(agentFixture)
			require.NoError(t, err, "failed at getting run dir")
			runMigrationMarker := filepath.Join(runDir, migrationMarkerFile)
			f, err := os.Create(runMigrationMarker)
			require.NoErrorf(t, err, "failed to create %q file", runMigrationMarker)
			_ = f.Close()
		}

		// --force is needed because the latest snapshot version may match the
		// locally built version (same patch), causing RPM to reject the upgrade
		// with "already installed" errors.
		out, err := exec.CommandContext(ctx, "sudo", "rpm", "-U", "-v", "--force", "--prefix", "/opt/elastic-agent", snapshotPackage).CombinedOutput()
		require.NoError(t, err, string(out))

		// RPM scriptlets do not restart the service for prefix installs; do it explicitly.
		out, err = exec.CommandContext(ctx, "sudo", "systemctl", "restart", "elastic-agent").CombinedOutput()
		require.NoError(t, err, string(out))

		t.Run("service file is not a symlink into prefix after upgrade", func(t *testing.T) {
			checkServiceFileNotSymlinkInPrefix(t, "/opt/elastic-agent")
		})

		if !sameVersion {
			newRunDir, err := atesting.FindRunDir(snapshotFixture)
			require.NoError(t, err, "failed at getting run dir")
			require.NotEqual(t, runDir, newRunDir, "the run dirs from upgrade should not match")
			newRunMigrationMarker := filepath.Join(newRunDir, migrationMarkerFile)
			require.FileExistsf(t, newRunMigrationMarker, "%q is missing", newRunMigrationMarker)
		}

		status, err := agentFixture.ExecStatus(ctx)
		require.NoError(t, err)
		agentID := status.Info.ID

		noSnapshotVersion := strings.TrimSuffix(snapshotFixture.Version(), "-SNAPSHOT")
		require.Eventually(t, func() bool {
			t.Log("Getting Agent version...")
			newVersion, err := fleettools.GetAgentVersion(ctx, info.KibanaClient, agentID)
			if err != nil {
				t.Logf("error getting agent version: %v", err)
				return false
			}
			if noSnapshotVersion == newVersion {
				return true
			}
			t.Logf("Got Agent version %s != %s", newVersion, noSnapshotVersion)
			return false
		}, 5*time.Minute, time.Second)

		t.Run("check components set", testComponentsPresence(ctx, snapshotFixture,
			[]componentPresenceDefinition{
				{"elastic-otel-collector", []string{"windows", "linux", "darwin"}},
				{"endpoint-security", []string{"windows", "linux", "darwin"}},
				{"pf-host-agent", []string{"linux"}},
			},
			[]componentPresenceDefinition{
				{"cloudbeat", []string{"linux"}},
				{"apm-server", []string{"windows", "linux", "darwin"}},
				{"fleet-server", []string{"windows", "linux", "darwin"}},
				{"pf-elastic-symbolizer", []string{"linux"}},
				{"pf-elastic-collector", []string{"linux"}},
			},
		))
	})
}

// TestRpmWithPrefix upgrade tests upgrading from 9.3.1 -> local build
func TestRpmWithPrefixUpgrade(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.RPM,
		Stack: &define.Stack{},
		OS: []define.OS{
			{
				Type:   define.Linux,
				Distro: "rhel",
			},
		},
		Local: false,
		Sudo:  true,
	})
	currentVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)
	fromVersion := version.NewParsedSemVer(9, 3, 1, "", "") // earliest patch of the 9.3.x release that has --prefix support

	// sanity check
	if !fromVersion.Less(*currentVersion) {
		t.Skipf("unexpected upgrade sequence, %s is not less then %s", fromVersion.String(), currentVersion.String())
	}
	testRpmUpgrade(t, fromVersion, info, false, false, "/opt/elastic-agent")
}

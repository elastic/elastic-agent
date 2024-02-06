package integration

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/dev-tools/mage"
	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/upgradetest"
	agtversion "github.com/elastic/elastic-agent/version"
)

func TestStandaloneUpgradeSameCommit(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Upgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	// we upgrade unto the same version
	currentVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	// 8.13.0-SNAPSHOT is the minimum version we need for testing upgrading with the same hash
	if currentVersion.Less(*upgradetest.Version_8_13_0_SNAPSHOT) {
		t.Skipf("Minimum version for running this test is %q, current version: %q", *upgradetest.Version_8_13_0_SNAPSHOT, currentVersion)
	}

	unprivilegedAvailable := true
	if runtime.GOOS != define.Linux {
		// only available on Linux at the moment
		unprivilegedAvailable = false
	}
	// This is probably redundant: see the skip statement above
	if unprivilegedAvailable && (currentVersion.Less(*upgradetest.Version_8_13_0) || currentVersion.Less(*upgradetest.Version_8_13_0)) {
		// only available if both versions are 8.13+
		unprivilegedAvailable = false
	}

	t.Run(fmt.Sprintf("Upgrade on the same version %s to %s (privileged)", currentVersion, currentVersion), func(t *testing.T) {
		// ensure we use the same package version
		err := testStandaloneUpgradeWithLocalArtifactFetcher(t, currentVersion, currentVersion.String(), false)
		assert.ErrorContainsf(t, err, fmt.Sprintf("agent version is already %s", currentVersion), "upgrade should fail indicating we are already at the same version")
	})
	if unprivilegedAvailable {
		t.Run(fmt.Sprintf("Upgrade on the same version %s to %s (unprivileged)", currentVersion, currentVersion), func(t *testing.T) {
			// ensure we use the same package version
			err := testStandaloneUpgradeWithLocalArtifactFetcher(t, currentVersion, currentVersion.String(), true)
			assert.ErrorContainsf(t, err, fmt.Sprintf("agent version is already %s", currentVersion), "upgrade should fail indicating we are already at the same version")
		})
	}

}

func testStandaloneUpgradeWithLocalArtifactFetcher(t *testing.T, startVersion *version.ParsedSemVer, endVersion string, unprivileged bool) error {
	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	startFixture, err := define.NewFixture(
		t,
		startVersion.String(),
	)
	require.NoError(t, err, "error creating previous agent fixture")

	endFixture, err := define.NewFixture(t, endVersion)

	err = upgradetest.PerformUpgrade(ctx, startFixture, endFixture, t,
		upgradetest.WithUnprivileged(unprivileged),
		upgradetest.WithDisableHashCheck(true),
	)

	return err

}

func TestBogusRepackage(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Upgrade,
		Local: true,
		Sudo:  false,
	})

	startFixture, err := define.NewFixture(
		t,
		define.Version(),
	)

	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Minute)
	defer cancel()

	err = startFixture.EnsurePrepared(ctx)
	require.NoErrorf(t, err, "fixture should be prepared")

	// the fixture must be prepared but NOT installed
	require.False(t, startFixture.IsInstalled(), "Fixture must not be installed to repackage the agent")

	srcPackage, err := startFixture.SrcPackage(ctx)
	require.NoErrorf(t, err, "error retrieving start fixture source package")

	originalPackageFileName := filepath.Base(srcPackage)

	parsedCurrentVersion, err := version.ParseVersion(define.Version())
	require.NoErrorf(t, err, "define.Version() string %q must be a valid agent version", define.Version())

	newVersionBuildMetadata := time.Now().Format("20060102150405")
	parsedNewVersion := version.NewParsedSemVer(parsedCurrentVersion.Major(), parsedCurrentVersion.Minor(), parsedCurrentVersion.Patch(), "", newVersionBuildMetadata)

	repackageExtractedAgent(t, startFixture.WorkDir(), parsedCurrentVersion, parsedNewVersion)

	t.Logf("srcPackage: %q originalPackageName: %q", srcPackage, originalPackageFileName)

	//dump logs
	assert.True(t, false)
}
func repackageExtractedAgent(t *testing.T, extractedPackageDir string, parsedCurrentVersion, parsedNewVersion *version.ParsedSemVer) string {
	workDir := extractedPackageDir
	t.Logf("fixture workdir: %q", workDir)
	topDir := filepath.Base(workDir)
	modifiedTopDir := strings.Replace(topDir, parsedCurrentVersion.String(), parsedNewVersion.String(), 1)
	modifiedTmp := t.TempDir()
	absModifiedTopDir := filepath.Join(modifiedTmp, modifiedTopDir)
	err := copy.Copy(workDir, absModifiedTopDir, copy.Options{NumOfWorkers: 4})
	require.NoErrorf(t, err, "error copying source package from %q to %q", workDir, absModifiedTopDir)

	modifyVersionForPackage(t, parsedNewVersion, absModifiedTopDir)
	manifestBytes, err := os.ReadFile(filepath.Join(absModifiedTopDir, "manifest.yaml"))
	require.NoError(t, err, "manifest file should be readable after modification")
	t.Logf("manifest file after rewrite:\n%s\n", string(manifestBytes))

	// TODO compress the modified directory, regenerate SHA and return the package full path location
	return absModifiedTopDir
}

func modifyVersionForPackage(t *testing.T, version *version.ParsedSemVer, extractedPackagePath string) {
	rewriteManifestFile(t, version, extractedPackagePath)
	err := rewritePackageVersionFile(version, extractedPackagePath)
	require.NoError(t, err, "error modifying agent package version file")
}

func rewritePackageVersionFile(version *version.ParsedSemVer, extractedPackagePath string) error {
	return filepath.WalkDir(extractedPackagePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.Name() == agtversion.PackageVersionFileName {
			info, err := d.Info()
			if err != nil {
				return fmt.Errorf("error getting info for agent package version file %q: %w", path, err)
			}
			err = os.WriteFile(path, []byte(version.String()), info.Mode())
			if err != nil {
				return fmt.Errorf("error writing new version in agent package version file %q: %w", path, err)
			}
		}
		return nil
	})
}

func rewriteManifestFile(t *testing.T, version *version.ParsedSemVer, extractedPackagePath string) {
	t.Logf("Start rewriting manifest for version %q", version)

	manifestPath := filepath.Join(extractedPackagePath, v1.ManifestFileName)
	require.FileExistsf(t, manifestPath, "%q manifest file should exist in the extracted package at %q", manifestPath, extractedPackagePath)

	// parse manifest, change version and snapshot flag and rewrite
	manifestFileBytes, err := os.ReadFile(manifestPath)
	require.NoErrorf(t, err, "reading file manifest %q for extracted package %q", manifestPath, extractedPackagePath)
	manifest, err := v1.ParseManifest(bytes.NewReader(manifestFileBytes))
	require.NoError(t, err, "parsing manifest file")

	packageDesc := manifest.Package
	previousSnapshot := packageDesc.Snapshot
	fullHash := packageDesc.Hash

	newManifest, err := mage.GeneratePackageManifest("elastic-agent", version.String(), previousSnapshot, fullHash, fullHash[:6])
	require.NoErrorf(t, err, "GeneratePackageManifest(%v, %v, %v, %v) failed", version.String(), previousSnapshot, fullHash, fullHash[:6])
	t.Logf("New manifest for repackaged version:\n%s", newManifest)
	stat, err := os.Stat(manifestPath)
	require.NoErrorf(t, err, "unable to Stat() manifest file %q", manifestPath)

	err = os.WriteFile(manifestPath, []byte(newManifest), stat.Mode())
	require.NoErrorf(t, err, "error writing manifest file %q", manifestPath)
}

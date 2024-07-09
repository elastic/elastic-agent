// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/upgradetest"
	agtversion "github.com/elastic/elastic-agent/version"
)

func TestUpgradeBrokenPackageVersion(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Upgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Start at the build version as we want to test the retry
	// logic that is in the build.
	startFixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), atesting.WithAdditionalArgs([]string{"-E", "output.elasticsearch.allow_older_versions=true"}))
	require.NoError(t, err)

	// This test won't work if the version in code and the one in package version file differ, check and skip it if we detect a version bump
	skipTestIfVersionIsBumped(ctx, t, startFixture)

	// Upgrade to an old build.
	upgradeToVersion, err := upgradetest.PreviousMinor()
	require.NoError(t, err)
	endFixture, err := atesting.NewFixture(
		t,
		upgradeToVersion.String(),
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)

	// Pre-upgrade remove the package version files.
	preUpgradeHook := func() error {
		// get rid of the package version files in the installed directory
		return removePackageVersionFiles(t, startFixture)
	}

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", define.Version(), upgradeToVersion)

	err = upgradetest.PerformUpgrade(ctx, startFixture, endFixture, t, upgradetest.WithPreUpgradeHook(preUpgradeHook))
	assert.NoError(t, err)
}

func skipTestIfVersionIsBumped(ctx context.Context, t *testing.T, startFixture *atesting.Fixture) {
	err := startFixture.EnsurePrepared(ctx)
	require.NoError(t, err, "error preparing startFixture")

	workDir := startFixture.WorkDir()
	packageVersionFiles, err := findPackageVersionFiles(workDir)
	require.NoErrorf(t, err, "error searching for package.version files in startFixture workdir %q", workDir)
	require.NotEmpty(t, packageVersionFiles, "there should be at least one package.version file in startFixture root dir %q", workDir)

	packageVersionBytes, err := os.ReadFile(filepath.Join(workDir, packageVersionFiles[0]))
	require.NoError(t, err, "error reading package.version file from startFixture in %q", workDir)
	agentPackageVersion := string(packageVersionBytes)
	if agtversion.GetDefaultVersion() != agentPackageVersion {
		t.Skipf(
			"Package version %q and default version %q differ: this means that we are probably running a bumped version of agent pinned as previous, skipping...",
			agentPackageVersion,
			agtversion.GetDefaultVersion(),
		)
	}
}

func removePackageVersionFiles(t *testing.T, f *atesting.Fixture) error {
	rootDir := f.WorkDir()
	matches, err := findPackageVersionFiles(rootDir)
	if err != nil {
		return err
	}

	t.Logf("package version files found: %v", matches)

	// the version files should have been removed from the other test, we just make sure
	for _, m := range matches {
		vFile := filepath.Join(rootDir, m)
		t.Logf("removing package version file %q", vFile)
		err = os.Remove(vFile)
		if err != nil {
			return fmt.Errorf("error removing package version file %q: %w", vFile, err)
		}
	}
	return nil
}

func findPackageVersionFiles(rootDir string) ([]string, error) {
	installFS := os.DirFS(rootDir)
	matches := []string{}

	err := fs.WalkDir(installFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.Name() == agtversion.PackageVersionFileName {
			matches = append(matches, path)
		}
		return nil
	})
	return matches, err
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgradetest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/version"
)

var (
	// Version_8_2_0 is the first version to include --non-interactive flag during install
	Version_8_2_0 = version.NewParsedSemVer(8, 2, 0, "", "")
	// Version_8_6_0 is the first version to use agent v2 protocol
	Version_8_6_0 = version.NewParsedSemVer(8, 6, 0, "", "")
	// Version_8_7_0 is the minimum version for passing --skip-verify when upgrading
	Version_8_7_0 = version.NewParsedSemVer(8, 7, 0, "", "")
	// Version_8_9_0_SNAPSHOT is the minimum version for upgrade to specific snapshot + minimum version
	// for setting shorter watch period after upgrade
	Version_8_9_0_SNAPSHOT = version.NewParsedSemVer(8, 9, 0, "SNAPSHOT", "")
	// Version_8_10_0_SNAPSHOT is the minimum version for upgrade with remote pgp and skipping
	// default pgp verification
	Version_8_10_0_SNAPSHOT = version.NewParsedSemVer(8, 10, 0, "SNAPSHOT", "")
	// Version_8_11_0_SNAPSHOT is the minimum version for uninstall command to kill the watcher upon uninstall
	Version_8_11_0_SNAPSHOT = version.NewParsedSemVer(8, 11, 0, "SNAPSHOT", "")
	// Version_8_13_0_SNAPSHOT is the minimum version for testing upgrading agent with the same hash
	Version_8_13_0_SNAPSHOT = version.NewParsedSemVer(8, 13, 0, "SNAPSHOT", "")
	// Version_8_14_0_SNAPSHOT is the minimum version for proper unprivileged execution on all platforms
	Version_8_14_0_SNAPSHOT = version.NewParsedSemVer(8, 14, 0, "SNAPSHOT", "")

	// ErrNoSnapshot is returned when a requested snapshot is not on the version list.
	ErrNoSnapshot = errors.New("failed to find a snapshot on the version list")
	// ErrNoPreviousMinor is returned when a requested previous minor is not on the version list.
	ErrNoPreviousMinor = errors.New("failed to find a previous minor on the version list")
)

type VersionsFetcher interface {
	FetchAgentVersions(ctx context.Context) (version.SortableParsedVersions, error)
}

type SnapshotFetcher interface {
	FindLatestSnapshots(ctx context.Context, branches []string) (version.SortableParsedVersions, error)
}

// VersionRequirements is to set requirements for upgradable versions while fetching them.
//
// Keep in mind that requirements can overlap. For example 2 previous minors might already
// cover 2 current majors, so the results would be combined.
//
// `SnapshotBranches` is a list of active release branches used for finding latest snapshots on them.
// A branch might have no snapshot, in this case it's getting silently skipped.
type VersionRequirements struct {
	UpgradeToVersion string
	CurrentMajors    int
	PreviousMajors   int
	PreviousMinors   int
	SnapshotBranches []string
}

var AgentVersionsFilename string

type AgentVersions struct {
	// TestVersions contains semver-compliant versions of the agent to run integration tests against.
	TestVersions []string `yaml:"testVersions"`
}

var (
	agentVersions *AgentVersions
)

func init() {
	AgentVersionsFilename = filepath.Join("testing", "integration", "testdata", ".upgrade-test-agent-versions.yml")

	v, err := getAgentVersions()
	if err != nil {
		panic(err)
	}
	agentVersions = v
}

func getAgentVersions() (*AgentVersions, error) {
	var (
		filePath string
		dir      string
	)
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get the current directory: %w", err)
	}
	dir = wd
	for {
		pathToCheck := filepath.Join(dir, AgentVersionsFilename)
		fi, err := os.Stat(pathToCheck)
		if (err == nil || os.IsExist(err)) && !fi.IsDir() {
			filePath = pathToCheck
			break
		}
		if strings.HasSuffix(dir, string(filepath.Separator)) {
			return nil, fmt.Errorf("failed to find %s using working directory %s", AgentVersionsFilename, wd)
		}
		dir = filepath.Dir(dir)
	}

	f, err := os.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", filePath, err)
	}
	defer f.Close()

	d := yaml.NewDecoder(f)
	var versionFile AgentVersions
	err = d.Decode(&versionFile)
	if err != nil {
		return nil, fmt.Errorf("failed to decode YAML in %s: %w", filePath, err)
	}

	return &versionFile, nil
}

// GetUpgradableVersions returns the versions list from the agent version file. The list
// is sorted in descending order (newer versions first).
func GetUpgradableVersions() ([]*version.ParsedSemVer, error) {
	parsedVersions := make([]*version.ParsedSemVer, 0, len(agentVersions.TestVersions))
	for _, v := range agentVersions.TestVersions {
		parsed, err := version.ParseVersion(v)
		if err != nil {
			return nil, fmt.Errorf("failed to parse version %q from %s: %w", v, AgentVersionsFilename, err)
		}
		parsedVersions = append(parsedVersions, parsed)
	}

	return parsedVersions, nil
}

// FetchUpgradableVersions returns a list of versions that meet the specified requirements, sorted
// in descending order (newer versions first).
//
// Every version on the resulting list will meet the given requirements (by OR condition).
// However, it's not guaranteed that the list contains the amount of versions per requirement.
// For example, if only 2 previous minor versions exist but 5 requested, the list will have only 2.
func FetchUpgradableVersions(ctx context.Context, vf VersionsFetcher, sf SnapshotFetcher, reqs VersionRequirements) ([]string, error) {
	releaseVersions, err := vf.FetchAgentVersions(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving release versions: %w", err)
	}
	if len(releaseVersions) == 0 {
		return nil, errors.New("retrieved release versions list is empty")
	}

	snapshotVersions, err := sf.FindLatestSnapshots(ctx, reqs.SnapshotBranches)
	if err != nil {
		return nil, fmt.Errorf("error retrieving snapshot versions: %w", err)
	}
	if len(snapshotVersions) == 0 {
		return nil, errors.New("retrieved snapshot versions list is empty")
	}

	allVersions := append(releaseVersions, snapshotVersions...)

	// now sort the complete list
	sort.Sort(sort.Reverse(allVersions))

	return findRequiredVersions(allVersions, reqs)
}

// findRequiredVersions filters the version list according to the set requirements.
func findRequiredVersions(sortedParsedVersions []*version.ParsedSemVer, reqs VersionRequirements) ([]string, error) {
	parsedUpgradeToVersion, err := version.ParseVersion(reqs.UpgradeToVersion)
	if err != nil {
		return nil, fmt.Errorf("upgradeToVersion %q is not a valid version string: %w", reqs.UpgradeToVersion, err)
	}
	upgradableVersions := make([]string, 0, reqs.CurrentMajors+reqs.PreviousMajors+reqs.PreviousMinors+len(reqs.SnapshotBranches))

	currentMajor := parsedUpgradeToVersion.Major()
	currentMinor := parsedUpgradeToVersion.Minor()

	currentMajorsToFind := reqs.CurrentMajors
	previousMajorsToFind := reqs.PreviousMajors
	previousMinorsToFind := reqs.PreviousMinors
	recentSnapshotsToFind := len(reqs.SnapshotBranches)
	for _, version := range sortedParsedVersions {
		switch {
		// we skip version above the target
		case !version.Less(*parsedUpgradeToVersion):
			continue

		case recentSnapshotsToFind > 0 && version.IsSnapshot():
			upgradableVersions = append(upgradableVersions, version.String())
			recentSnapshotsToFind--

		// for the rest of the checks we capture only released versions
		case version.Prerelease() != "" || (version.BuildMetadata() != "" && !version.IsIndependentRelease()):
			continue

		// previous minors
		case previousMinorsToFind > 0 && version.Major() == currentMajor && version.Minor() < currentMinor:
			upgradableVersions = append(upgradableVersions, version.String())
			currentMinor = version.Minor() // so, we pick a lower minor next time
			previousMinorsToFind--
			currentMajorsToFind-- // counts as the current major as well

		// current majors
		case currentMajorsToFind > 0 && version.Major() == currentMajor:
			upgradableVersions = append(upgradableVersions, version.String())
			currentMajorsToFind--

		// previous majors
		case previousMajorsToFind > 0 && version.Major() < currentMajor:
			upgradableVersions = append(upgradableVersions, version.String())
			currentMajor = version.Major()
			previousMajorsToFind--

		// since the list is sorted we can stop here
		default:
			break
		}
	}

	return upgradableVersions, nil
}

// PreviousMinor returns the previous minor version available for upgrade.
func PreviousMinor() (*version.ParsedSemVer, error) {
	versions, err := GetUpgradableVersions()
	if err != nil {
		return nil, fmt.Errorf("failed to get upgradable versions: %w", err)
	}
	current, err := version.ParseVersion(define.Version())
	if err != nil {
		return nil, fmt.Errorf("failed to parse the current version %s: %w", define.Version(), err)
	}

	// Special case: if we are in the first release of a new major (so vX.0.0), we should
	// return the latest release from the previous major.
	if current.Minor() == 0 && current.Patch() == 0 {
		// Since the current version is the first release of a new major (vX.0.0), there
		// will be no minor versions in the versions list from the same major (vX). The list
		// will only contain minors from the previous major (vX-1). Further, since the
		// version list is sorted in descending order (newer versions first), we can return the
		// first item from the list as it will be the newest minor of the previous major.
		return versions[0], nil
	}

	for _, v := range versions {
		if v.Prerelease() != "" || v.BuildMetadata() != "" {
			continue
		}
		if v.Major() == current.Major() && v.Minor() < current.Minor() {
			return v, nil
		}
	}
	return nil, ErrNoPreviousMinor
}

// EnsureSnapshot ensures that the version string is a snapshot version.
func EnsureSnapshot(version string) string {
	if !strings.HasSuffix(version, "-SNAPSHOT") {
		version += "-SNAPSHOT"
	}
	return version
}

// SupportsUnprivileged returns true when the version supports unprivileged mode.
func SupportsUnprivileged(versions ...*version.ParsedSemVer) bool {
	for _, ver := range versions {
		if ver.Less(*Version_8_13_0_SNAPSHOT) {
			return false
		}
		if runtime.GOOS != define.Linux && ver.Less(*Version_8_14_0_SNAPSHOT) {
			return false
		}
	}
	return true
}

// InstallChecksAllowed returns true when the upgrade test should verify installation.
//
// Unprivileged mode both versions must be 8.14+. This is because the older versions do not
// create the same user that is created in 8.14+. pre-8.14 was experimental.
//
// Privileged mode requires 8.13+ because pre-8.13 didn't set the `.installed` file to not have world access.
func InstallChecksAllowed(unprivileged bool, versions ...*version.ParsedSemVer) bool {
	if unprivileged {
		for _, ver := range versions {
			if ver.Less(*Version_8_14_0_SNAPSHOT) {
				// all versions must be 8.14+
				return false
			}
		}
		return true
	}
	for _, ver := range versions {
		if ver.Less(*Version_8_13_0_SNAPSHOT) {
			// all versions must be 8.13+
			return false
		}
	}
	return true
}

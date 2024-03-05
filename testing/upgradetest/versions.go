// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgradetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
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
	// Version_8_13_0 is the minimum version for proper unprivileged execution
	Version_8_13_0 = version.NewParsedSemVer(8, 13, 0, "", "")
)

// VersionRequirements is to set requirements for upgradable versions while fetching them.
//
// Keep in mind that requirements can overlap. For example 2 previous minors might already
// cover 2 current majors, so the results would be combined.
type VersionRequirements struct {
	UpgradeToVersion string
	CurrentMajors    int
	PreviousMajors   int
	PreviousMinors   int
	RecentSnapshots  int
}

const AgentVersionsFilename = ".agent-versions.json"

type AgentVersions struct {
	// TestVersions contains semver-compliant versions of the agent to run integration tests against.
	TestVersions []string `json:"testVersions"`
}

var (
	agentVersions *AgentVersions
)

func init() {
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

	d := json.NewDecoder(f)
	var versionFile AgentVersions
	err = d.Decode(&versionFile)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JSON in %s: %w", filePath, err)
	}

	return &versionFile, nil
}

// FetchUpgradableVersions returns the versions list from the agent version file.
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

// FetchUpgradableVersions returns a list of versions that meet the specified requirements.
//
// Every version on the resulting list will meet the given requirements (by OR condition).
// However, it's not guaranteed that the list contains the amount of versions per requirement.
// For example, if only 2 previous minor versions exist but 5 requested, the list will have only 2.
func FetchUpgradableVersions(ctx context.Context, aac *tools.ArtifactAPIClient, reqs VersionRequirements) ([]string, error) {
	vList, err := aac.GetVersions(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving versions from Artifact API: %w", err)
	}
	if len(vList.Versions) == 0 {
		return nil, errors.New("retrieved versions list from Artifact API is empty")
	}

	sortedParsedVersions := make(version.SortableParsedVersions, 0, len(vList.Versions))
	for _, v := range vList.Versions {
		pv, err := version.ParseVersion(v)
		if err != nil {
			return nil, fmt.Errorf("invalid version %q retrieved from artifact API: %w", v, err)
		}
		sortedParsedVersions = append(sortedParsedVersions, pv)
	}

	if len(sortedParsedVersions) == 0 {
		return nil, errors.New("parsed versions list is empty")
	}

	// normally the output of the versions returned by artifact API is already sorted in ascending order,
	// we want to sort in descending orders, so we sort them
	sort.Sort(sort.Reverse(sortedParsedVersions))

	return findRequiredVersions(sortedParsedVersions, reqs)
}

// findRequiredVersions filters the version list according to the set requirements.
func findRequiredVersions(sortedParsedVersions []*version.ParsedSemVer, reqs VersionRequirements) ([]string, error) {
	parsedUpgradeToVersion, err := version.ParseVersion(reqs.UpgradeToVersion)
	if err != nil {
		return nil, fmt.Errorf("upgradeToVersion %q is not a valid version string: %w", reqs.UpgradeToVersion, err)
	}
	upgradableVersions := make([]string, 0, reqs.CurrentMajors+reqs.PreviousMajors+reqs.PreviousMinors+reqs.RecentSnapshots)

	currentMajor := parsedUpgradeToVersion.Major()
	currentMinor := parsedUpgradeToVersion.Minor()

	currentMajorsToFind := reqs.CurrentMajors
	previousMajorsToFind := reqs.PreviousMajors
	previousMinorsToFind := reqs.PreviousMinors
	recentSnapshotsToFind := reqs.RecentSnapshots

	for _, version := range sortedParsedVersions {
		switch {
		// we skip version above the target
		case !version.Less(*parsedUpgradeToVersion):
			continue

		case recentSnapshotsToFind > 0 && version.IsSnapshot():
			upgradableVersions = append(upgradableVersions, version.String())
			recentSnapshotsToFind--

		// for the rest of the checks we capture only released versions
		case version.Prerelease() != "" || version.BuildMetadata() != "":
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
func PreviousMinor() (string, error) {
	versions, err := GetUpgradableVersions()
	if err != nil {
		return "", fmt.Errorf("failed to get upgradable versions: %w", err)
	}

	reqs := VersionRequirements{
		UpgradeToVersion: define.Version(),
		PreviousMinors:   1,
	}
	minors, err := findRequiredVersions(versions, reqs)
	if err != nil {
		return "", fmt.Errorf("failed to find required versions: %w", err)
	}
	if len(minors) == 0 {
		return "", fmt.Errorf("no previous minor on the list: %v", versions)
	}
	return minors[0], nil
}

// EnsureSnapshot ensures that the version string is a snapshot version.
func EnsureSnapshot(version string) string {
	if !strings.HasSuffix(version, "-SNAPSHOT") {
		version += "-SNAPSHOT"
	}
	return version
}

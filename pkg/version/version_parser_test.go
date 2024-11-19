// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSemVerRegexpCompiles(t *testing.T) {
	require.NotNil(t, semVerFmtRegEx)
	assert.Contains(t, namedGroups, "major")
	assert.Contains(t, namedGroups, "minor")
	assert.Contains(t, namedGroups, "patch")
	assert.Contains(t, namedGroups, "prerelease")
	assert.Contains(t, namedGroups, "buildmetadata")
}

func TestParseVersion(t *testing.T) {
	type expected struct {
		parsed            *ParsedSemVer
		versionPrerelease string
		err               error
	}

	testcases := []struct {
		name     string
		input    string
		expected expected
	}{
		{
			name:  "Simple semver",
			input: "1.2.3",
			expected: expected{
				parsed: &ParsedSemVer{
					original:      "1.2.3",
					major:         1,
					minor:         2,
					patch:         3,
					prerelease:    "",
					buildMetadata: "",
				},
				versionPrerelease: "1.2.3",
				err:               nil,
			},
		},
		{
			name:  "Biiig semver",
			input: "1111.2222.3333",
			expected: expected{
				parsed: &ParsedSemVer{
					original:      "1111.2222.3333",
					major:         1111,
					minor:         2222,
					patch:         3333,
					prerelease:    "",
					buildMetadata: "",
				},
				versionPrerelease: "1111.2222.3333",
				err:               nil,
			},
		},
		{
			name:  "Simple semver with spaces around",
			input: " \t1.2.3 \r\n ",
			expected: expected{
				parsed: &ParsedSemVer{
					original:      " \t1.2.3 \r\n ",
					major:         1,
					minor:         2,
					patch:         3,
					prerelease:    "",
					buildMetadata: "",
				},
				versionPrerelease: "1.2.3",
				err:               nil,
			},
		},
		{
			name:  "Semver with prerelease",
			input: "1.2.3-SNAPSHOT",
			expected: expected{
				parsed: &ParsedSemVer{
					original:      "1.2.3-SNAPSHOT",
					major:         1,
					minor:         2,
					patch:         3,
					prerelease:    "SNAPSHOT",
					buildMetadata: "",
				},
				versionPrerelease: "1.2.3-SNAPSHOT",
				err:               nil,
			},
		},
		{
			name:  "Semver with versioned prerelease",
			input: "1.2.3-er.1+abcdef",
			expected: expected{
				parsed: &ParsedSemVer{
					original:      "1.2.3-er.1+abcdef",
					major:         1,
					minor:         2,
					patch:         3,
					prerelease:    "er.1",
					buildMetadata: "abcdef",
				},
				versionPrerelease: "1.2.3-er.1",
				err:               nil,
			},
		},
		{
			name:  "Semver with prerelease and build metadata",
			input: "1.2.3-SNAPSHOT+abcdef",
			expected: expected{
				parsed: &ParsedSemVer{
					original:      "1.2.3-SNAPSHOT+abcdef",
					major:         1,
					minor:         2,
					patch:         3,
					prerelease:    "SNAPSHOT",
					buildMetadata: "abcdef",
				},
				versionPrerelease: "1.2.3-SNAPSHOT",
				err:               nil,
			},
		},
		{
			name:  "Semver string version, with double prerelease(er and snapshot)",
			input: "1.2.5-er.1-SNAPSHOT",
			expected: expected{
				parsed: &ParsedSemVer{
					original:      "1.2.5-er.1-SNAPSHOT",
					major:         1,
					minor:         2,
					patch:         5,
					prerelease:    "er.1-SNAPSHOT",
					buildMetadata: "",
				},
				versionPrerelease: "1.2.5-er.1-SNAPSHOT",
			},
		},
		{
			name:  "Error truncated semver",
			input: "2.3",
			expected: expected{
				parsed: nil,
				err:    ErrNoMatch,
			},
		},
		{
			name:  "Error missing prerelease type",
			input: "1.2.3-",
			expected: expected{
				parsed: nil,
				err:    ErrNoMatch,
			},
		},
		{
			name:  "Error missing build metadata",
			input: "1.2.3-beta.22+",
			expected: expected{
				parsed: nil,
				err:    ErrNoMatch,
			},
		},
		{
			name:  "Weird random string version",
			input: "asdasdasdasdasd",
			expected: expected{
				parsed: nil,
				err:    ErrNoMatch,
			},
		},
		{
			name:  "Almost semver string version, with double extra meta separator",
			input: "1.2.3++",
			expected: expected{
				parsed: nil,
				err:    ErrNoMatch,
			},
		},
		{
			name:  "Almost semver string version, with empty minor version",
			input: "1..2+ab",
			expected: expected{
				parsed: nil,
				err:    ErrNoMatch,
			},
		},
		{
			name:  "Almost semver string version, with patch containing non-digits",
			input: "1.2.5ab0",
			expected: expected{
				parsed: nil,
				err:    ErrNoMatch,
			},
		},
		{
			name:  "Split string version",
			input: "4.5\r\n.6",
			expected: expected{
				parsed: nil,
				err:    ErrNoMatch,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			actualParsed, err := ParseVersion(tc.input)

			if tc.expected.err != nil {
				assert.ErrorIs(t, err, tc.expected.err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.expected.parsed, actualParsed)

			// assert getters
			assert.Equal(t, tc.expected.parsed.original, actualParsed.Original())
			assert.Equal(t, tc.expected.parsed.major, actualParsed.Major())
			assert.Equal(t, tc.expected.parsed.minor, actualParsed.Minor())
			assert.Equal(t, tc.expected.parsed.patch, actualParsed.Patch())
			assert.Equal(t, tc.expected.parsed.prerelease, actualParsed.Prerelease())
			assert.Equal(t, tc.expected.parsed.buildMetadata, actualParsed.BuildMetadata())
			assert.Equal(t, tc.expected.versionPrerelease, actualParsed.VersionWithPrerelease())

			// verify that String() method returns the same input string (after trimming)
			assert.Equal(t, strings.TrimSpace(tc.input), actualParsed.String())
		})
	}
}

func TestIsSnapshot(t *testing.T) {
	testcases := []struct {
		name     string
		input    string
		snapshot bool
	}{
		{
			name:     "Simple snapshot",
			input:    "8.8.0-SNAPSHOT",
			snapshot: true,
		},
		{
			name:     "Snapshot with build meta",
			input:    "8.8.0-SNAPSHOT+abcdef",
			snapshot: true,
		},
		{
			name:     "Snapshot comparison is case sensitive",
			input:    "8.8.0-sNapShOt",
			snapshot: false,
		},
		{
			name:     "Only major minor patch",
			input:    "8.8.0",
			snapshot: false,
		},
		{
			name:     "Alpha prerelease is not snapshot",
			input:    "8.8.0-alpha",
			snapshot: false,
		},
		{
			name:     "Emergency release is not snapshot",
			input:    "8.8.0-er.1",
			snapshot: false,
		},
		{
			name:     "Emergency release snapshot is actually a snapshot",
			input:    "8.8.0-SNAPSHOT.er.1 ",
			snapshot: true,
		},
		{
			name:     "Emergency release with snapshot in the middle is a snapshot",
			input:    "8.8.0-er.SNAPSHOT.1 ",
			snapshot: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			psv, err := ParseVersion(tc.input)
			require.NoError(t, err)
			require.NotNil(t, psv)
			assert.Equal(t, tc.snapshot, psv.IsSnapshot())
		})

	}

}

func TestIsIndependentRelease(t *testing.T) {
	testcases := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Simple version",
			input:    "8.8.0",
			expected: false,
		},
		{
			name:     "Simple snapshot",
			input:    "8.8.0-SNAPSHOT",
			expected: false,
		},
		{
			name:     "Independent release",
			input:    "8.8.0+build20241224081012",
			expected: true,
		},
		{
			name:     "Independent release no time",
			input:    "8.8.0+build20241224",
			expected: false,
		},
		{
			name:     "Independent release and more",
			input:    "8.8.0+build20241224081012.meta.5",
			expected: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			psv, err := ParseVersion(tc.input)
			require.NoError(t, err)
			require.NotNil(t, psv)
			assert.Equal(t, tc.expected, psv.IsIndependentRelease())
		})
	}
}

func TestExtractSnapshotFromVersionString(t *testing.T) {
	testcases := []struct {
		name          string
		inputVersion  string
		outputVersion string
		snapshot      bool
	}{
		{
			name:          "Simple snapshot",
			inputVersion:  "8.8.0-SNAPSHOT",
			outputVersion: "8.8.0",
			snapshot:      true,
		},
		{
			name:          "Snapshot with build meta",
			inputVersion:  "8.8.0-SNAPSHOT+abcdef",
			outputVersion: "8.8.0+abcdef",
			snapshot:      true,
		},
		{
			name:          "Snapshot comparison is case sensitive",
			inputVersion:  "8.8.0-sNapShOt",
			outputVersion: "8.8.0-sNapShOt",
			snapshot:      false,
		},
		{
			name:          "Only major minor patch",
			inputVersion:  "8.8.0",
			outputVersion: "8.8.0",
			snapshot:      false,
		},
		{
			name:          "Alpha prerelease is not snapshot",
			inputVersion:  "8.8.0-alpha",
			outputVersion: "8.8.0-alpha",
			snapshot:      false,
		},
		{
			name:          "Emergency release is not snapshot",
			inputVersion:  "8.8.0-er.1",
			outputVersion: "8.8.0-er.1",
			snapshot:      false,
		},
		{
			name:          "Emergency release snapshot is actually a snapshot",
			inputVersion:  "8.8.0-SNAPSHOT.er.1 ",
			outputVersion: "8.8.0-er.1",
			snapshot:      true,
		},
		{
			name:          "Emergency release with SNAPSHOT in the middle is a snapshot",
			inputVersion:  "8.8.0-er.SNAPSHOT.1 ",
			outputVersion: "8.8.0-er.1",
			snapshot:      true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			psv, err := ParseVersion(tc.inputVersion)
			require.NoErrorf(t, err, "error parsing version %q", tc.inputVersion)
			require.NotNil(t, psv, "parsed semver should not be nil with no errors returned from ParseVersion")
			actualOutputVersion, actualIsSnapshot := psv.ExtractSnapshotFromVersionString()
			assert.Equalf(t, tc.outputVersion, actualOutputVersion, "(%q).ExtractSnapshotFromVersionString() is expected to return version: %q", tc.inputVersion, tc.outputVersion)
			assert.Equalf(t, tc.snapshot, actualIsSnapshot, "(%q).ExtractSnapshotFromVersionString() is expected to return snapshot: %v", tc.inputVersion, tc.snapshot)
			// make sure that the actual snapshot flag is coherent with isSnapshot()
			flagFromIsSnapshot := psv.IsSnapshot()
			assert.Equalf(t, flagFromIsSnapshot, actualIsSnapshot, "(%q).ExtractSnapshotFromVersionString() is expected to return same snapshot flag value as (%q).IsSnapshot()=%v", tc.inputVersion, tc.inputVersion, flagFromIsSnapshot)

		})
	}
}

func TestLess(t *testing.T) {
	testcases := []struct {
		name         string
		leftVersion  string
		rightVersion string
		less         bool
	}{
		// major, minor, patch section
		{
			name:         "major version less than ours",
			leftVersion:  "7.17.10",
			rightVersion: "8.9.0",
			less:         true,
		},
		{
			name:         "minor version less than ours",
			leftVersion:  "8.6.2",
			rightVersion: "8.9.0",
			less:         true,
		},
		{
			name:         "patch version less than ours",
			leftVersion:  "8.7.0",
			rightVersion: "8.7.1",
			less:         true,
		},
		// prerelease section
		{
			name:         "prerelease is always less than non-prerelease",
			leftVersion:  "8.9.0-SNAPSHOT",
			rightVersion: "8.9.0",
			less:         true,
		},
		{
			name:         "2 prereleases are compared by their tokens",
			leftVersion:  "8.9.0-SNAPSHOT",
			rightVersion: "8.9.0-er1",
			less:         false,
		},
		{
			name:         "2 prereleases are compared by their tokens, reversed",
			leftVersion:  "8.9.0-er1",
			rightVersion: "8.9.0-SNAPSHOT",
			less:         true,
		},
		{
			name:         "2 prereleases have no specific order",
			leftVersion:  "8.9.0-SNAPSHOT",
			rightVersion: "8.9.0-er1",
			less:         false,
		},
		// build metadata (these have no impact on precedence)
		{
			name:         "build metadata have no influence on precedence",
			leftVersion:  "8.9.0-SNAPSHOT+aaaaaa",
			rightVersion: "8.9.0-SNAPSHOT+bbbbbb",
			less:         false,
		},
		{
			name:         "build metadata have no influence on precedence, reversed",
			leftVersion:  "8.9.0-SNAPSHOT+bbbbbb",
			rightVersion: "8.9.0-SNAPSHOT+aaaaaa",
			less:         false,
		},
		// testcases taken from semver.org
		// 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta < 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0.
		{
			name:         "prerelease with fewer tokens is less than same prerelease with extra tokens",
			leftVersion:  "1.0.0-alpha",
			rightVersion: "1.0.0-alpha.1",
			less:         true,
		},
		{
			name:         "numeric identifiers always have lower precedence than non-numeric identifiers",
			leftVersion:  "1.0.0-alpha.1",
			rightVersion: "1.0.0-alpha.beta",
			less:         true,
		},
		{
			name:         "minimum number of prerelease string tokens must be compared alphabetically",
			leftVersion:  "1.0.0-alpha.beta",
			rightVersion: "1.0.0-beta",
			less:         true,
		},
		{
			name:         "prerelease with fewer tokens is less than same prerelease with extra tokens #2",
			leftVersion:  "1.0.0-beta",
			rightVersion: "1.0.0-beta.2",
			less:         true,
		},
		{
			name:         "numeric identifiers must be compared numerically",
			leftVersion:  "1.0.0-beta.2",
			rightVersion: "1.0.0-beta.11",
			less:         true,
		},
		{
			name:         "string identifiers are compared lexically",
			leftVersion:  "1.0.0-beta.11",
			rightVersion: "1.0.0-rc.1",
			less:         true,
		},
		{
			name:         "prerelease versions have lower precedence than non-prerelease version ",
			leftVersion:  "1.0.0-rc.1",
			rightVersion: "1.0.0",
			less:         true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			left, err := ParseVersion(tc.leftVersion)
			require.NoError(t, err)
			require.NotNil(t, left)
			right, err := ParseVersion(tc.rightVersion)
			require.NoError(t, err)
			require.NotNil(t, right)
			assert.Equalf(t, tc.less, left.Less(*right), "Expected %s < %s = %v", tc.leftVersion, tc.rightVersion, tc.less)
		})
	}
}

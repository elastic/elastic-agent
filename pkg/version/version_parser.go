// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package version

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// regexp taken from https://semver.org/ (see the FAQ section/Is there a suggested regular expression (RegEx) to check a SemVer string?)
const semVerFormat = `^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`
const numericPrereleaseTokenFormat = `\d+`
const preReleaseSeparator = "-"
const metadataSeparator = "+"
const prereleaseTokenSeparator = "."
const snapshotPrereleaseToken = "SNAPSHOT"
const isIndependentReleaseFormat = `^build\d{12}`

var semVerFmtRegEx *regexp.Regexp
var numericPrereleaseTokenRegEx *regexp.Regexp
var namedGroups map[string]int

func init() {
	// small init to compile the regex and build a map of named groups and indexes
	semVerFmtRegEx = regexp.MustCompile(semVerFormat)
	groups := semVerFmtRegEx.SubexpNames()
	namedGroups = make(map[string]int, len(groups))
	for i, groupName := range groups {
		namedGroups[groupName] = i
	}

	// compile the numeric prerelease token regex
	numericPrereleaseTokenRegEx = regexp.MustCompile(numericPrereleaseTokenFormat)
}

var ErrNoMatch = errors.New("version string does not match expected format")

type ParsedSemVer struct {
	original             string
	major                int
	minor                int
	patch                int
	prerelease           string
	buildMetadata        string
	isIndependentRelease bool
}

func (psv ParsedSemVer) Original() string {
	return psv.original
}

func (psv ParsedSemVer) Major() int {
	return psv.major
}

func (psv ParsedSemVer) Minor() int {
	return psv.minor
}

func (psv ParsedSemVer) Patch() int {
	return psv.patch
}

func (psv ParsedSemVer) CoreVersion() string {
	return fmt.Sprintf("%d.%d.%d", psv.Major(), psv.Minor(), psv.Patch())
}

func (psv ParsedSemVer) Prerelease() string {
	return psv.prerelease
}

func (psv ParsedSemVer) PrereleaseTokens() []string {
	if len(psv.prerelease) == 0 {
		return nil
	}

	return strings.Split(psv.Prerelease(), prereleaseTokenSeparator)
}

func (psv ParsedSemVer) BuildMetadata() string {
	return psv.buildMetadata
}

func (psv ParsedSemVer) VersionWithPrerelease() string {
	b := new(strings.Builder)
	b.WriteString(psv.CoreVersion())
	if psv.prerelease != "" {
		b.WriteString(preReleaseSeparator)
		b.WriteString(psv.prerelease)
	}
	return b.String()
}

func (psv ParsedSemVer) ExtractSnapshotFromVersionString() (string, bool) {

	b := new(strings.Builder)
	b.WriteString(psv.CoreVersion())

	prereleaseTokens := psv.PrereleaseTokens()
	isSnapshot := false

	for i, t := range prereleaseTokens {
		if t == snapshotPrereleaseToken {
			// we found the snapshot prerelease qualifier (we assume there's only 1)
			isSnapshot = true
			prereleaseTokens = append(prereleaseTokens[:i], prereleaseTokens[i+1:]...)
			break
		}
	}

	if len(prereleaseTokens) > 0 {
		b.WriteString(preReleaseSeparator)
		b.WriteString(assemblePrereleaseStringFromTokens(prereleaseTokens))
	}

	if len(psv.buildMetadata) > 0 {
		b.WriteString(metadataSeparator)
		b.WriteString(psv.buildMetadata)
	}
	return b.String(), isSnapshot
}

func (psv ParsedSemVer) IsSnapshot() bool {
	prereleaseTokens := psv.PrereleaseTokens()
	return slices.Contains(prereleaseTokens, snapshotPrereleaseToken)
}

func (psv ParsedSemVer) IsIndependentRelease() bool {
	return psv.isIndependentRelease
}

func (psv ParsedSemVer) Less(other ParsedSemVer) bool {
	// compare major version
	if psv.major != other.major {
		return psv.major < other.major
	}

	//same major, check minor
	if psv.minor != other.minor {
		return psv.minor < other.minor
	}

	//same minor, check patch
	if psv.patch != other.patch {
		return psv.patch < other.patch
	}

	// compare prerelease strings as major.minor.patch are equal
	return psv.comparePrerelease(other)
}

// comparePrerelease compares the prerelease part of 2 ParsedSemVer objects
// the return value must conform to psv.prerelease < other.prerelease following comparison rules from https://semver.org/
func (psv ParsedSemVer) comparePrerelease(other ParsedSemVer) bool {
	// last resort before parsing prerelease: check if one is prerelease and the other isn't
	if psv.prerelease != "" && other.prerelease == "" {
		return true
	}

	if psv.prerelease == "" && other.prerelease != "" {
		return false
	}

	// tokenize prereleases and compare them
	prereleaseTokens := strings.Split(psv.prerelease, prereleaseTokenSeparator)
	otherPrereleaseTokens := strings.Split(other.prerelease, prereleaseTokenSeparator)

	// compute the min amount of tokens
	minPrereleaseTokens := len(prereleaseTokens)
	if len(otherPrereleaseTokens) < minPrereleaseTokens {
		minPrereleaseTokens = len(otherPrereleaseTokens)
	}

	for i := 0; i < minPrereleaseTokens; i++ {
		token := prereleaseTokens[i]
		otherToken := otherPrereleaseTokens[i]

		isTokenNumeric := numericPrereleaseTokenRegEx.MatchString(token)
		isOtherTokenNumeric := numericPrereleaseTokenRegEx.MatchString(otherToken)

		// numeric identifiers always have lower precedence than non-numeric identifiers
		if isTokenNumeric && !isOtherTokenNumeric {
			return true
		}

		if !isTokenNumeric && isOtherTokenNumeric {
			return false
		}

		// prerelease tokens are of the same type: check if we have to compare them as numbers or strings
		if isTokenNumeric {
			// we can ignore the error as the regex we are using is even more restrictive than a generic integer regex
			numericToken, _ := strconv.Atoi(token)
			otherNumericToken, _ := strconv.Atoi(otherToken)
			if numericToken != otherNumericToken {
				return numericToken < otherNumericToken
			}
		} else {
			// compare them as strings
			if token != otherToken {
				return token < otherToken
			}
		}
	}

	// the minimum number of tokens is the same across the two versions, check if one of the two have more tokens
	return len(prereleaseTokens) < len(otherPrereleaseTokens)
}

func (psv ParsedSemVer) String() string {
	b := new(strings.Builder)
	b.WriteString(psv.CoreVersion())
	if psv.Prerelease() != "" {
		b.WriteString(preReleaseSeparator)
		b.WriteString(psv.Prerelease())
	}
	if psv.BuildMetadata() != "" {
		b.WriteString(metadataSeparator)
		b.WriteString(psv.buildMetadata)
	}
	return b.String()
}

func NewParsedSemVer(major int, minor int, patch int, prerelease string, metadata string) *ParsedSemVer {
	return &ParsedSemVer{
		major:         major,
		minor:         minor,
		patch:         patch,
		prerelease:    prerelease,
		buildMetadata: metadata,
	}
}

func ParseVersion(version string) (*ParsedSemVer, error) {
	matches := semVerFmtRegEx.FindStringSubmatch(strings.TrimSpace(version))
	if matches == nil {
		return nil, ErrNoMatch
	}

	major, err := strconv.Atoi(matches[namedGroups["major"]])
	if err != nil {
		return nil, fmt.Errorf("parsing major version: %w", err)
	}

	minor, err := strconv.Atoi(matches[namedGroups["minor"]])
	if err != nil {
		return nil, fmt.Errorf("parsing minor version: %w", err)
	}

	patch, err := strconv.Atoi(matches[namedGroups["patch"]])
	if err != nil {
		return nil, fmt.Errorf("parsing patch version: %w", err)
	}

	var isIndependentRelease bool
	if matched, err := regexp.MatchString(isIndependentReleaseFormat, matches[namedGroups["buildmetadata"]]); err == nil && matched {
		isIndependentRelease = true
	}

	return &ParsedSemVer{
		original:             version,
		major:                major,
		minor:                minor,
		patch:                patch,
		prerelease:           matches[namedGroups["prerelease"]],
		buildMetadata:        matches[namedGroups["buildmetadata"]],
		isIndependentRelease: isIndependentRelease,
	}, nil
}

func assemblePrereleaseStringFromTokens(tokens []string) string {
	builder := new(strings.Builder)
	for _, t := range tokens {
		if builder.Len() > 0 {
			builder.WriteString(prereleaseTokenSeparator)
		}
		builder.WriteString(t)
	}
	return builder.String()
}

type SortableParsedVersions []*ParsedSemVer

func (spv SortableParsedVersions) Len() int           { return len(spv) }
func (spv SortableParsedVersions) Swap(i, j int)      { spv[i], spv[j] = spv[j], spv[i] }
func (spv SortableParsedVersions) Less(i, j int) bool { return spv[i].Less(*spv[j]) }

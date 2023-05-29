// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package version

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// regexp taken from https://semver.org/ (see the FAQ section/Is there a suggested regular expression (RegEx) to check a SemVer string?) with the addition of the coreversion group
const semVerFormat = `^(?P<coreversion>(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*))(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`

var semVerFmtRegEx *regexp.Regexp
var namedGroups map[string]int

func init() {
	// small init to compile the regex and build a map of named groups and indexes
	semVerFmtRegEx = regexp.MustCompile(semVerFormat)
	groups := semVerFmtRegEx.SubexpNames()
	namedGroups = make(map[string]int, len(groups))
	for i, groupName := range groups {
		namedGroups[groupName] = i
	}
}

var ErrNoMatch = errors.New("version string does not match expected format")

type ParsedSemVer struct {
	original      string
	major         int
	minor         int
	patch         int
	coreVersion   string
	prerelease    string
	buildMetadata string
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
	return psv.coreVersion
}

func (psv ParsedSemVer) Prerelease() string {
	return psv.prerelease
}

func (psv ParsedSemVer) BuildMetadata() string {
	return psv.buildMetadata
}

func (psv ParsedSemVer) VersionWithPrerelease() string {
	b := new(strings.Builder)
	b.WriteString(psv.coreVersion)
	if psv.prerelease != "" {
		b.WriteString("-")
		b.WriteString(psv.prerelease)
	}
	return b.String()
}

func (psv ParsedSemVer) IsSnapshot() bool {
	return psv.prerelease == "SNAPSHOT"
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

	// last resort check if one is prereleas and the other isn't
	if psv.prerelease != "" && other.prerelease == "" {
		return true
	}

	return false
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
	return &ParsedSemVer{
		original:      version,
		major:         major,
		minor:         minor,
		patch:         patch,
		coreVersion:   matches[namedGroups["coreversion"]],
		prerelease:    matches[namedGroups["prerelease"]],
		buildMetadata: matches[namedGroups["buildmetadata"]],
	}, nil
}

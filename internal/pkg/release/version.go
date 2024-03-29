// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"os"
	"strconv"
	"strings"
	"time"

	agtversion "github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/version"
)

const (
	hashLen = 6
)

// snapshot is a flag marking build as a snapshot.
var snapshot = ""

// fips is a flag for marking a FIPS-capable build.
var fips = "false"

// complete is an environment variable marking the image as complete.
var complete = "ELASTIC_AGENT_COMPLETE"

// allowUpgrade is used as a debug flag and allows working
// with upgrade without requiring Agent to be installed correctly
var allowUpgrade string

// TrimCommit trims commit up to 6 characters.
func TrimCommit(commit string) string {
	hash := commit
	if len(hash) > hashLen {
		hash = hash[:hashLen]
	}
	return hash
}

// Commit returns the current build hash or unknown if it was not injected in the build process.
func Commit() string {
	return version.Commit()
}

// ShortCommit returns commit up to 6 characters.
func ShortCommit() string {
	return TrimCommit(Commit())
}

// BuildTime returns the build time of the binaries.
func BuildTime() time.Time {
	return version.BuildTime()
}

// Version returns the version of the application.
func Version() string {
	return version.GetAgentPackageVersion()
}

// VersionWithSnapshot returns the version of the application including SNAPSHOT string if we are dealing with a snapshot build.
func VersionWithSnapshot() string {
	// add the snapshot flag to the version string
	agentPackageVersion := version.GetAgentPackageVersion()
	versionWithSnapshotFlag, err := agtversion.GenerateAgentVersionWithSnapshotFlag(agentPackageVersion, Snapshot())
	if err != nil {
		// we cannot return an error here, either panic or log the error and return the unmodified agentPackageVersion
		// TODO add error log
		return agentPackageVersion
	}
	return versionWithSnapshotFlag
}

// Snapshot returns true if binary was built as snapshot.
func Snapshot() bool {
	val, err := strconv.ParseBool(snapshot)
	return err == nil && val
}

// Complete returns true if image was built as complete.
func Complete() bool {
	isComplete, ok := os.LookupEnv(complete)
	return ok && isComplete == "true"
}

func FIPSDistribution() bool {
	f, err := strconv.ParseBool(fips)
	return err == nil && f
}

// VersionInfo is structure used by `version --yaml`.
type VersionInfo struct {
	Version          string    `yaml:"version"`
	Commit           string    `yaml:"commit"`
	BuildTime        time.Time `yaml:"build_time"`
	Snapshot         bool      `yaml:"snapshot"`
	FIPSDistribution bool      `yaml:"fips"`
}

// Info returns current version information.
func Info() VersionInfo {
	return VersionInfo{
		Version:          Version(),
		Commit:           Commit(),
		BuildTime:        BuildTime(),
		Snapshot:         Snapshot(),
		FIPSDistribution: FIPSDistribution(),
	}
}

// String returns the string format for the version information.
func (v VersionInfo) String() string {
	var sb strings.Builder

	sb.WriteString(v.Version)
	sb.WriteString(" (build: ")
	sb.WriteString(v.Commit)
	if v.FIPSDistribution {
		sb.WriteString(" fips-distribution: true")
	}
	sb.WriteString(" at ")
	sb.WriteString(v.BuildTime.Format("2006-01-02 15:04:05 -0700 MST"))
	sb.WriteString(")")

	return sb.String()
}

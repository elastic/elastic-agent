// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/elastic-agent/version"
)

const (
	hashLen = 6
)

// snapshot is a flag marking build as a snapshot.
var snapshot = ""

// fips is a flag for marking a FIPS-capable build.
var fips = "false"

// variant identifies the distribution variant (e.g. "security"). Empty for
// the standard distribution. Stamped at build time via -ldflags.
var variant = ""

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

// VersionWithSnapshot returns the version of the application.
func VersionWithSnapshot() string {
	agentPackageVersion := version.GetAgentPackageVersion()
	if Snapshot() {
		agentPackageVersion += "-SNAPSHOT"
	}
	return agentPackageVersion
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

// VariantSecurityOnly is the variant string stamped into security-only builds.
const VariantSecurityOnly = "security"

// SetVariantForTesting overrides the variant for the duration of a test.
// Returns a restore function that must be called (typically via t.Cleanup).
func SetVariantForTesting(v string) func() {
	prev := variant
	variant = v
	return func() { variant = prev }
}

// Variant returns the distribution variant stamped at build time.
// Returns an empty string for the standard distribution.
func Variant() string {
	return variant
}

// IsSecurityOnlyVariant reports whether this binary was built as the
// security-only distribution variant.
func IsSecurityOnlyVariant() bool {
	return variant == VariantSecurityOnly
}

// VersionInfo is structure used by `version --yaml`.
type VersionInfo struct {
	Version          string    `yaml:"version"`
	Commit           string    `yaml:"commit"`
	BuildTime        time.Time `yaml:"build_time"`
	Snapshot         bool      `yaml:"snapshot"`
	FIPSDistribution bool      `yaml:"fips"`
	Variant          string    `yaml:"variant,omitempty"`
}

// Info returns current version information.
func Info() VersionInfo {
	return VersionInfo{
		Version:          Version(),
		Commit:           Commit(),
		BuildTime:        BuildTime(),
		Snapshot:         Snapshot(),
		FIPSDistribution: FIPSDistribution(),
		Variant:          Variant(),
	}
}

// String returns the string format for the version information.
func (v VersionInfo) String() string {
	var sb strings.Builder

	sb.WriteString(v.Version)
	if v.Snapshot {
		sb.WriteString("-SNAPSHOT")
	}
	sb.WriteString(" (build: ")
	sb.WriteString(v.Commit)
	if v.FIPSDistribution {
		sb.WriteString(" fips-distribution: true")
	}
	if v.Variant != "" {
		sb.WriteString(" variant: ")
		sb.WriteString(v.Variant)
	}
	sb.WriteString(" at ")
	sb.WriteString(v.BuildTime.Format("2006-01-02 15:04:05 -0700 MST"))
	sb.WriteString(")")

	return sb.String()
}

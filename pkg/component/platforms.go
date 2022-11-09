// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"fmt"
	goruntime "runtime"
	"strconv"
	"strings"

	"github.com/elastic/go-sysinfo"
)

const (
	// Container represents running inside a container
	Container = "container"
	// Darwin represents running on Mac OSX
	Darwin = "darwin"
	// Linux represents running on Linux
	Linux = "linux"
	// Windows represents running on Windows
	Windows = "windows"
)

const (
	// AMD64 represents the amd64 architecture
	AMD64 = "amd64"
	// ARM64 represents the arm64 architecture
	ARM64 = "arm64"
)

// Platform defines the platform that a component can support
type Platform struct {
	OS   string
	Arch string
	GOOS string
}

// Platforms is an array of platforms.
type Platforms []Platform

// GlobalPlatforms defines the platforms that a component can support
var GlobalPlatforms = Platforms{
	{
		OS:   Container,
		Arch: AMD64,
		GOOS: Linux,
	},
	{
		OS:   Container,
		Arch: ARM64,
		GOOS: Linux,
	},
	{
		OS:   Darwin,
		Arch: AMD64,
		GOOS: Darwin,
	},
	{
		OS:   Darwin,
		Arch: ARM64,
		GOOS: Darwin,
	},
	{
		OS:   Linux,
		Arch: AMD64,
		GOOS: Linux,
	},
	{
		OS:   Linux,
		Arch: ARM64,
		GOOS: Linux,
	},
	{
		OS:   Windows,
		Arch: AMD64,
		GOOS: Windows,
	},
}

// String returns the platform string identifier.
func (p *Platform) String() string {
	return fmt.Sprintf("%s/%s", p.OS, p.Arch)
}

// Exists returns true if the
func (p Platforms) Exists(platform string) bool {
	pieces := strings.SplitN(platform, "/", 2)
	if len(pieces) != 2 {
		return false
	}
	for _, platform := range p {
		if platform.OS == pieces[0] && platform.Arch == pieces[1] {
			return true
		}
	}
	return false
}

// PlatformDetail is platform that has more detail information about the running platform.
type PlatformDetail struct {
	Platform

	Family string
	Major  string
	Minor  string
}

// PlatformModifier can modify the platform details before the runtime specifications are loaded.
type PlatformModifier func(detail PlatformDetail) PlatformDetail

// LoadPlatformDetail loads the platform details for the current system.
func LoadPlatformDetail(modifiers ...PlatformModifier) (PlatformDetail, error) {
	info, err := sysinfo.Host()
	if err != nil {
		return PlatformDetail{}, err
	}
	os := info.Info().OS
	detail := PlatformDetail{
		Platform: Platform{
			OS:   goruntime.GOOS,
			Arch: goruntime.GOARCH,
			GOOS: goruntime.GOOS,
		},
		Family: os.Family,
		Major:  strconv.Itoa(os.Major),
		Minor:  strconv.Itoa(os.Minor),
	}
	for _, modifier := range modifiers {
		detail = modifier(detail)
	}
	return detail, nil
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package define

import (
	"errors"
	"fmt"

	"github.com/elastic/elastic-agent/pkg/component"
)

const (
	// Container is container platform
	Container = component.Container
	// Darwin is macOS platform
	Darwin = component.Darwin
	// Linux is Linux platform
	Linux = component.Linux
	// Windows is Windows platform
	Windows = component.Windows
)

var validTypes = []string{Darwin, Container, Linux, Windows}

const (
	// AMD64 is amd64 architecture
	AMD64 = component.AMD64
	// ARM64 is arm64 architecture
	ARM64 = component.ARM64
)

// OS defines an operating system, architecture, version and distribution combination.
type OS struct {
	// Type is the operating system type (darwin, linux or windows).
	//
	// This is always required to be defined on the OS structure.
	// If it is not defined the test runner will error.
	Type string `json:"type"`
	// Arch is the architecture type (amd64 or arm64).
	//
	// In the case that it's not provided the test will run on every
	// architecture that is supported.
	Arch string `json:"arch"`
	// Version is a specific version of the OS type to run this test on
	//
	// When defined the test runs on this specific version only. When not
	// defined the test is run on a selected version for this operating system.
	Version string `json:"version"`
	// Distro allows in the Linux case for a specific distribution to be
	// selected for running on. Example would be "ubuntu".
	Distro string `json:"distro"`
}

// Validate returns an error if not valid.
func (o OS) Validate() error {
	if o.Type == "" {
		return errors.New("type must be defined")
	}

	if !contains(validTypes, o.Type) {
		return fmt.Errorf("type must be one of %s", validTypes)
	}
	if o.Arch != "" {
		if o.Arch != AMD64 && o.Arch != ARM64 {
			return errors.New("arch must be either amd64 or arm64")
		}
		if o.Type == Windows && o.Arch == ARM64 {
			return errors.New("windows on arm64 not supported")
		}
	}
	if o.Distro != "" && o.Type != Linux {
		return errors.New("distro can only be set when type is linux")
	}
	return nil
}

// Stack defines the stack required for the test.
type Stack struct {
	// Version defines a specific stack version to create for this test.
	//
	// In the case that no version is provided the same version being used for
	// the current test execution is used.
	Version string `json:"version"`
}

// Requirements defines the testing requirements for the test to run.
type Requirements struct {
	// OS defines the operating systems this test can run on. In the case
	// multiple are provided the test is ran multiple times one time on each
	// combination.
	OS []OS `json:"os,omitempty"`

	// Stack defines the stack required for the test.
	Stack *Stack `json:"stack,omitempty"`

	// Local defines if this test can safely be performed on a local development machine.
	// If not set then the test will not be performed when local only testing is performed.
	//
	// This doesn't mean this test can only run locally. It will still run on defined OS's
	// when a full test run is performed.
	Local bool `json:"local"`

	// Isolate defines that this test must be isolated to its own dedicated VM and the test
	// cannot be shared with other tests.
	Isolate bool `json:"isolate"`

	// Sudo defines that this test must run under superuser permissions. On Mac and Linux the
	// test gets executed under sudo and on Windows it gets run under Administrator.
	Sudo bool `json:"sudo"`
}

// Validate returns an error if not valid.
func (r Requirements) Validate() error {
	for i, o := range r.OS {
		if err := o.Validate(); err != nil {
			return fmt.Errorf("invalid os [%d]: %w", i, err)
		}
	}
	return nil
}

// runtimeAllowed returns true if the runtime matches a valid OS.
func (r Requirements) runtimeAllowed(os string, arch string, version string, distro string) bool {
	if len(r.OS) == 0 {
		// all allowed
		return true
	}
	for _, o := range r.OS {
		if !(o.Type == Container && os == Linux) && o.Type != os {
			// not valid on this runtime
			continue
		}
		if o.Arch != "" && o.Arch != arch {
			// not allowed on specific architecture
			continue
		}
		if o.Version != "" && o.Version != version {
			// not allowed on specific version
			continue
		}
		if o.Distro != "" && o.Distro != distro {
			// not allowed on specific distro
			continue
		}
		// allowed
		return true
	}
	// made it this far, not allowed
	return false
}

func contains(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}

	return false
}

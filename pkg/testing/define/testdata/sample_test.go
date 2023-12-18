// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build batch_test

package testdata

import (
	"testing"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestAnyLocal(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: define.Default,
		Local: true,
	})
}

func TestAnySudo(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: define.Default,
		Sudo:  true,
	})
}

func TestDarwinLocal(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: define.Default,
		OS: []define.OS{
			{
				Type: define.Darwin,
			},
		},
		Local: true,
	})
}

func TestDarwinSudo(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: define.Default,
		OS: []define.OS{
			{
				Type: define.Darwin,
			},
		},
		Sudo: true,
	})
}

func TestLinuxLocal(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: define.Default,
		OS: []define.OS{
			{
				Type: define.Linux,
			},
		},
		Local: true,
	})
}

func TestLinuxSudo(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: define.Default,
		OS: []define.OS{
			{
				Type: define.Linux,
			},
		},
		Sudo: true,
	})
}

func TestWindowsLocal(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: define.Default,
		OS: []define.OS{
			{
				Type: define.Windows,
			},
		},
		Local: true,
	})
}

func TestWindowsSudo(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: define.Default,
		OS: []define.OS{
			{
				Type: define.Windows,
			},
		},
		Sudo: true,
	})
}

func TestSpecificCombinationOne(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: define.Default,
		OS: []define.OS{
			{
				Type:    define.Linux,
				Arch:    define.ARM64,
				Distro:  "ubuntu",
				Version: "20.04",
			},
		},
	})
}

func TestSpecificCombinationTwo(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: define.Default,
		OS: []define.OS{
			{
				Type:    define.Linux,
				Arch:    define.ARM64,
				Distro:  "ubuntu",
				Version: "20.04",
			},
		},
	})
}

func TestSpecificCombinationWithCloud(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: define.Default,
		OS: []define.OS{
			{
				Type:    define.Linux,
				Arch:    define.ARM64,
				Distro:  "ubuntu",
				Version: "20.04",
			},
		},
		Stack: &define.Stack{
			Version: "8.8.0",
		},
	})
}

func TestGroup_One_One(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: "one",
		OS: []define.OS{
			{
				Type:    define.Linux,
				Arch:    define.ARM64,
				Distro:  "ubuntu",
				Version: "20.04",
			},
		},
		Stack: &define.Stack{
			Version: "8.8.0",
		},
	})
}

func TestGroup_One_Two(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: "one",
		OS: []define.OS{
			{
				Type:    define.Linux,
				Arch:    define.ARM64,
				Distro:  "ubuntu",
				Version: "20.04",
			},
		},
		Stack: &define.Stack{
			Version: "8.8.0",
		},
	})
}

func TestGroup_Two_One(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: "two",
		OS: []define.OS{
			{
				Type: define.Linux,
				Arch: define.ARM64,
			},
		},
	})
}

func TestGroup_Two_Two(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: "two",
		OS: []define.OS{
			{
				Type: define.Linux,
				Arch: define.ARM64,
			},
		},
	})
}

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
		Local: true,
	})
}

func TestAnySudo(t *testing.T) {
	define.Require(t, define.Requirements{
		Sudo: true,
	})
}

func TestAnyIsolate(t *testing.T) {
	define.Require(t, define.Requirements{
		Isolate: true,
	})
}

func TestDarwinLocal(t *testing.T) {
	define.Require(t, define.Requirements{
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
		OS: []define.OS{
			{
				Type: define.Darwin,
			},
		},
		Sudo: true,
	})
}

func TestDarwinIsolate(t *testing.T) {
	define.Require(t, define.Requirements{
		OS: []define.OS{
			{
				Type: define.Darwin,
			},
		},
		Isolate: true,
	})
}

func TestLinuxLocal(t *testing.T) {
	define.Require(t, define.Requirements{
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
		OS: []define.OS{
			{
				Type: define.Linux,
			},
		},
		Sudo: true,
	})
}

func TestLinuxIsolate(t *testing.T) {
	define.Require(t, define.Requirements{
		OS: []define.OS{
			{
				Type: define.Linux,
			},
		},
		Isolate: true,
	})
}

func TestWindowsLocal(t *testing.T) {
	define.Require(t, define.Requirements{
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
		OS: []define.OS{
			{
				Type: define.Windows,
			},
		},
		Sudo: true,
	})
}

func TestWindowsIsolate(t *testing.T) {
	define.Require(t, define.Requirements{
		OS: []define.OS{
			{
				Type: define.Windows,
			},
		},
		Isolate: true,
	})
}

func TestSpecificCombinationOne(t *testing.T) {
	define.Require(t, define.Requirements{
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

func TestSpecificShardID_One_One(t *testing.T) {
	define.Require(t, define.Requirements{
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
		ShardID: "One",
	})
}

func TestSpecificShardID_One_Two(t *testing.T) {
	define.Require(t, define.Requirements{
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
		ShardID: "One",
	})
}

func TestShardID_Two_One(t *testing.T) {
	define.Require(t, define.Requirements{
		OS: []define.OS{
			{
				Type: define.Linux,
				Arch: define.ARM64,
			},
		},
		ShardID: "Two",
	})
}

func TestShardID_Two_Two(t *testing.T) {
	define.Require(t, define.Requirements{
		OS: []define.OS{
			{
				Type: define.Linux,
				Arch: define.ARM64,
			},
		},
		ShardID: "Two",
	})
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestGetSupported(t *testing.T) {
	scenarios := []struct {
		Name      string
		OS        define.OS
		Platforms []define.OS
		Results   []SupportedOS
		Err       error
	}{
		{
			Name: "not supported",
			OS: define.OS{
				Type: define.Darwin,
				Arch: define.AMD64,
			},
			Err: errors.New("os/arch not currently supported: darwin/amd64"),
		},
		{
			Name: "ubuntu/not specific",
			OS: define.OS{
				Type: define.Linux,
				Arch: define.AMD64,
			},
			Results: []SupportedOS{
				UbuntuAMD64_2204,
				UbuntuAMD64_2004,
			},
		},
		{
			Name: "ubuntu/specific",
			OS: define.OS{
				Type:    define.Linux,
				Arch:    define.AMD64,
				Distro:  Ubuntu,
				Version: "20.04",
			},
			Results: []SupportedOS{
				UbuntuAMD64_2004,
			},
		},
		{
			Name: "ubuntu/platform filter",
			OS: define.OS{
				Type: define.Linux,
				Arch: define.AMD64,
			},
			Platforms: []define.OS{
				{
					Type:    define.Linux,
					Arch:    define.AMD64,
					Distro:  Ubuntu,
					Version: "20.04",
				},
				// should not have an effect
				{
					Type:    define.Linux,
					Arch:    define.ARM64,
					Distro:  Ubuntu,
					Version: "20.04",
				},
			},
			Results: []SupportedOS{
				UbuntuAMD64_2004,
			},
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			actual, err := getSupported(scenario.OS, scenario.Platforms)
			if scenario.Err == nil {
				require.NoError(t, err)
				require.Equal(t, scenario.Results, actual)
			} else {
				require.EqualError(t, err, scenario.Err.Error())
			}
		})
	}
}

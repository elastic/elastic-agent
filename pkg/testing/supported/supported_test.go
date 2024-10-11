// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package supported

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/common"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestGetSupported(t *testing.T) {
	scenarios := []struct {
		Name      string
		OS        define.OS
		Platforms []define.OS
		Results   []common.SupportedOS
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
				Type:   define.Linux,
				Arch:   define.AMD64,
				Distro: Ubuntu,
			},
			Results: []common.SupportedOS{
				UbuntuAMD64_2404,
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
			Results: []common.SupportedOS{
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
			Results: []common.SupportedOS{
				UbuntuAMD64_2004,
			},
		},
		{
			Name: "rhel/not specific",
			OS: define.OS{
				Type:   define.Linux,
				Arch:   define.AMD64,
				Distro: Rhel,
			},
			Results: []common.SupportedOS{
				RhelAMD64_8,
			},
		},
		{
			Name: "rhel/specific",
			OS: define.OS{
				Type:    define.Linux,
				Arch:    define.AMD64,
				Distro:  Rhel,
				Version: "8",
			},
			Results: []common.SupportedOS{
				RhelAMD64_8,
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

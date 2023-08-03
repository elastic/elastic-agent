package runner

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestConfig_GetPlatforms(t *testing.T) {
	scenarios := []struct {
		Platforms []string
		Results   []define.OS
		Err       error
	}{
		{
			Platforms: nil,
		},
		{
			Platforms: []string{""},
			Err:       errors.New(`failed to parse platform string "": type must be defined`),
		},
		{
			Platforms: []string{"unknown"},
			Err:       errors.New(`failed to parse platform string "unknown": type must be either darwin, linux, or windows`),
		},
		{
			Platforms: []string{"linux/blah"},
			Err:       errors.New(`failed to parse platform string "linux/blah": arch must be either amd64 or arm64`),
		},
		{
			Platforms: []string{"linux/arm64/centos/12/toomany"},
			Err:       errors.New(`failed to parse platform string "linux/arm64/centos/12/toomany": more than 3 separators`),
		},
		{
			Platforms: []string{"windows/arm64"},
			Err:       errors.New(`failed to parse platform string "windows/arm64": windows on arm64 not supported`),
		},
		{
			Platforms: []string{"linux/arm64/centos", "windows/arm64/toomany/2022"},
			Err:       errors.New(`failed to parse platform string "windows/arm64/toomany/2022": more than 2 separators`),
		},
		{
			Platforms: []string{
				"linux",
				"linux/amd64",
				"linux/arm64",
				"linux/amd64/ubuntu",
				"linux/arm64/ubuntu/22.04",
				"darwin",
				"darwin/amd64",
				"darwin/arm64",
				"darwin/amd64/ventura",
				"windows",
				"windows/amd64",
				"windows/amd64/2022",
			},
			Results: []define.OS{
				{
					Type: define.Linux,
				},
				{
					Type: define.Linux,
					Arch: define.AMD64,
				},
				{
					Type: define.Linux,
					Arch: define.ARM64,
				},
				{
					Type:   define.Linux,
					Arch:   define.AMD64,
					Distro: Ubuntu,
				},
				{
					Type:    define.Linux,
					Arch:    define.ARM64,
					Distro:  Ubuntu,
					Version: "22.04",
				},
				{
					Type: define.Darwin,
				},
				{
					Type: define.Darwin,
					Arch: define.AMD64,
				},
				{
					Type: define.Darwin,
					Arch: define.ARM64,
				},
				{
					Type:    define.Darwin,
					Arch:    define.AMD64,
					Version: "ventura",
				},
				{
					Type: define.Windows,
				},
				{
					Type: define.Windows,
					Arch: define.AMD64,
				},
				{
					Type:    define.Windows,
					Arch:    define.AMD64,
					Version: "2022",
				},
			},
		},
	}
	for _, scenario := range scenarios {
		var name string
		if scenario.Platforms == nil {
			name = "empty"
		} else {
			name = fmt.Sprintf("platforms:%s", strings.Join(scenario.Platforms, ","))
		}
		t.Run(name, func(t *testing.T) {
			c := Config{
				Platforms: scenario.Platforms,
			}
			actual, err := c.GetPlatforms()
			if scenario.Err == nil {
				require.NoError(t, err)
				require.Equal(t, scenario.Results, actual)
			} else {
				require.EqualError(t, err, scenario.Err.Error())
			}
		})
	}
}

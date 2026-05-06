// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package define

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuntimeSkipped(t *testing.T) {
	cases := []struct {
		name          string
		skipOS        []OS
		os            string
		arch          string
		version       string
		distro        string
		dockerVariant string
		wantSkipped   bool
		wantMatch     OS
	}{
		{
			name:        "empty skip list does not skip",
			skipOS:      nil,
			os:          Windows,
			arch:        ARM64,
			wantSkipped: false,
		},
		{
			name:        "exact os+arch match",
			skipOS:      []OS{{Type: Windows, Arch: ARM64}},
			os:          Windows,
			arch:        ARM64,
			wantSkipped: true,
			wantMatch:   OS{Type: Windows, Arch: ARM64},
		},
		{
			name:        "type matches but arch mismatched",
			skipOS:      []OS{{Type: Windows, Arch: ARM64}},
			os:          Windows,
			arch:        AMD64,
			wantSkipped: false,
		},
		{
			name:        "no arch specified acts as wildcard",
			skipOS:      []OS{{Type: Windows}},
			os:          Windows,
			arch:        ARM64,
			wantSkipped: true,
			wantMatch:   OS{Type: Windows},
		},
		{
			name:        "no arch specified matches amd64 too",
			skipOS:      []OS{{Type: Linux}},
			os:          Linux,
			arch:        AMD64,
			wantSkipped: true,
			wantMatch:   OS{Type: Linux},
		},
		{
			name:        "type mismatch is not skipped",
			skipOS:      []OS{{Type: Windows, Arch: ARM64}},
			os:          Linux,
			arch:        ARM64,
			wantSkipped: false,
		},
		{
			name: "second entry matches when first does not",
			skipOS: []OS{
				{Type: Linux, Arch: ARM64},
				{Type: Windows, Arch: ARM64},
			},
			os:          Windows,
			arch:        ARM64,
			wantSkipped: true,
			wantMatch:   OS{Type: Windows, Arch: ARM64},
		},
		{
			name:        "version specified and matching",
			skipOS:      []OS{{Type: Linux, Version: "22.04"}},
			os:          Linux,
			arch:        AMD64,
			version:     "22.04",
			wantSkipped: true,
			wantMatch:   OS{Type: Linux, Version: "22.04"},
		},
		{
			name:        "version specified and mismatched",
			skipOS:      []OS{{Type: Linux, Version: "22.04"}},
			os:          Linux,
			arch:        AMD64,
			version:     "24.04",
			wantSkipped: false,
		},
		{
			name:        "distro specified and matching",
			skipOS:      []OS{{Type: Linux, Distro: "ubuntu"}},
			os:          Linux,
			arch:        AMD64,
			distro:      "ubuntu",
			wantSkipped: true,
			wantMatch:   OS{Type: Linux, Distro: "ubuntu"},
		},
		{
			name:        "distro specified and mismatched",
			skipOS:      []OS{{Type: Linux, Distro: "ubuntu"}},
			os:          Linux,
			arch:        AMD64,
			distro:      "rhel",
			wantSkipped: false,
		},
		{
			name:          "kubernetes docker variant match",
			skipOS:        []OS{{Type: Kubernetes, DockerVariant: "wolfi"}},
			os:            Kubernetes,
			arch:          AMD64,
			dockerVariant: "wolfi",
			wantSkipped:   true,
			wantMatch:     OS{Type: Kubernetes, DockerVariant: "wolfi"},
		},
		{
			name:          "kubernetes docker variant mismatch",
			skipOS:        []OS{{Type: Kubernetes, DockerVariant: "wolfi"}},
			os:            Kubernetes,
			arch:          AMD64,
			dockerVariant: "default",
			wantSkipped:   false,
		},
		{
			name: "all fields constrained and matching",
			skipOS: []OS{{
				Type:    Linux,
				Arch:    ARM64,
				Version: "22.04",
				Distro:  "ubuntu",
			}},
			os:          Linux,
			arch:        ARM64,
			version:     "22.04",
			distro:      "ubuntu",
			wantSkipped: true,
			wantMatch: OS{
				Type:    Linux,
				Arch:    ARM64,
				Version: "22.04",
				Distro:  "ubuntu",
			},
		},
		{
			name: "all fields constrained but arch mismatched",
			skipOS: []OS{{
				Type:    Linux,
				Arch:    ARM64,
				Version: "22.04",
				Distro:  "ubuntu",
			}},
			os:          Linux,
			arch:        AMD64,
			version:     "22.04",
			distro:      "ubuntu",
			wantSkipped: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Requirements{Group: Default, SkipOS: tc.skipOS}
			matched, ok := r.runtimeSkipped(tc.os, tc.arch, tc.version, tc.distro, tc.dockerVariant)
			require.Equal(t, tc.wantSkipped, ok, "unexpected skip decision")
			require.Equal(t, tc.wantMatch, matched, "unexpected matched OS entry")
		})
	}
}

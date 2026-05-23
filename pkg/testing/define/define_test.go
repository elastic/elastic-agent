// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package define

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalSudoBlocked(t *testing.T) {
	cases := []struct {
		name          string
		sudo          bool
		local         bool
		allowOverride string // value of TEST_RUN_LOCAL_SUDO
		want          bool
	}{
		{
			name:  "non-sudo local test is never blocked",
			sudo:  false,
			local: true,
			want:  false,
		},
		{
			name:  "sudo test on a remote runner is not blocked",
			sudo:  true,
			local: false,
			want:  false,
		},
		{
			name:  "sudo local test is blocked by default",
			sudo:  true,
			local: true,
			want:  true,
		},
		{
			name:          "sudo local test is allowed with override",
			sudo:          true,
			local:         true,
			allowOverride: "true",
			want:          false,
		},
		{
			name:          "explicit false override keeps the block",
			sudo:          true,
			local:         true,
			allowOverride: "false",
			want:          true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEST_RUN_LOCAL_SUDO", tc.allowOverride)
			got := localSudoBlocked(Requirements{Sudo: tc.sudo}, tc.local)
			require.Equal(t, tc.want, got)
		})
	}
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cpulimit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQuotaKindName(t *testing.T) {
	cases := map[QuotaKind]string{QuotaUnknown: "unknown", QuotaNone: "none", QuotaSet: "set"}
	for kind, want := range cases {
		require.Equal(t, want, kind.Name())
	}
}

func TestDeriveState(t *testing.T) {
	cases := []struct {
		name string
		in   StateInput
		exp  State
	}{
		{name: "cap off", in: StateInput{}, exp: StateDisabled},
		{name: "cap on", in: StateInput{CapRequested: true}, exp: StateApplied},
		{name: "cap on and changing", in: StateInput{CapRequested: true, Changing: true}, exp: StatePending},
		{name: "cap on and failed", in: StateInput{CapRequested: true, Failed: true}, exp: StateDegraded},
		{name: "failed and changing", in: StateInput{CapRequested: true, Failed: true, Changing: true}, exp: StateDegraded},
		{name: "cap on and unsupported", in: StateInput{CapRequested: true, Unsupported: true}, exp: StateUnsupported},
		{name: "cap off and unsupported", in: StateInput{Unsupported: true}, exp: StateDisabled},
		{name: "cap off ignores failed and changing", in: StateInput{Failed: true, Changing: true}, exp: StateDisabled},
		{name: "cap off and removing", in: StateInput{Removing: true}, exp: StateDisabled},
		{name: "cap off, removing and changing", in: StateInput{Removing: true, Changing: true}, exp: StatePending},
		{name: "cap off, removing and failed", in: StateInput{Removing: true, Failed: true}, exp: StateDegraded},
		{name: "cap off, removing and unsupported", in: StateInput{Removing: true, Unsupported: true}, exp: StateDisabled},
		{
			name: "cap on, unsupported and changing",
			in:   StateInput{CapRequested: true, Unsupported: true, Changing: true},
			exp:  StatePending,
		},
		{
			name: "cap on, unsupported and failed",
			in:   StateInput{CapRequested: true, Unsupported: true, Failed: true},
			exp:  StateDegraded,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.exp, DeriveState(tc.in))
		})
	}
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cpulimit

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/limits"
)

func TestControllerStatusState(t *testing.T) {
	cases := []struct {
		enabled, mayRemove, failed, pending, unsupported bool
		want                                             State
	}{
		{false, false, false, false, false, StateDisabled},
		{false, false, false, false, true, StateDisabled},
		{false, false, false, true, false, StateDisabled},
		{false, false, false, true, true, StateDisabled},
		{false, false, true, false, false, StateDisabled},
		{false, false, true, false, true, StateDisabled},
		{false, false, true, true, false, StateDisabled},
		{false, false, true, true, true, StateDisabled},
		{false, true, false, false, false, StateDisabled},
		{false, true, false, false, true, StateDisabled},
		{false, true, false, true, false, StatePending},
		{false, true, false, true, true, StatePending},
		{false, true, true, false, false, StateDegraded},
		{false, true, true, false, true, StateDegraded},
		{false, true, true, true, false, StateDegraded},
		{false, true, true, true, true, StateDegraded},
		{true, false, false, false, false, StateApplied},
		{true, false, false, false, true, StateUnsupported},
		{true, false, false, true, false, StatePending},
		{true, false, false, true, true, StatePending},
		{true, false, true, false, false, StateDegraded},
		{true, false, true, false, true, StateDegraded},
		{true, false, true, true, false, StateDegraded},
		{true, false, true, true, true, StateDegraded},
		{true, true, false, false, false, StateApplied},
		{true, true, false, false, true, StateUnsupported},
		{true, true, false, true, false, StatePending},
		{true, true, false, true, true, StatePending},
		{true, true, true, false, false, StateDegraded},
		{true, true, true, false, true, StateDegraded},
		{true, true, true, true, false, StateDegraded},
		{true, true, true, true, true, StateDegraded},
	}
	for _, tc := range cases {
		name := fmt.Sprintf("enabled=%t mayRemove=%t failed=%t pending=%t unsupported=%t",
			tc.enabled, tc.mayRemove, tc.failed, tc.pending, tc.unsupported)
		t.Run(name, func(t *testing.T) {
			var req limits.CPULimit
			if tc.enabled {
				req = cpuLimit(t, 50)
			}
			s := controllerStatus{pending: tc.pending}
			if tc.failed {
				s.err = errBackend
			}
			if tc.unsupported {
				s.unsupported = &UnsupportedError{Reason: "no systemd"}
			}
			require.Equal(t, tc.want, s.state(req, tc.mayRemove))
		})
	}
}

func TestControllerStatusRequestChanged(t *testing.T) {
	cases := []struct {
		name                      string
		pending                   bool
		active, effective         Quota
		wantActive, wantEffective Quota
	}{
		{"not pending set", false, quotaSet(4), quotaSet(3), quotaSkipped, quotaSkipped},
		{"not pending none", false, quotaNone, quotaNone, quotaSkipped, quotaSkipped},
		{"not pending unknown", false, Quota{}, Quota{}, quotaSkipped, quotaSkipped},
		{"not pending skipped", false, quotaSkipped, quotaSkipped, quotaSkipped, quotaSkipped},
		{"pending set", true, quotaSet(4), quotaSet(3), quotaSet(4), quotaSet(3)},
		{"pending none", true, quotaNone, quotaNone, quotaNone, quotaNone},
		{"pending unknown", true, Quota{}, Quota{}, Quota{}, Quota{}},
		{"pending skipped", true, quotaSkipped, quotaSkipped, quotaSkipped, quotaSkipped},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := controllerStatus{
				pending: !tc.pending, err: errBackend, unsupported: &UnsupportedError{Reason: "no systemd"},
				activeQuota: tc.active, effectiveQuota: tc.effective,
			}
			s.requestChanged(tc.pending)
			require.Equal(t, tc.pending, s.pending)
			require.NoError(t, s.err)
			require.Nil(t, s.unsupported)
			require.Equal(t, tc.wantActive, s.activeQuota)
			require.Equal(t, tc.wantEffective, s.effectiveQuota)
		})
	}
}

func TestControllerStatusRecordQuotas(t *testing.T) {
	cases := []struct {
		name              string
		active, effective Quota
	}{
		{"unknown", Quota{}, Quota{}},
		{"skipped", quotaSkipped, quotaSkipped},
		{"none", Quota{Kind: QuotaNone}, Quota{}},
		{"set", quotaSet(2), quotaSet(1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := controllerStatus{activeQuota: quotaSet(4), effectiveQuota: quotaSet(4), pending: true}
			s.record(passResult{activeQuota: tc.active, effectiveQuota: tc.effective})
			require.Equal(t, tc.active, s.activeQuota)
			require.Equal(t, tc.effective, s.effectiveQuota)
			require.False(t, s.pending)
		})
	}
}

func TestTargetQuota(t *testing.T) {
	var half limits.CPULimit
	require.NoError(t, half.Unpack(50))

	t.Run("no cap is none, also before the CPU count is read", func(t *testing.T) {
		require.Equal(t, Quota{Kind: QuotaNone}, targetQuota(limits.CPULimit{}, 0))
		require.Equal(t, Quota{Kind: QuotaNone}, targetQuota(limits.CPULimit{}, 4))
	})
	t.Run("a cap is unknown until the CPU count is read", func(t *testing.T) {
		require.Equal(t, Quota{}, targetQuota(half, 0))
	})
	t.Run("a cap with a CPU count is the target", func(t *testing.T) {
		require.Equal(t, Quota{Kind: QuotaSet, CPUs: 2}, targetQuota(half, 4))
	})
}

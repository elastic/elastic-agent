// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cpulimit

import (
	"github.com/elastic/elastic-agent/pkg/limits"
)

// controllerStatus is what the passes found and how the last one ended, plus whether a result is pending.
type controllerStatus struct {
	// pending is true while the requested cap is not confirmed yet, or while the quota is being changed or removed.
	pending bool
	err     error
	// unsupported is set when the host cannot enforce the cap by design.
	unsupported *UnsupportedError
	activeQuota Quota
	// effectiveQuota is the last effective quota, for reporting only.
	effectiveQuota Quota
	// logicalCPUs is the last logical CPU count, or 0 if it was never read.
	logicalCPUs int
}

// requestChanged starts a new request and forgets the old failure. A new request is pending when a check is needed, or
// when a quota may still be removed. Without one, the quotas are skipped.
func (s *controllerStatus) requestChanged(pending bool) {
	s.pending = pending
	s.err, s.unsupported = nil, nil
	if !pending {
		s.activeQuota, s.effectiveQuota = skippedQuota(), skippedQuota()
	}
}

// record stores the result of a finished pass.
func (s *controllerStatus) record(res passResult) {
	if res.logicalCPUs > 0 {
		s.logicalCPUs = res.logicalCPUs
	}
	s.activeQuota, s.effectiveQuota = res.activeQuota, res.effectiveQuota
	s.pending = false

	s.unsupported, s.err = res.unsupported, res.err
}

func (s controllerStatus) snapshot(req limits.CPULimit, mayRemove bool) Snapshot {
	snap := Snapshot{
		State:          s.state(req, mayRemove),
		Configured:     req,
		ActiveQuota:    s.activeQuota,
		EffectiveQuota: s.effectiveQuota,
		Err:            s.err,
		TargetQuota:    targetQuota(req, s.logicalCPUs),
	}
	if snap.State == StateUnsupported {
		snap.Reason = s.unsupported.Reason
	}
	return snap
}

// state returns the State. The order of the cases matters. With the cap off, a failure or a pending removal affects
// the State only while the controller's quota is being removed.
func (s controllerStatus) state(req limits.CPULimit, mayRemove bool) State {
	switch {
	case !req.Enabled() && !mayRemove:
		return StateDisabled
	case s.err != nil:
		return StateDegraded
	case s.pending:
		return StatePending
	case !req.Enabled():
		return StateDisabled
	case s.unsupported != nil:
		return StateUnsupported
	default:
		return StateApplied
	}
}

// unknownQuota returns a quota that is not known.
func unknownQuota() Quota {
	return Quota{Kind: QuotaUnknown}
}

// skippedQuota returns the quota shown when the cap is off and no quota may be removed.
func skippedQuota() Quota {
	return Quota{Kind: QuotaSkipped}
}

// targetQuota returns the quota that req asks for on a host with logicalCPUs CPUs. It is none without a cap, and
// unknown while the CPU count is not read.
func targetQuota(req limits.CPULimit, logicalCPUs int) Quota {
	switch {
	case !req.Enabled():
		return Quota{Kind: QuotaNone}
	case logicalCPUs > 0:
		return Quota{Kind: QuotaSet, CPUs: req.TargetCPUs(logicalCPUs)}
	default:
		return unknownQuota()
	}
}

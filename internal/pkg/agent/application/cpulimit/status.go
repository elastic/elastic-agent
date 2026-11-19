// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package cpulimit models the state of the CPU cap shared by the agent and its components.
package cpulimit

import (
	"time"

	"github.com/elastic/elastic-agent/pkg/limits"
)

// State is the state of the CPU cap.
type State string

const (
	// StateDisabled means no cap is requested and no agent quota needs to be removed.
	StateDisabled State = "disabled"
	// StatePending means the first check or a change of the cap is waiting or in progress.
	StatePending State = "pending"
	// StateApplied means the requested cap is set and verified. A lower quota from outside the agent may still govern.
	StateApplied State = "applied"
	// StateUnsupported means a cap is requested but enforcement is unavailable on this host by design.
	StateUnsupported State = "unsupported"
	// StateDegraded means an unexpected failure is not resolved yet.
	StateDegraded State = "degraded"
)

// QuotaKind tells what is known about the active quota.
type QuotaKind string

const (
	// QuotaUnknown means the quota was not checked yet, or it could not be read. It is the zero value.
	QuotaUnknown QuotaKind = ""
	// QuotaNone means a check confirmed that no quota is set.
	QuotaNone QuotaKind = "none"
	// QuotaSet means a check found a quota. Quota.CPUs holds its value.
	QuotaSet QuotaKind = "set"
)

// Quota is the CPU quota observed in the operating system.
type Quota struct {
	Kind QuotaKind
	// CPUs is the quota as a number of CPUs. It has a meaning only when Kind is QuotaSet.
	CPUs float64
	// LastKnown is true when the value comes from an earlier check and a newer request is not verified yet.
	// It applies only to QuotaNone and QuotaSet.
	LastKnown bool
}

// Snapshot is one consistent view of the CPU cap.
type Snapshot struct {
	State State
	// Configured is the accepted CPU setting.
	Configured limits.CPULimit
	// EffectiveCPUs is the requested number of CPUs after the floor. It is 0 when the cap is off.
	EffectiveCPUs float64
	// ActiveQuota is the quota observed in the operating system.
	ActiveQuota Quota
	// CheckedAt is the time of the check that observed ActiveQuota. It is zero if no check was done.
	CheckedAt time.Time
	// Err is the unresolved failure, if any.
	Err error
}

// StateInput holds the facts DeriveState uses to choose the State.
type StateInput struct {
	// CapRequested is true when the latest accepted setting has the cap on.
	CapRequested bool
	// Failed is true while an unexpected failure remains unresolved.
	Failed bool
	// Changing is true while a check or a change is waiting or running.
	// Until the first check ends, the caller keeps it true; otherwise a cap that was never checked reports StateApplied.
	Changing bool
	// Unsupported is true when enforcement is unavailable on this host by design.
	Unsupported bool
}

// DeriveState returns the State for in. The rules are checked in this order and the first match wins:
// Failed gives StateDegraded, Changing gives StatePending, CapRequested with Unsupported gives StateUnsupported,
// no CapRequested gives StateDisabled, and anything else gives StateApplied.
func DeriveState(in StateInput) State {
	switch {
	case in.Failed:
		return StateDegraded
	case in.Changing:
		return StatePending
	case in.CapRequested && in.Unsupported:
		return StateUnsupported
	case !in.CapRequested:
		return StateDisabled
	default:
		return StateApplied
	}
}

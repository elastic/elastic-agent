// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package cpulimit enforces the CPU cap shared by the agent and its components and reports its state.
package cpulimit

import (
	"github.com/elastic/elastic-agent/pkg/limits"
)

// State is the state of the CPU cap.
type State string

const (
	// StateDisabled means no cap is requested and the agent has nothing to remove: it never applied a quota, or the
	// removal is finished.
	StateDisabled State = "disabled"
	// StatePending means a first check, a change of the cap, or the first attempt to remove the agent's own quota after
	// the cap was turned off is waiting or in progress. A failed removal shows StateDegraded while it is retried.
	StatePending State = "pending"
	// StateApplied means the requested cap is set and verified. It is used only while a cap is requested. A lower quota
	// from outside the agent may still govern.
	StateApplied State = "applied"
	// StateUnsupported means a cap is requested but enforcement is unavailable on this host by design.
	StateUnsupported State = "unsupported"
	// StateDegraded means an unexpected failure is not resolved yet. This includes a failed removal of the agent's own
	// quota after the cap was turned off.
	StateDegraded State = "degraded"
)

// QuotaKind tells what is known about a quota.
type QuotaKind string

const (
	// QuotaUnknown means the quota was not checked yet, it could not be read, or the cap is off and no agent quota is
	// being removed. It is the zero value.
	QuotaUnknown QuotaKind = ""
	// QuotaNone means a check confirmed that no quota is set.
	QuotaNone QuotaKind = "none"
	// QuotaSet means a check found a quota. Quota.CPUs holds its value.
	QuotaSet QuotaKind = "set"
)

// Name returns the text used when the kind is shown to users or sent to other systems: "unknown" for QuotaUnknown,
// and the kind value otherwise.
func (k QuotaKind) Name() string {
	if k == QuotaUnknown {
		return "unknown"
	}
	return string(k)
}

// Quota is the CPU quota observed in the operating system.
type Quota struct {
	Kind QuotaKind
	// CPUs is the quota as a number of CPUs. It has a meaning only when Kind is QuotaSet.
	CPUs float64
}

// Snapshot is one consistent view of the CPU cap.
type Snapshot struct {
	State State
	// Configured is the accepted CPU setting.
	Configured limits.CPULimit
	// TargetCPUs is the number of CPUs the cap asks for, after the floor.
	// It is 0 when the cap is off or when the CPU count was never read.
	TargetCPUs float64
	// ActiveQuota is the quota on the Agent's own service. With the cap off, it is unknown, except while an agent quota
	// is being removed: then it is the quota found by the last check.
	ActiveQuota Quota
	// EffectiveQuota is the lowest limit that the system enforces on the Agent across its service and its parents.
	// It is informational only. It is unknown when it was not read. With the cap off, it follows the same rule as
	// ActiveQuota.
	EffectiveQuota Quota
	// Err is the unresolved unexpected failure, if any. It is nil when State is StateUnsupported.
	Err error
	// Reason tells why enforcement is unavailable on this host. It is set only when State is StateUnsupported.
	Reason string
}

// StateInput holds the facts DeriveState uses to choose the State.
type StateInput struct {
	// CapRequested is true when the latest accepted setting has the cap on.
	CapRequested bool
	// Removing is true when no cap is requested but an agent quota is still being removed.
	Removing bool
	// Failed is true while an unexpected failure remains unresolved.
	Failed bool
	// Changing is true while a check or a change is waiting or running.
	// When a cap is requested, the caller keeps it true until the first check ends; otherwise a cap that was never
	// checked reports StateApplied.
	Changing bool
	// Unsupported is true when enforcement is unavailable on this host by design.
	Unsupported bool
}

// DeriveState returns the State for in. The rules are checked in this order and the first match wins:
// neither CapRequested nor Removing gives StateDisabled, Failed gives StateDegraded, Changing gives StatePending,
// no CapRequested gives StateDisabled, Unsupported gives StateUnsupported, and anything else gives StateApplied.
// So with no cap requested, Failed and Changing count only while a quota is being removed.
func DeriveState(in StateInput) State {
	switch {
	case !in.CapRequested && !in.Removing:
		return StateDisabled
	case in.Failed:
		return StateDegraded
	case in.Changing:
		return StatePending
	case !in.CapRequested:
		return StateDisabled
	case in.Unsupported:
		return StateUnsupported
	default:
		return StateApplied
	}
}

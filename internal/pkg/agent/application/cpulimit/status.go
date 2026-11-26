// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package cpulimit models the state of the CPU cap shared by the agent and its components.
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
	// StatePending means a first check, a change of the cap, or the removal of the agent's own quota after the cap was
	// turned off is waiting or in progress.
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
}

// Snapshot is one consistent view of the CPU cap.
type Snapshot struct {
	State State
	// Configured is the accepted CPU setting.
	Configured limits.CPULimit
	// TargetCPUs is the number of CPUs the cap asks for, after the floor. It is 0 when the cap is off.
	TargetCPUs float64
	// ActiveQuota is the quota on the Agent's own service.
	ActiveQuota Quota
	// EffectiveQuota is the lowest limit that the system enforces on the Agent across its service and its parents.
	// It is informational only. It is unknown when it was not read.
	EffectiveQuota Quota
	// Err is the unresolved failure, if any.
	Err error
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
	// Until the first check ends, the caller keeps it true; otherwise a cap that was never checked reports StateApplied.
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

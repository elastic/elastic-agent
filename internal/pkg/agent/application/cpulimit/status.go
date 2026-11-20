// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package cpulimit enforces one CPU cap for the agent and its components. It also reports the cap state.
package cpulimit

import (
	"github.com/elastic/elastic-agent/pkg/limits"
)

// State is the state of the CPU cap.
type State string

const (
	// StateDisabled means no cap is requested and the agent has nothing to remove. Either it never set a quota, or
	// the removal is done.
	StateDisabled State = "disabled"
	// StatePending means one of these is waiting or in progress: a first check, a change of the cap, or the first try
	// to remove the quota the agent set after the cap is turned off. A failed removal shows StateDegraded while retried.
	StatePending State = "pending"
	// StateApplied means the requested cap is set and confirmed. It is used only while a cap is requested. A lower
	// quota from outside the agent may still limit the agent more.
	StateApplied State = "applied"
	// StateUnsupported means a cap is requested but this host cannot enforce it by design.
	StateUnsupported State = "unsupported"
	// StateDegraded means an unexpected failure is not fixed yet. This includes a failed removal of the quota the
	// agent set after the cap is turned off.
	StateDegraded State = "degraded"
)

// QuotaKind tells what is known about a quota.
type QuotaKind string

const (
	// QuotaUnknown means the quota is not known: it was not checked or computed yet, or it could not be read.
	// It is the zero value.
	QuotaUnknown QuotaKind = ""
	// QuotaNone means there is no quota: a check found that none is set, or no cap is requested.
	QuotaNone QuotaKind = "none"
	// QuotaSet means there is a quota. Quota.CPUs holds its value.
	QuotaSet QuotaKind = "set"
	// QuotaSkipped means the cap is off and no quota may be removed, so the controller does not check the quota. The
	// host may still have one. It is shown as unknown outside the controller. It may stay until the first check of a new
	// cap ends.
	QuotaSkipped QuotaKind = "skipped"
)

// Known reports whether a check or a computation gave a value: the quota is none or set. It is false for unknown and
// skipped, so code that does not care why a quota is not known can use it.
func (k QuotaKind) Known() bool {
	return k == QuotaNone || k == QuotaSet
}

// MarshalText shows the kind as Name does, so an encoder never writes the internal value skipped.
func (k QuotaKind) MarshalText() ([]byte, error) {
	return []byte(k.Name()), nil
}

// Name returns the text used to show the kind to users or to send it to other systems. It is "unknown" when the kind
// is not Known, and the kind value otherwise.
func (k QuotaKind) Name() string {
	if !k.Known() {
		return "unknown"
	}
	return string(k)
}

// Quota describes a CPU quota: unknown, skipped, none, or a number of CPUs. It does not say if the value is wanted or
// found. The field that holds it says that.
type Quota struct {
	Kind QuotaKind
	// CPUs is the quota as a number of CPUs. It is used only when Kind is QuotaSet.
	CPUs float64
}

// Snapshot is one consistent view of the CPU cap.
type Snapshot struct {
	State State
	// Configured is the accepted CPU setting.
	Configured limits.CPULimit
	// TargetQuota is the quota the cap asks for, after the floor. It is none when no cap is requested. It is unknown
	// when the CPU count was never read, because then it cannot be computed.
	TargetQuota Quota
	// ActiveQuota is the quota on the Agent's own service. It is not Known (skipped or unknown) when the cap is off and
	// no quota may be removed, or when the last check did not read it.
	ActiveQuota Quota
	// EffectiveQuota is the CPU quota that applies to the Agent after the limits above it, when it can be worked out.
	// It is for information only. It is not Known in the same cases as ActiveQuota, and also when it cannot be worked
	// out.
	EffectiveQuota Quota
	// Err is the unexpected failure that is not fixed yet, if any. It is nil when State is StateUnsupported.
	Err error
	// Reason tells why this host cannot enforce the cap. It is set only when State is StateUnsupported.
	Reason string
}

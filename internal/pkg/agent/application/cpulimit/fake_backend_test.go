// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cpulimit

import (
	"context"
	"fmt"
	"sync"
)

// fakeBackend models the quota of the agent service and the lowest quota of its parents. A hook, when set, runs
// instead of the model.
// Hooks must be set before the controller runs. They run without the lock, so they may call setQuota and model.
type fakeBackend struct {
	mu          sync.Mutex
	logicalCPUs int
	active      Quota
	// agentHeld is true when the agent's own mechanism holds the quota, so Remove clears it.
	agentHeld bool
	// parent is the lowest quota on the parents of the service.
	parent Quota
	calls  []string

	onLogicalCPUs func(ctx context.Context) (int, error)
	onInspect     func(ctx context.Context) (Inspection, error)
	onApply       func(ctx context.Context, cpus float64) error
	onRemove      func(ctx context.Context) error
}

func newFakeBackend(logicalCPUs int) *fakeBackend {
	return &fakeBackend{logicalCPUs: logicalCPUs, active: quotaNone, parent: quotaNone}
}

func (f *fakeBackend) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

// takeCalls returns the calls recorded since the last takeCalls.
func (f *fakeBackend) takeCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	calls := f.calls
	f.calls = nil
	return calls
}

// setQuota sets the active quota. agentHeld tells whether the agent's own mechanism holds it.
func (f *fakeBackend) setQuota(q Quota, agentHeld bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active, f.agentHeld = q, agentHeld
}

func (f *fakeBackend) setParent(q Quota) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.parent = q
}

func (f *fakeBackend) setLogicalCPUs(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logicalCPUs = n
}

func (f *fakeBackend) activeQuota() Quota {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active
}

func (f *fakeBackend) LogicalCPUs(ctx context.Context) (int, error) {
	f.record("cpus")
	if f.onLogicalCPUs != nil {
		return f.onLogicalCPUs(ctx)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logicalCPUs, nil
}

func (f *fakeBackend) Inspect(ctx context.Context) (Inspection, error) {
	f.record("inspect")
	if f.onInspect != nil {
		return f.onInspect(ctx)
	}
	return f.model(), nil
}

func (f *fakeBackend) model() Inspection {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Inspection{Active: f.active, Effective: lowest(f.active, f.parent)}
}

func (f *fakeBackend) Apply(ctx context.Context, cpus float64) error {
	f.record(fmt.Sprintf("apply %.2f", cpus))
	if f.onApply != nil {
		return f.onApply(ctx, cpus)
	}
	f.setQuota(quotaSet(cpus), true)
	return nil
}

func (f *fakeBackend) Remove(ctx context.Context) error {
	f.record("remove")
	if f.onRemove != nil {
		return f.onRemove(ctx)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.agentHeld {
		f.active, f.agentHeld = quotaNone, false
	}
	return nil
}

// lowest returns the lower of two set quotas, or the one that is set, or no quota. It is unknown when either is not
// known.
func lowest(a, b Quota) Quota {
	switch {
	case !a.Kind.Known() || !b.Kind.Known():
		return unknownQuota()
	case a.Kind != QuotaSet:
		return b
	case b.Kind != QuotaSet || a.CPUs <= b.CPUs:
		return a
	default:
		return b
	}
}

func quotaSet(cpus float64) Quota {
	return Quota{Kind: QuotaSet, CPUs: cpus}
}

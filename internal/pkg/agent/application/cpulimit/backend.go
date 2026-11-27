// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cpulimit

import (
	"context"
)

// Backend changes and reads the CPU quota in the operating system.
// Every method must return when ctx is done.
// A method returns an error that wraps *UnsupportedError when this host cannot enforce the CPU limit by design.
type Backend interface {
	// LogicalCPUs returns the number of online logical CPUs on the host.
	LogicalCPUs(ctx context.Context) (int, error)
	// Inspect reads the active and the effective quota. It fails when it cannot read Active, or when part of the agent
	// workload is outside the service. It must not fail only because the service is not prepared for a quota.
	Inspect(ctx context.Context) (Inspection, error)
	// Apply sets the quota on the Agent's own service to cpus CPUs with the Agent's own mechanism.
	Apply(ctx context.Context, cpus float64) error
	// Remove clears the quota held by the Agent's own mechanism. It does nothing when there is none, so it is safe to
	// call more than once. It never changes a quota set in any other way.
	Remove(ctx context.Context) error
}

// Inspection is the result of Backend.Inspect.
type Inspection struct {
	// Active is the quota that the system enforces on the Agent's own service, no matter who set it. It is never unknown.
	Active Quota
	// Effective is the CPU quota that applies to the Agent after the limits above it, when it can be worked out. It is
	// unknown when it cannot. That never makes Inspect fail.
	Effective Quota
}

// UnsupportedError reports that this host cannot enforce the CPU limit by design.
type UnsupportedError struct {
	// Reason explains why, for example "not running under systemd".
	Reason string
}

// Error returns the reason with a short prefix.
func (e *UnsupportedError) Error() string {
	return "CPU limit is not supported: " + e.Reason
}

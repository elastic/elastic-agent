// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cpulimit

import (
	"context"
)

// Backend changes and reads the CPU quota in the operating system.
// Every method must return when ctx is done.
// A method returns an error that wraps *UnsupportedError when enforcement is unavailable on this host by design.
type Backend interface {
	// LogicalCPUs returns the number of online logical CPUs on the host.
	LogicalCPUs(ctx context.Context) (int, error)
	// Inspect reads the quota on the Agent's own service, which Apply changes, and the effective quota.
	// It returns an error when part of the agent workload is outside the service.
	// It must not fail only because the service is not prepared for a quota.
	Inspect(ctx context.Context) (Inspection, error)
	// Apply sets the quota on the Agent's own service to cpus CPUs with the Agent's own mechanism.
	Apply(ctx context.Context, cpus float64) error
	// Remove clears the quota that the Agent's own mechanism holds. It does nothing when there is none, and it never
	// changes a quota set in any other way, so it is safe to call more than once.
	// The controller calls it when the cap goes off and when it stops, to remove the quota it applied or adopted.
	Remove(ctx context.Context) error
}

// Inspection is the result of Backend.Inspect.
type Inspection struct {
	// Service is the quota on the Agent's own service. Kind unknown only when the Agent's own mechanism holds a quota
	// that is not confirmed in place, for example its override is deleted and the reload is pending, or the kernel
	// value differs. Kind none when no quota is in effect. A quota that the kernel does not enforce counts as none,
	// unless the Agent's own mechanism holds it; then it is unknown.
	Service Quota
	// Effective is the lowest quota enforced on the Agent across its service and its parents. Unknown when it could
	// not be read; that never makes Inspect fail.
	Effective Quota
}

// UnsupportedError reports that enforcement is unavailable on this host by design.
type UnsupportedError struct {
	// Reason explains why, for example "not running under systemd". It is sent to Fleet, so it must be a short fixed
	// text with no host details (no unit names, paths or errno text) and no wrapped error text.
	Reason string
}

// Error returns the reason with a short prefix.
func (e *UnsupportedError) Error() string {
	return "CPU limit is not supported: " + e.Reason
}

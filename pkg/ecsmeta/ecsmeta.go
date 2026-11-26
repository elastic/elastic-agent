// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ecsmeta

// ECSMeta is a collection of agent related metadata in ECS compliant object form.
type ECSMeta struct {
	Elastic *ElasticECSMeta `json:"elastic"`
	Host    *HostECSMeta    `json:"host"`
	OS      *SystemECSMeta  `json:"os"`
}

// ElasticECSMeta is a collection of elastic vendor metadata in ECS compliant object form.
type ElasticECSMeta struct {
	Agent *AgentECSMeta `json:"agent"`
}

// AgentECSMeta is a collection of agent metadata in ECS compliant object form.
type AgentECSMeta struct {
	ID            string `json:"id"`
	Version       string `json:"version"`
	Snapshot      bool   `json:"snapshot"`
	BuildOriginal string `json:"build.original"`
	Upgradeable   bool   `json:"upgradeable"`
	LogLevel      string `json:"log_level"`
	Complete      bool   `json:"complete"`
	Unprivileged  bool   `json:"unprivileged"`
	FIPS          bool   `json:"fips"`
	// Limits is the state of the agent resource limits. It is set by the check-in when the agent runs the CPU limit
	// controller, also when the cap is off. It is absent in all other cases, for example in the enrollment metadata, in
	// the agent-info diagnostics and in metadata from agents that do not support it.
	Limits *LimitsECSMeta `json:"limits,omitempty" yaml:",omitempty"`
}

// LimitsECSMeta is the state of the agent resource limits.
type LimitsECSMeta struct {
	CPU CPULimitECSMeta `json:"cpu"`
}

// CPULimitECSMeta is the state of the agent CPU limit.
// Fleet Server merges new metadata into its stored copy, so a key that is no longer sent stays stored. All keys are always
// sent.
type CPULimitECSMeta struct {
	// State is the CPU limit state: "disabled", "pending", "applied", "unsupported" or "degraded".
	State string `json:"state"`
	// ConfiguredPercent is the configured limit in percent, from 1 to 100. It is 0 when the cap is off.
	ConfiguredPercent int `json:"configured_percent"`
	// TargetCPUs is the number of CPUs the cap asks for after the floor. It is 0 when no cap is requested or when the
	// CPU count was never read.
	TargetCPUs float64 `json:"target_cpus"`
	// ActiveQuota tells what is known about the quota on the agent service: "unknown", "none" or "set".
	ActiveQuota string `json:"active_quota"`
	// ActiveQuotaCPUs is the active quota in CPUs. It is 0 unless ActiveQuota is "set".
	ActiveQuotaCPUs float64 `json:"active_quota_cpus"`
	// EffectiveQuota tells what is known about the lowest limit that the system enforces on the agent across its
	// service and its parents: "unknown", "none" or "set". A lower value than the active quota means a quota above
	// the agent limits it.
	EffectiveQuota string `json:"effective_quota"`
	// EffectiveQuotaCPUs is the effective quota in CPUs. It is 0 unless EffectiveQuota is "set".
	EffectiveQuotaCPUs float64 `json:"effective_quota_cpus"`
	// Reason tells why the limit is not supported on this host. It is empty in other states. It is a short fixed
	// text with no host details, because Fleet Server logs and stores it.
	Reason string `json:"reason"`
}

// SystemECSMeta is a collection of operating system metadata in ECS compliant object form.
type SystemECSMeta struct {
	Family   string `json:"family"`
	Kernel   string `json:"kernel"`
	Platform string `json:"platform"`
	Version  string `json:"version"`
	Name     string `json:"name"`
	FullName string `json:"full"`
}

// HostECSMeta is a collection of host metadata in ECS compliant object form.
type HostECSMeta struct {
	Arch     string   `json:"architecture"`
	Hostname string   `json:"hostname"`
	Name     string   `json:"name"`
	ID       string   `json:"id"`
	IP       []string `json:"ip"`
	MAC      []string `json:"mac"`
	// Memory is the total physical memory of the host in bytes.
	// Omitted when the platform does not report it (value 0).
	Memory uint64 `json:"memory,omitempty" yaml:",omitempty"`
}

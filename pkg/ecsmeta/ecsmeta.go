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
}

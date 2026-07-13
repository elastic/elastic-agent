// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package info

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/ecsmeta"
	"github.com/elastic/elastic-agent/pkg/utils"
)

type Agent interface {
	// AgentID returns an agent identifier.
	AgentID() string

	// Headers returns custom headers used to communicate with elasticsearch.
	Headers() map[string]string

	// GetLogLevelRuntime returns the effective log level (override > policy > default).
	GetLogLevelRuntime() string

	// GetLogLevelPolicy returns the policy-defined log level.
	GetLogLevelPolicy() string

	// GetLogLevelOverride returns the per-agent log level override.
	GetLogLevelOverride() string

	// SetLogLevelPolicy updates the in-memory snapshot of the policy log level.
	SetLogLevelPolicy(level string)

	// SetLogLevelOverride updates the per-agent log level override and
	// persists it to the on-disk agent config.
	SetLogLevelOverride(ctx context.Context, level string) error

	// ReloadID reloads agent info ID from configuration file.
	ReloadID(ctx context.Context) error

	// Snapshot returns if this version is a snapshot.
	Snapshot() bool

	// Version returns the version for this Agent.
	Version() string

	// Unprivileged returns true when this Agent is running unprivileged.
	Unprivileged() bool

	// IsStandalone returns true is the agent is running in standalone mode, i.e, without fleet
	IsStandalone() bool

	// ECSMetadata returns the ECS metadata that is attached as part of every Fleet checkin.
	ECSMetadata(*logger.Logger) (*ecsmeta.ECSMeta, error)
}

// AgentInfo is a collection of information about agent.
type AgentInfo struct {
	agentID          string
	logLevelPolicy   string
	logLevelOverride string
	unprivileged     bool
	isStandalone     bool

	// esHeaders will be injected into the headers field of any elasticsearch
	// output created by this agent (see component.toIntermediate).
	esHeaders map[string]string
}

// for unit testing
var doLoadAgentInfoWithBackoff = loadAgentInfoWithBackoff

// NewAgentInfoWithLog creates a new agent information.
// In case when agent ID was already created it returns,
// this created ID otherwise it generates
// new unique identifier for agent.
// If agent config file does not exist it gets created.
// Initiates log level to predefined value.
func NewAgentInfoWithLog(ctx context.Context, level string, createAgentID bool) (*AgentInfo, error) {
	agentInfo, isStandalone, err := doLoadAgentInfoWithBackoff(ctx, false, level, createAgentID)
	if err != nil {
		return nil, err
	}
	isRoot, err := utils.HasRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to determine root/Administrator: %w", err)
	}

	// In managed mode the policy log level on disk wins over the supplied
	// default; in standalone mode keep the supplied default since there is no
	// fleet to round-trip a value through.
	policyLogLevel := level
	if !isStandalone {
		policyLogLevel = agentInfo.LogLevel
	}

	return &AgentInfo{
		agentID:          agentInfo.ID,
		logLevelPolicy:   policyLogLevel,
		logLevelOverride: agentInfo.LogLevelOverride,
		unprivileged:     !isRoot,
		esHeaders:        agentInfo.Headers,
		isStandalone:     isStandalone,
	}, nil
}

// NewAgentInfo creates a new agent information.
// In case when agent ID was already created it returns,
// this created ID otherwise it generates
// new unique identifier for agent.
// If agent config file does not exist it gets created.
func NewAgentInfo(ctx context.Context, createAgentID bool) (*AgentInfo, error) {
	return NewAgentInfoWithLog(ctx, defaultLogLevel, createAgentID)
}

// GetLogLevelRuntime returns the effective log level (override > policy > default).
func (i *AgentInfo) GetLogLevelRuntime() string {
	if i.logLevelOverride != "" {
		return i.logLevelOverride
	}
	if i.logLevelPolicy != "" {
		return i.logLevelPolicy
	}
	return logger.DefaultLogLevel.String()
}

// GetLogLevelPolicy returns the policy-defined log level.
func (i *AgentInfo) GetLogLevelPolicy() string {
	return i.logLevelPolicy
}

// GetLogLevelOverride returns the per-agent log level override.
func (i *AgentInfo) GetLogLevelOverride() string {
	return i.logLevelOverride
}

// SetLogLevelPolicy updates the in-memory snapshot of the policy log level.
func (i *AgentInfo) SetLogLevelPolicy(level string) {
	i.logLevelPolicy = level
}

// SetLogLevelOverride updates the per-agent log level override and persists
// it to the encrypted agent config file.
func (i *AgentInfo) SetLogLevelOverride(ctx context.Context, level string) error {
	if err := updateLogLevelOverride(ctx, level); err != nil {
		return err
	}
	i.logLevelOverride = level
	return nil
}

// ReloadID reloads agent info ID from configuration file.
func (i *AgentInfo) ReloadID(ctx context.Context) error {
	newInfo, err := NewAgentInfoWithLog(ctx, i.logLevelPolicy, false)
	if err != nil {
		return err
	}
	i.agentID = newInfo.agentID
	return nil
}

// AgentID returns an agent identifier.
func (i *AgentInfo) AgentID() string {
	return i.agentID
}

// Version returns the version for this Agent.
func (*AgentInfo) Version() string {
	return release.Version()
}

// Snapshot returns if this version is a snapshot.
func (*AgentInfo) Snapshot() bool {
	return release.Snapshot()
}

// Headers returns custom headers used to communicate with elasticsearch.
func (i *AgentInfo) Headers() map[string]string {
	return i.esHeaders
}

// Unprivileged returns true when this Agent is running unprivileged.
func (i *AgentInfo) Unprivileged() bool {
	return i.unprivileged
}

// IsStandalone returns true when the agent is running in standalone mode.
func (i *AgentInfo) IsStandalone() bool {
	return i.isStandalone
}

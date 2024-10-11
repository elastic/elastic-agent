// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package info

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/utils"
)

type Agent interface {
	// AgentID returns an agent identifier.
	AgentID() string

	// Headers returns custom headers used to communicate with elasticsearch.
	Headers() map[string]string

	// LogLevel retrieves a log level, returning a default if none is set
	LogLevel() string

	// RawLogLevel returns the set log level, no defaults
	RawLogLevel() string

	// ReloadID reloads agent info ID from configuration file.
	ReloadID(ctx context.Context) error

	// SetLogLevel updates log level of agent.
	SetLogLevel(ctx context.Context, level string) error

	// Snapshot returns if this version is a snapshot.
	Snapshot() bool

	// Version returns the version for this Agent.
	Version() string

	// Unprivileged returns true when this Agent is running unprivileged.
	Unprivileged() bool

	// IsStandalone returns true is the agent is running in standalone mode, i.e, without fleet
	IsStandalone() bool
}

// AgentInfo is a collection of information about agent.
type AgentInfo struct {
	agentID      string
	logLevel     string
	unprivileged bool
	isStandalone bool

	// esHeaders will be injected into the headers field of any elasticsearch
	// output created by this agent (see component.toIntermediate).
	esHeaders map[string]string
}

// NewAgentInfoWithLog creates a new agent information.
// In case when agent ID was already created it returns,
// this created ID otherwise it generates
// new unique identifier for agent.
// If agent config file does not exist it gets created.
// Initiates log level to predefined value.
func NewAgentInfoWithLog(ctx context.Context, level string, createAgentID bool) (*AgentInfo, error) {
	agentInfo, isStandalone, err := loadAgentInfoWithBackoff(ctx, false, level, createAgentID)
	if err != nil {
		return nil, err
	}
	isRoot, err := utils.HasRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to determine root/Administrator: %w", err)
	}

	return &AgentInfo{
		agentID:      agentInfo.ID,
		logLevel:     agentInfo.LogLevel,
		unprivileged: !isRoot,
		esHeaders:    agentInfo.Headers,
		isStandalone: isStandalone,
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

// LogLevel retrieves a log level.
func (i *AgentInfo) LogLevel() string {
	rawLogLevel := i.RawLogLevel()
	if rawLogLevel == "" {
		return logger.DefaultLogLevel.String()
	}
	return rawLogLevel
}

// RawLogLevel retrieves a log level.
func (i *AgentInfo) RawLogLevel() string {
	return i.logLevel
}

// SetLogLevel updates log level of agent.
func (i *AgentInfo) SetLogLevel(ctx context.Context, level string) error {
	if err := updateLogLevel(ctx, level); err != nil {
		return err
	}

	i.logLevel = level
	return nil
}

// ReloadID reloads agent info ID from configuration file.
func (i *AgentInfo) ReloadID(ctx context.Context) error {
	newInfo, err := NewAgentInfoWithLog(ctx, i.logLevel, false)
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

func (i *AgentInfo) IsStandalone() bool {
	return i.isStandalone
}

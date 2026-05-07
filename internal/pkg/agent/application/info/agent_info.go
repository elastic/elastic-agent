// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package info

import (
	"context"
	"fmt"

	"github.com/gofrs/uuid/v5"

	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const defaultLogLevel = "info"

type Agent interface {
	// GetAgentID returns the agent identifier.
	GetAgentID() string

	// GetHeaders returns custom headers used to communicate with elasticsearch.
	GetHeaders() map[string]string

	// GetLogLevelRuntime returns the effective log level (override > policy > default).
	GetLogLevelRuntime() string

	// GetLogLevelPolicy returns the policy-defined log level.
	GetLogLevelPolicy() string

	// GetLogLevelOverride returns the per-agent log level override.
	GetLogLevelOverride() string

	// ReloadID reloads agent info ID from configuration file.
	ReloadID(ctx context.Context) error

	// SetLogLevelPolicy updates the in-memory snapshot of the policy log level.
	SetLogLevelPolicy(level string)

	// SetLogLevelOverride updates the in-memory per-agent log level override.
	SetLogLevelOverride(level string)

	// Snapshot returns if this version is a snapshot.
	Snapshot() bool

	// Version returns the version for this Agent.
	Version() string

	// Unprivileged returns true when this Agent is running unprivileged.
	Unprivileged() bool

	// IsStandalone returns true is the agent is running in standalone mode, i.e, without fleet
	IsStandalone() bool

	// ECSMetadata returns the ECS metadata that is attached as part of every Fleet checkin.
	ECSMetadata(*logger.Logger) (*ECSMeta, error)
}

// AgentInfo is a collection of information about agent. Disk-loadable fields
// are public so they can be unpacked directly via ucfg from the encrypted
// config file. Runtime-derived fields stay unexported.
type AgentInfo struct {
	AgentID          string            `config:"id"`
	Headers          map[string]string `config:"headers"`
	LogLevelPolicy   string            `config:"logging.level"`
	LogLevelOverride string            `config:"logging.level_override"`

	unprivileged bool
	isStandalone bool
}

// defaultAgentInfoStore is the store used by NewAgentInfoWithLog. Overridable
// in tests via the package-level variable.
var defaultAgentInfoStore AgentInfoStore = NewEncryptedAgentInfoStore()

// NewAgentInfoWithLog returns the agent's information, loading whatever is
// persisted and filling in any missing fields with defaults.
func NewAgentInfoWithLog(ctx context.Context, defaultLogLevel string, createAgentID bool) (*AgentInfo, error) {
	info, err := defaultAgentInfoStore.Load(ctx)
	if err != nil {
		return nil, err
	}
	opts, err := initializeAgentInfo(info, defaultLogLevel, createAgentID)
	if err != nil {
		return nil, err
	}
	if len(opts) > 0 {
		if err := defaultAgentInfoStore.Save(ctx, opts...); err != nil {
			return nil, fmt.Errorf("failed to persist agent info: %w", err)
		}
	}
	return info, nil
}

// initializeAgentInfo fills in any missing fields on info and returns the
// changes that should be persisted.
func initializeAgentInfo(info *AgentInfo, defaultLogLevel string, createAgentID bool) ([]SaveOption, error) {
	var opts []SaveOption

	isRoot, err := utils.HasRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to determine root/Administrator: %w", err)
	}
	info.unprivileged = !isRoot

	if createAgentID && info.AgentID == "" {
		id, err := generateAgentID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate agent ID: %w", err)
		}
		info.AgentID = id
		opts = append(opts, WithID(id))
	}

	// Standalone agents always use the supplied default and don't persist it.
	if info.isStandalone {
		info.LogLevelPolicy = defaultLogLevel
		return opts, nil
	}

	// Fleet agents apply and persist the default only when no level is set.
	if info.LogLevelPolicy == "" {
		info.LogLevelPolicy = defaultLogLevel
		opts = append(opts, WithLogLevelPolicy(defaultLogLevel))
	}

	return opts, nil
}

// NewAgentInfo creates a new agent information.
// In case when agent ID was already created it returns,
// this created ID otherwise it generates
// new unique identifier for agent.
// If agent config file does not exist it gets created.
func NewAgentInfo(ctx context.Context, createAgentID bool) (*AgentInfo, error) {
	return NewAgentInfoWithLog(ctx, defaultLogLevel, createAgentID)
}

// GetAgentID returns the agent identifier.
func (i *AgentInfo) GetAgentID() string { return i.AgentID }

// GetHeaders returns custom headers used to communicate with elasticsearch.
func (i *AgentInfo) GetHeaders() map[string]string { return i.Headers }

// GetLogLevelRuntime returns the effective log level (override > policy > default).
func (i *AgentInfo) GetLogLevelRuntime() string {
	if i.LogLevelOverride != "" {
		return i.LogLevelOverride
	}
	if i.LogLevelPolicy != "" {
		return i.LogLevelPolicy
	}
	return logger.DefaultLogLevel.String()
}

// GetLogLevelPolicy returns the policy-defined log level.
func (i *AgentInfo) GetLogLevelPolicy() string { return i.LogLevelPolicy }

// GetLogLevelOverride returns the per-agent log level override.
func (i *AgentInfo) GetLogLevelOverride() string { return i.LogLevelOverride }

// SetLogLevelPolicy updates the in-memory snapshot of the policy log level.
func (i *AgentInfo) SetLogLevelPolicy(level string) { i.LogLevelPolicy = level }

// SetLogLevelOverride updates the in-memory per-agent log level override.
func (i *AgentInfo) SetLogLevelOverride(level string) { i.LogLevelOverride = level }

// ReloadID reloads agent info ID from configuration file.
func (i *AgentInfo) ReloadID(ctx context.Context) error {
	newInfo, err := NewAgentInfoWithLog(ctx, i.LogLevelPolicy, false)
	if err != nil {
		return err
	}
	i.AgentID = newInfo.AgentID
	return nil
}

// Version returns the version for this Agent.
func (*AgentInfo) Version() string { return release.Version() }

// Snapshot returns if this version is a snapshot.
func (*AgentInfo) Snapshot() bool { return release.Snapshot() }

// Unprivileged returns true when this Agent is running unprivileged.
func (i *AgentInfo) Unprivileged() bool { return i.unprivileged }

// IsStandalone returns true if the agent is running in standalone mode (no fleet).
func (i *AgentInfo) IsStandalone() bool { return i.isStandalone }

func generateAgentID() (string, error) {
	uid, err := uuid.NewV4()
	if err != nil {
		return "", fmt.Errorf("error while generating UUID for agent: %w", err)
	}
	return uid.String(), nil
}

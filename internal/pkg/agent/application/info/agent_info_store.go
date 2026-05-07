// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package info

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
)

const (
	agentInfoKey = "agent"
	fleetKey     = "fleet"

	maxRetriesAgentInfo = 5
)

// AgentInfoStore persists agent info to disk.
type AgentInfoStore interface {
	// Load returns an AgentInfo populated from the persisted state on disk.
	Load(ctx context.Context) (*AgentInfo, error)

	// Save uses load-merge-save semantics, only fields supplied via options are
	// modified. All other top-level keys and untouched keys are preserved.
	Save(ctx context.Context, opts ...SaveOption) error
}

// SaveOption mutates the on-disk config map for a single Save call.
type SaveOption func(configMap map[string]interface{})

// WithLogLevelOverride sets agent.logging.level_override. An empty level
// removes the key (matches the omitempty semantic).
func WithLogLevelOverride(level string) SaveOption {
	return setOrDeleteNested(level, level == "", agentInfoKey, "logging", "level_override")
}

// WithLogLevelPolicy sets agent.logging.level. An empty level removes the key.
func WithLogLevelPolicy(level string) SaveOption {
	return setOrDeleteNested(level, level == "", agentInfoKey, "logging", "level")
}

// WithEventLoggingToFiles sets agent.logging.event_data.to_files.
func WithEventLoggingToFiles(b bool) SaveOption {
	return setNested(b, agentInfoKey, "logging", "event_data", "to_files")
}

// WithEventLoggingToStderr sets agent.logging.event_data.to_stderr.
func WithEventLoggingToStderr(b bool) SaveOption {
	return setNested(b, agentInfoKey, "logging", "event_data", "to_stderr")
}

// WithMonitoringHTTP sets agent.monitoring.http.
func WithMonitoringHTTP(cfg any) SaveOption {
	return setNested(cfg, agentInfoKey, "monitoring", "http")
}

// WithMonitoringPprof sets agent.monitoring.pprof.
func WithMonitoringPprof(cfg any) SaveOption {
	return setNested(cfg, agentInfoKey, "monitoring", "pprof")
}

// WithHeaders sets agent.headers.
func WithHeaders(h map[string]string) SaveOption {
	return setNested(h, agentInfoKey, "headers")
}

// WithID sets agent.id.
func WithID(id string) SaveOption {
	return setNested(id, agentInfoKey, "id")
}

// WithFleet replaces the top-level fleet section.
func WithFleet(cfg any) SaveOption {
	return setNested(cfg, fleetKey)
}

// setNested places value at the given nested path, creating intermediate maps.
// Path must contain at least one segment.
func setNested(value any, path ...string) SaveOption {
	return func(m map[string]interface{}) {
		parent := navigateOrCreate(m, path[:len(path)-1])
		parent[path[len(path)-1]] = value
	}
}

// setOrDeleteNested either sets value at the given nested path or deletes the
// leaf key when del is true. Intermediate maps are created on set.
func setOrDeleteNested(value any, del bool, path ...string) SaveOption {
	return func(m map[string]interface{}) {
		if del {
			parent := navigate(m, path[:len(path)-1])
			if parent != nil {
				delete(parent, path[len(path)-1])
			}
			return
		}
		parent := navigateOrCreate(m, path[:len(path)-1])
		parent[path[len(path)-1]] = value
	}
}

// navigateOrCreate walks the path, creating any missing maps along the way.
func navigateOrCreate(m map[string]interface{}, path []string) map[string]interface{} {
	cur := m
	for _, seg := range path {
		next, ok := cur[seg].(map[string]interface{})
		if !ok {
			next = make(map[string]interface{})
			cur[seg] = next
		}
		cur = next
	}
	return cur
}

// navigate walks the path and returns nil if any segment is missing.
func navigate(m map[string]interface{}, path []string) map[string]interface{} {
	cur := m
	for _, seg := range path {
		next, ok := cur[seg].(map[string]interface{})
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

// NullAgentInfoStore is a no-op AgentInfoStore: Load returns an empty
// AgentInfo and Save discards the options. Useful for tests and code paths
// that don't need persistence.
type NullAgentInfoStore struct{}

// Load returns an empty AgentInfo.
func (NullAgentInfoStore) Load(context.Context) (*AgentInfo, error) {
	return &AgentInfo{}, nil
}

// Save discards the options and returns nil.
func (NullAgentInfoStore) Save(context.Context, ...SaveOption) error {
	return nil
}

// NewEncryptedAgentInfoStore returns an AgentInfoStore backed by the
// encrypted agent config file at paths.AgentConfigFile().
func NewEncryptedAgentInfoStore() AgentInfoStore {
	return &encryptedAgentInfoStore{}
}

// encryptedAgentInfoStore reads and writes the agent's encrypted config file.
type encryptedAgentInfoStore struct{}

// Load reads the agent config from disk, retrying briefly if another process holds the lock.
func (s *encryptedAgentInfoStore) Load(ctx context.Context) (*AgentInfo, error) {
	diskStore, err := storage.NewEncryptedDiskStore(ctx, paths.AgentConfigFile())
	if err != nil {
		return nil, fmt.Errorf("instantiating encrypted disk store: %w", err)
	}
	var info *AgentInfo
	withBackoff(ctx, func() error {
		info, err = loadLocked(diskStore)
		return err
	})
	return info, err
}

// loadLocked makes a single attempt to read and decode the agent config file
// while holding the agent config file lock.
func loadLocked(diskStore storage.Storage) (*AgentInfo, error) {
	idLock := paths.AgentConfigFileLock()
	if err := idLock.TryLock(); err != nil {
		return nil, err
	}
	//nolint:errcheck // best-effort unlock
	defer idLock.Unlock()

	exists, err := diskStore.Exists()
	if err != nil {
		return nil, fmt.Errorf("checking encrypted disk store: %w", err)
	}
	info := &AgentInfo{isStandalone: true}
	if !exists {
		return info, nil
	}

	configMap, err := loadConfigMap(diskStore)
	if err != nil {
		return nil, err
	}

	// fleet.enabled determines isStandalone (mirrors configuration.IsStandalone)
	if fleetCfg, ok := configMap[fleetKey].(map[string]interface{}); ok {
		if fleetCfg["enabled"] == true {
			info.isStandalone = false
		}
	}

	agentSubMap, found := configMap[agentInfoKey]
	if !found {
		return info, nil
	}
	cc, err := config.NewConfigFrom(agentSubMap)
	if err != nil {
		return nil, errors.New(err, "failed to create config from agent info submap")
	}
	if err := cc.UnpackTo(info); err != nil {
		return nil, errors.New(err, "failed to unpack agent info")
	}
	return info, nil
}

// withBackoff calls fn once and, while it returns filelock.ErrAppAlreadyRunning,
// retries up to maxRetriesAgentInfo times with exponential backoff. The wait
// between retries aborts early if ctx is canceled.
func withBackoff(ctx context.Context, fn func() error) {
	backExp := backoff.NewExpBackoff(ctx.Done(), 100*time.Millisecond, 3*time.Second)
	for i := 0; i <= maxRetriesAgentInfo; i++ {
		if err := fn(); !errors.Is(err, filelock.ErrAppAlreadyRunning) {
			return
		}
		if i == maxRetriesAgentInfo {
			return
		}
		backExp.Wait()
		if ctx.Err() != nil {
			return
		}
	}
}

// Save applies the given options to the on-disk config, retrying briefly if
// another process holds the lock. With no options it is a no-op (no I/O).
func (s *encryptedAgentInfoStore) Save(ctx context.Context, opts ...SaveOption) error {
	if len(opts) == 0 {
		return nil
	}
	agentConfigFile := paths.AgentConfigFile()
	diskStore, err := storage.NewEncryptedDiskStore(ctx, agentConfigFile)
	if err != nil {
		return fmt.Errorf("instantiating encrypted disk store: %w", err)
	}
	withBackoff(ctx, func() error {
		err = saveLocked(diskStore, agentConfigFile, opts)
		return err
	})
	return err
}

// saveLocked makes a single load-merge-write pass over the agent config file
// while holding the agent config file lock.
func saveLocked(diskStore storage.Storage, agentConfigFile string, opts []SaveOption) error {
	idLock := paths.AgentConfigFileLock()
	if err := idLock.TryLock(); err != nil {
		return err
	}
	//nolint:errcheck // best-effort unlock
	defer idLock.Unlock()

	exists, err := diskStore.Exists()
	if err != nil {
		return fmt.Errorf("checking encrypted disk store: %w", err)
	}
	configMap := make(map[string]interface{})
	if exists {
		configMap, err = loadConfigMap(diskStore)
		if err != nil {
			return err
		}
	}

	for _, opt := range opts {
		opt(configMap)
	}

	data, err := yaml.Marshal(configMap)
	if err != nil {
		return fmt.Errorf("marshalling agent config: %w", err)
	}
	if err := diskStore.Save(bytes.NewReader(data)); err != nil {
		return errors.New(err, "failed saving agent config",
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, agentConfigFile))
	}
	return nil
}

// loadConfigMap reads the storage and returns its contents as a generic map.
func loadConfigMap(s storage.Storage) (map[string]interface{}, error) {
	reader, err := s.Load()
	if err != nil {
		return nil, errors.New(err, "failed loading from store", errors.TypeFilesystem)
	}
	cfg, err := config.NewConfigFrom(reader)
	if err != nil {
		return nil, errors.New(err, "failed parsing existing agent config", errors.TypeFilesystem)
	}
	configMap := make(map[string]interface{})
	if err := cfg.UnpackTo(&configMap); err != nil {
		return nil, errors.New(err, "failed unpacking agent config")
	}
	return configMap, nil
}

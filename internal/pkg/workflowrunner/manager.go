// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package workflowrunner

import (
	"fmt"
	"sync"

	"github.com/rs/zerolog"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
)

const (
	healthyMsg       = "Healthy"
	waitingOutputMsg = "Waiting for an elasticsearch output"
	stoppedMsg       = "Stopped"
)

// Manager tracks the component's units and owns the workflow/http action.
type Manager struct {
	logger zerolog.Logger

	newIndexer func(map[string]interface{}) (Indexer, error)
	action     *httpAction

	mu        sync.Mutex
	input     *client.Unit
	output    *client.Unit
	indexer   Indexer
	namespace string
}

// NewManager returns a Manager that executes requests with executor and
// remembers completed actions in store.
func NewManager(logger zerolog.Logger, executor *Executor, store *Store) *Manager {
	m := &Manager{logger: logger, newIndexer: newESIndexer}
	m.action = &httpAction{
		logger:   logger,
		executor: executor,
		store:    store,
		target:   m.currentTarget,
	}
	return m
}

func (m *Manager) currentTarget() (Indexer, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.indexer, m.namespace
}

// HandleChange applies a unit change received from the agent.
func (m *Manager) HandleChange(change client.UnitChanged) {
	unit := change.Unit
	if unit == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	switch change.Type {
	case client.UnitChangedAdded, client.UnitChangedModified:
		if unit.Type() == client.UnitTypeOutput {
			m.applyOutputLocked(unit)
		} else {
			m.applyInputLocked(unit)
		}
	case client.UnitChangedRemoved:
		if unit.Type() == client.UnitTypeOutput && m.output != nil && m.output.ID() == unit.ID() {
			m.output, m.indexer = nil, nil
			m.updateInputStateLocked()
		}
		if unit.Type() == client.UnitTypeInput && m.input != nil && m.input.ID() == unit.ID() {
			m.input.UnregisterAction(m.action)
			m.input = nil
		}
	}
}

func (m *Manager) applyOutputLocked(unit *client.Unit) {
	expected := unit.Expected()
	if expected.State == client.UnitStateStopped {
		m.output, m.indexer = nil, nil
		_ = unit.UpdateState(client.UnitStateStopped, stoppedMsg, nil)
		m.updateInputStateLocked()
		return
	}

	m.output = unit
	m.indexer = nil
	if expected.Config == nil || expected.Config.GetSource() == nil {
		_ = unit.UpdateState(client.UnitStateFailed, "Output unit has no configuration", nil)
		m.updateInputStateLocked()
		return
	}
	indexer, err := m.newIndexer(expected.Config.GetSource().AsMap())
	if err != nil {
		m.logger.Error().Err(err).Msg("invalid workflow runner output")
		_ = unit.UpdateState(client.UnitStateFailed, err.Error(), nil)
		m.updateInputStateLocked()
		return
	}
	m.indexer = indexer
	_ = unit.UpdateState(client.UnitStateHealthy, healthyMsg, nil)
	m.updateInputStateLocked()
}

func (m *Manager) applyInputLocked(unit *client.Unit) {
	if m.input != nil && m.input.ID() != unit.ID() {
		_ = unit.UpdateState(client.UnitStateFailed,
			fmt.Sprintf("Only one %s input is supported per agent; %s is already running", ActionName, m.input.ID()), nil)
		return
	}

	expected := unit.Expected()
	if expected.State == client.UnitStateStopped {
		unit.UnregisterAction(m.action)
		m.input = nil
		_ = unit.UpdateState(client.UnitStateStopped, stoppedMsg, nil)
		return
	}

	m.input = unit
	m.namespace = expected.Config.GetDataStream().GetNamespace()
	unit.RegisterAction(m.action)
	m.updateInputStateLocked()
}

func (m *Manager) updateInputStateLocked() {
	if m.input == nil {
		return
	}
	if m.indexer == nil {
		_ = m.input.UpdateState(client.UnitStateDegraded, waitingOutputMsg, nil)
		return
	}
	_ = m.input.UpdateState(client.UnitStateHealthy, healthyMsg, nil)
}

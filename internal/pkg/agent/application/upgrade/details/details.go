// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package details

import "sync"

// Observer is a function that will be called with upgrade details
type Observer func(details *Details)

// Details consists of details regarding an ongoing upgrade.
type Details struct {
	TargetVersion string          `yaml:"target_version" json:"target_version"`
	State         State           `yaml:"state" json:"state"`
	ActionID      string          `yaml:"action_id" json:"action_id"`
	Metadata      DetailsMetadata `yaml:"metadata" json:"metadata"`

	observers []Observer
	mu        sync.RWMutex
}

// DetailsMetadata consists of metadata relating to a specific upgrade state
type DetailsMetadata struct {
	ScheduledAt     string  `yaml:"scheduled_at" json:"scheduled_at"`
	DownloadPercent float64 `yaml:"download_percent" json:"download_percent"`
	FailedState     State   `yaml:"failed_state" json:"failed_state"`
	ErrorMsg        string  `yaml:"error_msg" json:"error_msg"`
}

func NewDetails(targetVersion string, initialState State, actionID string) *Details {
	return &Details{
		TargetVersion: targetVersion,
		State:         initialState,
		ActionID:      actionID,
		Metadata:      DetailsMetadata{},
		observers:     []Observer{},
	}
}

// SetState is a convenience method to set the state of the upgrade and
// notify all observers.
func (d *Details) SetState(s State) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.State = s
	d.notifyObservers()
}

// Fail is a convenience method to set the state of the upgrade
// to StateFailed, set metadata associated with the failure, and
// notify all observers.
func (d *Details) Fail(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Record the state the upgrade process was in right before it
	// failed, but only do this if we haven't already transitioned the
	// state to the StateFailed state; otherwise we'll just end up recording
	// the state we failed from as StateFailed which is not useful.
	if d.State != StateFailed {
		d.Metadata.FailedState = d.State
	}

	d.Metadata.ErrorMsg = err.Error()
	d.State = StateFailed
	d.notifyObservers()
}

// RegisterObserver allows an interested consumer of Details to register
// themselves as an Observer. The registered observer is immediately notified
// of the current upgrade details.
func (d *Details) RegisterObserver(observer Observer) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.observers = append(d.observers, observer)
	d.notifyObserver(observer)
}

// NotifyObservers sends the current upgrade details to all registered
// observers. When an upgrade has completed (StateCompleted), the observers
// will be sent a nil value.
func (d *Details) NotifyObservers() {
	d.mu.RLock()
	defer d.mu.RUnlock()
	d.notifyObservers()
}

func (d *Details) notifyObservers() {
	for _, observer := range d.observers {
		d.notifyObserver(observer)
	}
}

func (d *Details) notifyObserver(observer Observer) {
	if d.State == StateCompleted {
		observer(nil)
	} else {
		observer(d)
	}
}

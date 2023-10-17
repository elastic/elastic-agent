// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package details

import (
	"sync"
	"time"
)

// Observer is a function that will be called with upgrade details
type Observer func(details *Details)

// Details consists of details regarding an ongoing upgrade.
type Details struct {
	TargetVersion string
	State         State
	ActionID      string
	Metadata      DetailsMetadata

	observers []Observer
	mu        sync.Mutex
}

// DetailsMetadata consists of metadata relating to a specific upgrade state
type DetailsMetadata struct {
	ScheduledAt     time.Time
	DownloadPercent float64
	DownloadRate    float64

	// FailedState is the state an upgrade was in if/when it failed. Use the
	// Fail() method of UpgradeDetails to correctly record details when
	// an upgrade fails.
	FailedState State

	// ErrorMsg is any error message encountered if/when an upgrade fails. Use
	// the Fail() method of UpgradeDetails to correctly record details when
	// an upgrade fails.
	ErrorMsg string
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

// SetDownloadProgress is a convenience method to set the download percent
// when the upgrade is in UPG_DOWNLOADING state.
func (d *Details) SetDownloadProgress(downloadPercent, downloadRate float64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.Metadata.DownloadPercent = downloadPercent
	d.Metadata.DownloadRate = downloadRate
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

func (d *Details) notifyObservers() {
	for _, observer := range d.observers {
		d.notifyObserver(observer)
	}
}

func (d *Details) notifyObserver(observer Observer) {
	if d.State == StateCompleted {
		observer(nil)
	} else {
		dCopy := Details{
			TargetVersion: d.TargetVersion,
			State:         d.State,
			ActionID:      d.ActionID,
			Metadata:      d.Metadata,
		}
		observer(&dCopy)
	}
}

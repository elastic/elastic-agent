// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package details

import (
	"sync"
	"time"

	"github.com/elastic/elastic-agent-libs/upgrade/details"
)

// Observer is a function that will be called with upgrade details
type Observer func(details *Details)

// Details consists of details regarding an ongoing upgrade.
type Details struct {
	TargetVersion string   `json:"target_version" yaml:"target_version"`
	State         State    `json:"state" yaml:"state"`
	ActionID      string   `json:"action_id,omitempty" yaml:"action_id,omitempty"`
	Metadata      Metadata `json:"metadata" yaml:"metadata"`

	observers []Observer
	mu        sync.Mutex
}

// Metadata consists of metadata relating to a specific upgrade state
type Metadata struct {
	ScheduledAt *time.Time `json:"scheduled_at,omitempty" yaml:"scheduled_at,omitempty"`

	// DownloadPercent is the percentage of the artifact that has been
	// downloaded. Minimum value is 0 and maximum value is 1.
	DownloadPercent float64 `json:"download_percent,omitempty" yaml:"download_percent,omitempty"`

	// DownloadRate is the rate, in bytes per second, at which the download
	// is progressing.
	DownloadRate details.DownloadRate `json:"download_rate,omitempty" yaml:"download_rate,omitempty"`

	// RetryErrorMsg is any error message that is a result of a retryable upgrade
	// step, e.g. the download step, being retried.
	RetryErrorMsg string `json:"retry_error_msg,omitempty" yaml:"retry_error_msg,omitempty"`

	// RetryUntil is the deadline until when a retryable upgrade step, e.g. the download
	// step, will be retried.
	RetryUntil *time.Time `json:"retry_until,omitempty" yaml:"retry_until"`

	// FailedState is the state an upgrade was in if/when it failed. Use the
	// Fail() method of UpgradeDetails to correctly record details when
	// an upgrade fails.
	FailedState State `json:"failed_state,omitempty" yaml:"failed_state,omitempty"`

	// ErrorMsg is any error message encountered if/when an upgrade fails. Use
	// the Fail() method of UpgradeDetails to correctly record details when
	// an upgrade fails.
	ErrorMsg string `json:"error_msg,omitempty" yaml:"error_msg,omitempty"`
}

func NewDetails(targetVersion string, initialState State, actionID string) *Details {
	return &Details{
		TargetVersion: targetVersion,
		State:         initialState,
		ActionID:      actionID,
		Metadata:      Metadata{},
		observers:     []Observer{},
	}
}

// SetState is a convenience method to set the state of the upgrade and
// notify all observers.
// Do NOT call SetState with StateFailed; call the Fail method instead.
func (d *Details) SetState(s State) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.State = s

	// If State is something other than StateFailed, make sure to clear
	// Metadata.FailedState and Metadata.ErrorMsg as those two fields
	// should be set when State is set to StateFailed. See the Fail method.
	if s != StateFailed {
		d.Metadata.ErrorMsg = ""
		d.Metadata.FailedState = ""
	}

	d.notifyObservers()
}

// SetDownloadProgress is a convenience method to set the download percent
// and download rate when the upgrade is in UPG_DOWNLOADING state.
func (d *Details) SetDownloadProgress(percent, rateBytesPerSecond float64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.Metadata.DownloadPercent = percent
	d.Metadata.DownloadRate = details.DownloadRate(rateBytesPerSecond)
	d.notifyObservers()
}

// SetRetryableError sets the RetryErrorMsg metadata field.
func (d *Details) SetRetryableError(retryableError error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if retryableError == nil {
		d.Metadata.RetryErrorMsg = ""
	} else {
		d.Metadata.RetryErrorMsg = retryableError.Error()
	}
	d.notifyObservers()
}

// SetRetryUntil sets the RetryUntil metadata field.
func (d *Details) SetRetryUntil(retryUntil *time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.Metadata.RetryUntil = retryUntil
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

// Equals compares the non-lock fields of two Details structs.
func (d *Details) Equals(otherD *Details) bool {
	// If both addresses are equal or both are nil
	if d == otherD {
		return true
	}

	// If only one is nil but the other is not
	if d == nil || otherD == nil {
		return false
	}

	return d.State == otherD.State &&
		d.TargetVersion == otherD.TargetVersion &&
		d.ActionID == otherD.ActionID &&
		d.Metadata.Equals(otherD.Metadata)
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

func (m Metadata) Equals(otherM Metadata) bool {
	return equalTimePointers(m.ScheduledAt, otherM.ScheduledAt) &&
		m.FailedState == otherM.FailedState &&
		m.ErrorMsg == otherM.ErrorMsg &&
		m.DownloadPercent == otherM.DownloadPercent &&
		m.DownloadRate == otherM.DownloadRate &&
		equalTimePointers(m.RetryUntil, otherM.RetryUntil) &&
		m.RetryErrorMsg == otherM.RetryErrorMsg
}

func equalTimePointers(t, otherT *time.Time) bool {
	if t == otherT {
		return true
	}
	if t == nil || otherT == nil {
		return false
	}

	return t.Equal(*otherT)
}

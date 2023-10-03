// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"

	"github.com/looplab/fsm"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	StateRequested   = "UPG_REQUESTED"
	StateScheduled   = "UPG_SCHEDULED"
	StateDownloading = "UPG_DOWNLOADING"
	StateExtracting  = "UPG_EXTRACTING"
	StateReplacing   = "UPG_REPLACING"
	StateRestarting  = "UPG_RESTARTING"
	StateWatching    = "UPG_WATCHING"
	StateRollback    = "UPG_ROLLBACK"
	StateCompleted   = "UPG_COMPLETED"
	StateFailed      = "UPG_FAILED"

	ActionSucceeded   = "succeeded"
	ActionFailed      = "failed"
	ActionScheduling  = "scheduling"
	ActionRollingBack = "rolling_back"
)

type FSM struct {
	m *fsm.FSM
}

type StateTransitionCallback func(oldState, newState, action string)

// NewFSM models the following finite state machine for Elastic Agent upgrades:
//
//	UPG_REQUESTED
//	├─ scheduling ─> UPG_SCHEDULED
//	└─ succeeded ─> UPG_DOWNLOADING
//	UPG_SCHEDULED
//	├─ succeeded ─> UPG_DOWNLOADING
//	└─ failed ─> UPG_FAILED
//	UPG_DOWNLOADING
//	├─ succeeded ─> UPG_EXTRACTING
//	└─ failed ─> UPG_FAILED
//	UPG_EXTRACTING
//	├─ succeeded ─> UPG_REPLACING
//	└─ failed ─> UPG_FAILED
//	UPG_REPLACING
//	├─ succeeded ─> UPG_RESTARTING
//	└─ failed ─> UPG_FAILED
//	UPG_RESTARTING
//	├─ succeeded ─> UPG_WATCHING
//	└─ failed ─> UPG_FAILED
//	UPG_WATCHING
//	├─ succeeded ─> UPG_COMPLETED
//	├─ rolling_back ─> UPG_ROLLBACK
//	└─ failed ─> UPG_FAILED
//	UPG_ROLLBACK
//	├─ succeeded ─> UPG_COMPLETED
//	└─ failed ─> UPG_FAILED
//
// It accepts an onAction callback that will be called any time a transition from one
// state to the next is performed.
func NewFSM(log *logger.Logger, onTransition StateTransitionCallback) *FSM {
	return &FSM{
		m: fsm.NewFSM(
			StateRequested,
			fsm.Events{
				{Name: ActionScheduling, Src: []string{StateRequested}, Dst: StateScheduled},
				{Name: ActionSucceeded, Src: []string{StateRequested, StateScheduled}, Dst: StateDownloading},
				{Name: ActionSucceeded, Src: []string{StateDownloading}, Dst: StateExtracting},
				{Name: ActionSucceeded, Src: []string{StateExtracting}, Dst: StateReplacing},
				{Name: ActionSucceeded, Src: []string{StateReplacing}, Dst: StateRestarting},
				{Name: ActionSucceeded, Src: []string{StateRestarting}, Dst: StateWatching},
				{Name: ActionSucceeded, Src: []string{StateWatching}, Dst: StateCompleted},
				{Name: ActionRollingBack, Src: []string{StateWatching}, Dst: StateRollback},
				{Name: ActionSucceeded, Src: []string{StateRollback}, Dst: StateCompleted},
				{Name: ActionFailed, Src: []string{StateScheduled, StateDownloading, StateExtracting, StateReplacing, StateRestarting, StateWatching, StateRollback}, Dst: StateFailed},
			},
			fsm.Callbacks{
				"enter_state": func(_ context.Context, e *fsm.Event) {
					// Log state entry
					log.Infow(
						"transitioning upgrade state machine",
						"from", e.Src, "to", e.Dst, "action", e.Event,
					)

					// Call onTransition
					onTransition(e.Src, e.Dst, e.Event)
				},
			},
		),
	}
}

func (f *FSM) Transition(ctx context.Context, action string, args ...interface{}) error {
	current := f.Current()
	if err := f.m.Event(ctx, action, args...); err != nil {
		return fmt.Errorf("unable to transition from [%s] with action [%s]: %w", current, action, err)
	}

	return nil
}

func (f *FSM) Current() string {
	return f.m.Current()
}

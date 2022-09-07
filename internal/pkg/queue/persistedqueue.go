// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package queue

import "github.com/elastic/elastic-agent/internal/pkg/fleetapi"

// PersistedQueue is an action queue with a Save function for persistency.
type PersistedQueue struct {
	ActionQueue
	qs persistor
}

type persistor interface {
	SetQueue(a []fleetapi.Action)
	Save() error
}

// NewPersistedQueue creates a persisted queue from an existing action queue and persistor.
//
// The persistor the minimal interface needed from the state storeage mechanism.
func NewPersistedQueue(q *ActionQueue, qs persistor) *PersistedQueue {
	return &PersistedQueue{
		*q,
		qs,
	}
}

// Save persists the queue to disk.
func (q *PersistedQueue) Save() error {
	q.qs.SetQueue(q.Actions())
	return q.qs.Save()
}

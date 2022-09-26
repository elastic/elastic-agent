// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package queue

import (
	"container/heap"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
)

// item tracks an action in the action queue
type item struct {
	action   fleetapi.Action
	priority int64
	index    int
}

// ActionQueue uses the standard library's container/heap to implement a priority queue
// This queue should not be indexed directly, instead use the provided Add, DequeueActions, or Cancel methods to add or remove items
// Actions() is indended to get the list of actions in the queue for serialization.
type ActionQueue []*item

// Len returns the length of the queue
func (q ActionQueue) Len() int {
	return len(q)
}

// Less will determine if item i's priority is less then item j's
func (q ActionQueue) Less(i, j int) bool {
	return q[i].priority < q[j].priority
}

// Swap will swap the items at index i and j
func (q ActionQueue) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].index = i
	q[j].index = j
}

// Push will add x as an item to the queue
// When using the queue, the Add method should be used instead.
func (q *ActionQueue) Push(x interface{}) {
	n := len(*q)
	e := x.(*item) //nolint:errcheck // should be an *item
	e.index = n
	*q = append(*q, e)
}

// Pop will return the last item from the queue
// When using the queue, DequeueActions should be used instead
func (q *ActionQueue) Pop() interface{} {
	old := *q
	n := len(old)
	e := old[n-1]
	old[n-1] = nil // avoid memory leak
	e.index = -1   // for safety
	*q = old[0 : n-1]
	return e
}

// NewActionQueue creates a new ActionQueue initialized with the passed actions.
// Will return an error if StartTime fails for any action.
func NewActionQueue(actions []fleetapi.Action) (*ActionQueue, error) {
	q := make(ActionQueue, len(actions))
	for i, action := range actions {
		ts, err := action.StartTime()
		if err != nil {
			return nil, err
		}
		q[i] = &item{
			action:   action,
			priority: ts.Unix(),
			index:    i,
		}
	}
	heap.Init(&q)
	return &q, nil
}

// Add will add an action to the queue with the associated priority.
// The priority is meant to be the start-time of the action as a unix epoch time.
// Complexity: O(log n)
func (q *ActionQueue) Add(action fleetapi.Action, priority int64) {
	e := &item{
		action:   action,
		priority: priority,
	}
	heap.Push(q, e)
}

// DequeueActions will dequeue all actions that have a priority less then time.Now().
// Complexity: O(n*log n)
func (q *ActionQueue) DequeueActions() []fleetapi.Action {
	ts := time.Now().Unix()
	actions := make([]fleetapi.Action, 0)
	for q.Len() != 0 {
		if (*q)[0].priority > ts {
			break
		}
		item := heap.Pop(q).(*item) //nolint:errcheck // should be an *item
		actions = append(actions, item.action)
	}
	return actions
}

// Cancel will remove any actions in the queue with a matching actionID and return the number of entries cancelled.
// Complexity: O(n*log n)
func (q *ActionQueue) Cancel(actionID string) int {
	items := make([]*item, 0)
	for _, item := range *q {
		if item.action.ID() == actionID {
			items = append(items, item)
		}
	}
	for _, item := range items {
		heap.Remove(q, item.index)
	}
	return len(items)
}

// Actions returns all actions in the queue, item 0 is garunteed to be the min, the rest may not be in sorted order.
func (q *ActionQueue) Actions() []fleetapi.Action {
	actions := make([]fleetapi.Action, q.Len())
	for i, item := range *q {
		actions[i] = item.action
	}
	return actions
}

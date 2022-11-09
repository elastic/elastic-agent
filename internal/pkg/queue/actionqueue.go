// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package queue

import (
	"container/heap"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
)

// saver is an the minimal interface needed for state storage.
type saver interface {
	SetQueue(a []fleetapi.Action)
	Save() error
}

// item tracks an action in the action queue
type item struct {
	action   fleetapi.ScheduledAction
	priority int64
	index    int
}

// queue uses the standard library's container/heap to implement a priority queue
// This queue should not be used directly, instead the exported ActionQueue should be used.
type queue []*item

// ActionQueue is a priority queue with the ability to persist to disk.
type ActionQueue struct {
	q *queue
	s saver
}

// Len returns the length of the queue
func (q queue) Len() int {
	return len(q)
}

// Less will determine if item i's priority is less then item j's
func (q queue) Less(i, j int) bool {
	return q[i].priority < q[j].priority
}

// Swap will swap the items at index i and j
func (q queue) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].index = i
	q[j].index = j
}

// Push will add x as an item to the queue
// When using the queue, the Add method should be used instead.
func (q *queue) Push(x interface{}) {
	n := len(*q)
	e := x.(*item) //nolint:errcheck // should be an *item
	e.index = n
	*q = append(*q, e)
}

// Pop will return the last item from the queue
// When using the queue, DequeueActions should be used instead
func (q *queue) Pop() interface{} {
	old := *q
	n := len(old)
	e := old[n-1]
	old[n-1] = nil // avoid memory leak
	e.index = -1   // for safety
	*q = old[0 : n-1]
	return e
}

// newQueue creates a new priority queue using container/heap.
// Will return an error if StartTime fails for any action.
func newQueue(actions []fleetapi.Action) (*queue, error) {
	q := make(queue, len(actions))
	for i, a := range actions {
		action, ok := a.(fleetapi.ScheduledAction)
		if !ok {
			continue
		}
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

// NewActionQueue creates a new queue with the passed actions using the persistor for state storage.
func NewActionQueue(actions []fleetapi.Action, s saver) (*ActionQueue, error) {
	q, err := newQueue(actions)
	if err != nil {
		return nil, err
	}
	return &ActionQueue{
		q: q,
		s: s,
	}, nil
}

// Add will add an action to the queue with the associated priority.
// The priority is meant to be the start-time of the action as a unix epoch time.
// Complexity: O(log n)
func (q *ActionQueue) Add(action fleetapi.ScheduledAction, priority int64) {
	e := &item{
		action:   action,
		priority: priority,
	}
	heap.Push(q.q, e)
}

// DequeueActions will dequeue all actions that have a priority less then time.Now().
// Complexity: O(n*log n)
func (q *ActionQueue) DequeueActions() []fleetapi.ScheduledAction {
	ts := time.Now().Unix()
	actions := make([]fleetapi.ScheduledAction, 0)
	for q.q.Len() != 0 {
		if (*q.q)[0].priority > ts {
			break
		}
		item := heap.Pop(q.q).(*item) //nolint:errcheck // should be an *item
		actions = append(actions, item.action)
	}
	return actions
}

// Cancel will remove any actions in the queue with a matching actionID and return the number of entries cancelled.
// Complexity: O(n*log n)
func (q *ActionQueue) Cancel(actionID string) int {
	items := make([]*item, 0)
	for _, item := range *q.q {
		if item.action.ID() == actionID {
			items = append(items, item)
		}
	}
	for _, item := range items {
		heap.Remove(q.q, item.index)
	}
	return len(items)
}

// Actions returns all actions in the queue, item 0 is garunteed to be the min, the rest may not be in sorted order.
func (q *ActionQueue) Actions() []fleetapi.Action {
	actions := make([]fleetapi.Action, q.q.Len())
	for i, item := range *q.q {
		actions[i] = item.action
	}
	return actions
}

// CancelType cancels all actions in the queue with a matching action type and returns the number of entries cancelled.
func (q *ActionQueue) CancelType(actionType string) int {
	items := make([]*item, 0)
	for _, item := range *q.q {
		if item.action.Type() == actionType {
			items = append(items, item)
		}
	}
	for _, item := range items {
		heap.Remove(q.q, item.index)
	}
	return len(items)
}

// Save persists the queue to disk.
func (q *ActionQueue) Save() error {
	q.s.SetQueue(q.Actions())
	return q.s.Save()
}

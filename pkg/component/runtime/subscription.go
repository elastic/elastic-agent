// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

// Subscription provides a channel for notifications on a component state.
type Subscription struct {
	manager *Manager
	ch      chan ComponentState
}

func newSubscription(manager *Manager) *Subscription {
	return &Subscription{
		manager: manager,
		ch:      make(chan ComponentState, 1), // buffer of 1 to allow initial latestState state
	}
}

// Ch provides the channel to get state changes.
func (s *Subscription) Ch() <-chan ComponentState {
	return s.ch
}

// Unsubscribe removes the subscription.
func (s *Subscription) Unsubscribe() {
	s.manager.unsubscribe(s)
}

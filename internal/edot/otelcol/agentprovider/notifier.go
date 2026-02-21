// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package agentprovider

import "sync"

// Notifier provides broadcast-style signaling using channels. Subscribers call
// Wait to get a channel that will be closed on the next Broadcast. This avoids
// the need to track the number of subscribers or use sync.Cond.
type Notifier struct {
	mu sync.Mutex
	ch chan struct{}
}

// NewNotifier creates a ready-to-use Notifier.
func NewNotifier() *Notifier {
	return &Notifier{ch: make(chan struct{})}
}

// Wait returns a channel that will be closed on the next Broadcast.
// Subscribers select on this alongside their own done/context channels.
func (n *Notifier) Wait() <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.ch
}

// Broadcast wakes all current waiters and resets for the next round.
func (n *Notifier) Broadcast() {
	n.mu.Lock()
	defer n.mu.Unlock()
	close(n.ch)
	n.ch = make(chan struct{})
}

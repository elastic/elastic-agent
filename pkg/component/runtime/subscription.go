// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
)

// Subscription provides a channel for notifications on a component state.
type Subscription struct {
	ctx context.Context
	ch  chan ComponentState
}

func newSubscription(ctx context.Context) *Subscription {
	return &Subscription{
		ctx: ctx,
		ch:  make(chan ComponentState),
	}
}

// Ch provides the channel to get state changes.
func (s *Subscription) Ch() <-chan ComponentState {
	return s.ch
}

/*
// SubscriptionAll provides a channel for notifications on all component state changes.
type SubscriptionAll struct {
	ctx context.Context
	ch  chan ComponentComponentState
}

func newSubscriptionAll(ctx context.Context) *SubscriptionAll {
	return &SubscriptionAll{
		ctx: ctx,
		ch:  make(chan ComponentComponentState),
	}
}

// NewSubscriptionAllWithChannel creates a SubscriptionAll using an existing channel
// For Test purposes ONLY.
func NewSubscriptionAllWithChannel(ctx context.Context, evtChan chan ComponentComponentState) *SubscriptionAll {
	return &SubscriptionAll{
		ctx: ctx,
		ch:  evtChan,
	}
}

// Ch provides the channel to get state changes.
func (s *SubscriptionAll) Ch() <-chan ComponentComponentState {
	return s.ch
}
*/

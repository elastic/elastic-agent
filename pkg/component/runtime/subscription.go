package runtime

// Subscription provides a channel for notifications on a component state.
type Subscription struct {
	manager *Manager
	ch      chan ComponentState
}

func newSubscription(manager *Manager) *Subscription {
	return &Subscription{
		manager: manager,
		ch:      make(chan ComponentState, 1), // buffer of 1 to allow initial latest state
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

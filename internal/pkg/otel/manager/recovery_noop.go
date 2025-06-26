package manager

import "time"

type recoveryNoop struct {
}

// newRestarterNoop returns a noop recovery timer
func newRestarterNoop() *recoveryNoop {
	return &recoveryNoop{}
}

// IsStopped returns always true
func (r *recoveryNoop) IsStopped() bool {
	return true
}

// Stop has no effect on the noop recovery timer
func (r *recoveryNoop) Stop() {
}

// ResetInitial has no effect on noop the recovery timer
func (r *recoveryNoop) ResetInitial() {
}

// C returns always nil
func (r *recoveryNoop) C() <-chan time.Time {
	return nil
}

// ResetNext has no effect on the noop recovery timer
func (r *recoveryNoop) ResetNext() {
}
